package com.github.unidbg.linux;

import capstone.api.Instruction;
import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.EventMemHook;
import com.github.unidbg.linux.signal.Arm64SignalFrame;
import com.github.unidbg.linux.signal.PendingSigSet;
import com.github.unidbg.linux.signal.SigAction;
import com.github.unidbg.linux.signal.SigAction64;
import com.github.unidbg.linux.signal.SigInfo;
import com.github.unidbg.linux.signal.SignalFrameTask;
import com.github.unidbg.linux.signal.ThreadSignalState;
import com.github.unidbg.linux.thread.AndroidWaiter;
import com.github.unidbg.memory.MemoryMap;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.signal.SigSet;
import com.github.unidbg.signal.SignalOps;
import com.github.unidbg.signal.SignalTask;
import com.github.unidbg.signal.UnixSigSet;
import com.github.unidbg.thread.RunnableTask;
import com.github.unidbg.thread.Task;
import com.github.unidbg.thread.ThreadContextSwitchException;
import com.github.unidbg.thread.ThreadTask;
import com.github.unidbg.thread.Waiter;
import com.github.unidbg.unix.UnixEmulator;
import com.github.unidbg.unix.struct.TimeSpec;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import unicorn.Arm64Const;
import unicorn.UnicornConst;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;

/**
 * The arm64 signal model of the backends with system register access (unicorn2): unidbg's own signal plumbing
 * completed to the kernel's semantics (doc/signal-delivery-fidelity.md, doc/diff-02-signal-delivery.md).
 * <p>
 * Dispositions stay in {@link AndroidSyscallHandler}'s sigActionMap, the blocked mask and the pending set in each
 * thread's {@link SignalOps} (the pending set as a {@link PendingSigSet}, which also keeps the siginfo). A signal that
 * may be delivered is queued on its {@link Task} as a {@link SignalFrameTask} with {@link Task#addSignalTask}, which
 * also ends the task's interruptible wait. It is delivered when the thread next enters user mode ({@link
 * #deliverPendingSignals}, called by AbstractEmulator#emulate through SignalDeliverer): a rt_sigframe on the thread's
 * own stack, the thread continuing in the handler, rt_sigreturn restoring the frame. A hook that raises a signal for
 * the running thread stops emulation, so this happens before the next guest instruction.
 * <p>
 * {@link ARM64SyscallHandler} parses the syscalls and falls back to unidbg's original implementation for whatever this
 * model does not cover.
 */
class Arm64Signals {

    private static final Logger log = LoggerFactory.getLogger(Arm64Signals.class);

    private static final long SIG_DFL = 0;
    private static final long SIG_IGN = 1;
    private static final int SA_RESTORER = 0x04000000;
    private static final int SA_ONSTACK = 0x08000000;
    private static final int SA_NODEFER = 0x40000000;
    private static final int SA_RESETHAND = 0x80000000;
    private static final long UNBLOCKABLE = (1L << (9 - 1)) | (1L << (19 - 1)); // SIGKILL, SIGSTOP
    private static final int SIG_BLOCK = 0;
    private static final int SIG_UNBLOCK = 1;
    private static final int SIG_SETMASK = 2;
    private static final int SIGSEGV = 11;
    private static final int SEGV_MAPERR = 1;
    private static final int SEGV_ACCERR = 2;
    /** a handler that keeps returning to a fault it does not repair would loop forever: stop after this many rounds */
    private static final int MAX_FAULT_RETRIES = 64;

    private final ARM64SyscallHandler handler;
    private final SvcMemory svcMemory;

    /** signals pending for the process as a whole, blocked by every thread (the kernel's shared_pending) */
    private final PendingSigSet sharedPending = new PendingSigSet();
    private final Map<Integer, ThreadSignalState> states = new HashMap<>();
    /**
     * Threads created by clone, until they are destroyed: the dispatcher lists a new thread among its tasks only once
     * it has been scheduled, but it can receive signals from the moment it exists.
     */
    private final Map<Integer, ThreadTask> threads = new HashMap<>();
    private boolean deliveryRequested;
    /** rt_sigreturn waiting to be applied once emulation has stopped */
    private boolean sigreturnPending;
    /** a signal's default action terminated the process */
    private boolean terminated;
    private long trampoline;
    /** the last memory fault the engine reported during this emu_start, delivered if the engine stops on it */
    private MemoryFault pendingMemoryFault;
    // the retry guard: the last fault, and whether its handler returned to it with nothing in between
    private int lastFaultSigno;
    private long lastFaultPc;
    private long lastFaultAddress;
    private int faultRetries;
    private boolean returnedToFault;

    Arm64Signals(ARM64SyscallHandler handler, SvcMemory svcMemory) {
        this.handler = handler;
        this.svcMemory = svcMemory;
    }

    // --- threads and their signal state ---

    private static Task currentTask(Emulator<?> emulator) {
        return emulator.get(Task.TASK_KEY);
    }

    /** the main thread keeps its signal state in the dispatcher, other threads in their task (as unidbg does) */
    private static SignalOps opsOf(Emulator<?> emulator, Task task) {
        return task.isMainThread() ? emulator.getThreadDispatcher() : task;
    }

    private static SignalOps currentOps(Emulator<?> emulator) {
        Task task = currentTask(emulator);
        return task == null ? emulator.getThreadDispatcher() : opsOf(emulator, task);
    }

    private static long blocked(SignalOps ops) {
        SigSet mask = ops.getSigMaskSet();
        return mask == null ? 0 : mask.getMask();
    }

    private static void setBlocked(SignalOps ops, long mask) {
        ops.setSigMaskSet(new UnixSigSet(mask & ~UNBLOCKABLE));
    }

    private ThreadSignalState state(Emulator<?> emulator) {
        Task task = currentTask(emulator);
        return state(task == null ? emulator.getPid() : task.getId());
    }

    private ThreadSignalState state(int tid) {
        ThreadSignalState state = states.get(tid);
        if (state == null) {
            state = new ThreadSignalState();
            states.put(tid, state);
        }
        return state;
    }

    /** every live thread: the dispatcher's unfinished tasks, and the threads clone created that have not run yet */
    private List<Task> liveTasks(Emulator<?> emulator) {
        List<Task> tasks = new ArrayList<>();
        for (Task task : emulator.getThreadDispatcher().getTaskList()) {
            if (!task.isFinish()) {
                tasks.add(task);
            }
        }
        for (ThreadTask thread : threads.values()) {
            if (!thread.isFinish() && !tasks.contains(thread)) {
                tasks.add(thread);
            }
        }
        return tasks;
    }

    private Task findTask(Emulator<?> emulator, int tid) {
        for (Task task : liveTasks(emulator)) {
            if (task.getId() == tid) {
                return task;
            }
        }
        return null;
    }

    boolean threadExists(Emulator<?> emulator, int tid) {
        return findTask(emulator, tid) != null;
    }

    /** clone: the new thread inherits the creator's blocked mask */
    void threadCreated(Emulator<?> emulator, final ThreadTask thread) {
        thread.setSigMaskSet(new UnixSigSet(blocked(currentOps(emulator))));
        final int tid = thread.getId();
        threads.put(tid, thread);
        thread.setDestroyListener(e -> {
            threads.remove(tid);
            states.remove(tid);
        });
    }

    /** a blocking signal wait can only end if another live thread may send the signal */
    private boolean canWait(Emulator<?> emulator) {
        return handler.isThreadDispatcherEnabled() && emulator.getThreadDispatcher().getRunningTask() != null &&
                liveTasks(emulator).size() > 1;
    }

    // --- generation ---

    /** kill, rt_sigqueueinfo: a signal for the process */
    int sendToProcess(Emulator<?> emulator, SigInfo info) {
        Task receiver = chooseReceiver(emulator, info.bit());
        if (receiver == null) {
            sharedPending.add(info);
        } else {
            send(emulator, receiver, info);
        }
        return 0;
    }

    /** tkill, tgkill, rt_tgsigqueueinfo: a signal for one thread */
    int sendToThread(Emulator<?> emulator, int tid, SigInfo info) {
        Task receiver = findTask(emulator, tid);
        if (receiver == null) {
            return -UnixEmulator.ESRCH;
        }
        send(emulator, receiver, info);
        return 0;
    }

    /**
     * The kernel's complete_signal(): the main thread if it wants the signal, else the first other thread that does
     * (the sending thread first). A thread waiting for the signal in rt_sigtimedwait wants it although it blocks it.
     */
    private Task chooseReceiver(Emulator<?> emulator, long bit) {
        List<Task> live = liveTasks(emulator);
        List<Task> candidates = new ArrayList<>(live.size());
        for (Task task : live) {
            if (task.isMainThread()) {
                candidates.add(task);
            }
        }
        Task current = currentTask(emulator);
        if (current != null && live.contains(current) && !candidates.contains(current)) {
            candidates.add(current);
        }
        for (Task task : live) {
            if (!candidates.contains(task)) {
                candidates.add(task);
            }
        }
        for (Task task : candidates) {
            if ((blocked(opsOf(emulator, task)) & bit) == 0 || (state(task.getId()).waitingMask & bit) != 0) {
                return task;
            }
        }
        return null;
    }

    /** a blocked signal stays pending until the mask lets it through; otherwise it is queued on its receiver */
    private void send(Emulator<?> emulator, Task receiver, SigInfo info) {
        SignalOps ops = opsOf(emulator, receiver);
        if ((blocked(ops) & info.bit()) != 0) {
            PendingSigSet.of(ops).add(info);
        } else {
            queue(emulator, receiver, info);
        }
    }

    /**
     * The signal is not blocked by its receiver: apply the disposition. Ignored (SIG_IGN, or SIG_DFL of a signal whose
     * default is to ignore or to stop): discarded. A handler: queued on the task (a standard signal at most once),
     * which also ends the task's interruptible wait; delivered before the next instruction if the receiver is the
     * running thread. Any other SIG_DFL: the default action terminates the process.
     */
    private void queue(Emulator<?> emulator, Task receiver, SigInfo info) {
        long sigHandler = handlerOf(info.signo);
        if (isIgnored(info.signo, sigHandler)) {
            return;
        }
        if (sigHandler == SIG_DFL) {
            terminate(emulator, info);
            return;
        }
        if (!info.isRealtime() && isQueued(receiver, info.signo)) {
            return;
        }
        receiver.addSignalTask(new SignalFrameTask(emulator, info));
        if (receiver == currentTask(emulator)) {
            requestDelivery(emulator);
        } else {
            interruptWait(emulator, receiver);
        }
    }

    private static boolean isQueued(Task task, int signo) {
        for (SignalTask signalTask : task.getSignalTaskList()) {
            if (signalTask instanceof SignalFrameTask && ((SignalFrameTask) signalTask).getInfo().signo == signo) {
                return true;
            }
        }
        return false;
    }

    /**
     * A signal to deliver ends an interruptible wait. unidbg's nanosleep waiter does that itself (Waiter#onSignal); a
     * futex wait does not, so it is ended here with -EINTR, as the kernel's futex_wait() is.
     */
    private static void interruptWait(Emulator<?> emulator, Task task) {
        final Waiter waiter = task.getWaiter();
        if (waiter != null && !(waiter instanceof Interrupted) && !waiter.canDispatch()) {
            task.setWaiter(emulator, new Interrupted(waiter));
        }
    }

    private static class Interrupted extends AndroidWaiter {
        private final Waiter waiter;

        Interrupted(Waiter waiter) {
            this.waiter = waiter;
        }

        @Override
        public boolean canDispatch() {
            return true;
        }

        @Override
        public void onContinueRun(Emulator<?> emulator) {
            if (waiter.canDispatch()) { // the wait completed anyway
                waiter.onContinueRun(emulator);
            } else {
                emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_X0, -UnixEmulator.EINTR);
            }
        }
    }

    /** the default action of the signal terminates the process: emulation stops with the reason, like exit_group */
    private void terminate(Emulator<?> emulator, SigInfo info) {
        String reason = signalName(info.signo) + " " + info + ": no handler installed, the default action terminates the process";
        log.warn("{}, emulation stopped at {}", reason, emulator.getContext().getPCPointer());
        if (LoggerFactory.getLogger(AbstractEmulator.class).isDebugEnabled()) {
            handler.breaker(emulator).debug(reason);
        }
        terminated = true;
        requestDelivery(emulator);
    }

    private long handlerOf(int signo) {
        SigAction action = handler.getSigAction(signo);
        return action == null ? SIG_DFL : action.getSaHandler();
    }

    private static boolean isIgnored(int signo, long sigHandler) {
        return sigHandler == SIG_IGN || (sigHandler == SIG_DFL && isIgnoredByDefault(signo)) ||
                (sigHandler == SIG_DFL && signo >= 19 && signo <= 22); // SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU: no job control
    }

    private static boolean isIgnoredByDefault(int signo) {
        return signo == 17 || signo == 18 || signo == 23 || signo == 28; // SIGCHLD, SIGCONT, SIGURG, SIGWINCH
    }

    /** after a mask change: what the new mask lets through is queued (the kernel's recalc_sigpending + do_signal) */
    private void deliverUnblocked(Emulator<?> emulator, Task task) {
        SignalOps ops = opsOf(emulator, task);
        PendingSigSet pending = PendingSigSet.of(ops);
        SigInfo info;
        while ((info = takeAllowed(pending, ~blocked(ops))) != null) {
            queue(emulator, task, info);
        }
    }

    private SigInfo takeAllowed(PendingSigSet pending, long allowed) {
        SigInfo info = pending.take(allowed);
        return info == null ? sharedPending.take(allowed) : info;
    }

    /**
     * A synchronous fault of the running thread (SIGILL for an UNDEF or an EL0-illegal system instruction, SIGTRAP for
     * BRK), as force_sig_fault(): called from a backend hook, it queues the signal and stops emulation so that the
     * handler runs before any later instruction, with uc_mcontext.pc = the faulting instruction (re-executed unless the
     * handler moves on, or leaves with siglongjmp).
     *
     * @return false if the fault is fatal for the guest — no handler (SIG_DFL/SIG_IGN), or the signal blocked (a SIGILL
     * inside the SIGILL handler) — where the kernel would kill the process: a warning is logged and the caller goes on
     * with unidbg's original handling (the Breaker)
     */
    boolean raiseSyncFault(Emulator<?> emulator, int sig, int siCode, long pc, long esr) {
        Task task = currentTask(emulator);
        String fatal = retriesExhausted(emulator, sig, pc, 0, false) ? "the handler keeps returning to it without repairing it" :
                whyFatal(emulator, task, sig);
        if (fatal != null) {
            log.warn("{} (si_code={}) at {} \"{}\": {}; on a device the default action terminates the process",
                    signalName(sig), siCode, UnidbgPointer.pointer(emulator, pc), describeInstruction(emulator, pc), fatal);
            return false;
        }
        task.addSignalTask(new SignalFrameTask(emulator, SigInfo.fault(sig, siCode, pc, esr)));
        requestDelivery(emulator);
        return true;
    }

    /** why a fault of the running thread cannot go to a guest handler (the kernel would kill the process), or null */
    private String whyFatal(Emulator<?> emulator, Task task, int sig) {
        long sigHandler = handlerOf(sig);
        return task == null ? "no running task" :
                sigHandler == SIG_DFL ? "no handler installed" :
                sigHandler == SIG_IGN ? "ignored, which the kernel overrides for a fault" :
                (blocked(opsOf(emulator, task)) & (1L << (sig - 1))) != 0 ? "blocked (raised inside its own handler?)" :
                !emulator.isRunning() ? "raised outside AbstractEmulator#emulate" : null;
    }

    /**
     * A memory fault of the running thread, from the engine's unmapped / protection hooks (SIGSEGV with SEGV_MAPERR or
     * SEGV_ACCERR, si_addr = uc_mcontext.fault_address = the address, the target pc for an instruction fetch). Only noted
     * here: every other hook still runs (unidbg's own report, and the user's hooks, which may handle the access). If the
     * engine then stops on it — at the faulting instruction, with the guest state restored to it — {@link #deliverFault}
     * delivers the signal with uc_mcontext.pc = that instruction, which a handler that repaired the mapping (mprotect,
     * mmap) returns to and re-executes. Without a handler that can take it, unidbg's original error follows, after a
     * warning saying why.
     *
     * @return true for a read the page permission denies but the architecture allows (write or execute permission
     * implies read on arm64 Linux): the engine performs it
     */
    boolean memoryFault(Emulator<?> emulator, long address, EventMemHook.UnmappedType access, boolean unmapped) {
        if (!unmapped && access == EventMemHook.UnmappedType.Read && isReadImplied(emulator, address)) {
            return true;
        }
        pendingMemoryFault = null;
        int code = unmapped ? SEGV_MAPERR : SEGV_ACCERR;
        String fatal = retriesExhausted(emulator, SIGSEGV, 0, address, true) ? "the handler keeps returning to it without repairing it" :
                whyFatal(emulator, currentTask(emulator), SIGSEGV);
        if (fatal != null) {
            log.warn("SIGSEGV ({}) on {} of 0x{}: {}; on a device the default action terminates the process",
                    unmapped ? "SEGV_MAPERR" : "SEGV_ACCERR", access, Long.toHexString(address), fatal);
            return false;
        }
        pendingMemoryFault = new MemoryFault(address, access, code);
        return false;
    }

    /**
     * Memory faults stay emulation errors (the backend factory's default): if the guest has a SIGSEGV handler, say how to
     * deliver them to it instead.
     */
    void suggestMemoryFaultSignals(Emulator<?> emulator) {
        long sigHandler = handlerOf(SIGSEGV);
        if (sigHandler != SIG_DFL && sigHandler != SIG_IGN) {
            log.warn("the guest has a SIGSEGV handler (0x{}); the invalid memory access below goes to it with " +
                    "new Unicorn2Factory(...).setMemoryFaultSignals(true)", Long.toHexString(sigHandler));
        }
    }

    private static boolean isReadImplied(Emulator<?> emulator, long address) {
        for (MemoryMap map : emulator.getMemory().getMemoryMap()) {
            if (address >= map.base && address < map.base + map.size) {
                return (map.prot & (UnicornConst.UC_PROT_WRITE | UnicornConst.UC_PROT_EXEC)) != 0;
            }
        }
        return false;
    }

    /**
     * Emulation stopped with a backend error: if it is the memory fault noted by {@link #memoryFault}, the backend stopped
     * at the faulting instruction (pc) and the signal is delivered.
     *
     * @return where the thread continues, -1 if a default action terminated the process, or null for any other error
     */
    Long deliverFault(Emulator<?> emulator, BackendException error, long pc) {
        MemoryFault fault = pendingMemoryFault;
        pendingMemoryFault = null;
        Task task = currentTask(emulator);
        if (fault == null || task == null || !String.valueOf(error.getMessage()).contains(fault.errorCode())) {
            return null;
        }
        // a fetch fault happens at the target itself
        pc = fault.access == EventMemHook.UnmappedType.Fetch ? fault.address : pc;
        task.addSignalTask(new SignalFrameTask(emulator, SigInfo.memoryFault(SIGSEGV, fault.code, pc, fault.address, fault.esr())));
        return deliverPendingSignals(emulator, pc);
    }

    /**
     * A prefetch abort: a jump to an address the CPU cannot translate (above the physical address range, e.g. a return
     * address a failed pointer authentication poisoned). SIGSEGV/SEGV_MAPERR at the target, as on a device.
     *
     * @return false if the fault is fatal for the guest (unidbg's original handling follows)
     */
    boolean instructionAbort(Emulator<?> emulator, long pc) {
        Task task = currentTask(emulator);
        String fatal = retriesExhausted(emulator, SIGSEGV, pc, pc, true) ? "the handler keeps returning to it without repairing it" :
                whyFatal(emulator, task, SIGSEGV);
        if (fatal != null) {
            log.warn("SIGSEGV (SEGV_MAPERR) on a jump to 0x{}: {}; on a device the default action terminates the process",
                    Long.toHexString(pc), fatal);
            return false;
        }
        MemoryFault fault = new MemoryFault(pc, EventMemHook.UnmappedType.Fetch, SEGV_MAPERR);
        task.addSignalTask(new SignalFrameTask(emulator, SigInfo.memoryFault(SIGSEGV, SEGV_MAPERR, pc, pc, fault.esr())));
        requestDelivery(emulator);
        return true;
    }

    /**
     * A handler that returns to its fault without repairing it makes the instruction fault again, forever (on a device
     * too). After {@link #MAX_FAULT_RETRIES} such rounds in a row — same signal, same instruction (a memory fault: same
     * address), the handler having returned to it with no syscall in between — the fault is treated as fatal instead:
     * unidbg's original error, not a hang.
     */
    private boolean retriesExhausted(Emulator<?> emulator, int signo, long pc, long address, boolean memory) {
        boolean same = returnedToFault && signo == lastFaultSigno && (memory ? address == lastFaultAddress : pc == lastFaultPc);
        faultRetries = same ? faultRetries + 1 : 0;
        if (faultRetries < MAX_FAULT_RETRIES) {
            return false;
        }
        log.warn("{} at 0x{}: the handler returned {} times without repairing the fault (on a device this loops forever)",
                signalName(signo), Long.toHexString(memory ? address : pc), faultRetries);
        faultRetries = 0;
        returnedToFault = false;
        return true;
    }

    private static class MemoryFault {
        final long address;
        final EventMemHook.UnmappedType access;
        final int code;

        MemoryFault(long address, EventMemHook.UnmappedType access, int code) {
            this.address = address;
            this.access = access;
            this.code = code;
        }

        /** the backend error the engine reports for it */
        String errorCode() {
            return "UC_ERR_" + access.name().toUpperCase() + (code == SEGV_MAPERR ? "_UNMAPPED" : "_PROT");
        }

        /** ESR of an abort from EL0: data abort (EC 0x24, WnR for a write) or instruction abort (EC 0x20) */
        long esr() {
            long ec = access == EventMemHook.UnmappedType.Fetch ? 0x20 : 0x24;
            long fsc = code == SEGV_MAPERR ? 0x07 : 0x0f; // translation / permission fault, level 3
            long wnr = access == EventMemHook.UnmappedType.Write ? 1L << 6 : 0;
            return (ec << 26) | (1L << 25) | wnr | fsc;
        }
    }

    /** a syscall ran: progress since a handler returned to its fault (the retry guard does not count the next one) */
    void syscallMade() {
        returnedToFault = false;
    }

    // --- delivery ---

    /** a hook or syscall queued a signal for the running thread: deliver it before the next guest instruction */
    private void requestDelivery(Emulator<?> emulator) {
        deliveryRequested = true;
        if (emulator.isRunning()) {
            emulator.getBackend().emu_stop();
        }
    }

    boolean takeDeliveryRequest() {
        boolean requested = deliveryRequested;
        deliveryRequested = false;
        return requested;
    }

    /**
     * The kernel's do_signal() on the way back to user mode: a pending rt_sigreturn is applied first (the mask it
     * restores may release pending signals), then every signal queued on the running thread enters its handler in
     * the kernel's dequeue order; several stack several frames, the last one running first. The disposition is read
     * now, as the kernel reads it at delivery.
     *
     * @return where the thread continues, or -1 if a default action terminated the process
     */
    long deliverPendingSignals(Emulator<?> emulator, long pc) {
        pendingMemoryFault = null; // a fault some hook handled during the last emu_start
        Task task = currentTask(emulator);
        if (task != null) {
            if (sigreturnPending) {
                sigreturnPending = false;
                pc = applySigreturn(emulator, task);
            }
            pc = enterHandlers(emulator, task, pc);
        }
        deliveryRequested = false;
        if (terminated) {
            terminated = false;
            return -1;
        }
        return pc;
    }

    private long enterHandlers(Emulator<?> emulator, Task task, long pc) {
        List<SignalFrameTask> queued = new ArrayList<>();
        for (SignalTask signalTask : task.getSignalTaskList()) {
            if (signalTask instanceof SignalFrameTask) {
                queued.add((SignalFrameTask) signalTask);
            }
        }
        ThreadSignalState state = state(task.getId());
        if (!queued.isEmpty()) {
            queued.sort(Comparator.comparingInt(signalTask -> signalTask.getInfo().priority()));
            emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_PC, pc);
            SignalOps ops = opsOf(emulator, task);
            for (SignalFrameTask signalTask : queued) {
                task.removeSignalTask(signalTask);
                signalTask.destroy(emulator);
                if (!terminated) {
                    enterHandler(emulator, ops, state, signalTask.getInfo());
                }
            }
            pc = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_PC).longValue();
        }
        if (state.suspendSavedMask != null) { // rt_sigsuspend returned without a handler running
            setBlocked(opsOf(emulator, task), state.suspendSavedMask);
            state.suspendSavedMask = null;
        }
        return pc;
    }

    /**
     * The kernel's handle_signal(): pushes the frame with the interrupted context (for a fault, pc = the faulting
     * instruction), enters the handler, blocks sa_mask and the signal itself (unless SA_NODEFER) and applies
     * SA_RESETHAND. A signal the previous frame's handler now blocks goes back to the pending set.
     */
    private void enterHandler(Emulator<?> emulator, SignalOps ops, ThreadSignalState state, SigInfo info) {
        SigAction action = handler.getSigAction(info.signo);
        long sigHandler = action == null ? SIG_DFL : action.getSaHandler();
        if (isIgnored(info.signo, sigHandler)) {
            return;
        }
        if (sigHandler == SIG_DFL) {
            terminate(emulator, info);
            return;
        }
        long blocked = blocked(ops);
        if ((blocked & info.bit()) != 0) {
            PendingSigSet.of(ops).add(info);
            return;
        }
        if (info.fault) {
            lastFaultSigno = info.signo;
            lastFaultPc = info.pc;
            lastFaultAddress = info.faultAddress;
            returnedToFault = false;
        }
        // rt_sigsuspend: the frame saves, and rt_sigreturn restores, the mask from before the call
        long saved = state.suspendSavedMask != null ? state.suspendSavedMask : blocked;
        state.suspendSavedMask = null;
        int flags = action.getFlags();
        long pc = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_PC).longValue();
        long restorer = (flags & SA_RESTORER) != 0 && saRestorer(action) != 0 ? saRestorer(action) : getTrampoline();
        try {
            Arm64SignalFrame.push(emulator, info, info.fault ? info.pc : pc, saved, sigHandler, restorer, state,
                    (flags & SA_ONSTACK) != 0, handler.getSveVectorLength());
        } catch (RuntimeException e) {
            log.warn("{}: the signal frame cannot be written ({}); on a device the process is killed, emulation stopped",
                    info, e.getMessage());
            terminated = true;
            return;
        }
        long mask = blocked | saMask(action);
        if ((flags & SA_NODEFER) == 0) {
            mask |= info.bit();
        }
        setBlocked(ops, mask);
        if ((flags & SA_RESETHAND) != 0) {
            action.setSaHandler(SIG_DFL);
        }
    }

    /*
     * SigAction64 keeps unidbg's field order (handler, flags, mask, restorer); the arm64 kernel's struct sigaction is
     * (handler, flags, restorer, mask). The two are read by their kernel offsets, so a real libc's sa_mask works here
     * while every other code path keeps its behaviour.
     */
    private static long saMask(SigAction action) {
        return action instanceof SigAction64 ? action.getSaRestorer() : action.getMask();
    }

    private static long saRestorer(SigAction action) {
        return action instanceof SigAction64 ? action.getMask() : action.getSaRestorer();
    }

    /** the vDSO's __kernel_rt_sigreturn: "mov x8, #__NR_rt_sigreturn; svc #0" */
    private long getTrampoline() {
        if (trampoline == 0) {
            UnidbgPointer pointer = svcMemory.allocate(8, "__kernel_rt_sigreturn");
            pointer.setInt(0, 0xd2801168); // mov x8, #139
            pointer.setInt(4, 0xd4000001); // svc #0
            trampoline = pointer.peer;
        }
        return trampoline;
    }

    /**
     * rt_sigreturn: restores the context from the frame at SP; x0 is restored with it (no return value). Inside
     * emulation the restore happens once emulation has stopped: writing PC from a hook makes unicorn continue at the
     * new PC and ignore a stop request, so a signal the restored mask releases could not be delivered right after the
     * return. (Outside AbstractEmulator#emulate, when the backend is driven directly, it happens at once.)
     */
    void rtSigreturn(Emulator<?> emulator) {
        Task task = currentTask(emulator);
        if (emulator.isRunning()) {
            sigreturnPending = true;
            requestDelivery(emulator);
        } else if (task != null) {
            applySigreturn(emulator, task);
        }
    }

    private long applySigreturn(Emulator<?> emulator, Task task) {
        setBlocked(opsOf(emulator, task), Arm64SignalFrame.restore(emulator, state(task.getId())));
        long pc = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_PC).longValue();
        returnedToFault = pc == lastFaultPc;
        deliverUnblocked(emulator, task);
        return pc;
    }

    // --- masks, pending signals, waits ---

    /** rt_sigprocmask: SETMASK leaves pending signals alone, oldset is always written, released signals are delivered */
    int sigprocmask(Emulator<?> emulator, int how, Pointer set, Pointer oldset) {
        SignalOps ops = currentOps(emulator);
        long old = blocked(ops);
        if (set != null) {
            long mask = set.getLong(0);
            long now;
            switch (how) {
                case SIG_BLOCK:
                    now = old | mask;
                    break;
                case SIG_UNBLOCK:
                    now = old & ~mask;
                    break;
                case SIG_SETMASK:
                    now = mask;
                    break;
                default:
                    return -UnixEmulator.EINVAL;
            }
            setBlocked(ops, now);
            Task task = currentTask(emulator);
            if (task != null) {
                deliverUnblocked(emulator, task);
            }
        }
        if (oldset != null) {
            oldset.setLong(0, old);
        }
        return 0;
    }

    /** rt_sigpending: the blocked signals pending for the thread and for the process */
    int rtSigpending(Emulator<?> emulator, Pointer set) {
        SignalOps ops = currentOps(emulator);
        if (set != null) {
            set.setLong(0, (PendingSigSet.of(ops).getMask() | sharedPending.getMask()) & blocked(ops));
        }
        return 0;
    }

    /**
     * rt_sigtimedwait: takes a pending signal of the set. Otherwise, with another thread alive that could send one,
     * waits (until the timeout, if any): the set is blocked meanwhile so that those signals stay pending for the wait
     * instead of running a handler (the kernel's real_blocked), and a handler for another signal ends it with -EINTR.
     *
     * @return the result, or null for an untimed wait nothing can end (unidbg's original handling reports it)
     */
    Integer rtSigtimedwait(Emulator<?> emulator, Pointer set, final Pointer info, Pointer timeout) {
        final long mask = set.getLong(0) & ~UNBLOCKABLE;
        final Task task = currentTask(emulator);
        final SignalOps ops = currentOps(emulator);
        SigInfo received = takeAllowed(PendingSigSet.of(ops), mask);
        if (received != null) {
            if (info != null) {
                received.write((UnidbgPointer) info);
            }
            return received.signo;
        }
        final long waitMillis = timeout == null ? -1 : TimeSpec.createTimeSpec(emulator, timeout).toMillis();
        final long deadline = handler.deadline(emulator, timeout);
        if (waitMillis == 0 || task == null || !canWait(emulator)) {
            if (timeout == null) {
                return null;
            }
            handler.waitedUntil(deadline); // nothing can send a signal: the kernel waits the whole timeout
            return -UnixEmulator.EAGAIN;
        }
        final long old = blocked(ops);
        final long start = System.currentTimeMillis();
        final ThreadSignalState state = state(task.getId());
        setBlocked(ops, old | mask);
        state.waitingMask = mask;
        RunnableTask runningTask = emulator.getThreadDispatcher().getRunningTask();
        final VirtualClock clock = handler.clock();
        runningTask.setWaiter(emulator, new SignalWaiter(deadline, () -> ((PendingSigSet.of(ops).getMask() | sharedPending.getMask()) & mask) != 0 ||
                !task.getSignalTaskList().isEmpty() || (deadline >= 0 ? clock.nanos() >= deadline :
                waitMillis > 0 && System.currentTimeMillis() - start >= waitMillis)) {
            @Override
            public void onContinueRun(Emulator<?> emulator) {
                SigInfo taken = takeAllowed(PendingSigSet.of(ops), mask);
                state.waitingMask = 0;
                setBlocked(ops, old);
                if (taken != null && info != null) {
                    taken.write((UnidbgPointer) info);
                }
                int ret = taken != null ? taken.signo : task.getSignalTaskList().isEmpty() ? -UnixEmulator.EAGAIN : -UnixEmulator.EINTR;
                if (ret == -UnixEmulator.EAGAIN) {
                    handler.waitedUntil(deadline);
                }
                emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_X0, ret);
                deliverUnblocked(emulator, task);
            }
        });
        throw new ThreadContextSwitchException();
    }

    /** rt_sigsuspend: waits with a temporary mask until a handler runs; that handler's frame saves the original mask */
    int rtSigsuspend(Emulator<?> emulator, Pointer set) {
        final Task task = currentTask(emulator);
        if (task == null) {
            return -UnixEmulator.EINTR;
        }
        SignalOps ops = opsOf(emulator, task);
        ThreadSignalState state = state(task.getId());
        state.suspendSavedMask = blocked(ops);
        setBlocked(ops, set.getLong(0));
        deliverUnblocked(emulator, task);
        if (!task.getSignalTaskList().isEmpty()) {
            return -UnixEmulator.EINTR;
        }
        if (canWait(emulator)) {
            emulator.getThreadDispatcher().getRunningTask().setWaiter(emulator, new SignalWaiter(-1, () -> !task.getSignalTaskList().isEmpty()));
            throw new ThreadContextSwitchException().setReturnValue(-UnixEmulator.EINTR);
        }
        // nothing deliverable and nothing able to send: the real call would block forever
        setBlocked(ops, state.suspendSavedMask);
        state.suspendSavedMask = null;
        log.warn("rt_sigsuspend would block forever: nothing can send a signal, LR={}", emulator.getContext().getLRPointer());
        if (LoggerFactory.getLogger(AbstractEmulator.class).isDebugEnabled()) {
            emulator.attach().debug("rt_sigsuspend would block forever");
        }
        return -UnixEmulator.EINTR;
    }

    private static class SignalWaiter extends AndroidWaiter implements GuestWaits.Timed {
        private final long deadline;
        private final BooleanSupplier ready;

        /** @param deadline the guest's CLOCK_MONOTONIC deadline of a timed wait, -1 without one (or without the clock) */
        SignalWaiter(long deadline, BooleanSupplier ready) {
            this.deadline = deadline;
            this.ready = ready;
        }

        @Override
        public long deadline() {
            return deadline;
        }

        @Override
        public boolean canDispatch() {
            if (ready.getAsBoolean()) {
                return true;
            }
            Thread.yield();
            return false;
        }
    }

    /**
     * nanosleep interrupted by a signal also writes the remaining time back to rem (on the guest's clock: deadline, -1
     * without it). Called right after unidbg's nanosleep put the running task to sleep: its waiter is wrapped.
     */
    void writeRemainingTimeOnSignal(Emulator<?> emulator, long deadline) {
        RunnableTask task = emulator.getThreadDispatcher().getRunningTask();
        Pointer rem = emulator.getContext().getPointerArg(1);
        if (task != null && task.getWaiter() != null && rem != null) {
            long waitMillis = TimeSpec.createTimeSpec(emulator, emulator.getContext().getPointerArg(0)).toMillis();
            task.setWaiter(emulator, new RemainingTime(task.getWaiter(), emulator, rem, waitMillis, deadline));
        }
    }

    private class RemainingTime implements Waiter {
        private final Waiter sleep;
        private final Emulator<?> emulator;
        private final Pointer rem;
        private final long waitMillis;
        private final long startMillis = System.currentTimeMillis();
        private final long deadline;

        RemainingTime(Waiter sleep, Emulator<?> emulator, Pointer rem, long waitMillis, long deadline) {
            this.sleep = sleep;
            this.emulator = emulator;
            this.rem = rem;
            this.waitMillis = waitMillis;
            this.deadline = deadline;
        }

        @Override
        public boolean canDispatch() {
            return sleep.canDispatch();
        }

        @Override
        public void onContinueRun(Emulator<?> emulator) {
            sleep.onContinueRun(emulator);
        }

        @Override
        public void onSignal(SignalTask task) {
            sleep.onSignal(task);
            VirtualClock clock = handler.clock();
            if (clock != null && deadline >= 0) {
                long remaining = Math.max(0, deadline - clock.nanos());
                rem.setLong(0, remaining / 1000000000L);
                rem.setLong(8, remaining % 1000000000L);
            } else {
                TimeSpec remaining = TimeSpec.createTimeSpec(emulator, rem);
                remaining.setMillis(Math.max(0, waitMillis - (System.currentTimeMillis() - startMillis)));
                remaining.pack();
            }
        }
    }

    /** sigaltstack: records the alternate stack (SA_ONSTACK handlers run on it) and reports the old one */
    int sigaltstack(Emulator<?> emulator, Pointer ss, Pointer oldSs) {
        ThreadSignalState state = state(emulator);
        long sp = emulator.getBackend().reg_read(Arm64Const.UC_ARM64_REG_SP).longValue();
        int oldFlags = state.altStackFlags(sp);
        long oldSp = state.getAltStackSp();
        long oldSize = state.getAltStackSize();
        if (ss != null) {
            int ret = state.setAltStack(sp, ss.getLong(0), ss.getInt(8), ss.getLong(16));
            if (ret != 0) {
                return ret;
            }
        }
        if (oldSs != null) {
            oldSs.setLong(0, oldSp);
            oldSs.setInt(8, oldFlags);
            oldSs.setLong(16, oldSize);
        }
        return 0;
    }

    /** rt_sigaction made the disposition ignore the signal: its pending instances are discarded (POSIX) */
    void dispositionChanged(Emulator<?> emulator, int signum) {
        if (!isIgnored(signum, handlerOf(signum))) {
            return;
        }
        sharedPending.discard(signum);
        for (Task task : liveTasks(emulator)) {
            PendingSigSet.of(opsOf(emulator, task)).discard(signum);
            for (SignalTask signalTask : task.getSignalTaskList()) {
                if (signalTask instanceof SignalFrameTask && ((SignalFrameTask) signalTask).getInfo().signo == signum) {
                    task.removeSignalTask(signalTask);
                    signalTask.destroy(emulator);
                }
            }
        }
    }

    // --- messages ---

    private static final String[] SIGNAL_NAMES = {null, "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT",
            "SIGBUS", "SIGFPE", "SIGKILL", "SIGUSR1", "SIGSEGV", "SIGUSR2", "SIGPIPE", "SIGALRM", "SIGTERM", "SIGSTKFLT",
            "SIGCHLD", "SIGCONT", "SIGSTOP", "SIGTSTP", "SIGTTIN", "SIGTTOU", "SIGURG", "SIGXCPU", "SIGXFSZ", "SIGVTALRM",
            "SIGPROF", "SIGWINCH", "SIGIO", "SIGPWR", "SIGSYS"};

    private static String signalName(int sig) {
        return sig > 0 && sig < SIGNAL_NAMES.length ? SIGNAL_NAMES[sig] : "signal " + sig;
    }

    /** e.g. "mrs x0, sctlr_el1" */
    private static String describeInstruction(Emulator<?> emulator, long pc) {
        try {
            Instruction[] instructions = emulator.disassemble(pc, 4, 1);
            if (instructions.length > 0) {
                return instructions[0].getMnemonic() + " " + instructions[0].getOpStr();
            }
        } catch (RuntimeException ignored) {
            // unmapped pc: no text
        }
        UnidbgPointer pointer = UnidbgPointer.pointer(emulator, pc);
        return pointer == null ? "?" : "0x" + Integer.toHexString(pointer.getInt(0));
    }

}
