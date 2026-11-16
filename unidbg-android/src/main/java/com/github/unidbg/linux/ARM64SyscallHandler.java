package com.github.unidbg.linux;

import com.github.unidbg.AbstractEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.LongJumpException;
import com.github.unidbg.StopEmulatorException;
import com.github.unidbg.Svc;
import com.github.unidbg.arm.ARM;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.EventMemHook;
import com.github.unidbg.arm.backend.SysRegBackend;
import com.github.unidbg.arm.backend.SysRegHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.context.Arm64RegisterContext;
import com.github.unidbg.arm.context.RegisterContext;
import com.github.unidbg.debugger.Breaker;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.file.linux.IOConstants;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.file.ByteArrayFileIO;
import com.github.unidbg.linux.file.DirectoryFileIO;
import com.github.unidbg.linux.file.DriverFileIO;
import com.github.unidbg.linux.file.LocalAndroidUdpSocket;
import com.github.unidbg.linux.file.LocalSocketIO;
import com.github.unidbg.linux.file.NetLinkSocket;
import com.github.unidbg.linux.file.PipedSocketIO;
import com.github.unidbg.linux.file.SocketIO;
import com.github.unidbg.linux.file.TcpSocket;
import com.github.unidbg.linux.file.UdpSocket;
import com.github.unidbg.linux.signal.SigInfo;
import com.github.unidbg.linux.struct.RLimit64;
import com.github.unidbg.linux.struct.Stat64;
import com.github.unidbg.linux.thread.MarshmallowThread;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryMap;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.signal.SignalDeliverer;
import com.github.unidbg.thread.DispatcherHooks;
import com.github.unidbg.thread.PopContextException;
import com.github.unidbg.thread.RunnableTask;
import com.github.unidbg.thread.Task;
import com.github.unidbg.thread.ThreadContextSwitchException;
import com.github.unidbg.thread.Waiter;
import com.github.unidbg.unix.IO;
import com.github.unidbg.unix.UnixEmulator;
import com.github.unidbg.unix.struct.TimeSpec;
import com.github.unidbg.utils.Inspector;
import com.sun.jna.Pointer;
import org.apache.commons.io.FilenameUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import unicorn.Arm64Const;
import unicorn.UnicornConst;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * <a href="http://androidxref.com/6.0.0_r5/xref/external/kernel-headers/original/uapi/asm-generic/unistd.h">unistd</a>
 */
public class ARM64SyscallHandler extends AndroidSyscallHandler implements SysRegHook, SignalDeliverer, DispatcherHooks {

    private static final Logger log = LoggerFactory.getLogger(ARM64SyscallHandler.class);

    private final SvcMemory svcMemory;

    public ARM64SyscallHandler(SvcMemory svcMemory) {
        super();

        this.svcMemory = svcMemory;
        this.signals = new Arm64Signals(this, svcMemory);
    }

    private static final int SIGILL = 4;
    private static final int EXCP_PREFETCH_ABORT = 3;
    private static final int SIGTRAP = 5;
    private static final int ILL_ILLOPC = 1;
    private static final int ILL_ILLOPN = 2;
    private static final int TRAP_BRKPT = 1;

    private Arm64CpuFeatures cpuFeatures;
    private long cntfrq;

    /**
     * The hooks are attached: reads what the kernel exposes to EL0 about the backend's CPU model and sets the backend's
     * EL1 controls up the way the kernel sets them for EL0 tasks.
     */
    @Override
    public void onAttach(SysRegBackend backend, Emulator<?> emulator) {
        Arm64CpuFeatures features = Arm64CpuFeatures.read(backend);
        features.configure(backend);
        cntfrq = backend.sysreg_read(3, 3, 14, 0, 0);
        cpuFeatures = features;
        log.debug("cpu features: {}", features);

        // memory faults go to the guest's SIGSEGV handler (the engine stops precisely at the faulting instruction)
        emulator.getBackend().hook_add_new(new MemoryFaultHook(true),
                UnicornConst.UC_HOOK_MEM_READ_UNMAPPED | UnicornConst.UC_HOOK_MEM_WRITE_UNMAPPED | UnicornConst.UC_HOOK_MEM_FETCH_UNMAPPED, emulator);
        backend.hook_add_protection_fault(new MemoryFaultHook(false), emulator);
        memoryFaultSignals = backend.isMemoryFaultSignals();
        // a subclass overriding one of unidbg's original signal or wait syscall methods keeps that syscall
        overridden = declaredBySubclass(new Class<?>[]{Emulator.class},
                "kill", "tgkill", "nanosleep", "futex", "sigaltstack", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueue");
        overridden.addAll(declaredBySubclass(new Class<?>[]{Emulator.class, int.class, Pointer.class, Pointer.class}, "sigprocmask", "sigaction"));
        overridden.addAll(declaredBySubclass(new Class<?>[]{Emulator.class, String.class, Pointer.class, int.class}, "readlink"));
        if (!overridden.isEmpty()) {
            log.debug("{} overrides {}: those syscalls stay unidbg's original path", getClass().getName(), overridden);
        }
        userRealtime = !declaredBySubclass(new Class<?>[0], "currentTimeMillis").isEmpty();
        attached = true;

        long count = backend.insn_count();
        if (count >= 0 && isSignalModelEnabled(emulator)) {
            clock = new VirtualClock(backend, count);
        }
    }

    /** the guest's clock, on an engine that counts instructions; null: time is the host's, as in unidbg */
    private VirtualClock clock;

    /** a subclass overrides currentTimeMillis() (e.g. to pin the time): CLOCK_REALTIME is its value, as in unidbg */
    private boolean userRealtime;

    VirtualClock clock() {
        return clock;
    }

    /** the names among {@code names} that a subclass of this handler declares with the given parameter types */
    private Set<String> declaredBySubclass(Class<?>[] parameterTypes, String... names) {
        Set<String> declared = new HashSet<>();
        for (Class<?> c = getClass(); c != ARM64SyscallHandler.class; c = c.getSuperclass()) {
            for (String name : names) {
                try {
                    c.getDeclaredMethod(name, parameterTypes);
                    declared.add(name);
                } catch (NoSuchMethodException ignored) {
                }
            }
        }
        return declared;
    }

    /** invalid memory accesses go to the guest's SIGSEGV handler (option of the backend factory), else unidbg's error */
    private boolean memoryFaultSignals;

    /**
     * Notes the fault for {@link #deliverFault} and lets every other hook run (unidbg's own report, the user's hooks,
     * which may still handle the access). Returns true only for a read the architecture allows although the page is
     * not readable: write and execute permission imply read on arm64 Linux.
     */
    private class MemoryFaultHook implements EventMemHook {
        private final boolean unmapped;

        MemoryFaultHook(boolean unmapped) {
            this.unmapped = unmapped;
        }

        @Override
        public boolean hook(Backend backend, long address, int size, long value, Object user, UnmappedType unmappedType) {
            Emulator<?> emulator = (Emulator<?>) user;
            if (!isSignalModelEnabled(emulator)) {
                return false;
            }
            if (!memoryFaultSignals) {
                signals.suggestMemoryFaultSignals(emulator);
                return false;
            }
            return signals.memoryFault(emulator, address, unmappedType, unmapped);
        }

        @Override
        public void onAttach(UnHook unHook) {
        }

        @Override
        public void detach() {
            throw new UnsupportedOperationException();
        }
    }

    /**
     * What the kernel exposes to EL0 about the backend's CPU model (ID registers, AT_HWCAP/AT_HWCAP2). <code>null</code>
     * when the backend has no system register access: then system instructions are left to the backend unchanged.
     */
    Arm64CpuFeatures getCpuFeatures() {
        return cpuFeatures;
    }

    private static int sysRegKey(int op0, int op1, int crn, int crm, int op2) {
        return SysRegHook.encode(op0, op1, crn, crm, op2);
    }

    // op0 == 3, op1 == 3: the EL0 register space. Linux leaves only these open to EL0; the rest SIGILL:
    // DAIF (SCTLR_EL1.UMA=0), CNTPCT/CNTP_*/CNTV_* (CNTKCTL_EL1 enables EL0VCTEN only), PMU (PMUSERENR_EL0.EN=0)
    private static final int CNTVCT_EL0 = sysRegKey(3, 3, 14, 0, 2);
    private static final int CNTVCTSS_EL0 = sysRegKey(3, 3, 14, 0, 6);
    private static final int PMUSERENR_EL0 = sysRegKey(3, 3, 9, 14, 0);

    /** EL0 registers the CPU model handles itself (it UNDEFs those it does not implement), MRS and MSR */
    private static final int[] EL0_READ_WRITE = {
            sysRegKey(3, 3, 4, 2, 0), // NZCV
            sysRegKey(3, 3, 4, 2, 2), // SVCR
            sysRegKey(3, 3, 4, 2, 5), // DIT
            sysRegKey(3, 3, 4, 2, 6), // SSBS
            sysRegKey(3, 3, 4, 2, 7), // TCO
            sysRegKey(3, 3, 4, 4, 0), // FPCR
            sysRegKey(3, 3, 4, 4, 1), // FPSR
            sysRegKey(3, 3, 13, 0, 2), // TPIDR_EL0
            sysRegKey(3, 3, 13, 0, 5), // TPIDR2_EL0
    };
    /** EL0 registers the CPU model handles itself, MRS only */
    private static final int[] EL0_READ_ONLY = {
            sysRegKey(3, 3, 13, 0, 3), // TPIDRRO_EL0
            sysRegKey(3, 3, 0, 0, 1), // CTR_EL0
            sysRegKey(3, 3, 0, 0, 7), // DCZID_EL0
            sysRegKey(3, 3, 14, 0, 0), // CNTFRQ_EL0
            sysRegKey(3, 3, 2, 4, 0), // RNDR
            sysRegKey(3, 3, 2, 4, 1), // RNDRRS
    };

    private static final Set<Integer> PASSTHROUGH_MRS = new HashSet<>();
    private static final Set<Integer> PASSTHROUGH_MSR = new HashSet<>();
    private static final Set<Integer> PASSTHROUGH_SYS = new HashSet<>();

    static {
        for (int key : EL0_READ_WRITE) {
            PASSTHROUGH_MRS.add(key);
            PASSTHROUGH_MSR.add(key);
        }
        for (int key : EL0_READ_ONLY) {
            PASSTHROUGH_MRS.add(key);
        }
        for (int crm = 0; crm < 16; crm++) { // MSR (immediate), crm holds the immediate
            for (int op2 = 0; op2 <= 2; op2++) {
                PASSTHROUGH_MSR.add(sysRegKey(0, 0, 4, crm, op2)); // CFINV, XAFLAG, AXFLAG
            }
            for (int op2 : new int[]{1, 2, 4}) {
                PASSTHROUGH_MSR.add(sysRegKey(0, 3, 4, crm, op2)); // SSBS, DIT, TCO
            }
        }
        // SYS #3, C7, Cm, #1: the VA-based cache maintenance EL0 may issue (SCTLR_EL1.UCI=1, DZE=1)
        for (int crm : new int[]{4, 5, 10, 11, 12, 13, 14}) { // DC ZVA, IC IVAU, DC CVAC/CVAU/CVAP/CVADP/CIVAC
            PASSTHROUGH_SYS.add(sysRegKey(1, 3, 7, crm, 1));
        }
    }

    private static Set<Integer> passthroughSet(int insn) {
        switch (insn) {
            case SysRegHook.INS_MRS:
                return PASSTHROUGH_MRS;
            case SysRegHook.INS_MSR:
                return PASSTHROUGH_MSR;
            case SysRegHook.INS_SYS:
                return PASSTHROUGH_SYS;
            default:
                return Collections.emptySet();
        }
    }

    @Override
    public int[] passthrough(int insn) {
        Set<Integer> set = passthroughSet(insn);
        int[] keys = new int[set.size()];
        int i = 0;
        for (int key : set) {
            keys[i++] = key;
        }
        return keys;
    }

    /**
     * EL0 privilege boundary for MRS/MSR/SYS/SYSL: the engine runs guest code at EL1, so every system instruction is
     * classified here the way the Linux kernel and the architecture treat it at EL0. EL0-legal encodings go to the
     * engine (which still UNDEFs whatever its CPU model does not implement; the backend may skip this hook for them,
     * see {@link #passthrough(int)}), ID registers return the kernel's user view, CNTVCT_EL0 is virtualised, and
     * everything else is a fault (SIGILL to the guest), never a passthrough to the engine's EL1 state.
     */
    @SuppressWarnings("unchecked")
    @Override
    public boolean hook(Backend backend, int insn, int op0, int op1, int crn, int crm, int op2, long[] val, Object user_data) {
        Emulator<AndroidFileIO> emulator = (Emulator<AndroidFileIO>) user_data;
        Arm64CpuFeatures features = cpuFeatures;
        int key = sysRegKey(op0, op1, crn, crm, op2);
        if (features == null || passthroughSet(insn).contains(key)) {
            return false;
        }
        if (insn == SysRegHook.INS_MRS && op0 == 3 && op1 == 0 && crn == 0) {
            // ID registers: the kernel traps and emulates EL0 reads
            Long value = features.readIdRegister(crm, op2);
            if (value == null) {
                return sysRegFault(emulator, backend);
            }
            val[0] = value;
            return true;
        }
        if (insn == SysRegHook.INS_MRS) {
            if (key == CNTVCTSS_EL0 && !features.hasEcv()) {
                return false; // not implemented by the CPU model: the engine UNDEFs it
            }
            if (key == CNTVCT_EL0 || key == CNTVCTSS_EL0) {
                val[0] = readVirtualCounter();
                return true;
            }
            if (key == PMUSERENR_EL0) {
                val[0] = 0; // readable at EL0; EN=0: the PMU is not open to EL0
                return true;
            }
        }
        // EL1/EL2/EL3 registers, debug registers, DAIFSet/DAIFClr/SPSel/PAN/UAO, DC set/way, IC IALLU, AT, TLBI...
        return sysRegFault(emulator, backend);
    }

    private long lastVirtualCounter;

    /**
     * CNTVCT_EL0: clock_gettime(CLOCK_MONOTONIC) at CNTFRQ_EL0 ticks per second, so the two agree. Strictly increasing
     * between reads: a read within the tick of the last one moves the guest's clock on to the next tick.
     */
    private long readVirtualCounter() {
        long value = ticks(monotonicNanos());
        if (value <= lastVirtualCounter) {
            value = lastVirtualCounter + 1;
            if (clock != null) {
                clock.advanceTo(nanosOfTicks(value));
            }
        }
        lastVirtualCounter = value;
        return value;
    }

    private long ticks(long ns) {
        return ns / 1000000000L * cntfrq + ns % 1000000000L * cntfrq / 1000000000L;
    }

    /** the first ns at which the counter reads ticks */
    private long nanosOfTicks(long ticks) {
        return ticks / cntfrq * 1000000000L + (ticks % cntfrq * 1000000000L + cntfrq - 1) / cntfrq;
    }

    /** CLOCK_MONOTONIC in ns: the guest's clock, else the host's time since the emulator was created (unidbg) */
    private long monotonicNanos() {
        return clock == null ? System.nanoTime() - nanoTime : clock.nanos();
    }

    /** CLOCK_REALTIME in ns: the guest's clock, unless a subclass's currentTimeMillis() decides it (unidbg) */
    private long realtimeNanos() {
        return clock == null || userRealtime ? currentTimeMillis() * 1000000L : clock.realtimeNanos();
    }

    /** unidbg's wall time (gettimeofday, and super for a subclass that overrides it): the guest's clock */
    @Override
    protected long currentTimeMillis() {
        return clock == null ? super.currentTimeMillis() : clock.realtimeNanos() / 1000000L;
    }

    /** the CLOCK_MONOTONIC deadline of a wait of timeout (a timespec), or -1 without the guest's clock */
    long deadline(Emulator<?> emulator, Pointer timeout) {
        if (clock == null || timeout == null) {
            return -1;
        }
        TimeSpec timeSpec = TimeSpec.createTimeSpec(emulator, timeout);
        return clock.nanos() + timeSpec.getTvSec() * 1000000000L + timeSpec.getTvNsec();
    }

    /** the guest waited until deadline (from {@link #deadline}) */
    void waitedUntil(long deadline) {
        if (clock != null && deadline >= 0) {
            clock.advanceTo(deadline);
        }
    }

    /**
     * The system instruction at PC is UNDEFINED at EL0: deliver SIGILL. Returns true so the engine skips it; the
     * instruction never retires and Rt keeps its value. Without a guest handler the kernel would kill the process:
     * a warning, then unidbg's own handling of an undefined instruction (the Breaker), as for EXCP_UDEF.
     */
    private boolean sysRegFault(Emulator<?> emulator, Backend backend) {
        long pc = backend.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue();
        if (log.isDebugEnabled()) {
            log.debug("EL0 UNDEFINED system instruction 0x{} at 0x{}", Integer.toHexString(readInstruction(emulator, pc)), Long.toHexString(pc));
        }
        if (!isSignalModelEnabled(emulator) || !signals.raiseSyncFault(emulator, SIGILL, ILL_ILLOPC, pc, 0)) {
            createBreaker(emulator).debug("EL0 UNDEFINED system instruction at " + UnidbgPointer.pointer(emulator, pc));
        }
        return true;
    }

    // ---------------------------------------------------------------------------------------------------------------
    // Signals (arm64): on backends with system register access the signal syscalls go to the signal model
    // (Arm64Signals: unidbg's signal plumbing completed to the kernel's semantics), which delivers to the running
    // thread through SignalDeliverer. Whatever the model does not cover, and every other backend, keeps unidbg's
    // original implementation.
    // ---------------------------------------------------------------------------------------------------------------

    private final Arm64Signals signals;

    /**
     * Whether the signal and wait syscalls use the kernel model (signals, the guest's clock): on the backends with
     * system register access (unicorn2), where it has been verified. A subclass overriding one of unidbg's syscall
     * methods for them (kill, tgkill, sigaction, nanosleep, futex...) keeps that syscall without doing anything
     * ({@link #modelHandles}); returning false here keeps all of them on unidbg's original path, and time on the host's.
     * It also covers the syscalls added for arm64 ({@link #addedSyscall}) and -ENOSYS for the unknown ones.
     */
    protected boolean isSignalModelEnabled(Emulator<?> emulator) {
        return attached && emulator.getBackend() instanceof SysRegBackend;
    }

    /** the system register hooks are attached ({@link #onAttach}): the backend has the engine the model was verified on */
    private boolean attached;

    /** whether the kernel model handles the syscall of unidbg's original method {@code original}: not if a subclass overrides it */
    private boolean modelHandles(Emulator<?> emulator, String original) {
        return isSignalModelEnabled(emulator) && !overridden.contains(original);
    }

    /** unidbg's original signal and wait syscall methods that a subclass overrides */
    private Set<String> overridden = Collections.emptySet();

    @Override
    public Long deliverFault(Emulator<?> emulator, BackendException error, long pc) {
        return isSignalModelEnabled(emulator) ? signals.deliverFault(emulator, error, pc) : null;
    }

    boolean isThreadDispatcherEnabled() {
        return threadDispatcherEnabled;
    }

    Breaker breaker(Emulator<?> emulator) {
        return createBreaker(emulator);
    }

    int getSveVectorLength() {
        return cpuFeatures == null ? 0 : cpuFeatures.getSveVectorLength();
    }

    @Override
    public boolean takeDeliveryRequest() {
        return signals.takeDeliveryRequest();
    }

    @Override
    public long deliverPendingSignals(Emulator<?> emulator, long pc) {
        if (clock != null) {
            clock.enter(emulator.getThreadDispatcher().getRunningTask());
        }
        deadlockReported = false;
        return isSignalModelEnabled(emulator) ? signals.deliverPendingSignals(emulator, pc) : pc;
    }

    private static boolean validSignal(int sig) {
        return sig > 0 && sig <= 64;
    }

    /** kill() to this process; signal 0, invalid signals and other processes (unsupported) are unidbg's original kill() */
    private int kernelKill(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int pid = context.getIntArg(0);
        int sig = context.getIntArg(1);
        if (validSignal(sig) && (pid == 0 || pid == emulator.getPid())) {
            return signals.sendToProcess(emulator, SigInfo.fromProcess(sig, SigInfo.SI_USER, emulator.getPid(), 0));
        }
        return kill(emulator);
    }

    private int tkill(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int tid = context.getIntArg(0);
        int sig = context.getIntArg(1);
        if (tid <= 0 || sig < 0 || sig > 64) {
            return -UnixEmulator.EINVAL;
        }
        if (sig == 0) {
            return signals.threadExists(emulator, tid) ? 0 : -UnixEmulator.ESRCH;
        }
        return signals.sendToThread(emulator, tid, SigInfo.fromProcess(sig, SigInfo.SI_TKILL, emulator.getPid(), 0));
    }

    /**
     * tgkill() to a thread the emulator runs; signal 0, invalid signals and threads that do not run (created while the
     * thread dispatcher is disabled) are unidbg's original tgkill()
     */
    private int kernelTgkill(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int tid = context.getIntArg(1);
        int sig = context.getIntArg(2);
        if (validSignal(sig) && tid > 0 && signals.threadExists(emulator, tid)) {
            return signals.sendToThread(emulator, tid, SigInfo.fromProcess(sig, SigInfo.SI_TKILL, emulator.getPid(), 0));
        }
        return tgkill(emulator);
    }

    /** rt_sigqueueinfo() to this process; everything else is unidbg's original rt_sigqueue() */
    private int kernelRtSigqueue(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int tgid = context.getIntArg(0);
        int sig = context.getIntArg(1);
        UnidbgPointer info = context.getPointerArg(2);
        if (validSignal(sig) && (tgid == 0 || tgid == -1 || Math.abs(tgid) == emulator.getPid())) {
            return info == null ? -UnixEmulator.EFAULT : signals.sendToProcess(emulator, SigInfo.fromUser(sig, info));
        }
        return rt_sigqueue(emulator);
    }

    private int rt_tgsigqueueinfo(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int tgid = context.getIntArg(0);
        int tid = context.getIntArg(1);
        int sig = context.getIntArg(2);
        UnidbgPointer info = context.getPointerArg(3);
        if (sig < 0 || sig > 64 || tid <= 0) {
            return -UnixEmulator.EINVAL;
        }
        if (tgid != emulator.getPid() || !signals.threadExists(emulator, tid)) {
            return -UnixEmulator.ESRCH;
        }
        if (sig == 0) {
            return 0;
        }
        return info == null ? -UnixEmulator.EFAULT : signals.sendToThread(emulator, tid, SigInfo.fromUser(sig, info));
    }

    private int kernelRtSigpending(Emulator<AndroidFileIO> emulator) {
        return signals.rtSigpending(emulator, emulator.getContext().getPointerArg(0));
    }

    /** rt_sigtimedwait; an untimed wait nothing can end is reported by unidbg's original rt_sigtimedwait() */
    private int kernelRtSigtimedwait(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Integer ret = signals.rtSigtimedwait(emulator, context.getPointerArg(0), context.getPointerArg(1), context.getPointerArg(2));
        return ret != null ? ret : rt_sigtimedwait(emulator);
    }

    private int rt_sigsuspend(Emulator<?> emulator) {
        return signals.rtSigsuspend(emulator, emulator.getContext().getPointerArg(0));
    }

    private int kernelSigaltstack(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        return signals.sigaltstack(emulator, context.getPointerArg(0), context.getPointerArg(1));
    }

    /**
     * rt_sigaction: changing a disposition is unidbg's original sigaction(); on top of it a query (act == NULL) leaves
     * the disposition alone, and a disposition that ignores a signal discards its pending instances.
     */
    private int kernelSigaction(Emulator<?> emulator, int signum, Pointer act, Pointer oldact) {
        if (act == null && signum >= 1 && signum <= 64) { // only a query, also allowed for SIGKILL/SIGSTOP
            writeOldAction(emulator, getSigAction(signum), oldact);
            return 0;
        }
        int ret = sigaction(emulator, signum, act, oldact);
        if (ret == 0 && act != null && signum >= 1 && signum <= 64) {
            signals.dispositionChanged(emulator, signum);
        }
        return ret;
    }

    /**
     * nanosleep() is unidbg's original; the sleep takes the requested time on the guest's clock, and when a signal
     * interrupts it the remaining time is written back to rem.
     */
    private int kernelNanosleep(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        long deadline = deadline(emulator, context.getPointerArg(0));
        RunnableTask running = emulator.getThreadDispatcher().getRunningTask();
        if (deadline >= 0 && threadDispatcherEnabled && running != null) { // a sleep on the guest's clock
            running.setWaiter(emulator, new GuestWaits.Sleep(clock, deadline, context.getPointerArg(1)));
            throw new ThreadContextSwitchException().setReturnValue(0);
        }
        try {
            int ret = nanosleep(emulator);
            waitedUntil(deadline); // no other thread: the whole request passes
            return ret;
        } catch (ThreadContextSwitchException e) {
            signals.writeRemainingTimeOnSignal(emulator, deadline);
            throw e;
        }
    }

    /**
     * futex() is unidbg's original, except FUTEX_WAIT with a timeout, which lasts until its deadline on the guest's
     * clock. One that nothing can wake (no other thread; unidbg returns 0 at once) times out the same way, as with the
     * kernel.
     */
    private static final int FUTEX_WAIT = 0;
    private static final int FUTEX_WAKE = 1;
    private static final int FUTEX_WAIT_BITSET = 9;
    private static final int FUTEX_WAKE_BITSET = 10;
    private static final int FUTEX_PRIVATE_FLAG = 128;
    private static final int FUTEX_CLOCK_REALTIME = 256;
    private static final int FUTEX_BITSET_MATCH_ANY = 0xffffffff;

    private int kernelFutex(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int op = context.getIntArg(1);
        int cmd = op & 0x7f;
        if ((cmd == FUTEX_WAIT_BITSET || cmd == FUTEX_WAKE_BITSET) && context.getIntArg(5) == FUTEX_BITSET_MATCH_ANY && clock != null) {
            // with every bit set these are FUTEX_WAIT with an absolute timeout and FUTEX_WAKE, which unidbg has (it threw
            // for them); any other bitset stays unidbg's (the waits here keep no bitset). op reads as the plain one
            // while unidbg's futex runs, and is given back: the syscall leaves the registers as they were
            Backend backend = emulator.getBackend();
            backend.reg_write(Arm64Const.UC_ARM64_REG_X1, (op & FUTEX_PRIVATE_FLAG) | (cmd == FUTEX_WAIT_BITSET ? FUTEX_WAIT : FUTEX_WAKE));
            try {
                long deadline = cmd == FUTEX_WAIT_BITSET ? absoluteDeadline(emulator, context.getPointerArg(3), (op & FUTEX_CLOCK_REALTIME) != 0) : -1;
                return futexWait(emulator, deadline);
            } finally {
                backend.reg_write(Arm64Const.UC_ARM64_REG_X1, op);
            }
        }
        long deadline = cmd == 0 ? deadline(emulator, context.getPointerArg(3)) : -1; // FUTEX_WAIT
        return futexWait(emulator, deadline);
    }

    /**
     * The deadline (CLOCK_MONOTONIC ns of the guest's clock) of an absolute timeout on CLOCK_MONOTONIC, or on
     * CLOCK_REALTIME, as FUTEX_WAIT_BITSET takes it; -1 for none
     */
    private long absoluteDeadline(Emulator<?> emulator, Pointer timeout, boolean realtime) {
        if (timeout == null) {
            return -1;
        }
        TimeSpec timeSpec = TimeSpec.createTimeSpec(emulator, timeout);
        long at = timeSpec.getTvSec() * 1000000000L + timeSpec.getTvNsec();
        return Math.max(0, realtime ? clock.nanos() + at - realtimeNanos() : at);
    }

    /** FUTEX_WAIT or FUTEX_WAKE (as x1 has it) with a deadline (-1: none): the model's timed wait, else unidbg's futex */
    private int futexWait(Emulator<?> emulator, long deadline) {
        RegisterContext context = emulator.getContext();
        RunnableTask running = emulator.getThreadDispatcher().getRunningTask();
        if (deadline >= 0 && threadDispatcherEnabled && running != null) {
            Pointer uaddr = context.getPointerArg(0);
            int val = context.getIntArg(2);
            if (uaddr.getInt(0) != val) {
                return -UnixEmulator.EAGAIN;
            }
            running.setWaiter(emulator, new GuestWaits.Futex(clock, deadline, uaddr, val));
            throw new ThreadContextSwitchException();
        }
        try {
            int ret = futex(emulator);
            if (ret == 0 && deadline >= 0) {
                waitedUntil(deadline);
                return -AndroidSyscallHandler.ETIMEDOUT;
            }
            return ret;
        } catch (ThreadContextSwitchException e) {
            if (deadline >= 0) {
                waitedUntil(deadline); // timed out at once (several threads, but no running task)
            }
            throw e;
        }
    }

    /**
     * Every thread waits: the guest's time moves on to the earliest timed wait (at most maxNanos). With none, the call
     * cannot finish; this is reported once (unidbg keeps waiting, as before).
     */
    @Override
    public boolean idle(Emulator<?> emulator, List<Task> tasks, long maxNanos) {
        if (clock == null) {
            return false;
        }
        long deadline = Long.MAX_VALUE;
        for (Task task : tasks) {
            Waiter waiter = task.getWaiter();
            if (!task.isFinish() && waiter instanceof GuestWaits.Timed && ((GuestWaits.Timed) waiter).deadline() >= 0) {
                deadline = Math.min(deadline, ((GuestWaits.Timed) waiter).deadline());
            }
        }
        if (deadline == Long.MAX_VALUE) {
            if (maxNanos == Long.MAX_VALUE && !deadlockReported) {
                deadlockReported = true;
                StringBuilder waits = new StringBuilder();
                for (Task task : tasks) {
                    if (!task.isFinish()) {
                        Waiter waiter = task.getWaiter();
                        waits.append(waits.length() == 0 ? "" : ", ").append(task.isMainThread() ? "main" : "tid " + task.getId())
                                .append(": ").append(waiter == null ? "?" : waiter.getClass().getSimpleName());
                    }
                }
                log.warn("every thread waits and nothing can wake them up ({}): the call cannot finish (on a device the process would hang here)", waits);
            }
            return false;
        }
        long now = clock.nanos();
        clock.advanceTo(deadline - now <= maxNanos ? deadline : now + maxNanos);
        return true;
    }

    /** a deadlock has been reported; reset when a thread runs again */
    private boolean deadlockReported;

    @Override
    public boolean isEnabled(Emulator<?> emulator) {
        return isSignalModelEnabled(emulator);
    }

    private static int readInstruction(Emulator<?> emulator, long pc) {
        UnidbgPointer pointer = UnidbgPointer.pointer(emulator, pc);
        return pointer == null ? 0 : pointer.getInt(0);
    }

    /**
     * ESR for an FPAC fault (EC 0x1c) if insn is a pointer authentication instruction whose UNDEF, on a core with
     * FEAT_FPAC, can only be a failed authentication, else 0. The kernel reports those as SIGILL/ILL_ILLOPN with an
     * esr_context record.
     */
    static long fpacSyndrome(int insn) {
        final long ec = (0x1cL << 26) | (1L << 25);
        if ((insn & 0xffffd000) == 0xdac11000) { // AUTIA/AUTIB/AUTDA/AUTDB and the Z forms
            return ec | ((insn >>> 10) & 3);
        }
        switch (insn) {
            case 0xd503219f: // AUTIA1716
            case 0xd503239f: // AUTIAZ
            case 0xd50323bf: // AUTIASP
                return ec;
            case 0xd50321df: // AUTIB1716
            case 0xd50323df: // AUTIBZ
            case 0xd50323ff: // AUTIBSP
                return ec | 1;
        }
        int opc = (insn >>> 21) & 0xf;
        if ((insn & 0xfe000000) == 0xd6000000 && ((insn >>> 11) & 0x1f) == 1 &&
                (opc == 0 || opc == 1 || opc == 2 || opc == 8 || opc == 9)) { // BRA*, BLRA*, RETA* (not ERETA*)
            return ec | ((insn >>> 10) & 1);
        }
        if ((insn & 0xff200400) == 0xf8200400) { // LDRAA/LDRAB
            return ec | 2 | ((insn >>> 23) & 1);
        }
        return 0;
    }

    @SuppressWarnings("unchecked")
    @Override
    public void hook(Backend backend, int intno, int swi, Object user) {
        Emulator<AndroidFileIO> emulator = (Emulator<AndroidFileIO>) user;
        UnidbgPointer pc = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_PC);

        if (intno == ARMEmulator.EXCP_BKPT) { // brk
            if (pc != null && isSignalModelEnabled(emulator) && signals.raiseSyncFault(emulator, SIGTRAP, TRAP_BRKPT, pc.peer, 0)) {
                return;
            }
            createBreaker(emulator).brk(pc, pc == null ? swi : (pc.getInt(0) >> 5) & 0xffff);
            return;
        }
        if (intno == ARMEmulator.EXCP_UDEF) {
            if (pc != null && isSignalModelEnabled(emulator)) {
                long esr = cpuFeatures != null && cpuFeatures.hasFpac() ? fpacSyndrome(pc.getInt(0)) : 0;
                if (signals.raiseSyncFault(emulator, SIGILL, esr == 0 ? ILL_ILLOPC : ILL_ILLOPN, pc.peer, esr)) {
                    return;
                }
            }
            createBreaker(emulator).debug("Undefined instruction (EXCP_UDEF) at " + pc);
            return;
        }

        if (intno == EXCP_PREFETCH_ABORT && pc != null && isSignalModelEnabled(emulator) && memoryFaultSignals && signals.instructionAbort(emulator, pc.peer)) {
            return; // a jump outside the address space (e.g. a return address a failed authentication poisoned)
        }

        if (intno != ARMEmulator.EXCP_SWI) {
            throw new BackendException("intno=" + intno);
        }

        int NR = backend.reg_read(Arm64Const.UC_ARM64_REG_X8).intValue();
        String syscall = null;
        Throwable exception = null;
        boolean askedSubclass = false; // handleUnknownSyscall already had the syscall
        try {
            if (swi == 0 && NR == 0 && backend.reg_read(Arm64Const.UC_ARM64_REG_X16).intValue() == Svc.POST_CALLBACK_SYSCALL_NUMBER) { // postCallback
                int number = backend.reg_read(Arm64Const.UC_ARM64_REG_X12).intValue();
                Svc svc = svcMemory.getSvc(number);
                if (svc != null) {
                    svc.handlePostCallback(emulator);
                    return;
                }
                backend.emu_stop();
                throw new IllegalStateException("svc number: " + swi);
            }
            if (swi == 0 && NR == 0 && backend.reg_read(Arm64Const.UC_ARM64_REG_X16).intValue() == Svc.PRE_CALLBACK_SYSCALL_NUMBER) { // preCallback
                int number = backend.reg_read(Arm64Const.UC_ARM64_REG_X12).intValue();
                Svc svc = svcMemory.getSvc(number);
                if (svc != null) {
                    svc.handlePreCallback(emulator);
                    return;
                }
                backend.emu_stop();
                throw new IllegalStateException("svc number: " + swi);
            }
            if (swi != 0) {
                if (swi == Arm64Svc.SVC_MAX) {
                    throw new PopContextException();
                }
                if (swi == Arm64Svc.SVC_MAX - 1) {
                    throw new ThreadContextSwitchException();
                }
                Svc svc = svcMemory.getSvc(swi);
                if (svc != null) {
                    log.debug("swi={}, svc={}", swi, svc);
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, svc.handle(emulator));
                    return;
                }
                backend.emu_stop();
                throw new BackendException("svc number: " + swi);
            }

            if (log.isTraceEnabled()) {
                ARM.showRegs64(emulator, null);
            }

            if (handleSyscall(emulator, NR)) {
                return;
            }

            if (NR != 139 && isSignalModelEnabled(emulator)) {
                signals.syscallMade();
            }

            switch (NR) {
                case 17:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getcwd(emulator));
                    return;
                case 19:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, eventfd2(emulator));
                    return;
                case 64:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, write(emulator));
                    return;
                case 221:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, execve(emulator));
                    return;
                case 62:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, lseek(emulator));
                    return;
                case 172: // getpid
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, emulator.getPid());
                    return;
                case 178: // gettid
                    Task task = emulator.get(Task.TASK_KEY);
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, task == null ? 0 : task.getId());
                    return;
                case 129:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, modelHandles(emulator, "kill") ? kernelKill(emulator) : kill(emulator));
                    return;
                case 29:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, ioctl(emulator));
                    return;
                case 34:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, mkdirat(emulator));
                    return;
                case 35:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, unlinkat(emulator));
                    return;
                case 38:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, renameat(emulator));
                    return;
                case 47:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, fallocate(emulator));
                    return;
                case 53:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, fchmodat(emulator));
                    return;
                case 54:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, fchownat(emulator));
                    return;
                case 56:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, openat(emulator));
                    return;
                case 57:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, close(backend, emulator));
                    return;
                case 59:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, pipe2(emulator));
                    return;
                case 63:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, read(backend, emulator));
                    return;
                // pread64(fd, buf, count, offset): arm32 dispatches it (ARM32SyscallHandler case 180) and FileIO.pread
                // is implemented, but arm64 had no entry, so a target that reads at an offset without lseek (a statically
                // linked libc parsing an ELF section table or a zip central directory) stopped here.
                case 67:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, pread(emulator));
                    return;
                case 24:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, dup3(emulator));
                    return;
                case 43: {
                    RegisterContext context = emulator.getContext();
                    Pointer pathPointer = context.getPointerArg(0);
                    Pointer buf = context.getPointerArg(1);
                    String path = pathPointer.getString(0);
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, statfs64(emulator, path, buf));
                    return;
                }
                case 46: {
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, ftruncate(emulator));
                    return;
                }
                case 134:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sigaction(emulator));
                    return;
                // tkill, rt_sigsuspend, rt_tgsigqueueinfo: unidbg had no implementation, so a subclass's
                // handleUnknownSyscall comes first
                case 130:
                    if (isSignalModelEnabled(emulator)) {
                        if (!handleUnknownSyscall(emulator, NR)) {
                            backend.reg_write(Arm64Const.UC_ARM64_REG_X0, tkill(emulator));
                        }
                        return;
                    }
                    break;
                case 133:
                    if (isSignalModelEnabled(emulator)) {
                        if (!handleUnknownSyscall(emulator, NR)) {
                            backend.reg_write(Arm64Const.UC_ARM64_REG_X0, rt_sigsuspend(emulator));
                        }
                        return;
                    }
                    break;
                case 139:
                    if (isSignalModelEnabled(emulator)) { // the return of the model's own signal frames
                        signals.rtSigreturn(emulator); // restores x0 with the rest of the context
                        return;
                    }
                    break;
                case 240:
                    if (isSignalModelEnabled(emulator)) {
                        if (!handleUnknownSyscall(emulator, NR)) {
                            backend.reg_write(Arm64Const.UC_ARM64_REG_X0, rt_tgsigqueueinfo(emulator));
                        }
                        return;
                    }
                    break;
                case 72:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, pselect6(emulator));
                    return;
                case 78:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, readlinkat(emulator));
                    return;
                case 80:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, fstat(backend, emulator));
                    return;
                case 83:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, fdatasync(emulator));
                    return;
                case 96:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, set_tid_address(emulator));
                    return;
                case 98:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, modelHandles(emulator, "futex") ? kernelFutex(emulator) : futex(emulator));
                    return;
                case 220: {
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, clone(emulator));
                    return;
                }
                case 160:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, uname(emulator));
                    return;
                case 132:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, modelHandles(emulator, "sigaltstack") ? kernelSigaltstack(emulator) : sigaltstack(emulator));
                    return;
                case 135:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sigprocmask(emulator));
                    return;
                case 32:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, flock(emulator));
                    return;
                case 66:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, writev(emulator));
                    return;
                case 101:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, modelHandles(emulator, "nanosleep") ? kernelNanosleep(emulator) : nanosleep(emulator));
                    return;
                case 119:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sched_setscheduler(emulator));
                    return;
                case 122:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sched_setaffinity(emulator));
                    return;
                case 123:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sched_getaffinity(emulator));
                    return;
                case 124:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sched_yield(emulator));
                    return;
                case 136:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, modelHandles(emulator, "rt_sigpending") ? kernelRtSigpending(emulator) : rt_sigpending(emulator));
                    return;
                case 137:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, modelHandles(emulator, "rt_sigtimedwait") ? kernelRtSigtimedwait(emulator) : rt_sigtimedwait(emulator));
                    return;
                case 138:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, modelHandles(emulator, "rt_sigqueue") ? kernelRtSigqueue(emulator) : rt_sigqueue(emulator));
                    return;
                case 140:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, setpriority(emulator));
                    return;
                case 167:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, prctl(emulator));
                    return;
                case 169:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, gettimeofday(emulator));
                    return;
                case 73:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, ppoll(emulator));
                    return;
                case 173:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getppid(emulator));
                    return;
                case 174: // getuid
                case 175: // geteuid
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, 0);
                    return;
                case 200:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, bind(emulator));
                    return;
                case 201:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, listen(emulator));
                    return;
                case 214:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, brk(backend, emulator));
                    return;
                case 215:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, munmap(backend, emulator));
                    return;
                case 216:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, mremap(emulator));
                    return;
                case 61:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getdents64(emulator));
                    return;
                case 233:
                    syscall = "madvise";
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, 0);
                    return;
                case 25:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, fcntl(emulator));
                    return;
                case 222:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, mmap(backend, emulator));
                    return;
                case 226:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, mprotect(backend, emulator));
                    return;
                case 227:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, msync(emulator));
                    return;
                case 93:
                    exit(emulator);
                    return;
                case 94:
                    exit_group(emulator);
                    return;
                case 113:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, clock_gettime(emulator));
                    return;
                case 117:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, ptrace(emulator));
                    return;
                case 120:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sched_getscheduler(emulator));
                    return;
                case 121:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sched_getparam(emulator));
                    return;
                case 131:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, modelHandles(emulator, "tgkill") ? kernelTgkill(emulator) : tgkill(emulator));
                    return;
                case 141:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getpriority(emulator));
                    return;
                case 163:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getrlimit64(emulator));
                    return;
                case 198:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, socket(emulator));
                    return;
                case 199:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, socketpair(emulator));
                    return;
                case 203:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, connect(emulator));
                    return;
                case 204:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getsockname(emulator));
                    return;
                case 242:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, accept4(emulator));
                    return;
                case 205:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getpeername(emulator));
                    return;
                case 206:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sendto(emulator));
                    return;
                case 207:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, recvfrom(emulator));
                    return;
                case 208:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, setsockopt(emulator));
                    return;
                case 209:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, getsockopt(emulator));
                    return;
                case 228:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, mlock(emulator));
                    return;
                case 278:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, gerrandom(emulator));
                    return;
                case 79:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, fstatat64(emulator));
                    return;
                case 48:
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, faccessat(emulator));
                    return;
                // dup, fsync, getgid, getegid, process_vm_readv: unidbg had no arm64 implementation, so a subclass's
                // handleUnknownSyscall comes first
                case 23:
                case 82:
                case 176:
                case 177:
                case 270:
                    if (isSignalModelEnabled(emulator)) {
                        askedSubclass = true;
                        if (handleUnknownSyscall(emulator, NR)) {
                            return;
                        }
                        Long ret = addedSyscall(emulator, NR);
                        if (ret != null) {
                            backend.reg_write(Arm64Const.UC_ARM64_REG_X0, ret);
                            return;
                        }
                    }
                    break;
            }
        } catch (StopEmulatorException e) {
            backend.emu_stop();
            return;
        } catch (LongJumpException e) {
            backend.emu_stop();
            throw e;
        } catch (Throwable e) {
            backend.emu_stop();
            exception = e;
        }

        if (exception == null && !askedSubclass && handleUnknownSyscall(emulator, NR)) {
            return;
        }

        log.warn("handleInterrupt intno={}, NR={}, svcNumber=0x{}, PC={}, LR={}, syscall={}", intno, NR, Integer.toHexString(swi), pc, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_LR), syscall, exception);
        if (exception == null && isSignalModelEnabled(emulator)) {
            // the kernel's answer to a syscall it does not have, instead of whatever x0 held; set before the debugger,
            // which can still change it
            backend.reg_write(Arm64Const.UC_ARM64_REG_X0, -UnixEmulator.ENOSYS);
        }
        if (log.isDebugEnabled()) {
            emulator.attach().debug("Unhandled syscall NR=" + NR + " (" + syscall + ") at " + pc);
        }
        if (exception instanceof RuntimeException) {
            throw (RuntimeException) exception;
        }
    }

    private static final int RLIMIT_STACK = 3; /* max stack size */

    private long getrlimit64(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int resource = context.getIntArg(0);
        Pointer ptr = context.getPointerArg(1);
        if (resource == RLIMIT_STACK) {
            RLimit64 rlimit64 = new RLimit64(ptr);
            long size = (long) Memory.STACK_SIZE_OF_PAGE * emulator.getPageAlign();
            rlimit64.rlim_cur = size;
            rlimit64.rlim_max = size;
            rlimit64.pack();
            return 0;
        } else {
            throw new UnsupportedOperationException("getrlimit64 resource=" + resource + ", rlimit64=" + ptr);
        }
    }

    private long msync(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer addr = context.getPointerArg(0);
        int len = context.getIntArg(1);
        int flags = context.getIntArg(2);
        if (log.isDebugEnabled()) {
            log.debug("msync addr={}, len={}, flags=0x{}", addr, len, Integer.toHexString(flags));
        }
        return 0;
    }

    private long fdatasync(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        if (log.isDebugEnabled()) {
            log.debug("fdatasync fd={}", fd);
        }
        return 0;
    }

    /**
     * Syscalls unidbg has no arm64 implementation of, answered from what it already models (the fd table, the identity
     * getuid reports, the process's memory) with the kernel's results.
     *
     * @return the result, or null where unidbg does not model the case (it then takes the unknown syscall path)
     */
    private Long addedSyscall(Emulator<AndroidFileIO> emulator, int NR) {
        RegisterContext context = emulator.getContext();
        switch (NR) {
            case 23: { // dup
                int oldfd = context.getIntArg(0);
                if (log.isDebugEnabled()) {
                    log.debug("dup oldfd={}", oldfd);
                }
                FileIO old = fdMap.get(oldfd);
                if (old == null) {
                    return errno(emulator, UnixEmulator.EBADF);
                }
                AndroidFileIO dup = (AndroidFileIO) old.dup2();
                if (dup == null) {
                    throw new UnsupportedOperationException(); // as unidbg's dup on arm32
                }
                int newfd = getMinFd();
                fdMap.put(newfd, dup);
                return (long) newfd;
            }
            case 82: { // fsync, as fdatasync
                int fd = context.getIntArg(0);
                if (log.isDebugEnabled()) {
                    log.debug("fsync fd={}", fd);
                }
                return fdMap.containsKey(fd) ? 0 : errno(emulator, UnixEmulator.EBADF);
            }
            case 176: // getgid
            case 177: // getegid
                return 0L; // as getuid and geteuid
            case 270:
                return processVmReadv(emulator);
            default:
                return null;
        }
    }

    private static long errno(Emulator<?> emulator, int errno) {
        emulator.getMemory().setErrno(errno);
        return -errno;
    }

    private static final int IOV_MAX = 1024;

    /**
     * process_vm_readv on the process itself (a way to read memory that may not be mapped without faulting): copies
     * whole remote iovec elements while they are readable. Another process is not modelled (null).
     */
    private Long processVmReadv(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int pid = context.getIntArg(0);
        Pointer localIov = context.getPointerArg(1);
        long localCount = context.getLongArg(2);
        Pointer remoteIov = context.getPointerArg(3);
        long remoteCount = context.getLongArg(4);
        long flags = context.getLongArg(5);
        if (log.isDebugEnabled()) {
            log.debug("process_vm_readv pid={}, local_iov={}, liovcnt={}, remote_iov={}, riovcnt={}, flags=0x{}", pid, localIov, localCount, remoteIov, remoteCount, Long.toHexString(flags));
        }
        if (pid != emulator.getPid()) {
            return null;
        }
        if (flags != 0 || localCount < 0 || localCount > IOV_MAX || remoteCount < 0 || remoteCount > IOV_MAX) {
            return errno(emulator, UnixEmulator.EINVAL);
        }
        long[] local = iovecs(emulator, localIov, (int) localCount);
        long[] remote = iovecs(emulator, remoteIov, (int) remoteCount);
        if (local == null || remote == null) {
            return errno(emulator, UnixEmulator.EFAULT);
        }
        Backend backend = emulator.getBackend();
        long copied = 0;
        boolean faulted = false;
        int li = 0;
        long lo = 0; // offset in local element li
        copy:
        for (int ri = 0; ri < remote.length; ri += 2) {
            long base = remote[ri], len = remote[ri + 1];
            if (len == 0) {
                continue;
            }
            if (!accessible(emulator, base, len, UnicornConst.UC_PROT_READ)) {
                faulted = true; // partial transfers do not split an element
                break;
            }
            for (long ro = 0; ro < len; ) {
                if (li >= local.length) {
                    break copy;
                }
                long room = local[li + 1] - lo;
                if (room == 0) {
                    li += 2;
                    lo = 0;
                    continue;
                }
                int n = (int) Math.min(Math.min(len - ro, room), 0x10000);
                if (!accessible(emulator, local[li] + lo, n, UnicornConst.UC_PROT_WRITE)) {
                    faulted = true;
                    break copy;
                }
                // written as the other syscalls write the guest's buffers, through UnidbgPointer: a system write that
                // setTraceSystemMemoryWrite reports
                UnidbgPointer.pointer(emulator, local[li] + lo).write(0, backend.mem_read(base + ro, n), 0, n);
                ro += n;
                lo += n;
                copied += n;
            }
        }
        // a guest reading its own memory this way does not show in memory read hooks (the copy is not an instruction's
        // access): it used to be an unknown syscall's warning, it stays visible as ptrace is
        log.info("process_vm_readv of its own memory: {} element(s) from {}, {} bytes copied{}", remote.length / 2,
                remote.length == 0 ? null : UnidbgPointer.pointer(emulator, remote[0]), copied, faulted ? ", stopped at memory it cannot read" : "");
        return faulted && copied == 0 ? errno(emulator, UnixEmulator.EFAULT) : copied;
    }

    /** base and length pairs of count iovecs, or null if they cannot be read */
    private static long[] iovecs(Emulator<?> emulator, Pointer iov, int count) {
        if (count == 0) {
            return new long[0];
        }
        if (iov == null || !accessible(emulator, ((UnidbgPointer) iov).peer, count * 16L, UnicornConst.UC_PROT_READ)) {
            return null;
        }
        long[] pairs = new long[count * 2];
        for (int i = 0; i < count; i++) {
            pairs[i * 2] = iov.getLong(i * 16L);
            pairs[i * 2 + 1] = iov.getLong(i * 16L + 8);
        }
        return pairs;
    }

    /**
     * Whether [address, address + length) is mapped with prot. unidbg's memory map has the protection of what mmap and
     * the loader mapped; the rest (stack, brk heap) is mapped read-write by the backend directly.
     */
    private static boolean accessible(Emulator<?> emulator, long address, long length, int prot) {
        long end = address + length;
        if (length < 0 || end < address) {
            return false;
        }
        Backend backend = emulator.getBackend();
        int page = emulator.getPageAlign();
        long at = address;
        while (at < end) {
            MemoryMap map = null;
            for (MemoryMap m : emulator.getMemory().getMemoryMap()) {
                if (at >= m.base && at < m.base + m.size) {
                    map = m;
                    break;
                }
            }
            if (map != null) {
                if ((map.prot & prot) != prot) {
                    return false;
                }
                at = map.base + map.size;
                continue;
            }
            try {
                backend.mem_read(at, 1);
            } catch (BackendException e) {
                return false;
            }
            at = (at & -(long) page) + page;
        }
        return true;
    }

    private long gerrandom(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer buf = context.getPointerArg(0);
        int bufSize = context.getIntArg(1);
        int flags = context.getIntArg(2);
        return getrandom(buf, bufSize, flags);
    }

    private long clone(Emulator<?> emulator) {
        Arm64RegisterContext context = emulator.getContext();
        Pointer child_stack = context.getPointerArg(1);
        if (child_stack == null &&
                context.getPointerArg(2) == null) {
            // http://androidxref.com/6.0.1_r10/xref/bionic/libc/bionic/fork.cpp#47
            return fork(emulator); // vfork
        }

        long fn = context.getXLong(5);
        long arg = context.getXLong(6);
        if (child_stack != null && child_stack.getLong(0) == fn && child_stack.getLong(8) == arg) {
            // http://androidxref.com/6.0.1_r10/xref/bionic/libc/arch-arm/bionic/__bionic_clone.S#49
            return bionic_clone(emulator);
        } else {
            return pthread_clone(emulator);
        }
    }

    private int pthread_clone(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int flags = context.getIntArg(0);
        UnidbgPointer child_stack = context.getPointerArg(1);
        List<String> list = new ArrayList<>();
        if ((flags & CLONE_VM) != 0) {
            list.add("CLONE_VM");
        }
        if ((flags & CLONE_FS) != 0) {
            list.add("CLONE_FS");
        }
        if ((flags & CLONE_FILES) != 0) {
            list.add("CLONE_FILES");
        }
        if ((flags & CLONE_SIGHAND) != 0) {
            list.add("CLONE_SIGHAND");
        }
        if ((flags & CLONE_PTRACE) != 0) {
            list.add("CLONE_PTRACE");
        }
        if ((flags & CLONE_VFORK) != 0) {
            list.add("CLONE_VFORK");
        }
        if ((flags & CLONE_PARENT) != 0) {
            list.add("CLONE_PARENT");
        }
        if ((flags & CLONE_THREAD) != 0) {
            list.add("CLONE_THREAD");
        }
        if ((flags & CLONE_NEWNS) != 0) {
            list.add("CLONE_NEWNS");
        }
        if ((flags & CLONE_SYSVSEM) != 0) {
            list.add("CLONE_SYSVSEM");
        }
        if ((flags & CLONE_SETTLS) != 0) {
            list.add("CLONE_SETTLS");
        }
        if ((flags & CLONE_PARENT_SETTID) != 0) {
            list.add("CLONE_PARENT_SETTID");
        }
        if ((flags & CLONE_CHILD_CLEARTID) != 0) {
            list.add("CLONE_CHILD_CLEARTID");
        }
        if ((flags & CLONE_DETACHED) != 0) {
            list.add("CLONE_DETACHED");
        }
        if ((flags & CLONE_UNTRACED) != 0) {
            list.add("CLONE_UNTRACED");
        }
        if ((flags & CLONE_CHILD_SETTID) != 0) {
            list.add("CLONE_CHILD_SETTID");
        }
        if ((flags & CLONE_STOPPED) != 0) {
            list.add("CLONE_STOPPED");
        }
        int threadId = incrementThreadId(emulator);

        UnidbgPointer fn = child_stack.getPointer(0);
        child_stack = child_stack.share(8, 0);
        UnidbgPointer arg = child_stack.getPointer(0);
        child_stack = child_stack.share(8, 0);

        if (threadDispatcherEnabled) {
            throw new UnsupportedOperationException();
        }

        log.info("pthread_clone child_stack={}, thread_id={}, fn={}, arg={}, flags={}", child_stack, threadId, fn, arg, list);
        Logger log = LoggerFactory.getLogger(AbstractEmulator.class);
        if (log.isDebugEnabled()) {
            emulator.attach().debug("pthread_clone thread_id=" + threadId + ", fn=" + fn);
        }
        return threadId;
    }

    protected long fork(Emulator<?> emulator) {
        log.info("fork");
        emulator.getMemory().setErrno(UnixEmulator.ENOSYS);
        return -1;
    }

    private static final int CLONE_VM = 0x00000100;
    private static final int CLONE_FS = 0x00000200;
    private static final int CLONE_FILES = 0x00000400;
    private static final int CLONE_SIGHAND = 0x00000800;
    private static final int CLONE_PTRACE = 0x00002000;
    private static final int CLONE_VFORK = 0x00004000;
    private static final int CLONE_PARENT = 0x00008000;
    private static final int CLONE_THREAD = 0x00010000;
    private static final int CLONE_NEWNS = 0x00020000;
    private static final int CLONE_SYSVSEM = 0x00040000;
    private static final int CLONE_SETTLS = 0x00080000;
    private static final int CLONE_PARENT_SETTID = 0x00100000;
    private static final int CLONE_CHILD_CLEARTID = 0x00200000;
    private static final int CLONE_DETACHED = 0x00400000;
    private static final int CLONE_UNTRACED = 0x00800000;
    private static final int CLONE_CHILD_SETTID = 0x01000000;
    private static final int CLONE_STOPPED = 0x02000000;

    private int bionic_clone(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int flags = context.getIntArg(0);
        Pointer child_stack = context.getPointerArg(1);
        Pointer pid = context.getPointerArg(2);
        Pointer tls = context.getPointerArg(3);
        Pointer ctid = context.getPointerArg(4);
        UnidbgPointer fn = context.getPointerArg(5);
        UnidbgPointer arg = context.getPointerArg(6);
        List<String> list = new ArrayList<>();
        if ((flags & CLONE_VM) != 0) {
            list.add("CLONE_VM");
        }
        if ((flags & CLONE_FS) != 0) {
            list.add("CLONE_FS");
        }
        if ((flags & CLONE_FILES) != 0) {
            list.add("CLONE_FILES");
        }
        if ((flags & CLONE_SIGHAND) != 0) {
            list.add("CLONE_SIGHAND");
        }
        if ((flags & CLONE_PTRACE) != 0) {
            list.add("CLONE_PTRACE");
        }
        if ((flags & CLONE_VFORK) != 0) {
            list.add("CLONE_VFORK");
        }
        if ((flags & CLONE_PARENT) != 0) {
            list.add("CLONE_PARENT");
        }
        if ((flags & CLONE_THREAD) != 0) {
            list.add("CLONE_THREAD");
        }
        if ((flags & CLONE_NEWNS) != 0) {
            list.add("CLONE_NEWNS");
        }
        if ((flags & CLONE_SYSVSEM) != 0) {
            list.add("CLONE_SYSVSEM");
        }
        if ((flags & CLONE_SETTLS) != 0) {
            list.add("CLONE_SETTLS");
        }
        if ((flags & CLONE_PARENT_SETTID) != 0) {
            list.add("CLONE_PARENT_SETTID");
        }
        if ((flags & CLONE_CHILD_CLEARTID) != 0) {
            list.add("CLONE_CHILD_CLEARTID");
        }
        if ((flags & CLONE_DETACHED) != 0) {
            list.add("CLONE_DETACHED");
        }
        if ((flags & CLONE_UNTRACED) != 0) {
            list.add("CLONE_UNTRACED");
        }
        if ((flags & CLONE_CHILD_SETTID) != 0) {
            list.add("CLONE_CHILD_SETTID");
        }
        if ((flags & CLONE_STOPPED) != 0) {
            list.add("CLONE_STOPPED");
        }
        if (log.isDebugEnabled()) {
            log.debug("bionic_clone child_stack={}, pid={}, tls={}, ctid={}, fn={}, arg={}, flags={}", child_stack, pid, tls, ctid, fn, arg, list);
        }
        int threadId = incrementThreadId(emulator);
        if (threadDispatcherEnabled) {
            if (verbose) {
                System.out.printf("bionic_clone fn=%s, LR=%s%n", fn, context.getLRPointer());
            }
            MarshmallowThread thread = new MarshmallowThread(emulator, fn, arg, ctid, threadId);
            if (isSignalModelEnabled(emulator)) {
                signals.threadCreated(emulator, thread);
            }
            emulator.getThreadDispatcher().addThread(thread);
        }
        ctid.setInt(0, threadId);
        return threadId;
    }

    private int flock(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        int operation = context.getIntArg(1);
        if (log.isDebugEnabled()) {
            log.debug("flock fd={}, operation={}", fd, operation);
        }
        return 0;
    }

    private int execve(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer filename = context.getPointerArg(0);
        Pointer argv = context.getPointerArg(1);
        Pointer envp = context.getPointerArg(2);
        assert filename != null;
        List<String> args = new ArrayList<>();
        Pointer pointer;
        while ((pointer = argv.getPointer(0)) != null) {
            args.add(pointer.getString(0));
            argv = argv.share(8);
        }
        List<String> env = new ArrayList<>();
        while ((pointer = envp.getPointer(0)) != null) {
            env.add(pointer.getString(0));
            envp = envp.share(8);
        }
        log.info("execve filename={}, args={}, env={}", filename.getString(0), args, env);
        emulator.getMemory().setErrno(UnixEmulator.EACCES);
        return -1;
    }

    private int bind(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        Pointer addr = context.getPointerArg(1);
        int addrlen = context.getIntArg(2);
        return bind(emulator, sockfd, addr, addrlen);
    }

    private int listen(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        int backlog = context.getIntArg(1);
        return listen(emulator, sockfd, backlog);
    }

    protected int stat64(Emulator<AndroidFileIO> emulator, String pathname, Pointer statbuf) {
        FileResult<AndroidFileIO> result = resolve(emulator, pathname, IOConstants.O_RDONLY);
        if (result != null && result.isSuccess()) {
            return result.io.fstat(emulator, new Stat64(statbuf));
        }

        if (verbose) {
            log.info("stat64 pathname={}", pathname);
        }
        emulator.getMemory().setErrno(result != null ? result.errno : UnixEmulator.ENOENT);
        return -1;
    }

    private int getpeername(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        Pointer addr = context.getPointerArg(1);
        Pointer addrlen = context.getPointerArg(2);
        if (log.isDebugEnabled()) {
            log.debug("getpeername sockfd={}, addr={}, addrlen={}", sockfd, addr, addrlen);
        }

        FileIO io = fdMap.get(sockfd);
        if (io == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }

        return io.getpeername(addr, addrlen);
    }

    private static final short POLLIN = 0x0001;
    private static final short POLLOUT = 0x0004;

    private int ppoll(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer fds = context.getPointerArg(0);
        int nfds = context.getIntArg(1);
        Pointer tmo_p = context.getPointerArg(2);
        Pointer sigmask = context.getPointerArg(3);
        int count = 0;
        for (int i = 0; i < nfds; i++) {
            Pointer pollfd = fds.share(i * 8L);
            int fd = pollfd.getInt(0);
            short events = pollfd.getShort(4); // requested events
            if (log.isDebugEnabled()) {
                log.debug("ppoll fds={}, nfds={}, tmo_p={}, sigmask={}, fd={}, events={}", fds, nfds, tmo_p, sigmask, fd, events);
            }
            if (fd < 0) {
                pollfd.setShort(6, (short) 0);
            } else {
                short revents = 0;
                if ((events & POLLOUT) != 0) {
                    revents = POLLOUT;
                } else if ((events & POLLIN) != 0) {
                    revents = POLLIN;
                }
                pollfd.setShort(6, revents); // returned events
                count++;
            }
        }
        if (count == 0) {
            waitedUntil(deadline(emulator, tmo_p)); // nothing to wait for: the timeout passes
        }
        return count;
    }

    private int sigprocmask(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int how = context.getIntArg(0);
        Pointer set = context.getPointerArg(1);
        Pointer oldset = context.getPointerArg(2);
        return modelHandles(emulator, "sigprocmask") ? signals.sigprocmask(emulator, how, set, oldset) : sigprocmask(emulator, how, set, oldset);
    }

    private int ftruncate(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        int length = context.getIntArg(1);
        if (log.isDebugEnabled()) {
            log.debug("ftruncate fd={}, length={}", fd, length);
        }
        FileIO file = fdMap.get(fd);
        if (file == null) {
            throw new UnsupportedOperationException();
        }
        return file.ftruncate(length);
    }

    private int sigaction(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int signum = context.getIntArg(0);
        Pointer act = context.getPointerArg(1);
        Pointer oldact = context.getPointerArg(2);

        return modelHandles(emulator, "sigaction") ? kernelSigaction(emulator, signum, act, oldact) : sigaction(emulator, signum, act, oldact);
    }

    private int pselect6(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int nfds = context.getIntArg(0);
        Pointer readfds = context.getPointerArg(1);
        Pointer writefds = context.getPointerArg(2);
        Pointer exceptfds = context.getPointerArg(3);
        Pointer timeout = context.getPointerArg(4);
        int size = (nfds - 1) / 8 + 1;
        if (log.isDebugEnabled()) {
            log.debug("pselect6 nfds={}, readfds={}, writefds={}, exceptfds={}, timeout={}, LR={}", nfds, readfds, writefds, exceptfds, timeout, context.getLRPointer());
            if (readfds != null) {
                byte[] data = readfds.getByteArray(0, size);
                Inspector.inspect(data, "readfds");
            }
            if (writefds != null) {
                byte[] data = writefds.getByteArray(0, size);
                Inspector.inspect(data, "writefds");
            }
        }
        if (exceptfds != null) {
            emulator.getMemory().setErrno(UnixEmulator.ENOMEM);
            return -1;
        }
        if (writefds != null) {
            int count = select(nfds, writefds, readfds, false);
            if (count > 0) {
                return count;
            }
        }
        if (readfds != null) {
            int count = select(nfds, readfds, writefds, true);
            if (count == 0) {
                long deadline = clock == null ? -1 : timeout == null ? clock.nanos() + 1000000000L : deadline(emulator, timeout);
                try {
                    TimeUnit.SECONDS.sleep(1);
                } catch (InterruptedException e) {
                    throw new IllegalStateException(e);
                }
                waitedUntil(deadline); // the timeout (unidbg waits a second) passes on the guest's clock
            }
            return count;
        }
        throw new AbstractMethodError("pselect6 nfds=" + nfds + ", readfds=null, writefds=" + writefds + ", exceptfds=null, timeout=" + timeout + ", LR=" + context.getLRPointer());
    }

    private int recvfrom(Emulator<?> emulator) {
        Backend backend = emulator.getBackend();
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        Pointer buf = context.getPointerArg(1);
        int len = context.getIntArg(2);
        int flags = context.getIntArg(3);
        Pointer src_addr = context.getPointerArg(4);
        Pointer addrlen = context.getPointerArg(5);

        log.debug("recvfrom sockfd={}, buf={}, len={}, flags={}, src_addr={}, addrlen={}", sockfd, buf, len, flags, src_addr, addrlen);
        FileIO file = fdMap.get(sockfd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        return file.recvfrom(backend, buf, len, flags, src_addr, addrlen);
    }

    private int sendto(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        Pointer buf = context.getPointerArg(1);
        int len = context.getIntArg(2);
        int flags = context.getIntArg(3);
        Pointer dest_addr = context.getPointerArg(4);
        int addrlen = context.getIntArg(5);

        return sendto(emulator, sockfd, buf, len, flags, dest_addr, addrlen);
    }

    private int connect(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        Pointer addr = context.getPointerArg(1);
        int addrlen = context.getIntArg(2);
        return connect(emulator, sockfd, addr, addrlen);
    }

    private int getsockname(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        Pointer addr = context.getPointerArg(1);
        Pointer addrlen = context.getPointerArg(2);
        if (log.isDebugEnabled()) {
            log.debug("getsockname sockfd={}, addr={}, addrlen={}", sockfd, addr, addrlen);
        }
        FileIO file = fdMap.get(sockfd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        return file.getsockname(addr, addrlen);
    }

    private int accept4(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        Pointer addr = context.getPointerArg(1);
        Pointer addrlen = context.getPointerArg(2);
        int flags = context.getIntArg(3);
        return accept(emulator, sockfd, addr, addrlen, flags);
    }

    protected final int accept(Emulator<AndroidFileIO> emulator, int sockfd, Pointer addr, Pointer addrlen, int flags) {
        if (log.isDebugEnabled()) {
            log.debug("accept sockfd={}, addr={}, addrlen={}, flags={}", sockfd, addr, addrlen, flags);
        }

        AndroidFileIO file = fdMap.get(sockfd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        AndroidFileIO newIO = file.accept(addr, addrlen);
        if (newIO == null) {
            return -1;
        } else {
            int fd = getMinFd();
            fdMap.put(fd, newIO);
            return fd;
        }
    }

    private int getsockopt(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        int level = context.getIntArg(1);
        int optname = context.getIntArg(2);
        Pointer optval = context.getPointerArg(3);
        Pointer optlen = context.getPointerArg(4);
        if (log.isDebugEnabled()) {
            log.debug("getsockopt sockfd={}, level={}, optname={}, optval={}, optlen={}", sockfd, level, optname, optval, optlen);
        }

        FileIO file = fdMap.get(sockfd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        return file.getsockopt(level, optname, optval, optlen);
    }

    private int setsockopt(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int sockfd = context.getIntArg(0);
        int level = context.getIntArg(1);
        int optname = context.getIntArg(2);
        Pointer optval = context.getPointerArg(3);
        int optlen = context.getIntArg(4);
        if (log.isDebugEnabled()) {
            log.debug("setsockopt sockfd={}, level={}, optname={}, optval={}, optlen={}", sockfd, level, optname, optval, optlen);
        }

        FileIO file = fdMap.get(sockfd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        return file.setsockopt(level, optname, optval, optlen);
    }

    private int sdk;

    @Override
    public void addIOResolver(IOResolver<AndroidFileIO> resolver) {
        super.addIOResolver(resolver);

        if (resolver instanceof AndroidResolver) {
            sdk = ((AndroidResolver) resolver).getSdk();
        }
    }

    /**
     * create AF_UNIX local SOCK_STREAM
     */
    protected AndroidFileIO createLocalSocketIO(Emulator<?> emulator, int sdk) {
        return new LocalSocketIO(emulator, sdk);
    }

    private long socketpair(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int domain = context.getIntArg(0);
        int type = context.getIntArg(1) & 0x7ffff;
        int protocol = context.getIntArg(2);
        Pointer sv = context.getPointerArg(3);
        log.debug("socketpair domain={}, type={}, protocol={}, sv={}", domain, type, protocol, sv);

        if (protocol != SocketIO.AF_UNSPEC) {
            throw new UnsupportedOperationException();
        }
        if (domain == SocketIO.AF_LOCAL) {
            switch (type) {
                case SocketIO.SOCK_STREAM:
                case SocketIO.SOCK_SEQPACKET: {
                    int fd0 = getMinFd();
                    PipedSocketIO one = new PipedSocketIO(emulator);
                    fdMap.put(fd0, one);
                    int fd1 = getMinFd();
                    PipedSocketIO two = new PipedSocketIO(emulator);
                    fdMap.put(fd1, two);
                    one.connectPeer(two);
                    sv.setInt(0, fd0);
                    sv.setInt(4, fd1);
                    return 0;
                }
                default:
                    break;
            }
        }
        throw new UnsupportedOperationException("domain=" + domain + ", type=" + type + ", LR=" + context.getLRPointer());
    }

    private int socket(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int domain = context.getIntArg(0);
        int type = context.getIntArg(1) & 0x7ffff;
        int protocol = context.getIntArg(2);
        log.debug("socket domain={}, type={}, protocol={}", domain, type, protocol);

        if (protocol == SocketIO.IPPROTO_ICMP) {
            throw new UnsupportedOperationException();
        }

        int fd;
        switch (domain) {
            case SocketIO.AF_UNSPEC:
                throw new UnsupportedOperationException();
            case SocketIO.AF_LOCAL:
                switch (type) {
                    case SocketIO.SOCK_STREAM:
                        fd = getMinFd();
                        fdMap.put(fd, createLocalSocketIO(emulator, sdk));
                        return fd;
                    case SocketIO.SOCK_DGRAM:
                        fd = getMinFd();
                        fdMap.put(fd, new LocalAndroidUdpSocket(emulator));
                        return fd;
                    default:
                        emulator.getMemory().setErrno(UnixEmulator.EACCES);
                        return -1;
                }
            case SocketIO.AF_INET:
            case SocketIO.AF_INET6:
                switch (type) {
                    case SocketIO.SOCK_STREAM:
                        fd = getMinFd();
                        fdMap.put(fd, new TcpSocket(emulator));
                        return fd;
                    case SocketIO.SOCK_DGRAM:
                        fd = getMinFd();
                        fdMap.put(fd, new UdpSocket(emulator));
                        return fd;
                    case SocketIO.SOCK_RAW:
                        throw new UnsupportedOperationException();
                }
                break;
            case SocketIO.AF_NETLINK:
                switch (type) {
                    case SocketIO.SOCK_DGRAM:
                        fd = getMinFd();
                        fdMap.put(fd, new NetLinkSocket(emulator));
                        return fd;
                    case SocketIO.SOCK_RAW:
                    default:
                        throw new UnsupportedOperationException();
                }
        }
        log.info("socket domain={}, type={}, protocol={}", domain, type, protocol);
        emulator.getMemory().setErrno(UnixEmulator.EAFNOSUPPORT);
        return -1;
    }

    protected int uname(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        Pointer buf = context.getPointerArg(0);
        if (log.isDebugEnabled()) {
            log.debug("uname buf={}", buf);
        }

        final int SYS_NMLN = 65;

        Pointer sysName = buf.share(0);
        sysName.setString(0, "Linux"); /* Operating system name (e.g., "Linux") */

        Pointer nodeName = sysName.share(SYS_NMLN);
        nodeName.setString(0, "localhost"); /* Name within "some implementation-defined network" */

        Pointer release = nodeName.share(SYS_NMLN);
        release.setString(0, "1.0.0-unidbg"); /* Operating system release (e.g., "2.6.28") */

        Pointer version = release.share(SYS_NMLN);
        version.setString(0, "#1 SMP PREEMPT Thu Apr 19 14:36:58 CST 2018"); /* Operating system version */

        Pointer machine = version.share(SYS_NMLN);
        machine.setString(0, "armv8l"); /* Hardware identifier */

        Pointer domainName = machine.share(SYS_NMLN);
        domainName.setString(0, "localdomain"); /* NIS or YP domain name */

        return 0;
    }

    private int getppid(Emulator<AndroidFileIO> emulator) {
        if (log.isDebugEnabled()) {
            log.debug("getppid");
        }
        return emulator.getPid();
    }

    private void exit_group(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int status = context.getIntArg(0);
        if (log.isDebugEnabled()) {
            log.debug("exit with code: {}", status, new Exception("exit_group status=" + status));
        } else {
            System.out.println("exit with code: " + status);
        }
        if (LoggerFactory.getLogger(AbstractEmulator.class).isDebugEnabled()) {
            createBreaker(emulator).debug("exit_group status=" + status);
        }
        emulator.getBackend().emu_stop();
    }

    private int munmap(Backend backend, Emulator<?> emulator) {
        long timeInMillis = System.currentTimeMillis();
        long start = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
        int length = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).intValue();
        emulator.getMemory().munmap(start, length);
        if (log.isDebugEnabled()) {
            log.debug("munmap start=0x{}, length={}, offset={}", Long.toHexString(start), length, System.currentTimeMillis() - timeInMillis);
        }
        return 0;
    }

    private long mremap(Emulator<?> emulator) {
        Arm64RegisterContext context = emulator.getContext();
        UnidbgPointer old_address = context.getXPointer(0);
        int old_size = context.getXInt(1);
        int new_size = context.getXInt(2);
        int flags = context.getXInt(3);
        UnidbgPointer new_address = context.getXPointer(4);
        if (log.isDebugEnabled()) {
            log.debug("mremap old_address={}, old_size={}, new_size={}, flags={}, new_address={}", old_address, old_size, new_size, flags, new_address);
        }
        if (old_size == 0) {
            throw new BackendException("old_size is zero");
        }
        boolean fixed = (flags & MREMAP_FIXED) != 0;
        if ((flags & MREMAP_MAYMOVE) == 0) {
            throw new BackendException("flags=" + flags);
        }

        Memory memory = emulator.getMemory();
        byte[] data = old_address.getByteArray(0, old_size);
        int prot = memory.munmap(old_address.toUIntPeer(), old_size);
        final long address;
        if (fixed) {
            address = memory.mmap2(new_address.toUIntPeer(), new_size, prot, AndroidElfLoader.MAP_ANONYMOUS | AndroidElfLoader.MAP_FIXED, 0, 0);
        } else {
            address = memory.mmap2(0, new_size, prot, AndroidElfLoader.MAP_ANONYMOUS, 0, 0);
        }
        UnidbgPointer pointer = UnidbgPointer.pointer(emulator, address);
        assert pointer != null;
        pointer.write(0, data, 0, data.length);
        return pointer.toUIntPeer();
    }

    // PR_GET_DUMPABLE/PR_SET_DUMPABLE are called routinely on Android (bionic, and hardened loaders during
    // .init_array). This fork's baseline predates upstream's handling, so they fell through to the default branch
    // and threw UnsupportedOperationException, ending the emulation.
    private static final int PR_GET_DUMPABLE = 3;
    private static final int PR_SET_DUMPABLE = 4;
    private static final int PR_SET_NAME = 15;
    private static final int PR_SET_NO_NEW_PRIVS = 38;
    private static final int PR_GET_NO_NEW_PRIVS = 39;
    private static final int PR_SET_THP_DISABLE = 41;

    // A zygote child that has setresuid'd to the app uid gets dumpable from /proc/sys/fs/suid_dumpable, which is 0 on
    // Android: an app process reads back 0, so answering 1 would be a visible difference from a real device.
    private int dumpable = 0;
    private int noNewPrivs = 0;
    private static final int BIONIC_PR_SET_VMA = 0x53564d41;
    private static final int PR_SET_PTRACER = 0x59616d61;

    private int prctl(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int option = context.getIntArg(0);
        long arg2 = context.getLongArg(1);
        if (log.isDebugEnabled()) {
            log.debug("prctl option=0x{}, arg2=0x{}, task={}", Integer.toHexString(option), Long.toHexString(arg2), emulator.getThreadDispatcher().getRunningTask());
        }
        switch (option) {
            case PR_SET_NAME:
                Pointer threadName = context.getPointerArg(1);
                if (log.isDebugEnabled()) {
                    log.debug("prctl set thread name: {}", threadName.getString(0));
                }
                return 0;
            case BIONIC_PR_SET_VMA:
                Pointer addr = context.getPointerArg(2);
                int len = context.getIntArg(3);
                Pointer pointer = context.getPointerArg(4);
                if (log.isDebugEnabled()) {
                    log.debug("prctl set vma addr={}, len={}, pointer={}, name={}", addr, len, pointer, pointer.getString(0));
                }
                return 0;
            case PR_SET_PTRACER:
                int pid = (int) arg2;
                if (log.isDebugEnabled()) {
                    log.debug("prctl set ptracer: {}", pid);
                }
                return 0;
            case PR_SET_THP_DISABLE:
                return 0;
            case PR_SET_NO_NEW_PRIVS:
                noNewPrivs = (int) arg2;
                return 0;
            case PR_GET_NO_NEW_PRIVS:
                return noNewPrivs;
            case PR_SET_DUMPABLE:
                if (log.isDebugEnabled()) {
                    log.debug("prctl set dumpable: {}", arg2);
                }
                dumpable = (int) arg2;
                return 0;
            case PR_GET_DUMPABLE:
                return dumpable;
            default:
                throw new UnsupportedOperationException("option=" + option);
        }
    }

    private static final int CLOCK_REALTIME = 0;
    private static final int CLOCK_MONOTONIC = 1;
    private static final int CLOCK_THREAD_CPUTIME_ID = 3;
    private static final int CLOCK_MONOTONIC_RAW = 4;
    private static final int CLOCK_MONOTONIC_COARSE = 6;
    private static final int CLOCK_BOOTTIME = 7;
    private static final int CLOCK_PROCESS_CPUTIME_ID = 2;
    private static final int CLOCK_REALTIME_COARSE = 5;
    private static final int CLOCK_TAI = 11;

    private final long nanoTime = System.nanoTime();

    protected int clock_gettime(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        if (clock != null) {
            // clocks unidbg had no answer for (it threw, or read CLOCK_TAI as 3 once masked), from the guest's clock:
            // the process's CPU time is its instructions' time without the waits; CLOCK_TAI is CLOCK_REALTIME, the
            // kernel's TAI offset staying 0 on Android
            int id = context.getIntArg(0);
            long nanos = id == CLOCK_PROCESS_CPUTIME_ID ? clock.cpuNanos() : id == CLOCK_REALTIME_COARSE || id == CLOCK_TAI ? realtimeNanos() : -1;
            if (nanos >= 0) {
                Pointer tp = context.getPointerArg(1);
                tp.setLong(0, nanos / 1000000000L);
                tp.setLong(8, nanos % 1000000000L);
                return 0;
            }
        }
        int clk_id = context.getIntArg(0) & 0x7;
        Pointer tp = context.getPointerArg(1);
        long offset = clk_id == CLOCK_REALTIME ? realtimeNanos() : monotonicNanos();
        long tv_sec = offset / 1000000000L;
        long tv_nsec = offset % 1000000000L;
        if (log.isDebugEnabled()) {
            log.debug("clock_gettime clk_id={}, tp={}, offset={}, tv_sec={}, tv_nsec={}", clk_id, tp, offset, tv_sec, tv_nsec);
        }
        switch (clk_id) {
            case CLOCK_REALTIME:
            case CLOCK_MONOTONIC:
            case CLOCK_THREAD_CPUTIME_ID:
            case CLOCK_MONOTONIC_RAW:
            case CLOCK_MONOTONIC_COARSE:
            case CLOCK_BOOTTIME:
                tp.setLong(0, tv_sec);
                tp.setLong(8, tv_nsec);
                return 0;
        }
        if (log.isDebugEnabled()) {
            emulator.attach().debug("Unsupported clock_gettime clk_id=" + clk_id);
        }
        throw new UnsupportedOperationException("clk_id=" + clk_id);
    }

    protected long ptrace(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int request = context.getIntArg(0);
        int pid = context.getIntArg(1);
        Pointer addr = context.getPointerArg(2);
        Pointer data = context.getPointerArg(3);
        log.info("ptrace request=0x{}, pid={}, addr={}, data={}", Integer.toHexString(request), pid, addr, data);
        return 0;
    }

    private int fcntl(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        int cmd = context.getIntArg(1);
        int arg = context.getIntArg(2);
        return fcntl(emulator, fd, cmd, arg);
    }

    private int writev(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        Pointer iov = context.getPointerArg(1);
        int iovcnt = context.getIntArg(2);
        if (log.isDebugEnabled()) {
            for (int i = 0; i < iovcnt; i++) {
                Pointer iov_base = iov.getPointer(i * 16L);
                long iov_len = iov.getLong(i * 16L + 8);
                byte[] data = iov_base.getByteArray(0, (int) iov_len);
                Inspector.inspect(data, "writev fd=" + fd + ", iov=" + iov + ", iov_base=" + iov_base);
            }
        }

        FileIO file = fdMap.get(fd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }

        int count = 0;
        for (int i = 0; i < iovcnt; i++) {
            Pointer iov_base = iov.getPointer(i * 16L);
            long iov_len = iov.getLong(i * 16L + 8);
            byte[] data = iov_base.getByteArray(0, (int) iov_len);
            count += file.write(data);
        }
        return count;
    }

    private long brk(Backend backend, Emulator<?> emulator) {
        long address = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
        if (log.isDebugEnabled()) {
            log.debug("brk address=0x{}", Long.toHexString(address));
        }
        return emulator.getMemory().brk(address);
    }

    private int mprotect(Backend backend, Emulator<?> emulator) {
        long address = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
        int length = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).intValue();
        int prot = backend.reg_read(Arm64Const.UC_ARM64_REG_X2).intValue();
        long pageAlign = emulator.getPageAlign();
        long alignedAddress = address / pageAlign * pageAlign;
        long offset = address - alignedAddress;

        long alignedLength = ARM.alignSize(length + offset, emulator.getPageAlign());
        if (log.isDebugEnabled()) {
            log.debug("mprotect address=0x{}, alignedAddress=0x{}, offset={}, length={}, alignedLength={}, prot=0x{}", Long.toHexString(address), Long.toHexString(alignedAddress), offset, length, alignedLength, Integer.toHexString(prot));
        }
        return emulator.getMemory().mprotect(alignedAddress, (int) alignedLength, prot);
    }

    private long mmap(Backend backend, Emulator<?> emulator) {
        long start = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
        int length = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).intValue();
        int prot = backend.reg_read(Arm64Const.UC_ARM64_REG_X2).intValue();
        int flags = backend.reg_read(Arm64Const.UC_ARM64_REG_X3).intValue();
        int fd = backend.reg_read(Arm64Const.UC_ARM64_REG_X4).intValue();
        int offset = backend.reg_read(Arm64Const.UC_ARM64_REG_X5).intValue();
        if (offset % emulator.getPageAlign() != 0) {
            throw new IllegalArgumentException("offset=0x" + Long.toHexString(offset));
        }

        boolean warning = length > 0x10000000;
        if (log.isDebugEnabled() || warning) {
            String msg = "mmap start=0x" + Long.toHexString(start) + ", length=" + length + ", prot=0x" + Integer.toHexString(prot) + ", flags=0x" + Integer.toHexString(flags) + ", fd=" + fd + ", offset=" + offset;
            if (warning) {
                log.warn(msg);
                if (log.isTraceEnabled()) {
                    emulator.attach().debug("mmap warning");
                }
            } else {
                log.debug(msg);
            }
        }
        if ((flags & AndroidElfLoader.MAP_ANONYMOUS) == 0 && isSignalModelEnabled(emulator)) {
            warnUnmappable(fd);
        }
        long mapped = emulator.getMemory().mmap2(start, length, prot, flags, fd, offset);
        if (log.isDebugEnabled()) {
            log.debug("mmap start=0x{}, mapped=0x{}, length=0x{}, prot=0x{}, flags=0x{}, fd={}, offset={}, task={}", Long.toHexString(start), Long.toHexString(mapped), Integer.toHexString(length), Integer.toHexString(prot), Integer.toHexString(flags), fd, offset, emulator.getThreadDispatcher().getRunningTask());
        }
        return mapped;
    }

    /**
     * Files a device kernel cannot mmap: procfs (the status, stat and wchan a ptrace check reads, maps, ...) and sysfs
     * attributes fail with -ENODEV or -EIO. unidbg maps their content; mapping one is something a check can tell apart.
     */
    private static final String[] UNMAPPABLE_PREFIXES = {"/proc/", "/sys/"};

    /** warns when the guest maps one of those files, which is then mapped as before */
    private void warnUnmappable(int fd) {
        FileIO file = fdMap.get(fd);
        String path = String.valueOf(file); // the path, as for the FileListener
        for (String prefix : UNMAPPABLE_PREFIXES) {
            if (file != null && path.startsWith(prefix)) {
                log.warn("mmap of {} (fd={}): a device cannot map this file, its mmap fails; mapped here as before", path, fd);
                return;
            }
        }
    }

    private int gettimeofday(Emulator<?> emulator) {
        Pointer tv = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
        Pointer tz = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
        return gettimeofday64(tv, tz);
    }

    private int faccessat(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int dirfd = context.getIntArg(0);
        Pointer pathname_p = context.getPointerArg(1);
        int oflags = context.getIntArg(2);
        int mode = context.getIntArg(3);
        String pathname = pathname_p.getString(0);
        if (log.isDebugEnabled()) {
            log.debug("faccessat dirfd={}, pathname={}, oflags=0x{}, mode=0x{}", dirfd, pathname, Integer.toHexString(oflags), Integer.toHexString(mode));
        }
        // Resolving faccessat(dirfd, relative path) is plain POSIX and has nothing to do with the signal model: gating
        // it meant a relative path was looked up from the rootfs' root instead, and reported as absent.
        if (dirfd != IO.AT_FDCWD && !pathname.startsWith("/")) {
            String path = atPath(dirfd, pathname);
            if (path != null) {
                pathname = path; // not the relative path on its own, which unidbg looks up from the rootfs' root
            }
        }
        int ret = faccessat(emulator, pathname);
        if (ret == -1 && verbose) {
            log.info("faccessat failed dirfd={}, pathname={}, oflags=0x{}, mode=0x{}", dirfd, pathname, Integer.toHexString(oflags), Integer.toHexString(mode));
        }
        return ret;
    }

    private int faccessat(Emulator<AndroidFileIO> emulator, String pathname) {
        FileResult<?> result = resolve(emulator, pathname, IOConstants.O_RDONLY);
        if (result != null && result.isSuccess()) {
            return 0;
        }

        emulator.getMemory().setErrno(result != null ? result.errno : UnixEmulator.EACCES);
        return -1;
    }

    private int fstatat64(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int dirfd = context.getIntArg(0);
        Pointer pathname = context.getPointerArg(1);
        Pointer statbuf = context.getPointerArg(2);
        int flags = context.getIntArg(3);
        String path = FilenameUtils.normalize(pathname.getString(0), true);
        if (log.isDebugEnabled()) {
            log.debug("fstatat64 dirfd={}, pathname={}, statbuf={}, flags={}", dirfd, path, statbuf, flags);
        }
        String raw = pathname.getString(0);
        // Same as faccessat: fstatat(dirfd, relative path) is plain POSIX. While this was gated, an ordinary fstatat
        // fell through to the BackendException below and ended the emulation (seen with a loader reading its own apk:
        // openat for a directory fd, then fstatat on an entry relative to it).
        if (dirfd != IO.AT_FDCWD && !raw.startsWith("/")) {
            String at = atPath(dirfd, raw);
            if (at != null) {
                path = at;
            }
        }
        if (dirfd == IO.AT_FDCWD && "".equals(path)) {
            return stat64(emulator, ".", statbuf);
        }
        if (path.startsWith("/")) {
            return stat64(emulator, path, statbuf);
        } else {
            if (dirfd != IO.AT_FDCWD) {
                // An fstatat that finds nothing is an ordinary error the guest handles; throwing turned it into an
                // unrecoverable stop. Report it the way the AT_FDCWD case below does, so it stays visible in the log.
                log.warn("fstatat64 could not resolve dirfd={}, pathname={}, flags={}", dirfd, path, flags);
                emulator.getMemory().setErrno(UnixEmulator.ENOENT);
                return -1;
            }

            log.warn("fstatat64 dirfd={}, pathname={}, statbuf={}, flags={}", dirfd, path, statbuf, flags);
            if (log.isDebugEnabled()) {
                emulator.attach().debug("fstatat64 path=" + path);
            }
            emulator.getMemory().setErrno(UnixEmulator.EACCES);
            return -1;
        }
    }

    private int openat(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int dirfd = context.getIntArg(0);
        Pointer pathname_p = context.getPointerArg(1);
        int oflags = context.getIntArg(2);
        int mode = context.getIntArg(3);
        String pathname = pathname_p.getString(0);
        log.debug("openat dirfd={}, pathname={}, oflags=0x{}, mode={}", dirfd, pathname, Integer.toHexString(oflags), Integer.toHexString(mode));
        // Same as fstatat/faccessat: openat's dirfd-relative resolution is plain POSIX.
        if (dirfd != IO.AT_FDCWD && !pathname.startsWith("/")) {
            String path = atPath(dirfd, pathname);
            if (path != null) {
                pathname = path;
            }
        }
        pathname = FilenameUtils.normalize(pathname, true);
        if ("/data/misc/zoneinfo/current/tzdata".equals(pathname) || "/dev/pmsg0".equals(pathname)) {
            emulator.getMemory().setErrno(UnixEmulator.ENOENT);
            return -UnixEmulator.ENOENT;
        }
        if (pathname.startsWith("/")) {
            int fd = open(emulator, pathname, oflags);
            if (fd == -1) {
                if (verbose) {
                    log.info("openat dirfd={}, pathname={}, oflags=0x{}, mode={}", dirfd, pathname, Integer.toHexString(oflags), Integer.toHexString(mode));
                }
                return -emulator.getMemory().getLastErrno();
            } else {
                return fd;
            }
        } else {
            if (dirfd != IO.AT_FDCWD) {
                throw new BackendException();
            }

            int fd = open(emulator, pathname, oflags);
            if (fd == -1) {
                if (log.isTraceEnabled()) {
                    emulator.attach().debug("openat failed: " + pathname);
                }
                if (verbose) {
                    log.info("openat AT_FDCWD dirfd={}, pathname={}, oflags=0x{}, mode={}", dirfd, pathname, Integer.toHexString(oflags), Integer.toHexString(mode));
                }
                return -emulator.getMemory().getLastErrno();
            } else {
                return fd;
            }
        }
    }

    private int lseek(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        int offset = context.getIntArg(1);
        int whence = context.getIntArg(2);
        FileIO file = fdMap.get(fd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        int pos = file.lseek(offset, whence);
        if (log.isDebugEnabled()) {
            log.debug("lseek fd={}, offset={}, whence={}, pos={}", fd, offset, whence, pos);
        }
        return pos;
    }

    private int close(Backend backend, Emulator<?> emulator) {
        int fd = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).intValue();
        if (log.isDebugEnabled()) {
            log.debug("close fd={}", fd);
        }

        return close(emulator, fd);
    }

    private int getdents64(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        UnidbgPointer dirp = context.getPointerArg(1);
        int size = context.getIntArg(2);
        if (log.isDebugEnabled()) {
            log.debug("getdents64 fd={}, dirp={}, size={}", fd, dirp, size);
        }

        AndroidFileIO io = fdMap.get(fd);
        if (io == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        } else {
            dirp.setSize(size);
            return io.getdents64(dirp, size);
        }
    }

    private int readlinkat(Emulator<AndroidFileIO> emulator) {
        RegisterContext context = emulator.getContext();
        int dirfd = context.getIntArg(0);
        Pointer pathname = context.getPointerArg(1);
        Pointer buf = context.getPointerArg(2);
        int bufSize = context.getIntArg(3);
        String path = pathname.getString(0);
        if (dirfd != IO.AT_FDCWD) {
            String fdLink = isSignalModelEnabled(emulator) && !path.startsWith("/") ? atPath(dirfd, path) : null;
            if (fdLink == null || !isOpenFdLink(emulator, fdLink)) {
                // only an entry of a /proc/.../fd directory listing (an fd scan) is answered: any other path would get
                // readlink's answer for what it does not know, the path itself, as if it existed
                throw new BackendException();
            }
            path = fdLink;
        }
        return modelHandles(emulator, "readlink") ? kernelReadlink(emulator, path, buf, bufSize) : readlink(emulator, path, buf, bufSize);
    }

    /**
     * The path a *at syscall names by a path relative to the directory dirfd: the directory's path joined with it,
     * which unidbg then looks up as any whole path (the IOResolvers see it so). null where unidbg does not know dirfd
     * as a directory, or the path is empty (AT_EMPTY_PATH): unidbg's original handling then applies.
     */
    private String atPath(int dirfd, String path) {
        FileIO dir = fdMap.get(dirfd);
        if (!(dir instanceof DirectoryFileIO) || path.isEmpty()) {
            return null;
        }
        return FilenameUtils.normalize(dir.getPath() + "/" + path, true);
    }

    /** /proc/self/fd/N or /proc/&lt;own pid&gt;/fd/N of an open fd */
    private boolean isOpenFdLink(Emulator<?> emulator, String path) {
        Matcher matcher = Pattern.compile("/proc/(?:self|" + emulator.getPid() + ")/fd/(\\d{1,9})").matcher(path);
        return matcher.matches() && fdMap.containsKey(Integer.parseInt(matcher.group(1)));
    }

    /**
     * readlink with the link unidbg's own method resolves, written back as the kernel does: at most bufsiz bytes, no
     * terminating NUL, the count returned (unidbg's method writes the whole path and its NUL, whatever bufsiz is, and
     * counts the NUL). Which paths resolve to what is unchanged, except that /proc/&lt;own pid&gt;/fd/N of an open fd
     * resolves like /proc/self/fd/N.
     */
    private int kernelReadlink(Emulator<?> emulator, String path, Pointer buf, int bufSize) {
        if (bufSize <= 0) {
            return (int) errno(emulator, UnixEmulator.EINVAL);
        }
        String ownFd = "/proc/" + emulator.getPid() + "/fd/";
        if (path.startsWith(ownFd)) {
            String name = path.substring(ownFd.length());
            if (name.matches("\\d{1,9}") && fdMap.containsKey(Integer.parseInt(name))) {
                // the same open fd as /proc/self/fd/N, as unidbg's open takes it; its readlink knows the /proc/self form only
                path = "/proc/self/fd/" + name;
            }
        }
        final String[] link = new String[1];
        int ret = readlink(emulator, path, new Pointer(0) {
            @Override
            public void setString(long offset, String value) {
                link[0] = value; // unidbg's method writes the link with this
            }
        }, bufSize);
        if (link[0] == null) {
            return ret;
        }
        byte[] bytes = link[0].getBytes(StandardCharsets.UTF_8); // as UnidbgPointer#setString
        int length = Math.min(bytes.length, bufSize);
        buf.write(0, bytes, 0, length);
        return length;
    }

    private int fstat(Backend backend, Emulator<?> emulator) {
        int fd = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).intValue();
        Pointer stat = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
        return fstat(emulator, fd, stat);
    }

    protected int fstat(Emulator<?> emulator, int fd, Pointer stat) {
        AndroidFileIO file = fdMap.get(fd);
        if (file == null) {
            if (log.isDebugEnabled()) {
                log.debug("fstat fd={}, stat={}, errno=" + UnixEmulator.EBADF, fd, stat);
            }

            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        if (log.isDebugEnabled()) {
            log.debug("fstat file={}, stat={}, from={}", file, stat, emulator.getContext().getLRPointer());
        }
        return file.fstat(emulator, new Stat64(stat));
    }

    private int ioctl(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        long request = context.getLongArg(1);
        long argp = context.getLongArg(2);
        if (log.isDebugEnabled()) {
            log.debug("ioctl fd={}, request=0x{}, argp=0x{}", fd, Long.toHexString(request), Long.toHexString(argp));
        }

        FileIO file = fdMap.get(fd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        int ret = file.ioctl(emulator, request, argp);
        if (ret == -1) {
            emulator.getMemory().setErrno(UnixEmulator.ENOTTY);
        }
        return ret;
    }

    private int write(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        Pointer buffer = context.getPointerArg(1);
        int count = context.getIntArg(2);
        return write(emulator, fd, buffer, count);
    }

    private int read(Backend backend, Emulator<?> emulator) {
        int fd = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).intValue();
        Pointer buffer = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
        int count = backend.reg_read(Arm64Const.UC_ARM64_REG_X2).intValue();
        return read(emulator, fd, buffer, count);
    }

    /** pread64(fd, buf, count, offset): reads at an absolute offset and leaves the file position alone */
    private int pread(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int fd = context.getIntArg(0);
        Pointer buffer = context.getPointerArg(1);
        int count = context.getIntArg(2);
        long offset = context.getLongArg(3);
        if (log.isDebugEnabled()) {
            log.debug("pread64 fd={}, buffer={}, count={}, offset={}", fd, buffer, count, offset);
        }
        FileIO file = fdMap.get(fd);
        if (file == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }
        return file.pread(emulator.getBackend(), buffer, count, offset);
    }

    private int dup3(Emulator<?> emulator) {
        RegisterContext context = emulator.getContext();
        int oldfd = context.getIntArg(0);
        int newfd = context.getIntArg(1);
        int flags = context.getIntArg(2);
        if (log.isDebugEnabled()) {
            log.debug("dup3 oldfd={}, newfd={}, flags=0x{}", oldfd, newfd, Integer.toHexString(flags));
        }

        FileIO old = fdMap.get(oldfd);
        if (old == null) {
            emulator.getMemory().setErrno(UnixEmulator.EBADF);
            return -1;
        }

        if (oldfd == newfd) {
            return newfd;
        }
        AndroidFileIO _new = fdMap.remove(newfd);
        if (_new != null) {
            _new.close();
        }
        _new = (AndroidFileIO) old.dup2();
        fdMap.put(newfd, _new);
        return newfd;
    }

    @Override
    protected AndroidFileIO createByteArrayFileIO(String pathname, int oflags, byte[] data) {
        return new ByteArrayFileIO(oflags, pathname, data);
    }

    @Override
    protected AndroidFileIO createDriverFileIO(Emulator<?> emulator, int oflags, String pathname) {
        return DriverFileIO.create(emulator, oflags, pathname);
    }
}
