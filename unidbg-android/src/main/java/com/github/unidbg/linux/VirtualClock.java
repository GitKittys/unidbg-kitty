package com.github.unidbg.linux;

import com.github.unidbg.arm.backend.SysRegBackend;
import com.github.unidbg.thread.MainTask;
import com.github.unidbg.thread.RunnableTask;

import java.lang.ref.WeakReference;

/**
 * The guest's time: the one clock CLOCK_MONOTONIC, CLOCK_REALTIME and CNTVCT_EL0 all derive from, so they agree. It
 * moves with the instructions the engine executes, at a fixed rate, and with the time the guest waits (a sleep or a
 * timed wait ends exactly at its deadline), never with host time: the host pausing (a debugger, a slow hook,
 * Thread.sleep) does not show, and the same run reads the same times.
 */
final class VirtualClock {

    /** about two instructions per nanosecond, a typical arm64 core */
    private static final long PICOS_PER_INSTRUCTION = 500;

    private final SysRegBackend backend;
    private final long startCount;

    /** time added by waits and by strictly increasing counter reads */
    private long waited;

    /** CLOCK_REALTIME - CLOCK_MONOTONIC */
    private long realtimeOffset;

    /** the main task of the call being run */
    private WeakReference<RunnableTask> call = new WeakReference<>(null);

    VirtualClock(SysRegBackend backend, long count) {
        this.backend = backend;
        this.startCount = count;
        this.realtimeOffset = System.currentTimeMillis() * 1000000L;
    }

    /** CLOCK_MONOTONIC in ns: 0 when the emulator was created, like unidbg's host-based clock */
    long nanos() {
        return (backend.insn_count() - startCount) * PICOS_PER_INSTRUCTION / 1000 + waited;
    }

    long realtimeNanos() {
        return realtimeOffset + nanos();
    }

    /** CLOCK_PROCESS_CPUTIME_ID in ns: the time of the instructions executed, the waits left out */
    long cpuNanos() {
        return (backend.insn_count() - startCount) * PICOS_PER_INSTRUCTION / 1000;
    }

    /** a wait ended at its deadline (CLOCK_MONOTONIC ns): the clock is there at least */
    void advanceTo(long deadline) {
        long now = nanos();
        if (deadline > now) {
            waited += deadline - now;
        }
    }

    /**
     * The guest starts running task: if it is a new call from the host, CLOCK_REALTIME catches up with the host's
     * wall clock (never back), so the timestamps the guest makes stay current in a long-lived emulator. Between calls
     * the guest does not run, like a device asleep: CLOCK_MONOTONIC and the counter do not move.
     */
    void enter(RunnableTask task) {
        if (task instanceof MainTask && task != call.get()) {
            call = new WeakReference<>(task);
            long behind = System.currentTimeMillis() * 1000000L - realtimeNanos();
            if (behind > 0) {
                realtimeOffset += behind;
            }
        }
    }

}
