package com.github.unidbg.thread;

import com.github.unidbg.Emulator;

import java.util.List;

/**
 * Optional capability of a syscall handler whose kernel model takes part in {@link UniThreadDispatcher}'s scheduling
 * (check with <code>instanceof</code>, like {@link com.github.unidbg.signal.SignalDeliverer}). Without it the
 * dispatcher works as it always has.
 */
public interface DispatcherHooks {

    /**
     * A whole round of the dispatcher ran no task: every task waits. The model may let the guest's time pass so that
     * a timed wait can end.
     *
     * @param maxNanos how much guest time may pass at most: {@link Long#MAX_VALUE} while a call waits for its main
     *                 task (as far as the earliest timed wait), else the host time the round took
     * @return true if time passed
     */
    boolean idle(Emulator<?> emulator, List<Task> tasks, long maxNanos);

    /**
     * Whether the model takes part in scheduling for this emulator. Then a thread that finished is released at once
     * (its stack slot) instead of when the call returns, and {@link ThreadDispatcher#runThreads} leaves the CPU state
     * as the last call left it (the main thread's registers, TLS...). A call made while one runs is refused with
     * emulate's "running" error before its task is added.
     */
    boolean isEnabled(Emulator<?> emulator);

}
