package com.github.unidbg.linux;

import com.github.unidbg.Emulator;
import com.github.unidbg.linux.thread.AndroidWaiter;
import com.github.unidbg.linux.thread.FutexWaiter;
import com.github.unidbg.signal.SignalTask;
import com.github.unidbg.unix.UnixEmulator;
import com.sun.jna.Pointer;
import unicorn.Arm64Const;

/**
 * Timed waits of threads the dispatcher puts to sleep, on the guest's clock: the guest's time passes with the
 * instructions other threads execute and, when every thread waits, the dispatcher moves it on to the earliest deadline
 * ({@link ARM64SyscallHandler#idle}). A wait therefore lasts as long as on a device however slow the emulation is,
 * and the same run waits the same way.
 */
final class GuestWaits {

    /** a waiter whose wait ends at a CLOCK_MONOTONIC deadline (-1: no deadline) */
    interface Timed {
        long deadline();
    }

    /** FUTEX_WAIT with a timeout: unidbg's futex waiter (FUTEX_WAKE finds it), ending at the deadline */
    static final class Futex extends FutexWaiter implements Timed {
        private final VirtualClock clock;
        private final long deadline;

        Futex(VirtualClock clock, long deadline, Pointer uaddr, int val) {
            super(uaddr, val);
            this.clock = clock;
            this.deadline = deadline;
        }

        @Override
        public long deadline() {
            return deadline;
        }

        @Override
        public boolean canDispatch() {
            return super.canDispatch() || clock.nanos() >= deadline;
        }

        @Override
        protected void onContinueRunInternal(Emulator<?> emulator) {
            // not woken by FUTEX_WAKE: timed out, or the word changed (unidbg treats that as a wake)
            emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_X0, clock.nanos() >= deadline ? -AndroidSyscallHandler.ETIMEDOUT : 0);
        }
    }

    /** nanosleep: a signal ends it with -EINTR and the remaining time in rem */
    static final class Sleep extends AndroidWaiter implements Timed {
        private final VirtualClock clock;
        private final long deadline;
        private final Pointer rem;
        private boolean interrupted;

        Sleep(VirtualClock clock, long deadline, Pointer rem) {
            this.clock = clock;
            this.deadline = deadline;
            this.rem = rem;
        }

        @Override
        public long deadline() {
            return deadline;
        }

        @Override
        public boolean canDispatch() {
            return interrupted || clock.nanos() >= deadline;
        }

        @Override
        public void onSignal(SignalTask task) {
            interrupted = true;
            if (rem != null) {
                long remaining = Math.max(0, deadline - clock.nanos());
                rem.setLong(0, remaining / 1000000000L);
                rem.setLong(8, remaining % 1000000000L);
            }
        }

        @Override
        public void onContinueRun(Emulator<?> emulator) {
            if (interrupted) {
                emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_X0, -UnixEmulator.EINTR);
            }
        }
    }

    private GuestWaits() {
    }

}
