package com.github.unidbg.linux.signal;

import com.github.unidbg.unix.UnixEmulator;

/**
 * Per-thread signal state the kernel keeps besides the blocked mask and the pending set (which stay in the thread's
 * {@link com.github.unidbg.signal.SignalOps}): the sigaltstack, the mask rt_sigsuspend restores, and the set a
 * rt_sigtimedwait is waiting for.
 */
public final class ThreadSignalState {

    public static final int SS_ONSTACK = 1;
    public static final int SS_DISABLE = 2;
    public static final int SS_AUTODISARM = 1 << 31;
    private static final int MINSIGSTKSZ = 5120;

    long altStackSp;
    long altStackSize;
    boolean altStackAutoDisarm;

    /** mask to save in the next signal frame instead of the current one (set by rt_sigsuspend), or null */
    public Long suspendSavedMask;

    /** signals a rt_sigtimedwait of this thread is waiting for: it wants them although it blocks them meanwhile */
    public long waitingMask;

    public long getAltStackSp() {
        return altStackSp;
    }

    public long getAltStackSize() {
        return altStackSize;
    }

    public boolean hasAltStack() {
        return altStackSize != 0;
    }

    /** kernel on_sig_stack() */
    public boolean onAltStack(long sp) {
        return hasAltStack() && sp > altStackSp && sp - altStackSp <= altStackSize;
    }

    /** ss_flags reported for a thread at sp (sigaltstack old_ss, the frame's uc_stack) */
    public int altStackFlags(long sp) {
        int flags = !hasAltStack() ? SS_DISABLE : onAltStack(sp) ? SS_ONSTACK : 0;
        return altStackAutoDisarm ? flags | SS_AUTODISARM : flags;
    }

    /**
     * The kernel's do_sigaltstack() for a new stack, from sigaltstack() or from a frame's uc_stack on rt_sigreturn.
     *
     * @param sp the thread's stack pointer: the alternate stack cannot change while the thread runs on it
     * @return 0, or -errno
     */
    public int setAltStack(long sp, long ssSp, int ssFlags, long ssSize) {
        if (onAltStack(sp)) {
            return -UnixEmulator.EPERM;
        }
        int mode = ssFlags & ~SS_AUTODISARM;
        if (mode != 0 && mode != SS_ONSTACK && mode != SS_DISABLE) {
            return -UnixEmulator.EINVAL;
        }
        if (mode == SS_DISABLE) {
            altStackSp = 0;
            altStackSize = 0;
            altStackAutoDisarm = false;
        } else {
            if (ssSize < MINSIGSTKSZ) {
                return -UnixEmulator.ENOMEM;
            }
            altStackSp = ssSp;
            altStackSize = ssSize;
            altStackAutoDisarm = (ssFlags & SS_AUTODISARM) != 0;
        }
        return 0;
    }

    /** SS_AUTODISARM: the handler entered runs without an alternate stack until rt_sigreturn restores uc_stack */
    void disarmAltStack() {
        altStackSp = 0;
        altStackSize = 0;
        altStackAutoDisarm = false;
    }

}
