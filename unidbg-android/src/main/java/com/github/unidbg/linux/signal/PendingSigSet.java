package com.github.unidbg.linux.signal;

import com.github.unidbg.signal.SigSet;
import com.github.unidbg.signal.SignalOps;
import com.github.unidbg.signal.UnixSigSet;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * The pending set of a thread (or of the process) as the kernel keeps it: the bitmask unidbg's {@link SignalOps}
 * already hold, plus the siginfo of each pending signal. Standard signals (1-31) do not queue, a second instance of
 * one already pending is dropped; real-time signals (32-64) queue in order, each with its own siginfo.
 */
public class PendingSigSet extends UnixSigSet {

    private final List<SigInfo> queue = new ArrayList<>();

    public PendingSigSet() {
        super(0);
    }

    /** the thread's pending set, upgraded in place from the plain bitmask unidbg may have put there */
    public static PendingSigSet of(SignalOps ops) {
        SigSet set = ops.getSigPendingSet();
        if (set instanceof PendingSigSet) {
            return (PendingSigSet) set;
        }
        PendingSigSet pending = new PendingSigSet();
        if (set != null) {
            pending.setMask(set.getMask());
        }
        ops.setSigPendingSet(pending);
        return pending;
    }

    /**
     * @return false if the signal was a standard one that is already pending (dropped, as the kernel does)
     */
    public boolean add(SigInfo info) {
        if (!info.isRealtime() && containsSigNumber(info.signo)) {
            return false;
        }
        queue.add(info);
        super.setMask(getMask() | info.bit());
        return true;
    }

    /**
     * Removes and returns the signal the kernel would dequeue next among <code>allowed</code> (see {@link
     * SigInfo#priority()}; the oldest within one number), or null if none is allowed.
     */
    public SigInfo take(long allowed) {
        SigInfo best = null;
        for (SigInfo info : queue) {
            if ((info.bit() & allowed) != 0 && (best == null || info.priority() < best.priority())) {
                best = info;
            }
        }
        if (best != null) {
            queue.remove(best);
            syncMask();
        }
        return best;
    }

    /** discards every pending instance of a signal (its disposition became "ignore") */
    public void discard(int signum) {
        for (Iterator<SigInfo> iterator = queue.iterator(); iterator.hasNext(); ) {
            if (iterator.next().signo == signum) {
                iterator.remove();
            }
        }
        syncMask();
    }

    private void syncMask() {
        long mask = 0;
        for (SigInfo info : queue) {
            mask |= info.bit();
        }
        super.setMask(mask);
    }

    /*
     * SigSet's bitmask operations, as unidbg's own code applies them to a pending set (add/remove a signal number,
     * rebuild it from a mask): kept in step with the queue. The name blockSigSet/unblockSigSet comes from the mask use
     * of SigSet; on a pending set they add or remove signals.
     */

    @Override
    public void addSigNumber(int signum) {
        add(SigInfo.fromProcess(signum, SigInfo.SI_TKILL, 0, 0));
    }

    @Override
    public void removeSigNumber(int signum) {
        take(1L << (signum - 1));
    }

    @Override
    public void blockSigSet(long mask) {
        for (int bit = 0; bit < 64; bit++) {
            if ((mask & (1L << bit)) != 0) {
                addSigNumber(bit + 1);
            }
        }
    }

    @Override
    public void unblockSigSet(long mask) {
        for (int bit = 0; bit < 64; bit++) {
            if ((mask & (1L << bit)) != 0) {
                discard(bit + 1);
            }
        }
    }

    @Override
    public void setMask(long mask) {
        unblockSigSet(getMask() & ~mask);
        blockSigSet(mask & ~getMask());
    }

}
