package com.github.unidbg.linux.signal;

import com.github.unidbg.pointer.UnidbgPointer;

/**
 * A generated signal with the siginfo the kernel would report for it (arm64 siginfo_t: si_signo@0, si_errno@4,
 * si_code@8, the union at 16).
 */
public final class SigInfo {

    public static final int SI_USER = 0;
    public static final int SI_TKILL = -6;

    public static final int SIZE = 128;

    /** SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGFPE, SIGSYS: dequeued before anything else (the kernel's SYNCHRONOUS_MASK) */
    private static final long SYNCHRONOUS_MASK = (1L << (11 - 1)) | (1L << (7 - 1)) | (1L << (4 - 1)) |
            (1L << (5 - 1)) | (1L << (8 - 1)) | (1L << (31 - 1));

    public final int signo;
    public final int code;
    public final int pid;
    public final int uid;
    /** si_value (sigqueue), or si_addr for a fault */
    public final long value;
    /** synchronous fault raised by the instruction at {@link #pc} */
    public final boolean fault;
    /** the faulting instruction, where the thread resumes unless the handler moves it */
    public final long pc;
    /** uc_mcontext.fault_address: the address of a memory fault, 0 otherwise */
    public final long faultAddress;
    /** syndrome for the frame's esr_context, 0 for none */
    public final long esr;

    private SigInfo(int signo, int code, int pid, int uid, long value, boolean fault, long pc, long faultAddress, long esr) {
        this.signo = signo;
        this.code = code;
        this.pid = pid;
        this.uid = uid;
        this.value = value;
        this.fault = fault;
        this.pc = pc;
        this.faultAddress = faultAddress;
        this.esr = esr;
    }

    /** kill/tgkill/tkill: si_pid, si_uid of the sender */
    public static SigInfo fromProcess(int signo, int code, int pid, int uid) {
        return new SigInfo(signo, code, pid, uid, 0, false, 0, 0, 0);
    }

    /** rt_sigqueueinfo/rt_tgsigqueueinfo: the caller's siginfo (si_code, si_pid, si_uid, si_value) */
    public static SigInfo fromUser(int signo, UnidbgPointer info) {
        return new SigInfo(signo, info.getInt(8), info.getInt(16), info.getInt(20), info.getLong(24), false, 0, 0, 0);
    }

    /** an instruction fault (SIGILL, SIGTRAP): si_addr = the faulting instruction */
    public static SigInfo fault(int signo, int code, long pc, long esr) {
        return new SigInfo(signo, code, 0, 0, pc, true, pc, 0, esr);
    }

    /** a memory fault (SIGSEGV) of the instruction at pc: si_addr = uc_mcontext.fault_address = the faulting address */
    public static SigInfo memoryFault(int signo, int code, long pc, long address, long esr) {
        return new SigInfo(signo, code, 0, 0, address, true, pc, address, esr);
    }

    public long bit() {
        return 1L << (signo - 1);
    }

    public boolean isRealtime() {
        return signo >= 32;
    }

    /** the kernel's dequeue order: faults first, then the synchronous signals, then the lowest number */
    public int priority() {
        if (fault) {
            return signo;
        }
        if ((bit() & SYNCHRONOUS_MASK) != 0) {
            return 64 + signo;
        }
        return 128 + signo;
    }

    public void write(UnidbgPointer info) {
        info.write(0, new byte[SIZE], 0, SIZE);
        info.setInt(0, signo);
        info.setInt(8, code);
        if (fault) {
            info.setLong(16, value); // si_addr
        } else {
            info.setInt(16, pid); // si_pid
            info.setInt(20, uid); // si_uid
            info.setLong(24, value); // si_value
        }
    }

    @Override
    public String toString() {
        return "SigInfo{signo=" + signo + ", code=" + code + (fault ? ", addr=0x" + Long.toHexString(value) : ", pid=" + pid) + '}';
    }

}
