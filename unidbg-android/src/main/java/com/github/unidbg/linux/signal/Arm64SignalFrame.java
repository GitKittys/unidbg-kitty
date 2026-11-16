package com.github.unidbg.linux.signal;

import com.github.unidbg.Emulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.pointer.UnidbgPointer;
import unicorn.Arm64Const;

/**
 * The arm64 Linux signal frame (arch/arm64/kernel/signal.c): <code>struct rt_sigframe { siginfo_t info; struct
 * ucontext uc; }</code> plus a frame record, pushed on the interrupted stack. {@link #push} does what setup_rt_frame()
 * does for a handler, {@link #restore} what rt_sigreturn does when the handler returns through the trampoline.
 */
public final class Arm64SignalFrame {

    // arch/arm64/include/uapi/asm/sigcontext.h, ucontext.h
    private static final int SIGINFO_SIZE = SigInfo.SIZE;
    private static final int UC_STACK_OFFSET = 16;
    private static final int UC_SIGMASK_OFFSET = 40;
    private static final int UC_MCONTEXT_OFFSET = 176;
    private static final int SC_FAULT_ADDRESS = 0;
    private static final int SC_REGS = 8;
    private static final int SC_SP = SC_REGS + 31 * 8;
    private static final int SC_PC = SC_SP + 8;
    private static final int SC_PSTATE = SC_PC + 8;
    private static final int SC_RESERVED = 288;
    private static final int SC_RESERVED_SIZE = 4096;
    private static final int UCONTEXT_SIZE = UC_MCONTEXT_OFFSET + SC_RESERVED + SC_RESERVED_SIZE;
    private static final int RT_SIGFRAME_SIZE = SIGINFO_SIZE + UCONTEXT_SIZE;
    private static final int FRAME_RECORD_SIZE = 16;
    private static final int FPSIMD_MAGIC = 0x46508001;
    private static final int FPSIMD_CONTEXT_SIZE = 528;
    private static final int ESR_MAGIC = 0x45535201;
    private static final int ESR_CONTEXT_SIZE = 16;
    private static final int SVE_MAGIC = 0x53564501;
    private static final int SVE_CONTEXT_SIZE = 16; // SVE_SIG_CONTEXT_SIZE(0): the thread is not in SVE state
    /** NZCV; PSTATE.M stays EL0t (0) */
    private static final long PSTATE_USER_MASK = 0xf0000000L;
    private static final long UNBLOCKABLE = (1L << (9 - 1)) | (1L << (19 - 1)); // SIGKILL, SIGSTOP

    // unicorn2 register ids beyond the unicorn1 Arm64Const set (the frame is only built on unicorn2)
    private static final int UC_ARM64_REG_FPCR = 291;
    private static final int UC_ARM64_REG_FPSR = 292;

    private Arm64SignalFrame() {
    }

    /**
     * Pushes a frame for a signal and enters the handler: x0 = signo, x1 = &amp;info, x2 = &amp;uc, x29 = the frame
     * record, x30 = <code>restorer</code>, sp = the frame, pc = the handler. The interrupted context (with
     * <code>pc</code> as the resume address) is saved in the frame's ucontext; all registers are read before any is
     * written.
     *
     * @param pc       uc_mcontext.pc: where rt_sigreturn resumes unless the handler changes it
     * @param sigmask  the interrupted thread's blocked mask, saved in uc_sigmask
     * @param restorer return address of the handler, code that issues rt_sigreturn
     * @param onStack  SA_ONSTACK was requested: use the thread's sigaltstack unless already running on it
     * @param sveVl    the thread's SVE vector length in bytes for the sve_context record, 0 without SVE
     */
    public static void push(Emulator<?> emulator, SigInfo signal, long pc, long sigmask, long handler, long restorer,
                            ThreadSignalState state, boolean onStack, int sveVl) {
        Backend backend = emulator.getBackend();
        long sp = backend.reg_read(Arm64Const.UC_ARM64_REG_SP).longValue();
        long top = onStack && state.hasAltStack() && !state.onAltStack(sp) ? state.altStackSp + state.altStackSize : sp;
        long nextFrame = (top - FRAME_RECORD_SIZE) & ~15L;
        long frame = (nextFrame - RT_SIGFRAME_SIZE) & ~15L;

        UnidbgPointer frameRecord = UnidbgPointer.pointer(emulator, nextFrame);
        UnidbgPointer info = UnidbgPointer.pointer(emulator, frame);
        UnidbgPointer uc = UnidbgPointer.pointer(emulator, frame + SIGINFO_SIZE);
        if (frameRecord == null || info == null || uc == null) {
            throw new IllegalStateException("signal frame for " + signal + " outside mapped memory: sp=0x" + Long.toHexString(sp) +
                    " (the signal stack overflowed; on a device this is a fatal SIGSEGV)");
        }
        info.write(0, new byte[RT_SIGFRAME_SIZE], 0, RT_SIGFRAME_SIZE);

        signal.write(info);

        uc.setLong(UC_STACK_OFFSET, state.altStackSp); // uc_stack.ss_sp
        uc.setInt(UC_STACK_OFFSET + 8, state.altStackFlags(sp)); // uc_stack.ss_flags
        uc.setLong(UC_STACK_OFFSET + 16, state.altStackSize); // uc_stack.ss_size
        if (state.altStackAutoDisarm) {
            state.disarmAltStack();
        }
        uc.setLong(UC_SIGMASK_OFFSET, sigmask);
        UnidbgPointer mcontext = uc.share(UC_MCONTEXT_OFFSET, 0);
        mcontext.setLong(SC_FAULT_ADDRESS, signal.faultAddress);
        for (int i = 0; i <= 28; i++) {
            mcontext.setLong(SC_REGS + i * 8L, backend.reg_read(Arm64Const.UC_ARM64_REG_X0 + i).longValue());
        }
        long fp = backend.reg_read(Arm64Const.UC_ARM64_REG_FP).longValue();
        long lr = backend.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue();
        mcontext.setLong(SC_REGS + 29 * 8L, fp);
        mcontext.setLong(SC_REGS + 30 * 8L, lr);
        mcontext.setLong(SC_SP, sp);
        mcontext.setLong(SC_PC, pc);
        mcontext.setLong(SC_PSTATE, backend.reg_read(Arm64Const.UC_ARM64_REG_NZCV).longValue() & PSTATE_USER_MASK);

        // __reserved: fpsimd_context, esr_context for a fault with a syndrome, sve_context on an SVE core, terminator
        UnidbgPointer fpsimd = mcontext.share(SC_RESERVED, 0);
        fpsimd.setInt(0, FPSIMD_MAGIC);
        fpsimd.setInt(4, FPSIMD_CONTEXT_SIZE);
        fpsimd.setInt(8, backend.reg_read(UC_ARM64_REG_FPSR).intValue());
        fpsimd.setInt(12, backend.reg_read(UC_ARM64_REG_FPCR).intValue());
        for (int i = 0; i < 32; i++) {
            fpsimd.write(16 + i * 16L, backend.reg_read_vector(Arm64Const.UC_ARM64_REG_Q0 + i), 0, 16);
        }
        int next = FPSIMD_CONTEXT_SIZE;
        if (signal.esr != 0) {
            UnidbgPointer esrContext = fpsimd.share(next, 0);
            esrContext.setInt(0, ESR_MAGIC);
            esrContext.setInt(4, ESR_CONTEXT_SIZE);
            esrContext.setLong(8, signal.esr);
            next += ESR_CONTEXT_SIZE;
        }
        if (sveVl != 0) {
            UnidbgPointer sveContext = fpsimd.share(next, 0);
            sveContext.setInt(0, SVE_MAGIC);
            sveContext.setInt(4, SVE_CONTEXT_SIZE);
            sveContext.setShort(8, (short) sveVl); // vl; flags and reserved stay 0
            next += SVE_CONTEXT_SIZE;
        }
        fpsimd.setLong(next, 0); // terminator: magic 0, size 0

        frameRecord.setLong(0, fp);
        frameRecord.setLong(8, lr);

        backend.reg_write(Arm64Const.UC_ARM64_REG_SP, frame);
        backend.reg_write(Arm64Const.UC_ARM64_REG_X0, signal.signo);
        backend.reg_write(Arm64Const.UC_ARM64_REG_X1, frame); // &frame->info
        backend.reg_write(Arm64Const.UC_ARM64_REG_X2, frame + SIGINFO_SIZE); // &frame->uc
        backend.reg_write(Arm64Const.UC_ARM64_REG_FP, nextFrame);
        backend.reg_write(Arm64Const.UC_ARM64_REG_LR, restorer);
        backend.reg_write(Arm64Const.UC_ARM64_REG_PC, handler);
    }

    /**
     * rt_sigreturn: reloads the interrupted context from the frame at SP, as the handler (or anything it called) may
     * have edited it, and re-applies its uc_stack (the kernel's restore_altstack(), errors ignored).
     *
     * @return the restored blocked mask (uc_sigmask, without SIGKILL/SIGSTOP)
     */
    public static long restore(Emulator<?> emulator, ThreadSignalState state) {
        Backend backend = emulator.getBackend();
        long frame = backend.reg_read(Arm64Const.UC_ARM64_REG_SP).longValue();
        UnidbgPointer uc = UnidbgPointer.pointer(emulator, frame + SIGINFO_SIZE);
        if (uc == null) {
            throw new IllegalStateException("rt_sigreturn with no signal frame at sp=0x" + Long.toHexString(frame));
        }
        UnidbgPointer mcontext = uc.share(UC_MCONTEXT_OFFSET, 0);

        for (int i = 0; i <= 28; i++) {
            backend.reg_write(Arm64Const.UC_ARM64_REG_X0 + i, mcontext.getLong(SC_REGS + i * 8L));
        }
        long sp = mcontext.getLong(SC_SP);
        backend.reg_write(Arm64Const.UC_ARM64_REG_FP, mcontext.getLong(SC_REGS + 29 * 8L));
        backend.reg_write(Arm64Const.UC_ARM64_REG_LR, mcontext.getLong(SC_REGS + 30 * 8L));
        backend.reg_write(Arm64Const.UC_ARM64_REG_SP, sp);
        backend.reg_write(Arm64Const.UC_ARM64_REG_PC, mcontext.getLong(SC_PC));
        long nzcv = backend.reg_read(Arm64Const.UC_ARM64_REG_NZCV).longValue() & ~PSTATE_USER_MASK;
        backend.reg_write(Arm64Const.UC_ARM64_REG_NZCV, nzcv | (mcontext.getLong(SC_PSTATE) & PSTATE_USER_MASK));

        UnidbgPointer fpsimd = mcontext.share(SC_RESERVED, 0);
        if (fpsimd.getInt(0) == FPSIMD_MAGIC) {
            backend.reg_write(UC_ARM64_REG_FPSR, fpsimd.getInt(8) & 0xffffffffL);
            backend.reg_write(UC_ARM64_REG_FPCR, fpsimd.getInt(12) & 0xffffffffL);
            for (int i = 0; i < 32; i++) {
                backend.reg_write_vector(Arm64Const.UC_ARM64_REG_Q0 + i, fpsimd.getByteArray(16 + i * 16L, 16));
            }
        }
        state.setAltStack(sp, uc.getLong(UC_STACK_OFFSET), uc.getInt(UC_STACK_OFFSET + 8), uc.getLong(UC_STACK_OFFSET + 16));
        return uc.getLong(UC_SIGMASK_OFFSET) & ~UNBLOCKABLE;
    }

}
