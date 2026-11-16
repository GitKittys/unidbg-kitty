package com.github.unidbg.arm.backend;

import com.github.unidbg.Emulator;

/**
 * Hook for AArch64 system-class instructions (UC_HOOK_INSN): MRS/MSR, SYS/SYSL, registered through
 * {@link SysRegBackend#hook_add_new(SysRegHook, int, Object)} on backends that model system registers.
 */
public interface SysRegHook {

    /** uc_arm64_insn: UC_ARM64_INS_MRS */
    int INS_MRS = 1;
    /**
     * uc_arm64_insn: UC_ARM64_INS_MSR. MSR (immediate) is reported with op0 == 0, crn == 4 and the
     * immediate in crm (unidbg engine fork extension).
     */
    int INS_MSR = 2;
    /** uc_arm64_insn: UC_ARM64_INS_SYS (DC/IC/AT/TLBI...), op0 == 1 */
    int INS_SYS = 3;
    /** uc_arm64_insn: UC_ARM64_INS_SYSL, op0 == 1 */
    int INS_SYSL = 4;

    /**
     * @param op0 op1 crn crm op2 identify the system register / system instruction
     * @param val val[0] holds Rt on entry (the value being written for MSR); if this method returns true,
     *            val[0] is written back to Rt (the read result for MRS). Leaving it untouched keeps Rt unchanged.
     * @return true if handled (the engine skips the instruction), false to fall back to the engine's default
     *         handling. To report a fault, call {@link Backend#emu_stop()} and return true: the engine ends the
     *         translation block after a hooked instruction, so no later instruction runs.
     */
    boolean hook(Backend backend, int insn, int op0, int op1, int crn, int crm, int op2, long[] val, Object user_data);

    /**
     * Encodings ({@link #encode}) for which {@link #hook} would always return false without side effects. The backend
     * may then leave them to the CPU model without calling the hook at all, which keeps frequent accesses such as
     * TPIDR_EL0 reads fast.
     */
    default int[] passthrough(int insn) {
        return new int[0];
    }

    /**
     * Called once the hooks are registered, before any guest code runs: the place for one-time setup of the backend's
     * system registers and of what else needs the engine features that come with them.
     */
    default void onAttach(SysRegBackend backend, Emulator<?> emulator) {
    }

    /** 16-bit op0:op1:CRn:CRm:op2 key used by {@link #passthrough(int)} */
    static int encode(int op0, int op1, int crn, int crm, int op2) {
        return (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2;
    }

}
