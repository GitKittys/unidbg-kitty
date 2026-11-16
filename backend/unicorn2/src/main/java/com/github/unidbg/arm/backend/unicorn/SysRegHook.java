package com.github.unidbg.arm.backend.unicorn;

/**
 * Bridges Unicorn's UC_HOOK_INSN(MRS/MSR/SYS/SYSL) callback (uc_cb_insn_sys_t).
 * Mirrors the native uc_arm64_cp_reg fields (op0/op1/crn/crm/op2/val).
 */
public interface SysRegHook extends Hook {

    /**
     * @param val val[0] holds the current register value on entry (the value being
     *            written for MSR); if this method returns true, val[0] is written back
     *            to Unicorn as the value to use (the read result for MRS).
     * @return true if handled (Unicorn skips its default read/write), false to fall
     *         back to Unicorn's default handling.
     */
    boolean hook(Unicorn u, int op0, int op1, int crn, int crm, int op2, long[] val, Object user);

}
