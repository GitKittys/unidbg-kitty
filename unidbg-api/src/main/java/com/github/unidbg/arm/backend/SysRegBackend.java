package com.github.unidbg.arm.backend;

/**
 * Optional capability of a {@link Backend} that models AArch64 system registers (currently the unicorn2 backend):
 * hooks on system-class instructions and direct system register access. Check with <code>instanceof</code>; the
 * {@link Backend} interface itself is unchanged.
 */
public interface SysRegBackend {

    /**
     * Registers a hook for AArch64 system-class instructions (UC_HOOK_INSN).
     *
     * @param insn {@link SysRegHook#INS_MRS}, {@link SysRegHook#INS_MSR}, {@link SysRegHook#INS_SYS} or
     *             {@link SysRegHook#INS_SYSL}
     */
    void hook_add_new(SysRegHook callback, int insn, Object user_data) throws BackendException;

    /**
     * Reads a system register by its encoding, bypassing the guest's access checks.
     *
     * @throws BackendException if the CPU model does not implement this register
     */
    long sysreg_read(int op0, int op1, int crn, int crm, int op2) throws BackendException;

    /**
     * Writes a system register by its encoding, bypassing the guest's access checks.
     *
     * @throws BackendException if the CPU model does not implement this register
     */
    void sysreg_write(int op0, int op1, int crn, int crm, int op2, long value) throws BackendException;

    /**
     * Registers a hook for accesses the page permissions deny (UC_HOOK_MEM_READ_PROT, WRITE_PROT, FETCH_PROT), which
     * {@link Backend#hook_add_new(EventMemHook, int, Object)} only reports for unmapped memory. With the engine of this
     * backend the access stops precisely at the faulting instruction when the hook returns false.
     */
    void hook_add_protection_fault(EventMemHook callback, Object user_data) throws BackendException;

    /**
     * Whether invalid memory accesses are to be delivered to the guest as SIGSEGV (an option of the backend's factory);
     * otherwise they stay emulation errors.
     */
    default boolean isMemoryFaultSignals() {
        return false;
    }

    /**
     * Guest instructions the engine has executed since it was created, or -1 if the engine does not count them.
     */
    default long insn_count() {
        return -1;
    }

}
