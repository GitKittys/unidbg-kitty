package com.github.unidbg.linux;

import com.github.unidbg.arm.backend.BackendException;
import com.github.unidbg.arm.backend.SysRegBackend;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * What the Linux kernel exposes to EL0 about the emulated AArch64 core, derived from the backend's own CPU model:
 * <ul>
 * <li>ID register reads (arch/arm64/kernel/cpufeature.c emulate_sys_reg(): the kernel traps EL0 MRS of the ID space
 * and returns the sanitised "user view", in which only user-visible fields carry the CPU's value and every hidden
 * field reads as its fixed safe value);</li>
 * <li>AT_HWCAP / AT_HWCAP2, computed from the same registers with the kernel's arm64_elf_hwcaps table, so ID
 * registers, auxv and what the engine can execute always agree;</li>
 * <li>the EL1 controls the kernel sets up for every EL0 task ({@link #configure(SysRegBackend)}).</li>
 * </ul>
 * Nothing here is specific to a device: a different CPU model in the backend yields its own consistent view.
 */
class Arm64CpuFeatures {

    private static final Logger log = LoggerFactory.getLogger(Arm64CpuFeatures.class);

    /** MPIDR_EL1 as the kernel emulates it for EL0 (SYS_MPIDR_SAFE_VAL) */
    private static final long MPIDR_USER_VALUE = 0x80000000L;

    private static final int PFR0 = idKey(4, 0);
    private static final int PFR1 = idKey(4, 1);
    private static final int ZFR0 = idKey(4, 4);
    private static final int DFR0 = idKey(5, 0);
    private static final int ISAR0 = idKey(6, 0);
    private static final int ISAR1 = idKey(6, 1);
    private static final int ISAR2 = idKey(6, 2);
    private static final int MMFR0 = idKey(7, 0);
    private static final int MMFR1 = idKey(7, 1);
    private static final int MMFR2 = idKey(7, 2);

    /** the AArch64 feature registers the kernel tracks, with their user view: {key, visible field mask, hidden value} */
    private static final long[][] USER_VIEW = {
            // FP, AdvSIMD, SVE, DIT visible; EL0/EL1 read as "AArch64 only" (1), everything else 0
            {PFR0, fields(16, 20, 32, 48), 0x11L},
            // BT, SSBS, MTE, SME
            {PFR1, fields(0, 4, 8, 24), 0},
            // SVEver, AES, BitPerm, BF16, SHA3, SM4, I8MM, F32MM, F64MM
            {ZFR0, fields(0, 4, 16, 20, 32, 40, 44, 52, 56), 0},
            // all hidden; DebugVer reads as 6 (ARMv8 debug)
            {DFR0, 0, 0x6L},
            // AES SHA1 SHA2 CRC32 ATOMIC RDM SHA3 SM3 SM4 DP FHM TS RNDR; TME and TLB hidden
            {ISAR0, fields(4, 8, 12, 16, 20, 28, 32, 36, 40, 44, 48, 52, 60), 0},
            // DPB APA API JSCVT FCMA LRCPC GPA GPI FRINTTS SB BF16 DGH I8MM; SPECRES, XS, LS64 hidden
            {ISAR1, fields(0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 44, 48, 52), 0},
            // WFxT RPRES GPA3 APA3
            {ISAR2, fields(0, 4, 8, 12), 0},
            // all hidden: TGran4/TGran64 "not implemented" (0xf), TGran{16,64,4}_2 = 1, everything else 0
            {MMFR0, 0, 0x00000111ff000000L},
            // AFP
            {MMFR1, fields(44), 0},
            // AT
            {MMFR2, fields(32), 0},
    };

    private static long fields(int... shifts) {
        long mask = 0;
        for (int shift : shifts) {
            mask |= 0xfL << shift;
        }
        return mask;
    }

    private static int idKey(int crm, int op2) {
        return (crm << 3) | op2;
    }

    /**
     * Reads the backend's CPU model.
     */
    static Arm64CpuFeatures read(SysRegBackend backend) {
        long[] system = new long[USER_VIEW.length];
        for (int i = 0; i < USER_VIEW.length; i++) {
            int key = (int) USER_VIEW[i][0];
            system[i] = sysreg(backend, 3, 0, 0, key >>> 3, key & 7);
        }
        if ((sysreg(backend, 3, 0, 1, 0, 0) & SCTLR_EnIA) == 0) {
            // pointer authentication left off by the backend (Unicorn2Factory): the core reports none, so the ID
            // registers and AT_HWCAP agree with what the PAC instructions do
            for (int i = 0; i < USER_VIEW.length; i++) {
                if (USER_VIEW[i][0] == ISAR1) {
                    system[i] &= ~fields(4, 8, 24, 28); // APA, API, GPA, GPI
                } else if (USER_VIEW[i][0] == ISAR2) {
                    system[i] &= ~fields(8, 12); // GPA3, APA3
                }
            }
        }
        return new Arm64CpuFeatures(sysreg(backend, 3, 0, 0, 0, 0), system);
    }

    private static long sysreg(SysRegBackend backend, int op0, int op1, int crn, int crm, int op2) {
        try {
            return backend.sysreg_read(op0, op1, crn, crm, op2);
        } catch (BackendException e) {
            return 0; // not implemented by the CPU model: RAZ
        }
    }

    private final long midr;
    /** the CPU model's values, in USER_VIEW order (the kernel's "system" value with a single CPU) */
    private final long[] system;
    private final long hwcap;
    private final long hwcap2;

    private Arm64CpuFeatures(long midr, long[] system) {
        this.midr = midr;
        this.system = system;
        this.hwcap = deriveHwcap();
        this.hwcap2 = deriveHwcap2();
    }

    private long system(int key) {
        for (int i = 0; i < USER_VIEW.length; i++) {
            if (USER_VIEW[i][0] == key) {
                return system[i];
            }
        }
        return 0;
    }

    /**
     * Value of an EL0 read of S3_0_C0_C&lt;crm&gt;_&lt;op2&gt;, or null if the kernel does not emulate it (SIGILL). CRm 0
     * only has MIDR/MPIDR/REVIDR; CRm 2..7 return the user view, every untracked or reserved encoding reading 0.
     */
    Long readIdRegister(int crm, int op2) {
        if (crm == 0) {
            switch (op2) {
                case 0:
                    return midr;
                case 5:
                    return MPIDR_USER_VALUE;
                case 6:
                    return 0L; // REVIDR_EL1: IMPLEMENTATION DEFINED, emulated as 0
                default:
                    return null;
            }
        }
        if (crm >= 2 && crm <= 7) {
            int key = idKey(crm, op2);
            for (int i = 0; i < USER_VIEW.length; i++) {
                if (USER_VIEW[i][0] == key) {
                    return (system[i] & USER_VIEW[i][1]) | USER_VIEW[i][2];
                }
            }
            return 0L;
        }
        return null;
    }

    long getHwcap() {
        return hwcap;
    }

    long getHwcap2() {
        return hwcap2;
    }

    private static int field(long reg, int shift) {
        return (int) ((reg >>> shift) & 0xf);
    }

    private static int signedField(long reg, int shift) {
        int value = field(reg, shift);
        return value >= 8 ? value - 16 : value;
    }

    /** FEAT_FPAC: a failed authentication is an UNDEF (APA or API >= 4) */
    boolean hasFpac() {
        long isar1 = system(ISAR1);
        return field(isar1, 4) >= 4 || field(isar1, 8) >= 4;
    }

    /** the SVE vector length of a process, in bytes ({@link #configure}), 0 without SVE */
    int getSveVectorLength() {
        return hasSve() ? SVE_DEFAULT_VL : 0;
    }

    boolean hasSve() {
        return field(system(PFR0), 32) >= 1;
    }

    /** FEAT_ECV: CNTVCTSS_EL0/CNTPCTSS_EL0 exist */
    boolean hasEcv() {
        return field(system(MMFR0), 60) >= 1;
    }

    /** arm64_elf_hwcaps, AT_HWCAP part (computed from the system values, as the kernel does) */
    private long deriveHwcap() {
        long pfr0 = system(PFR0), pfr1 = system(PFR1), isar0 = system(ISAR0), isar1 = system(ISAR1), mmfr2 = system(MMFR2);
        long hwcap = 0;
        if (signedField(pfr0, 16) >= 0) hwcap |= 1L; // FP
        if (signedField(pfr0, 20) >= 0) hwcap |= 1L << 1; // ASIMD
        hwcap |= 1L << 2; // EVTSTRM: arch timer event stream (CONFIG_ARM_ARCH_TIMER_EVTSTREAM, default on)
        if (field(isar0, 4) >= 1) hwcap |= 1L << 3; // AES
        if (field(isar0, 4) >= 2) hwcap |= 1L << 4; // PMULL
        if (field(isar0, 8) >= 1) hwcap |= 1L << 5; // SHA1
        if (field(isar0, 12) >= 1) hwcap |= 1L << 6; // SHA2
        if (field(isar0, 16) >= 1) hwcap |= 1L << 7; // CRC32
        if (field(isar0, 20) >= 2) hwcap |= 1L << 8; // ATOMICS
        if (signedField(pfr0, 16) >= 1) hwcap |= 1L << 9; // FPHP
        if (signedField(pfr0, 20) >= 1) hwcap |= 1L << 10; // ASIMDHP
        hwcap |= 1L << 11; // CPUID: EL0 reads of the ID registers are emulated
        if (field(isar0, 28) >= 1) hwcap |= 1L << 12; // ASIMDRDM
        if (field(isar1, 12) >= 1) hwcap |= 1L << 13; // JSCVT
        if (field(isar1, 16) >= 1) hwcap |= 1L << 14; // FCMA
        if (field(isar1, 20) >= 1) hwcap |= 1L << 15; // LRCPC
        if (field(isar1, 0) >= 1) hwcap |= 1L << 16; // DCPOP
        if (field(isar0, 32) >= 1) hwcap |= 1L << 17; // SHA3
        if (field(isar0, 36) >= 1) hwcap |= 1L << 18; // SM3
        if (field(isar0, 40) >= 1) hwcap |= 1L << 19; // SM4
        if (field(isar0, 44) >= 1) hwcap |= 1L << 20; // ASIMDDP
        if (field(isar0, 12) >= 2) hwcap |= 1L << 21; // SHA512
        if (field(pfr0, 32) >= 1) hwcap |= 1L << 22; // SVE
        if (field(isar0, 48) >= 1) hwcap |= 1L << 23; // ASIMDFHM
        if (field(pfr0, 48) >= 1) hwcap |= 1L << 24; // DIT
        if (field(mmfr2, 32) >= 1) hwcap |= 1L << 25; // USCAT
        if (field(isar1, 20) >= 2) hwcap |= 1L << 26; // ILRCPC
        if (field(isar0, 52) >= 1) hwcap |= 1L << 27; // FLAGM
        if (field(pfr1, 4) >= 2) hwcap |= 1L << 28; // SSBS
        if (field(isar1, 36) >= 1) hwcap |= 1L << 29; // SB
        if (field(isar1, 4) >= 1 || field(isar1, 8) >= 1) hwcap |= 1L << 30; // PACA
        if (field(isar1, 24) >= 1 || field(isar1, 28) >= 1) hwcap |= 1L << 31; // PACG
        return hwcap;
    }

    /** arm64_elf_hwcaps, AT_HWCAP2 part */
    private long deriveHwcap2() {
        long pfr0 = system(PFR0), pfr1 = system(PFR1), zfr0 = system(ZFR0), isar0 = system(ISAR0), isar1 = system(ISAR1);
        long isar2 = system(ISAR2), mmfr0 = system(MMFR0), mmfr1 = system(MMFR1);
        boolean sve = field(pfr0, 32) >= 1;
        long hwcap2 = 0;
        if (field(isar1, 0) >= 2) hwcap2 |= 1L; // DCPODP
        if (sve && field(zfr0, 0) >= 1) hwcap2 |= 1L << 1; // SVE2
        if (sve && field(zfr0, 4) >= 1) hwcap2 |= 1L << 2; // SVEAES
        if (sve && field(zfr0, 4) >= 2) hwcap2 |= 1L << 3; // SVEPMULL
        if (sve && field(zfr0, 16) >= 1) hwcap2 |= 1L << 4; // SVEBITPERM
        if (sve && field(zfr0, 32) >= 1) hwcap2 |= 1L << 5; // SVESHA3
        if (sve && field(zfr0, 40) >= 1) hwcap2 |= 1L << 6; // SVESM4
        if (field(isar0, 52) >= 2) hwcap2 |= 1L << 7; // FLAGM2
        if (field(isar1, 32) >= 1) hwcap2 |= 1L << 8; // FRINT
        if (sve && field(zfr0, 44) >= 1) hwcap2 |= 1L << 9; // SVEI8MM
        if (sve && field(zfr0, 52) >= 1) hwcap2 |= 1L << 10; // SVEF32MM
        if (sve && field(zfr0, 56) >= 1) hwcap2 |= 1L << 11; // SVEF64MM
        if (sve && field(zfr0, 20) >= 1) hwcap2 |= 1L << 12; // SVEBF16
        if (field(isar1, 52) >= 1) hwcap2 |= 1L << 13; // I8MM
        if (field(isar1, 44) >= 1) hwcap2 |= 1L << 14; // BF16
        if (field(isar1, 48) >= 1) hwcap2 |= 1L << 15; // DGH
        if (field(isar0, 60) >= 1) hwcap2 |= 1L << 16; // RNG
        if (field(pfr1, 0) >= 1) hwcap2 |= 1L << 17; // BTI
        if (field(pfr1, 8) >= 2) hwcap2 |= 1L << 18; // MTE
        if (field(mmfr0, 60) >= 1) hwcap2 |= 1L << 19; // ECV
        if (field(mmfr1, 44) >= 1) hwcap2 |= 1L << 20; // AFP
        if (field(isar2, 4) >= 1) hwcap2 |= 1L << 21; // RPRES
        if (field(pfr1, 8) >= 3) hwcap2 |= 1L << 22; // MTE3
        if (field(isar2, 0) >= 2) hwcap2 |= 1L << 31; // WFXT
        return hwcap2;
    }

    private static final long SCTLR_EnIA = 1L << 31;
    private static final long TCR_TBI0 = 1L << 37;
    private static final long CPACR_ZEN = 3L << 16;
    private static final long CPTR_EL3_EZ = 1L << 8;
    /** the kernel's default SVE vector length (sve_default_vector_length), in bytes */
    private static final int SVE_DEFAULT_VL = 64;

    /**
     * Puts the engine's EL1 controls into the state the Linux kernel gives every EL0 task: top-byte-ignore for user
     * addresses; if the core has SVE, SVE enabled at the default vector length. (Pointer authentication is the
     * backend's: the keys are a per-process setting of the factory.)
     */
    void configure(SysRegBackend backend) {
        long tcr = backend.sysreg_read(3, 0, 2, 0, 2);
        backend.sysreg_write(3, 0, 2, 0, 2, tcr | TCR_TBI0);

        if (hasSve()) {
            long cpacr = backend.sysreg_read(3, 0, 1, 0, 2);
            backend.sysreg_write(3, 0, 1, 0, 2, cpacr | CPACR_ZEN);
            try {
                // when the CPU model implements EL3, CPTR_EL3.EZ=0 traps every SVE instruction
                long cptr = backend.sysreg_read(3, 6, 1, 1, 2);
                backend.sysreg_write(3, 6, 1, 1, 2, cptr | CPTR_EL3_EZ);
            } catch (BackendException e) {
                log.debug("no CPTR_EL3", e);
            }
            // firmware and hypervisor leave ZCR_EL3/ZCR_EL2 at the maximum; they cap ZCR_EL1 otherwise
            for (int op1 : new int[]{6, 4}) {
                try {
                    backend.sysreg_write(3, op1, 1, 2, 0, 0xf);
                } catch (BackendException e) {
                    log.debug("no ZCR_EL{}", op1 == 6 ? 3 : 2, e);
                }
            }
            backend.sysreg_write(3, 0, 1, 2, 0, SVE_DEFAULT_VL / 16 - 1); // ZCR_EL1.LEN
        }
    }

    @Override
    public String toString() {
        return "Arm64CpuFeatures{midr=0x" + Long.toHexString(midr) +
                ", hwcap=0x" + Long.toHexString(hwcap) +
                ", hwcap2=0x" + Long.toHexString(hwcap2) +
                '}';
    }

}
