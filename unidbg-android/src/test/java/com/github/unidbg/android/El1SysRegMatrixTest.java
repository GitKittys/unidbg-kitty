package com.github.unidbg.android;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.SysRegBackend;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.debugger.Breaker;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.signal.SigAction;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;
import keystone.Keystone;
import keystone.KeystoneArchitecture;
import keystone.KeystoneEncoded;
import keystone.KeystoneMode;
import unicorn.Arm64Const;
import unicorn.UnicornConst;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * EL0 privilege boundary acceptance test (doc/el0-boundary-undef-and-time-sources.md): runs privileged, EL0-legal and
 * UNDEFINED instructions, each in a fresh emulator with a real SA_SIGINFO handler for SIGILL and SIGTRAP installed
 * through rt_sigaction, and compares the outcome with what Linux and the architecture do at EL0 for the emulated CPU
 * model (expected values are read from the backend's model, never from a particular device). The handler records the
 * siginfo/ucontext it gets and advances uc_mcontext.pc by 4, the way a probing handler skips the faulting instruction.
 * <p>
 * Checks per probe: classification (SIGILL / SIGTRAP / runs), Rt untouched by a faulting instruction, the handler ran
 * before the next instruction, x0 untouched, si_code/si_addr/uc_mcontext.pc, the frame sits on the interrupted stack
 * and holds the interrupted registers, and probe-specific values.
 * <p>
 * Instruction words are encoded by hand (keystone only assembles the scaffolding). Run with
 * -Dprobe.filter=&lt;regex&gt; to select probes.
 */
public class El1SysRegMatrixTest {

    private static final int SIGILL = 4;
    private static final int SIGTRAP = 5;
    private static final int SA_SIGINFO = 4;
    private static final int ILL_ILLOPC = 1;
    private static final int ILL_ILLOPN = 2;
    private static final int TRAP_BRKPT = 1;
    private static final int NR_rt_sigaction = 134;

    // bit0 clear: if an "msr sctlr_el1" leaked through it must not switch the MMU on
    private static final long SENTINEL = 0x4141414141414140L;
    private static final long X0_SENTINEL = 0x7777L;
    private static final long USER_POINTER = 0x0000007f12345670L;

    // arm64 ucontext_t: uc_mcontext at 0xb0 = {fault_address, regs[31], sp, pc, pstate, __reserved}
    private static final int UC_REGS = 0xb8;
    private static final int UC_SP = 0x1b0;
    private static final int UC_PC = 0x1b8;

    private static final long CODE_BASE = 0x8000L;
    private static final long HANDLER_BASE = 0x9000L;
    private static final long SCRATCH_BASE = 0xa000L;

    private enum Expect { SIGILL, SIGTRAP, OK }

    private interface Check {
        String verify(Result r);
    }

    private static final class Probe {
        final String name;
        final int[] insns;
        final List<String> setup;
        final Expect expect;
        final int siCode;
        final boolean rtUntouched;
        final long restartUntil;
        final Check check;
        final String note;

        Probe(String name, int[] insns, List<String> setup, Expect expect, int siCode, boolean rtUntouched,
              long restartUntil, Check check, String note) {
            this.name = name;
            this.insns = insns;
            this.setup = setup;
            this.expect = expect;
            this.siCode = siCode;
            this.rtUntouched = rtUntouched;
            this.restartUntil = restartUntil;
            this.check = check;
            this.note = note;
        }
    }

    private static final class Result {
        long sigCount;
        int signo;
        int siCode;
        long siAddr;
        long ucPc;
        long handlerSp;
        long ucSp;
        long ucX9;
        long probePc;
        long x9;
        long x9Before;
        long x10;
        long x16;
        long faultSp;
        long markerAtNext;
        long x0;
        String debugger;
        String error;
        boolean hang;
    }

    private static Probe probe(String name, int insn, Expect expect, String note) {
        return new Probe(name, new int[]{insn}, Collections.<String>emptyList(), expect,
                expect == Expect.SIGTRAP ? TRAP_BRKPT : ILL_ILLOPC, true, 0, null, note);
    }

    private static Probe value(String name, int insn, final long expected, String note) {
        return new Probe(name, new int[]{insn}, Collections.<String>emptyList(), Expect.OK, 0, false, 0, r ->
                r.x9 == expected ? null : "x9=0x" + Long.toHexString(r.x9) + ", expected 0x" + Long.toHexString(expected), note);
    }

    private interface ModelValue {
        long get();
    }

    private static Probe model(String name, int insn, final ModelValue expected) {
        return new Probe(name, new int[]{insn}, Collections.<String>emptyList(), Expect.OK, 0, false, 0, r ->
                r.x9 == expected.get() ? null : "x9=0x" + Long.toHexString(r.x9) + ", model 0x" + Long.toHexString(expected.get()),
                "model value");
    }

    private static int mrs(int op0, int op1, int crn, int crm, int op2) {
        return 0xD5200000 | (op0 << 19) | (op1 << 16) | (crn << 12) | (crm << 8) | (op2 << 5) | 9;
    }

    private static int msr(int op0, int op1, int crn, int crm, int op2) {
        return 0xD5000000 | (op0 << 19) | (op1 << 16) | (crn << 12) | (crm << 8) | (op2 << 5) | 9;
    }

    private static int sys(int op1, int crn, int crm, int op2, int rt) {
        return 0xD5080000 | (op1 << 16) | (crn << 12) | (crm << 8) | (op2 << 5) | rt;
    }

    private static int msrImm(int op1, int crm, int op2) {
        return 0xD500401F | (op1 << 16) | (crm << 8) | (op2 << 5);
    }

    /** the emulated CPU model's own values, read once from the backend */
    private static long engineMidr, engineCtr, engineDczid, engineCntfrq, engineIsar1;

    private static List<Probe> probes() {
        List<Probe> list = new ArrayList<>();
        list.add(probe("nop", 0xD503201F, Expect.OK, "baseline"));

        // op0=3, op1=0, CRn!=0: EL1 registers
        list.add(probe("mrs TPIDR_EL1", mrs(3, 0, 13, 0, 4), Expect.SIGILL, ""));
        list.add(probe("mrs SCTLR_EL1", mrs(3, 0, 1, 0, 0), Expect.SIGILL, ""));
        list.add(probe("mrs CPACR_EL1", mrs(3, 0, 1, 0, 2), Expect.SIGILL, ""));
        list.add(probe("mrs TTBR0_EL1", mrs(3, 0, 2, 0, 0), Expect.SIGILL, ""));
        list.add(probe("mrs TCR_EL1", mrs(3, 0, 2, 0, 2), Expect.SIGILL, ""));
        list.add(probe("mrs SPSR_EL1", mrs(3, 0, 4, 0, 0), Expect.SIGILL, ""));
        list.add(probe("mrs ELR_EL1", mrs(3, 0, 4, 0, 1), Expect.SIGILL, ""));
        list.add(probe("mrs SP_EL0", mrs(3, 0, 4, 1, 0), Expect.SIGILL, ""));
        list.add(probe("mrs SPSel", mrs(3, 0, 4, 2, 0), Expect.SIGILL, ""));
        list.add(probe("mrs CurrentEL", mrs(3, 0, 4, 2, 2), Expect.SIGILL, "engine would expose EL1"));
        list.add(probe("mrs PAN", mrs(3, 0, 4, 2, 3), Expect.SIGILL, ""));
        list.add(probe("mrs UAO", mrs(3, 0, 4, 2, 4), Expect.SIGILL, ""));
        list.add(probe("mrs ESR_EL1", mrs(3, 0, 5, 2, 0), Expect.SIGILL, ""));
        list.add(probe("mrs FAR_EL1", mrs(3, 0, 6, 0, 0), Expect.SIGILL, ""));
        list.add(probe("mrs MAIR_EL1", mrs(3, 0, 10, 2, 0), Expect.SIGILL, ""));
        list.add(probe("mrs VBAR_EL1", mrs(3, 0, 12, 0, 0), Expect.SIGILL, ""));
        list.add(probe("mrs CONTEXTIDR_EL1", mrs(3, 0, 13, 0, 1), Expect.SIGILL, ""));
        list.add(probe("mrs CNTKCTL_EL1", mrs(3, 0, 14, 1, 0), Expect.SIGILL, ""));
        list.add(probe("mrs S3_0_C15_C0_0", mrs(3, 0, 15, 0, 0), Expect.SIGILL, "IMPDEF, unknown to the engine"));
        list.add(probe("mrs S2_0_C0_C2_0", mrs(2, 0, 0, 2, 0), Expect.SIGILL, "op0=2 debug"));
        list.add(probe("mrs CCSIDR_EL1", mrs(3, 1, 0, 0, 0), Expect.SIGILL, "op1=1"));
        // op0=3, op1=3: EL0 space, only the whitelist works
        list.add(probe("mrs DAIF", mrs(3, 3, 4, 2, 1), Expect.SIGILL, "SCTLR_EL1.UMA=0"));
        list.add(probe("mrs PMCR_EL0", mrs(3, 3, 9, 12, 0), Expect.SIGILL, ""));
        list.add(probe("mrs PMCCNTR_EL0", mrs(3, 3, 9, 13, 0), Expect.SIGILL, ""));
        list.add(value("mrs PMUSERENR_EL0", mrs(3, 3, 9, 14, 0), 0, "PMU closed to EL0"));
        list.add(probe("mrs CNTPCT_EL0", mrs(3, 3, 14, 0, 1), Expect.SIGILL, "CNTKCTL_EL1.EL0PCTEN=0"));
        list.add(probe("mrs CNTP_CTL_EL0", mrs(3, 3, 14, 2, 1), Expect.SIGILL, ""));
        list.add(probe("mrs CNTV_CTL_EL0", mrs(3, 3, 14, 3, 1), Expect.SIGILL, ""));
        list.add(probe("mrs RNDR", mrs(3, 3, 2, 4, 0), Expect.OK, "model has FEAT_RNG"));
        list.add(probe("mrs DIT", mrs(3, 3, 4, 2, 5), Expect.SIGILL, "model lacks FEAT_DIT"));
        list.add(probe("mrs SSBS", mrs(3, 3, 4, 2, 6), Expect.SIGILL, "model lacks FEAT_SSBS"));
        list.add(probe("mrs TCO", mrs(3, 3, 4, 2, 7), Expect.SIGILL, "model lacks FEAT_MTE"));
        list.add(probe("mrs CNTVCTSS_EL0", mrs(3, 3, 14, 0, 6), Expect.SIGILL, "model lacks FEAT_ECV"));
        list.add(probe("mrs TPIDR_EL0", mrs(3, 3, 13, 0, 2), Expect.OK, ""));
        list.add(probe("mrs TPIDRRO_EL0", mrs(3, 3, 13, 0, 3), Expect.OK, ""));
        list.add(new Probe("mrs CNTVCT_EL0 x2", new int[]{mrs(3, 3, 14, 0, 2), 0xD53BE050}, // + mrs x16, cntvct_el0
                Collections.<String>emptyList(), Expect.OK, 0, false, 0,
                r -> r.x16 > r.x9 ? null : "not strictly increasing: 0x" + Long.toHexString(r.x9) + " then 0x" + Long.toHexString(r.x16), ""));
        list.add(model("mrs CNTFRQ_EL0", mrs(3, 3, 14, 0, 0), () -> engineCntfrq));
        list.add(model("mrs CTR_EL0", mrs(3, 3, 0, 0, 1), () -> engineCtr));
        list.add(model("mrs DCZID_EL0", mrs(3, 3, 0, 0, 7), () -> engineDczid));
        list.add(probe("mrs NZCV", mrs(3, 3, 4, 2, 0), Expect.OK, ""));
        list.add(probe("mrs FPCR", mrs(3, 3, 4, 4, 0), Expect.OK, ""));
        list.add(probe("mrs FPSR", mrs(3, 3, 4, 4, 1), Expect.OK, ""));
        // op0=3, op1=0, CRn=0: kernel-emulated ID registers
        list.add(model("mrs MIDR_EL1", mrs(3, 0, 0, 0, 0), () -> engineMidr));
        list.add(value("mrs MPIDR_EL1", mrs(3, 0, 0, 0, 5), 0x80000000L, "kernel safe value"));
        list.add(value("mrs REVIDR_EL1", mrs(3, 0, 0, 0, 6), 0, ""));
        list.add(probe("mrs S3_0_C0_C0_1", mrs(3, 0, 0, 0, 1), Expect.SIGILL, "CRm=0 not emulated"));
        list.add(probe("mrs ID_PFR0_EL1", mrs(3, 0, 0, 1, 0), Expect.SIGILL, "CRm=1 not emulated"));
        list.add(value("mrs S3_0_C0_C3_7", mrs(3, 0, 0, 3, 7), 0, "unallocated ID reads 0"));
        list.add(probe("mrs S3_0_C0_C8_0", mrs(3, 0, 0, 8, 0), Expect.SIGILL, "CRm>=8 not emulated"));
        // kernel user view: visible fields carry the model's value, hidden fields their fixed safe value
        list.add(new Probe("mrs ID_AA64ISAR1_EL1", new int[]{mrs(3, 0, 0, 6, 1)}, Collections.<String>emptyList(), Expect.OK, 0, false, 0,
                r -> {
                    if (((r.x9 >>> 40) & 0xf) != 0) return "SPECRES not hidden";
                    return ((r.x9 >>> 4) & 0xf) == ((engineIsar1 >>> 4) & 0xf) ? null : "APA differs from the model";
                }, "SPECRES hidden"));
        list.add(new Probe("mrs ID_AA64PFR0_EL1", new int[]{mrs(3, 0, 0, 4, 0)}, Collections.<String>emptyList(), Expect.OK, 0, false, 0,
                r -> (r.x9 & 0xffff) == 0x11 && ((r.x9 >>> 24) & 0xff) == 0 ? null : "x9=0x" + Long.toHexString(r.x9),
                "EL0/EL1=1, EL2/EL3/GIC/RAS hidden"));
        list.add(value("mrs ID_AA64MMFR0_EL1", mrs(3, 0, 0, 7, 0), 0x00000111ff000000L, "all hidden"));
        list.add(value("mrs ID_AA64DFR0_EL1", mrs(3, 0, 0, 5, 0), 0x6, "all hidden"));

        // MSR (register)
        list.add(probe("msr TPIDR_EL1", msr(3, 0, 13, 0, 4), Expect.SIGILL, ""));
        list.add(probe("msr VBAR_EL1", msr(3, 0, 12, 0, 0), Expect.SIGILL, ""));
        list.add(probe("msr SCTLR_EL1", msr(3, 0, 1, 0, 0), Expect.SIGILL, ""));
        list.add(probe("msr DAIF", msr(3, 3, 4, 2, 1), Expect.SIGILL, ""));
        list.add(probe("msr PMCR_EL0", msr(3, 3, 9, 12, 0), Expect.SIGILL, ""));
        list.add(probe("msr PMUSERENR_EL0", msr(3, 3, 9, 14, 0), Expect.SIGILL, "read-only at EL0"));
        list.add(probe("msr TPIDRRO_EL0", msr(3, 3, 13, 0, 3), Expect.SIGILL, "read-only at EL0"));
        list.add(probe("msr CNTVCT_EL0", msr(3, 3, 14, 0, 2), Expect.SIGILL, "read-only (engine used to hang)"));
        list.add(probe("msr CNTFRQ_EL0", msr(3, 3, 14, 0, 0), Expect.SIGILL, "read-only at EL0"));
        list.add(probe("msr MIDR_EL1", msr(3, 0, 0, 0, 0), Expect.SIGILL, "ID registers are read-only"));
        list.add(probe("msr TPIDR_EL0", msr(3, 3, 13, 0, 2), Expect.OK, ""));
        list.add(probe("msr FPCR", msr(3, 3, 4, 4, 0), Expect.OK, ""));

        // MSR (immediate)
        list.add(probe("msr DAIFSet, #2", msrImm(3, 2, 6), Expect.SIGILL, "UMA=0"));
        list.add(probe("msr DAIFClr, #2", msrImm(3, 2, 7), Expect.SIGILL, "UMA=0"));
        list.add(probe("msr SPSel, #1", msrImm(0, 1, 5), Expect.SIGILL, ""));
        list.add(probe("msr PAN, #1", msrImm(0, 1, 4), Expect.SIGILL, ""));
        list.add(probe("msr UAO, #1", msrImm(0, 1, 3), Expect.SIGILL, ""));
        list.add(probe("msr DIT, #1", msrImm(3, 1, 2), Expect.SIGILL, "model lacks FEAT_DIT"));
        list.add(probe("cfinv", msrImm(0, 0, 0), Expect.OK, "FlagM"));
        list.add(probe("xaflag", msrImm(0, 0, 1), Expect.OK, "FlagM2"));

        // SYS/SYSL: x9 = scratch address
        list.add(probe("dc ivac, x9", sys(0, 7, 6, 1, 9), Expect.SIGILL, "EL1-only"));
        list.add(probe("dc isw, x9", sys(0, 7, 6, 2, 9), Expect.SIGILL, ""));
        list.add(probe("ic iallu", sys(0, 7, 5, 0, 31), Expect.SIGILL, ""));
        list.add(probe("tlbi vmalle1", sys(0, 8, 7, 0, 31), Expect.SIGILL, ""));
        list.add(probe("at s1e1r, x9", sys(0, 7, 8, 0, 9), Expect.SIGILL, ""));
        list.add(probe("cfp rctx, x9", sys(3, 7, 3, 4, 9), Expect.SIGILL, "SCTLR_EL1.EnRCTX=0"));
        list.add(probe("dc civac, x9", sys(3, 7, 14, 1, 9), Expect.OK, "UCI=1"));
        list.add(probe("dc cvau, x9", sys(3, 7, 11, 1, 9), Expect.OK, ""));
        list.add(probe("dc zva, x9", sys(3, 7, 4, 1, 9), Expect.OK, "DZE=1"));
        list.add(probe("ic ivau, x9", sys(3, 7, 5, 1, 9), Expect.OK, ""));

        // exception-generating / exception-return
        list.add(probe("hvc #0", 0xD4000002, Expect.SIGILL, ""));
        list.add(probe("smc #0", 0xD4000003, Expect.SIGILL, ""));
        list.add(probe("eret", 0xD69F03E0, Expect.SIGILL, ""));
        list.add(probe("hlt #0", 0xD4400000, Expect.SIGILL, ""));
        list.add(probe("udf #0", 0x00000000, Expect.SIGILL, ""));
        list.add(probe("brk #0", 0xD4200000, Expect.SIGTRAP, "TRAP_BRKPT"));

        // UNDEFINED encodings (doc bucket #2)
        list.add(new Probe("ldp x9, x9, [x15]", new int[]{0xA94025E9}, Collections.singletonList("mov x15, x13"),
                Expect.SIGILL, ILL_ILLOPC, true, 0, null, "Rt == Rt2"));
        list.add(new Probe("ldp x9, x16, [x15]", new int[]{0xA94041E9}, Collections.singletonList("mov x15, x13"),
                Expect.OK, 0, false, 0, null, "control"));
        list.add(new Probe("casp x1, x2, x4, x5", new int[]{0x48217DE4}, Collections.singletonList("mov x15, x13"),
                Expect.SIGILL, ILL_ILLOPC, true, 0, null, "odd Rs"));
        list.add(new Probe("casp x2, x3, x4, x5", new int[]{0x48227DE4}, Collections.singletonList("mov x15, x13"),
                Expect.OK, 0, false, 0, null, "control"));

        // PAC (the model has PAuth without FPAC); x9 = a user pointer, x13/x14 = modifiers
        List<String> pacSetup = Arrays.asList("movz x9, #0x5670", "movk x9, #0x1234, lsl #16", "movk x9, #0x7f, lsl #32",
                "mov x13, #0x1111", "mov x14, #0x2222");
        // mov x16, x9; pacia x9, x13; pacia x16, x14: a 7-bit PAC may be 0 by chance, two of them hardly
        list.add(new Probe("pacia x9, x13", new int[]{0xAA0903F0, 0xDAC101A9, 0xDAC101D0}, pacSetup, Expect.OK, 0, false, 0, r -> {
            for (long signed : new long[]{r.x9, r.x16}) {
                if ((signed & 0xffffffffffffL) != USER_POINTER) return "address bits changed: 0x" + Long.toHexString(signed);
                if ((signed >>> 56) != 0) return "top byte changed (TBI0 not honoured): 0x" + Long.toHexString(signed);
            }
            return r.x9 != USER_POINTER || r.x16 != USER_POINTER ? null : "no PAC added (PAC is a NOP)";
        }, "PAC in [54:48], TBI0"));
        list.add(new Probe("pacia+autia", new int[]{0xDAC101A9, 0xDAC111A9}, pacSetup, Expect.OK, 0, false, 0,
                r -> r.x9 == USER_POINTER ? null : "auth round trip: x9=0x" + Long.toHexString(r.x9), ""));
        list.add(new Probe("pacia+autia bad modifier", new int[]{0xDAC101A9, 0xDAC111C9}, pacSetup, Expect.OK, 0,
                false, 0, r -> (r.x9 & 0xffffffffffffL) == USER_POINTER && r.x9 != USER_POINTER ? null
                : "pointer not poisoned: x9=0x" + Long.toHexString(r.x9), "no FPAC: pointer poisoned"));
        list.add(new Probe("xpaci", new int[]{0xDAC101A9, 0xDAC143E9}, pacSetup, Expect.OK, 0, false, 0,
                r -> r.x9 == USER_POINTER ? null : "strip: x9=0x" + Long.toHexString(r.x9), ""));

        // SVE at the kernel's default vector length (64 bytes)
        list.add(value("cntb x9", 0x0420E3E9, 64, "SVE default VL"));
        list.add(new Probe("ptrue+cntp", new int[]{0x2518E3E0, 0x25208009}, Collections.<String>emptyList(), Expect.OK, 0,
                false, 0, r -> r.x9 == 64 ? null : "cntp=" + r.x9, "SVE predicate"));

        // the handler leaves uc_mcontext.pc on the faulting instruction twice: it must run again each time
        list.add(new Probe("restart x3", new int[]{mrs(3, 0, 13, 0, 4)}, Collections.<String>emptyList(), Expect.SIGILL,
                ILL_ILLOPC, true, 3, r -> r.sigCount == 3 ? null : "sigCount=" + r.sigCount + ", expected 3", "re-executed until pc moves"));
        return list;
    }

    public static void main(String[] args) throws Exception {
        new El1SysRegMatrixTest().test();
        System.exit(0);
    }

    private byte[] assemble(List<String> asm) {
        try (Keystone keystone = new Keystone(KeystoneArchitecture.Arm64, KeystoneMode.LittleEndian)) {
            KeystoneEncoded encoded = keystone.assemble(asm);
            return encoded.getMachineCode();
        }
    }

    private void loadImm64(List<String> asm, String reg, long value) {
        asm.add("movz " + reg + ", #" + (value & 0xffffL));
        asm.add("movk " + reg + ", #" + ((value >>> 16) & 0xffffL) + ", lsl #16");
        asm.add("movk " + reg + ", #" + ((value >>> 32) & 0xffffL) + ", lsl #32");
        asm.add("movk " + reg + ", #" + ((value >>> 48) & 0xffffL) + ", lsl #48");
    }

    private void test() throws Exception {
        String filter = System.getProperty("probe.filter");
        List<Probe> probes = new ArrayList<>();
        for (Probe probe : probes()) {
            if (filter == null || probe.name.matches(filter)) {
                probes.add(probe);
            }
        }
        printFeatures();
        ExecutorService executor = newExecutor();
        int failures = 0;
        System.out.printf("%-26s %-7s %-9s %-4s %-18s %-5s %-6s %-5s %s%n", "probe", "expect", "observed", "ok?", "x9 after", "frame", "inline", "x0", "note");
        for (Probe probe : probes) {
            Result r;
            Future<Result> future = executor.submit(() -> run(probe));
            try {
                r = future.get(20, TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                r = new Result();
                r.hang = true;
                executor.shutdownNow();
                executor = newExecutor();
            }
            String problem = verify(probe, r);
            if (problem != null) {
                failures++;
            }
            System.out.printf("%-26s %-7s %-9s %-4s %-18s %-5s %-6s %-5s %s%s%n",
                    probe.name, probe.expect, observed(r), problem == null ? "ok" : "FAIL",
                    "0x" + Long.toHexString(r.x9), frame(probe, r),
                    r.sigCount == 0 ? "-" : (r.markerAtNext >= 1 ? "yes" : "no"),
                    r.x0 == X0_SENTINEL ? "kept" : "0x" + Long.toHexString(r.x0), probe.note,
                    problem != null ? " [" + problem + "]" : "");
        }
        System.out.println();
        System.out.println("failures vs Linux EL0 behaviour: " + failures + "/" + probes.size());
        executor.shutdownNow();
    }

    private void printFeatures() {
        AndroidEmulator emulator = createEmulator();
        SysRegBackend backend = (SysRegBackend) emulator.getBackend();
        engineMidr = backend.sysreg_read(3, 0, 0, 0, 0);
        engineCtr = backend.sysreg_read(3, 3, 0, 0, 1);
        engineDczid = backend.sysreg_read(3, 3, 0, 0, 7);
        engineCntfrq = backend.sysreg_read(3, 3, 14, 0, 0);
        engineIsar1 = backend.sysreg_read(3, 0, 0, 6, 1);
        System.out.println("CPU model: MIDR=0x" + Long.toHexString(engineMidr) + ", CTR=0x" + Long.toHexString(engineCtr) +
                ", CNTFRQ=" + engineCntfrq);
        int[][] regs = {{4, 0}, {4, 1}, {4, 4}, {5, 0}, {6, 0}, {6, 1}, {6, 2}, {7, 0}, {7, 1}, {7, 2}};
        for (int[] reg : regs) {
            long engine;
            try {
                engine = backend.sysreg_read(3, 0, 0, reg[0], reg[1]);
            } catch (RuntimeException e) {
                engine = -1;
            }
            System.out.printf("  S3_0_C0_C%d_%d model=0x%016x%n", reg[0], reg[1], engine);
        }
        System.out.println();
    }

    private static ExecutorService newExecutor() {
        return Executors.newSingleThreadExecutor(r -> {
            Thread thread = new Thread(r, "probe");
            thread.setDaemon(true);
            return thread;
        });
    }

    private static String observed(Result r) {
        if (r.hang) {
            return "HANG";
        }
        if (r.error != null) {
            return "ERROR";
        }
        if (r.debugger != null) {
            return "debugger";
        }
        if (r.sigCount > 0) {
            String name = r.signo == SIGILL ? "SIGILL" : r.signo == SIGTRAP ? "SIGTRAP" : "SIG" + r.signo;
            return r.sigCount == 1 ? name : name + "x" + r.sigCount;
        }
        return r.x10 == 0x5a5aL ? "runs" : "lost";
    }

    private static String verify(Probe probe, Result r) {
        if (r.hang) return "hang";
        if (r.error != null) return r.error;
        if (r.debugger != null) return "debugger: " + r.debugger;
        if (r.x10 != 0x5a5aL) return "did not resume after the probe";
        if (r.x0 != X0_SENTINEL) return "x0 clobbered";
        if (probe.expect == Expect.OK) {
            if (r.sigCount != 0) return "unexpected signal " + r.signo;
        } else {
            long expectedCount = probe.restartUntil == 0 ? 1 : probe.restartUntil;
            int expectedSigno = probe.expect == Expect.SIGILL ? SIGILL : SIGTRAP;
            if (r.sigCount == 0) return "no signal";
            if (r.signo != expectedSigno) return "signo " + r.signo;
            if (probe.check == null && r.sigCount != expectedCount) return "sigCount " + r.sigCount;
            if (r.markerAtNext < 1) return "handler ran late";
            String frame = frameProblem(probe, r);
            if (frame != null) return frame;
            if (probe.rtUntouched && r.x9 != r.x9Before) return "Rt modified by a faulting instruction";
        }
        return probe.check == null ? null : probe.check.verify(r);
    }

    private static String frameProblem(Probe probe, Result r) {
        if (r.siCode != probe.siCode) return "si_code " + r.siCode;
        if (r.siAddr != r.probePc) return "si_addr 0x" + Long.toHexString(r.siAddr);
        if (r.ucPc != r.probePc) return "uc pc 0x" + Long.toHexString(r.ucPc);
        if (r.ucSp != r.faultSp) return "uc sp 0x" + Long.toHexString(r.ucSp) + " != 0x" + Long.toHexString(r.faultSp);
        if (r.handlerSp >= r.faultSp || r.faultSp - r.handlerSp > 0x2000) return "frame not on the interrupted stack";
        if (probe.rtUntouched && r.ucX9 != r.x9Before) return "uc x9 0x" + Long.toHexString(r.ucX9);
        return null;
    }

    private static String frame(Probe probe, Result r) {
        if (r.sigCount == 0) {
            return "-";
        }
        return frameProblem(probe, r) == null ? "good" : "bad";
    }

    private static AndroidEmulator createEmulator() {
        return AndroidEmulatorBuilder
                .for64Bit()
                .addBackendFactory(new Unicorn2Factory(false))
                .build();
    }

    private Result run(Probe probe) {
        AndroidEmulator emulator = createEmulator();
        final Result r = new Result();
        try {
            final Backend backend = emulator.getBackend();
            if (!"Unicorn2Backend".equals(backend.getClass().getSimpleName())) {
                throw new IllegalStateException("expected Unicorn2Backend, got " + backend.getClass());
            }
            Memory memory = emulator.getMemory();
            backend.mem_map(CODE_BASE, 0x1000, UnicornConst.UC_PROT_ALL);
            backend.mem_map(HANDLER_BASE, 0x1000, UnicornConst.UC_PROT_ALL);
            backend.mem_map(SCRATCH_BASE, 0x1000, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_WRITE);

            MemoryBlock markerBlock = memory.malloc(64, true);
            UnidbgPointer marker = markerBlock.getPointer();
            marker.write(0, new byte[64], 0, 64);
            marker.setLong(40, probe.restartUntil);

            MemoryBlock actBlock = memory.malloc(32, true);
            long actAddr = actBlock.getPointer().peer;

            // handler(sig, info, uc): count++, record signo/si_code/si_addr/uc pc/sp/x9 and its own sp,
            // then uc pc += 4 unless count < restartUntil
            List<String> handlerAsm = new ArrayList<>();
            loadImm64(handlerAsm, "x3", marker.peer);
            handlerAsm.addAll(Arrays.asList(
                    "ldr x4, [x3]",
                    "add x4, x4, #1",
                    "str x4, [x3]",
                    "str w0, [x3, #8]",
                    "ldr w5, [x1, #8]",
                    "str w5, [x3, #12]",
                    "ldr x5, [x1, #16]",
                    "str x5, [x3, #16]",
                    "mov x6, sp",
                    "str x6, [x3, #32]",
                    "ldr x6, [x2, #" + UC_SP + "]",
                    "str x6, [x3, #48]",
                    "ldr x6, [x2, #" + (UC_REGS + 9 * 8) + "]",
                    "str x6, [x3, #56]",
                    "ldr x5, [x2, #" + UC_PC + "]",
                    "str x5, [x3, #24]",
                    "ldr x6, [x3, #40]",
                    "cmp x4, x6",
                    "b.lt keep_pc",
                    "add x5, x5, #4",
                    "str x5, [x2, #" + UC_PC + "]",
                    "keep_pc:",
                    "ret"));
            backend.mem_write(HANDLER_BASE, assemble(handlerAsm));

            SigAction action = SigAction.create(emulator, UnidbgPointer.pointer(emulator, actAddr));
            action.setSaHandler(HANDLER_BASE);
            action.setFlags(SA_SIGINFO);
            action.setMask(0);
            action.setSaRestorer(0);
            action.pack();

            r.x9Before = probe.name.startsWith("dc ") || probe.name.startsWith("ic ") || probe.name.startsWith("at ") ||
                    probe.name.startsWith("cfp ") ? SCRATCH_BASE : SENTINEL;

            List<String> prefixAsm = new ArrayList<>();
            for (int sig : new int[]{SIGILL, SIGTRAP}) {
                prefixAsm.add("mov x0, #" + sig);
                loadImm64(prefixAsm, "x1", actAddr);
                prefixAsm.add("mov x2, #0");
                prefixAsm.add("mov x3, #8");
                prefixAsm.add("mov x8, #" + NR_rt_sigaction);
                prefixAsm.add("svc #0");
            }
            prefixAsm.add("movz x10, #0");
            loadImm64(prefixAsm, "x9", r.x9Before);
            loadImm64(prefixAsm, "x12", marker.peer);
            loadImm64(prefixAsm, "x13", SCRATCH_BASE);
            prefixAsm.add("movz x0, #" + X0_SENTINEL);
            prefixAsm.addAll(probe.setup);
            if (probe.setup.size() > 0 && probe.setup.get(0).startsWith("movz x9")) {
                r.x9Before = USER_POINTER;
            }
            prefixAsm.add("mov x17, sp");
            byte[] prefix = assemble(prefixAsm);
            // x11 = handler count as seen by the very next instruction: a real kernel delivers SIGILL
            // before anything after the faulting instruction runs
            byte[] suffix = assemble(Arrays.asList("ldr x11, [x12]", "movz x10, #0x5a5a", "ret"));

            byte[] code = new byte[prefix.length + 4 * probe.insns.length + suffix.length];
            System.arraycopy(prefix, 0, code, 0, prefix.length);
            for (int n = 0; n < probe.insns.length; n++) {
                for (int i = 0; i < 4; i++) {
                    code[prefix.length + 4 * n + i] = (byte) (probe.insns[n] >>> (8 * i));
                }
            }
            System.arraycopy(suffix, 0, code, prefix.length + 4 * probe.insns.length, suffix.length);
            backend.mem_write(CODE_BASE, code);
            r.probePc = CODE_BASE + prefix.length + 4L * (probe.insns.length - 1);

            // a fault the guest cannot handle goes to the debugger: record it and step over instead of blocking
            emulator.getSyscallHandler().setBreaker(new Breaker() {
                @Override
                public void debug(String reason) {
                    if (r.debugger == null) {
                        r.debugger = reason;
                    }
                    long pc = backend.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue();
                    backend.reg_write(Arm64Const.UC_ARM64_REG_PC, pc + 4);
                }

                @Override
                public void brk(UnidbgPointer pc, int svcNumber) {
                    debug("brk at " + pc);
                }
            });

            try {
                Number ret = emulator.eFunc(CODE_BASE);
                r.x0 = ret == null ? -1 : ret.longValue();
            } catch (Throwable t) {
                r.error = t.getClass().getSimpleName() + ": " + t.getMessage();
            }

            r.sigCount = marker.getLong(0);
            r.signo = marker.getInt(8);
            r.siCode = marker.getInt(12);
            r.siAddr = marker.getLong(16);
            r.ucPc = marker.getLong(24);
            r.handlerSp = marker.getLong(32);
            r.ucSp = marker.getLong(48);
            r.ucX9 = marker.getLong(56);
            r.x9 = backend.reg_read(Arm64Const.UC_ARM64_REG_X9).longValue();
            r.x10 = backend.reg_read(Arm64Const.UC_ARM64_REG_X10).longValue();
            r.x16 = backend.reg_read(Arm64Const.UC_ARM64_REG_X16).longValue();
            r.faultSp = backend.reg_read(Arm64Const.UC_ARM64_REG_X17).longValue();
            r.markerAtNext = backend.reg_read(Arm64Const.UC_ARM64_REG_X11).longValue();
        } catch (Throwable t) {
            r.error = t.getClass().getSimpleName() + ": " + t.getMessage();
        }
        // Deliberately not closed: on windows_64 the 4th Unicorn.nativeDestroy in one JVM corrupts the
        // native heap (reproducible with the unicorn.dll shipped in HEAD and with no hooks at all).
        return r;
    }

}
