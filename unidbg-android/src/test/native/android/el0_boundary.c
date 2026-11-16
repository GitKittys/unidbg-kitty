/*
 * End-to-end check of the EL0 privilege boundary and synchronous-fault signals, written the way detection code is:
 * real bionic sigaction/sigsetjmp/siglongjmp/getauxval, handlers that siglongjmp or edit the ucontext. Every check is
 * a Linux/architecture rule, so the same library must also pass on a real arm64 Android device.
 *
 * el0_run_all() returns the number of failed checks; el0_no_handler() executes a privileged instruction with no SIGILL
 * handler installed (on a device: killed by SIGILL).
 */
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/ucontext.h>
#include <time.h>

#include <asm/hwcap.h>

#ifndef HWCAP2_RNG
#define HWCAP2_RNG (1 << 16)
#endif

static int failures;
static int checks;

#define CHECK(cond, ...) do { \
    checks++; \
    if (cond) { printf("ok   "); } else { printf("FAIL "); failures++; } \
    printf(__VA_ARGS__); \
    printf("\n"); \
} while (0)

/* ---- probes: the first instruction is the one under test, then "ret" ---- */

#define PROBE(name, insn) \
    __attribute__((naked, noinline)) static void name(void) { __asm__ volatile(".inst " #insn "\n ret"); }

PROBE(p_mrs_tpidr_el1, 0xd538d089)   /* mrs x9, tpidr_el1 */
PROBE(p_mrs_currentel, 0xd5384249)   /* mrs x9, CurrentEL */
PROBE(p_mrs_sctlr_el1, 0xd5381009)   /* mrs x9, sctlr_el1 */
PROBE(p_mrs_daif, 0xd53b4229)        /* mrs x9, daif */
PROBE(p_mrs_cntpct, 0xd53be029)      /* mrs x9, cntpct_el0 */
PROBE(p_mrs_pmccntr, 0xd53b9d09)     /* mrs x9, pmccntr_el0 */
PROBE(p_mrs_id_pfr0, 0xd5380109)     /* mrs x9, ID_PFR0_EL1 (AArch32 ID, not emulated) */
PROBE(p_mrs_impdef, 0xd538f009)      /* mrs x9, s3_0_c15_c0_0 */
PROBE(p_mrs_dbg, 0xd5300249)         /* mrs x9, s2_0_c0_c2_2 */
PROBE(p_msr_tpidrro, 0xd51bd069)     /* msr tpidrro_el0, x9 */
PROBE(p_msr_daifset, 0xd50342df)     /* msr daifset, #2 */
PROBE(p_msr_spsel, 0xd50041bf)       /* msr spsel, #1 */
PROBE(p_dc_ivac, 0xd5087629)         /* dc ivac, x9 */
PROBE(p_ic_iallu, 0xd508751f)        /* ic iallu */
PROBE(p_tlbi, 0xd508871f)            /* tlbi vmalle1 */
PROBE(p_at, 0xd5087809)              /* at s1e1r, x9 */
PROBE(p_hvc, 0xd4000002)             /* hvc #0 */
PROBE(p_smc, 0xd4000003)             /* smc #0 */
PROBE(p_eret, 0xd69f03e0)            /* eret */
PROBE(p_hlt, 0xd4400000)             /* hlt #0 */
PROBE(p_udf, 0x00000000)             /* udf #0 */
PROBE(p_ldp_same, 0xa94027e9)        /* ldp x9, x9, [sp] */
PROBE(p_casp_odd, 0x48217fe4)        /* casp x1, x2, x4, x5, [sp] */
PROBE(p_brk, 0xd4200000)             /* brk #0 */

struct probe {
    const char *name;
    void (*fn)(void);
    int sig;
};

static const struct probe probes[] = {
        {"mrs tpidr_el1", p_mrs_tpidr_el1, SIGILL},
        {"mrs CurrentEL", p_mrs_currentel, SIGILL},
        {"mrs sctlr_el1", p_mrs_sctlr_el1, SIGILL},
        {"mrs daif", p_mrs_daif, SIGILL},
        {"mrs cntpct_el0", p_mrs_cntpct, SIGILL},
        {"mrs pmccntr_el0", p_mrs_pmccntr, SIGILL},
        {"mrs ID_PFR0_EL1", p_mrs_id_pfr0, SIGILL},
        {"mrs s3_0_c15_c0_0", p_mrs_impdef, SIGILL},
        {"mrs s2_0_c0_c2_2", p_mrs_dbg, SIGILL},
        {"msr tpidrro_el0", p_msr_tpidrro, SIGILL},
        {"msr daifset", p_msr_daifset, SIGILL},
        {"msr spsel", p_msr_spsel, SIGILL},
        {"dc ivac", p_dc_ivac, SIGILL},
        {"ic iallu", p_ic_iallu, SIGILL},
        {"tlbi vmalle1", p_tlbi, SIGILL},
        {"at s1e1r", p_at, SIGILL},
        {"hvc", p_hvc, SIGILL},
        {"smc", p_smc, SIGILL},
        {"eret", p_eret, SIGILL},
        {"hlt", p_hlt, SIGILL},
        {"udf", p_udf, SIGILL},
        {"ldp x9, x9", p_ldp_same, SIGILL},
        {"casp odd Rs", p_casp_odd, SIGILL},
        {"brk", p_brk, SIGTRAP},
};

/* ---- paradigm 1: sigsetjmp + siglongjmp out of the handler (the INSDET pattern) ---- */

static sigjmp_buf jmp;
static volatile int got_sig, got_code;
static void *volatile got_addr;
static volatile uint64_t got_pc, got_sp;
static volatile int blocked_in_handler, extra_blocked_in_handler;

static int is_blocked(int sig) {
    sigset_t cur;
    sigprocmask(SIG_BLOCK, NULL, &cur);
    return sigismember(&cur, sig);
}

static void longjmp_handler(int sig, siginfo_t *info, void *ctx) {
    ucontext_t *uc = (ucontext_t *) ctx;
    got_sig = sig;
    got_code = info->si_code;
    got_addr = info->si_addr;
    got_pc = uc->uc_mcontext.pc;
    got_sp = uc->uc_mcontext.sp;
    blocked_in_handler = is_blocked(sig);
    extra_blocked_in_handler = is_blocked(SIGUSR2);
    siglongjmp(jmp, 1);
}

static int install(int sig, void (*handler)(int, siginfo_t *, void *), int flags, int extra_mask_sig) {
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    sigemptyset(&act.sa_mask);
    if (extra_mask_sig) {
        sigaddset(&act.sa_mask, extra_mask_sig);
    }
    act.sa_sigaction = handler;
    act.sa_flags = SA_SIGINFO | flags;
    return sigaction(sig, &act, NULL);
}

static int run_longjmp(void (*fn)(void)) {
    got_sig = 0;
    if (sigsetjmp(jmp, 1) == 0) {
        fn();
    }
    return got_sig;
}

static void test_longjmp_paradigm(void) {
    CHECK(install(SIGILL, longjmp_handler, 0, SIGUSR2) == 0, "sigaction(SIGILL)");
    CHECK(install(SIGTRAP, longjmp_handler, 0, SIGUSR2) == 0, "sigaction(SIGTRAP)");
    for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
        const struct probe *p = &probes[i];
        int sig = run_longjmp(p->fn);
        int code_ok = p->sig == SIGILL ? got_code == ILL_ILLOPC : got_code == TRAP_BRKPT;
        CHECK(sig == p->sig && code_ok && got_addr == (void *) p->fn && got_pc == (uint64_t) p->fn,
              "siglongjmp  %-20s sig=%d code=%d si_addr=%s uc_pc=%s", p->name, sig, got_code,
              got_addr == (void *) p->fn ? "ok" : "BAD", got_pc == (uint64_t) p->fn ? "ok" : "BAD");
    }
    run_longjmp(p_mrs_tpidr_el1);
    CHECK(blocked_in_handler, "signal blocked while its handler runs");
    CHECK(extra_blocked_in_handler, "sa_mask (SIGUSR2) blocked while the handler runs");
    CHECK(!is_blocked(SIGILL) && !is_blocked(SIGUSR2), "siglongjmp(savemask=1) restored the mask");
    char here;
    CHECK(got_sp > (uint64_t) &here - 0x10000 && got_sp < (uint64_t) &here + 0x10000, "uc_mcontext.sp is the interrupted stack");
}

/* ---- paradigm 2: the handler edits uc_mcontext.pc and returns (rt_sigreturn) ---- */

static volatile int skip_count, restart_until, trap_inside_ill;

static void skip_handler(int sig, siginfo_t *info, void *ctx) {
    ucontext_t *uc = (ucontext_t *) ctx;
    (void) info;
    skip_count++;
    if (sig == SIGILL && trap_inside_ill) {
        trap_inside_ill = 0;
        p_brk(); /* a SIGTRAP while handling SIGILL: nested frame */
    }
    if (skip_count >= restart_until) {
        uc->uc_mcontext.pc += 4;
    }
}

/* x9 is the probe's Rt, d16 a vector register: both must survive the fault and the signal frame */
__attribute__((naked, noinline)) static uint64_t skip_regs(void) {
    __asm__ volatile(
            "movz x9, #0x1234\n"
            "movk x9, #0x5678, lsl #16\n"
            "fmov d16, x9\n"
            ".inst 0xd538d089\n" /* mrs x9, tpidr_el1 */
            "fmov x10, d16\n"
            "add x0, x9, x10\n"
            "ret");
}

static void test_ucontext_paradigm(void) {
    CHECK(install(SIGILL, skip_handler, 0, SIGUSR2) == 0, "sigaction(SIGILL) skip handler");
    CHECK(install(SIGTRAP, skip_handler, 0, 0) == 0, "sigaction(SIGTRAP) skip handler");

    skip_count = 0;
    restart_until = 1;
    uint64_t r = skip_regs();
    CHECK(skip_count == 1 && r == 2 * 0x56781234ULL, "uc pc += 4: resumes after the fault, x9/d16 intact (r=0x%llx)",
          (unsigned long long) r);
    CHECK(!is_blocked(SIGILL) && !is_blocked(SIGUSR2), "rt_sigreturn restored the mask");

    skip_count = 0;
    restart_until = 3;
    p_mrs_currentel();
    CHECK(skip_count == 3, "unchanged uc pc re-executes the faulting instruction (%d deliveries)", skip_count);

    skip_count = 0;
    restart_until = 1;
    trap_inside_ill = 1;
    p_mrs_sctlr_el1();
    CHECK(skip_count == 2, "SIGTRAP inside the SIGILL handler is delivered (nested frame), count=%d", skip_count);
}

/* ---- the reported CPU features are consistent and executable ---- */

static uint64_t read_isar0(void) { uint64_t v; __asm__ volatile("mrs %0, ID_AA64ISAR0_EL1" : "=r"(v)); return v; }
static uint64_t read_isar1(void) { uint64_t v; __asm__ volatile("mrs %0, ID_AA64ISAR1_EL1" : "=r"(v)); return v; }
static uint64_t read_pfr0(void) { uint64_t v; __asm__ volatile("mrs %0, ID_AA64PFR0_EL1" : "=r"(v)); return v; }
static uint64_t read_pfr1(void) { uint64_t v; __asm__ volatile("mrs %0, ID_AA64PFR1_EL1" : "=r"(v)); return v; }
#define FIELD(reg, shift) (((reg) >> (shift)) & 0xf)

static void x_ldadd(void) { uint32_t m = 1, old; __asm__ volatile(".arch_extension lse\n ldadd %w2, %w0, [%1]" : "=&r"(old) : "r"(&m), "r"(1) : "memory"); }
static void x_aese(void) { __asm__ volatile(".inst 0x4e284820" ::: "v0", "v1"); }
static void x_sha256h(void) { __asm__ volatile(".inst 0x5e004000" ::: "v0", "v1", "v2"); }
static void x_crc32(void) { uint32_t c; __asm__ volatile(".inst 0x1ac04000\n mov %w0, w0" : "=r"(c) :: "x0"); }
static void x_cntb(void) { __asm__ volatile(".inst 0x0420e3e9" ::: "x9"); }
static void x_rndr(void) { __asm__ volatile(".inst 0xd53b2409" ::: "x9"); }
static void x_mrs_dit(void) { __asm__ volatile(".inst 0xd53b42a9" ::: "x9"); }
static void x_mrs_ssbs(void) { __asm__ volatile(".inst 0xd53b42c9" ::: "x9"); }

static uint64_t pac_roundtrip(uint64_t ptr) {
    uint64_t signed_ptr = ptr, auth;
    __asm__ volatile("mov x9, %1\n .inst 0xdac101a9\n mov %0, x9" : "=r"(signed_ptr) : "r"(ptr) : "x9", "x13"); /* pacia x9, x13 */
    __asm__ volatile("mov x9, %1\n .inst 0xdac111a9\n mov %0, x9" : "=r"(auth) : "r"(signed_ptr) : "x9", "x13");  /* autia x9, x13 */
    return auth;
}

static void expect_feature(const char *name, int advertised, void (*fn)(void)) {
    int sig = run_longjmp(fn);
    CHECK(advertised ? sig == 0 : sig == SIGILL, "%-8s advertised=%d executes=%s", name, advertised, sig == 0 ? "yes" : "SIGILL");
}

static void test_features(void) {
    unsigned long hwcap = getauxval(AT_HWCAP), hwcap2 = getauxval(AT_HWCAP2);
    CHECK(hwcap & HWCAP_CPUID, "AT_HWCAP=0x%lx AT_HWCAP2=0x%lx, HWCAP_CPUID set", hwcap, hwcap2);
    CHECK(install(SIGILL, longjmp_handler, 0, 0) == 0, "sigaction(SIGILL)");
    uint64_t isar0 = read_isar0(), isar1 = read_isar1(), pfr0 = read_pfr0(), pfr1 = read_pfr1();
    CHECK(FIELD(pfr0, 8) <= 1 && FIELD(pfr0, 12) == 0, "ID_AA64PFR0 hides EL2/EL3 (0x%llx)", (unsigned long long) pfr0);
    CHECK(!!(hwcap & HWCAP_AES) == (FIELD(isar0, 4) >= 1), "HWCAP_AES matches ID_AA64ISAR0.AES");
    CHECK(!!(hwcap & HWCAP_ATOMICS) == (FIELD(isar0, 20) >= 2), "HWCAP_ATOMICS matches ID_AA64ISAR0.ATOMIC");
    CHECK(!!(hwcap & HWCAP_SVE) == (FIELD(pfr0, 32) >= 1), "HWCAP_SVE matches ID_AA64PFR0.SVE");
    CHECK(!!(hwcap & HWCAP_PACA) == (FIELD(isar1, 4) >= 1 || FIELD(isar1, 8) >= 1), "HWCAP_PACA matches ID_AA64ISAR1.APA/API");
    CHECK(!!(hwcap & HWCAP_SSBS) == (FIELD(pfr1, 4) >= 2), "HWCAP_SSBS matches ID_AA64PFR1.SSBS");
    CHECK(!!(hwcap2 & HWCAP2_RNG) == (FIELD(isar0, 60) >= 1), "HWCAP2_RNG matches ID_AA64ISAR0.RNDR");

    expect_feature("ldadd", !!(hwcap & HWCAP_ATOMICS), x_ldadd);
    expect_feature("aese", !!(hwcap & HWCAP_AES), x_aese);
    expect_feature("sha256h", !!(hwcap & HWCAP_SHA2), x_sha256h);
    expect_feature("crc32b", !!(hwcap & HWCAP_CRC32), x_crc32);
    expect_feature("cntb", !!(hwcap & HWCAP_SVE), x_cntb);
    expect_feature("rndr", !!(hwcap2 & HWCAP2_RNG), x_rndr);
    expect_feature("mrs dit", !!(hwcap & HWCAP_DIT), x_mrs_dit);
    expect_feature("mrs ssbs", !!(hwcap & HWCAP_SSBS), x_mrs_ssbs);
    if (hwcap & HWCAP_PACA) {
        uint64_t ptr = (uint64_t) &hwcap;
        CHECK(pac_roundtrip(ptr) == ptr, "pacia/autia round trip");
    }
}

/* ---- counters ---- */

static uint64_t cntvct(void) { uint64_t v; __asm__ volatile("isb\n mrs %0, cntvct_el0" : "=r"(v)); return v; }
static uint64_t cntfrq(void) { uint64_t v; __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(v)); return v; }

static void test_counters(void) {
    uint64_t a = cntvct(), b = cntvct();
    CHECK(b > a, "CNTVCT_EL0 strictly increasing");
    uint64_t frq = cntfrq();
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    uint64_t c0 = cntvct();
    volatile uint64_t sink = 0;
    for (int i = 0; i < 200000; i++) {
        sink += i;
    }
    uint64_t c1 = cntvct();
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double ns = (t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec);
    double counter_ns = (double) (c1 - c0) * 1e9 / (double) frq;
    CHECK(frq != 0 && counter_ns <= ns * 1.5 + 1000 && counter_ns * 1.5 + 1000 >= ns,
          "CNTVCT/CNTFRQ agrees with CLOCK_MONOTONIC (counter %.0f ns, clock %.0f ns, CNTFRQ %llu)",
          counter_ns, ns, (unsigned long long) frq);
}

int el0_run_all(void) {
    failures = 0;
    checks = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    test_longjmp_paradigm();
    test_ucontext_paradigm();
    test_features();
    test_counters();
    printf("%d/%d checks failed\n", failures, checks);
    return failures;
}

/* cost of EL0-legal system register accesses (TLS reads are everywhere in libc) and of a plain loop */
uint64_t el0_bench_tls(int n) {
    uint64_t sum = 0;
    for (int i = 0; i < n; i++) {
        uint64_t v;
        __asm__ volatile("mrs %0, tpidr_el0" : "=r"(v));
        sum += v;
    }
    return sum;
}

uint64_t el0_bench_loop(int n) {
    uint64_t sum = 0;
    for (int i = 0; i < n; i++) {
        __asm__ volatile("" : "+r"(sum));
        sum += i;
    }
    return sum;
}

int el0_no_handler(void) {
    signal(SIGILL, SIG_DFL);
    p_mrs_tpidr_el1();
    return 0;
}
