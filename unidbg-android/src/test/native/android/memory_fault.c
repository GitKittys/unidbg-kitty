/*
 * Memory faults as apps rely on them (doc/memory-fault-fidelity.md, acceptance table): an invalid access raises
 * SIGSEGV in the faulting thread with si_code SEGV_MAPERR (nothing mapped) or SEGV_ACCERR (no permission), si_addr =
 * uc_mcontext.fault_address = the address (the target for an instruction fetch), uc_mcontext.pc = the faulting
 * instruction and an esr_context; a handler that repairs the mapping and returns makes the instruction run again.
 * Every expectation is a Linux rule, so the library behaves the same on a real arm64 Android device.
 *
 * mem_run_all()          single thread; returns the number of failed checks
 * mem_run_threads()      needs the thread dispatcher; returns the number of failed checks
 * mem_fault_unfixed()    a handler that returns without repairing: loops forever on a device
 * mem_fault_no_handler() SIGSEGV without a handler: the process dies on a device
 * mem_probe_once()       one sigsetjmp probe of an unmapped address: 1234 if the handler took it
 */
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ucontext.h>
#include <unistd.h>

static int failures;
static int checks;

#define CHECK(cond, ...) do { \
    checks++; \
    if (cond) { printf("ok   "); } else { printf("FAIL "); failures++; } \
    printf(__VA_ARGS__); \
    printf("\n"); \
} while (0)

#define ESR_MAGIC 0x45535201
#define ESR_EC(esr) (((esr) >> 26) & 0x3f)
#define ESR_WNR(esr) (((esr) >> 6) & 1)
#define ESR_FSC(esr) ((esr) & 0x3f)

enum fix { FIX_PROTECT_RW, FIX_PROTECT_R, FIX_LONGJMP, FIX_SKIP, FIX_RETURN_LR, FIX_NONE };

static volatile int seg_count, seg_code, seg_tid, seg_fix;
static volatile uintptr_t seg_addr, seg_pc, seg_fault_address, seg_sp, seg_x9;
static volatile uint64_t seg_esr;
static sigjmp_buf jump_back;
static void *volatile fix_page;
static size_t page_size;

static uint64_t find_esr(ucontext_t *uc) {
    unsigned char *p = (unsigned char *) uc->uc_mcontext.__reserved;
    for (int off = 0; off + 8 <= (int) sizeof(uc->uc_mcontext.__reserved);) {
        uint32_t magic = *(uint32_t *) (p + off), size = *(uint32_t *) (p + off + 4);
        if (magic == 0 || size == 0) {
            break;
        }
        if (magic == ESR_MAGIC) {
            return *(uint64_t *) (p + off + 8);
        }
        off += size;
    }
    return 0;
}

static void segv_handler(int sig, siginfo_t *info, void *ctx) {
    (void) sig;
    ucontext_t *uc = (ucontext_t *) ctx;
    uintptr_t sp;
    __asm__ volatile("mov %0, sp" : "=r"(sp));
    seg_count++;
    seg_code = info->si_code;
    seg_addr = (uintptr_t) info->si_addr;
    seg_pc = uc->uc_mcontext.pc;
    seg_fault_address = uc->uc_mcontext.fault_address;
    seg_esr = find_esr(uc);
    seg_tid = gettid();
    seg_sp = sp;
    seg_x9 = uc->uc_mcontext.regs[9];
    switch (seg_fix) {
        case FIX_PROTECT_RW:
            mprotect(fix_page, page_size, PROT_READ | PROT_WRITE);
            break;
        case FIX_PROTECT_R:
            mprotect(fix_page, page_size, PROT_READ);
            break;
        case FIX_LONGJMP:
            siglongjmp(jump_back, 1);
        case FIX_SKIP:
            uc->uc_mcontext.pc += 4;
            break;
        case FIX_RETURN_LR:
            uc->uc_mcontext.pc = uc->uc_mcontext.regs[30];
            break;
        default:
            break;
    }
}

static void install_segv(int flags) {
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    sigemptyset(&act.sa_mask);
    act.sa_sigaction = segv_handler;
    act.sa_flags = SA_SIGINFO | flags;
    sigaction(SIGSEGV, &act, NULL);
}

static void reset(void) {
    seg_count = seg_code = 0;
    seg_addr = seg_pc = seg_fault_address = 0;
    seg_esr = 0;
}

static int is_blocked(int sig) {
    sigset_t cur;
    sigprocmask(SIG_BLOCK, NULL, &cur);
    return sigismember(&cur, sig);
}

static void *map(int prot) {
    return mmap(NULL, page_size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

/* A: write to a PROT_NONE page, the handler makes it writable and returns: the store is retried and lands */
static void test_write_retry(void) {
    void *page = map(PROT_NONE);
    fix_page = page;
    seg_fix = FIX_PROTECT_RW;
    reset();
    uintptr_t insn;
    __asm__ volatile("adr %0, 1f\n"
                     "1: str %w2, [%1]\n"
                     : "=&r"(insn) : "r"(page), "r"(0xa5a5a5a5) : "memory");
    CHECK(seg_count == 1 && *(volatile uint32_t *) page == 0xa5a5a5a5, "A: store to PROT_NONE, handler mprotect(RW), retried: 0x%x (faults %d)",
          *(volatile uint32_t *) page, seg_count);
    CHECK(seg_code == SEGV_ACCERR && seg_addr == (uintptr_t) page && seg_fault_address == seg_addr && seg_pc == insn,
          "A: SEGV_ACCERR, si_addr = fault_address = the page, uc.pc = the str (code %d, addr %lx, pc %lx/%lx)",
          seg_code, (unsigned long) seg_addr, (unsigned long) seg_pc, (unsigned long) insn);
    CHECK(ESR_EC(seg_esr) == 0x24 && ESR_WNR(seg_esr) == 1 && ESR_FSC(seg_esr) == 0x0f,
          "A: esr_context: data abort, write, permission fault (esr 0x%llx)", (unsigned long long) seg_esr);
    munmap(page, page_size);
}

/* D: read from a PROT_NONE page, the handler makes it readable: the load is retried */
static void test_read_retry(void) {
    void *page = map(PROT_READ | PROT_WRITE);
    *(volatile uint32_t *) page = 0x1234567;
    mprotect(page, page_size, PROT_NONE);
    fix_page = page;
    seg_fix = FIX_PROTECT_R;
    reset();
    uint32_t v = *(volatile uint32_t *) page;
    CHECK(seg_count == 1 && v == 0x1234567 && seg_code == SEGV_ACCERR && ESR_WNR(seg_esr) == 0,
          "D: load from PROT_NONE, handler mprotect(R), retried: 0x%x (WnR %d)", v, (int) ESR_WNR(seg_esr));

    /* R -> NONE keeps the page read-only for writes: the read permission must still be enforced */
    reset();
    v = *(volatile uint32_t *) page; /* readable now, cached */
    mprotect(page, page_size, PROT_NONE);
    v = *(volatile uint32_t *) page;
    CHECK(seg_count == 1 && v == 0x1234567 && seg_code == SEGV_ACCERR, "D: a page read, then made PROT_NONE, faults on the next read (%d)", seg_count);

    /* write and execute permission imply read on arm64 Linux */
    void *wo = mmap(NULL, page_size, PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    reset();
    *(volatile uint32_t *) wo = 0x55;
    uint32_t w = *(volatile uint32_t *) wo;
    CHECK(seg_count == 0 && w == 0x55, "D: a PROT_WRITE page is readable (faults %d)", seg_count);
    munmap(wo, page_size);
    munmap(page, page_size);
}

/* B: probing an address with sigsetjmp/siglongjmp */
static void test_probe(void) {
    seg_fix = FIX_LONGJMP;
    reset();
    volatile int reached = 0;
    if (sigsetjmp(jump_back, 1) == 0) {
        volatile int v = *(volatile int *) 0x10;
        (void) v;
        reached = 1;
    }
    CHECK(!reached && seg_count == 1 && seg_code == SEGV_MAPERR && seg_addr == 0x10 && seg_fault_address == 0x10,
          "B: read of 0x10: SEGV_MAPERR, si_addr = fault_address = 0x10 (code %d, addr %lx)", seg_code, (unsigned long) seg_addr);
    CHECK(ESR_EC(seg_esr) == 0x24 && ESR_FSC(seg_esr) == 0x07 && !is_blocked(SIGSEGV),
          "B: translation fault in esr (0x%llx); siglongjmp restored the mask", (unsigned long long) seg_esr);

    /* the same address probed again and again: every probe reports, nothing is treated as a stuck handler */
    int probes = 0;
    for (int i = 0; i < 100; i++) {
        if (sigsetjmp(jump_back, 1) == 0) {
            volatile int v = *(volatile int *) 0x10;
            (void) v;
        } else {
            probes++;
        }
    }
    CHECK(probes == 100, "B: 100 probes of the same address all fault and come back (%d)", probes);
}

/* C: executing a page that is not executable; then making it executable */
static void test_exec(void) {
    uint32_t *page = (uint32_t *) map(PROT_READ | PROT_WRITE);
    page[0] = 0xd2800540; /* mov x0, #42 */
    page[1] = 0xd65f03c0; /* ret */
    seg_fix = FIX_RETURN_LR;
    reset();
    long (*fn)(void) = (long (*)(void)) page;
    fn();
    CHECK(seg_count == 1 && seg_code == SEGV_ACCERR && seg_addr == (uintptr_t) page && seg_pc == (uintptr_t) page && ESR_EC(seg_esr) == 0x20,
          "C: call into a RW page: SEGV_ACCERR, si_addr = uc.pc = the target, instruction abort (esr 0x%llx)", (unsigned long long) seg_esr);
    mprotect(page, page_size, PROT_READ | PROT_EXEC);
    __builtin___clear_cache((char *) page, (char *) page + 8);
    reset();
    long r = fn();
    CHECK(seg_count == 0 && r == 42, "C: after mprotect(RX) the same call runs (ret %ld, faults %d)", r, seg_count);
    mprotect(page, page_size, PROT_READ);
    seg_fix = FIX_RETURN_LR;
    reset();
    fn();
    CHECK(seg_count == 1 && seg_code == SEGV_ACCERR && seg_pc == (uintptr_t) page, "C: code that already ran, made PROT_READ, faults when called again");

    /* a jump to nothing at all */
    seg_fix = FIX_RETURN_LR;
    reset();
    long (*nowhere)(void) = (long (*)(void)) (uintptr_t) 0x2000;
    nowhere();
    CHECK(seg_count == 1 && seg_code == SEGV_MAPERR && seg_addr == 0x2000 && seg_pc == 0x2000, "C: call to unmapped 0x2000: SEGV_MAPERR at the target");
    munmap(page, page_size);
}

/* E: the fault is precise: no later instruction has run when the handler sees the context */
static void test_precise(void) {
    void *page = map(PROT_READ);
    seg_fix = FIX_SKIP;
    reset();
    long result;
    __asm__ volatile("mov x9, #0\n"
                     "str x9, [%1]\n"
                     "add x9, x9, #1\n"
                     "add x9, x9, #1\n"
                     "mov %0, x9\n"
                     : "=r"(result) : "r"(page) : "x9", "memory");
    CHECK(seg_count == 1 && seg_x9 == 0 && result == 2,
          "E: store fault is precise: handler saw x9=%lu (later adds not run), skipping it continues (x9=%ld)", (unsigned long) seg_x9, result);
    reset();
    __asm__ volatile("mov x9, #5\n"
                     "ldp x10, x9, [%1, #-8]\n" /* first half readable? no: the page before may be unmapped too */
                     "mov %0, x9\n"
                     : "=r"(result) : "r"((uintptr_t) 0x10) : "x9", "x10", "memory");
    CHECK(seg_count == 1 && seg_x9 == 5 && result == 5, "E: a faulting ldp leaves its registers alone (x9=%ld)", result);
    munmap(page, page_size);
}

/* H1: bionic dereferences the sigprocmask arguments in user space: a bad pointer is a SIGSEGV in libc */
static void test_bad_pointer(void) {
    seg_fix = FIX_LONGJMP;
    reset();
    if (sigsetjmp(jump_back, 1) == 0) {
        sigprocmask(SIG_BLOCK, (sigset_t *) 16, NULL);
    }
    CHECK(seg_count == 1 && seg_addr == 16 && seg_code == SEGV_MAPERR, "H1: sigprocmask(SIG_BLOCK, (sigset_t *) 16): SIGSEGV in libc, si_addr 16");
}

/* G: a fault inside another signal's handler nests, and returning from both resumes the interrupted code */
static volatile int usr1_ran, usr1_after;

static void usr1_handler(int sig) {
    (void) sig;
    usr1_ran = 1;
    *(volatile uint32_t *) fix_page = 7; /* faults, repaired by the SIGSEGV handler */
    usr1_after = *(volatile uint32_t *) fix_page;
}

static void test_nested(void) {
    void *page = map(PROT_NONE);
    fix_page = page;
    seg_fix = FIX_PROTECT_RW;
    reset();
    signal(SIGUSR1, usr1_handler);
    usr1_ran = usr1_after = 0;
    raise(SIGUSR1);
    CHECK(usr1_ran && usr1_after == 7 && seg_count == 1, "G: fault inside a SIGUSR1 handler: repaired, the handler finished (%d)", usr1_after);
    signal(SIGUSR1, SIG_DFL);
    munmap(page, page_size);
}

/* H: stack overflow caught on the alternate stack, then siglongjmp out */
static char altstack[64 * 1024] __attribute__((aligned(16)));
static volatile int depth;

static int recurse(int n) {
    volatile char frame[4096];
    frame[0] = (char) n;
    depth = n;
    return recurse(n + 1) + frame[0];
}

static void test_stack_overflow(void) {
    stack_t ss;
    memset(&ss, 0, sizeof(ss));
    ss.ss_sp = altstack;
    ss.ss_size = sizeof(altstack);
    sigaltstack(&ss, NULL);
    install_segv(SA_ONSTACK);
    seg_fix = FIX_LONGJMP;
    reset();
    if (sigsetjmp(jump_back, 1) == 0) {
        recurse(0);
    }
    CHECK(seg_count == 1 && seg_sp > (uintptr_t) altstack && seg_sp <= (uintptr_t) altstack + sizeof(altstack),
          "H: stack overflow after %d frames: SIGSEGV handled on the alternate stack (sp %lx)", depth, (unsigned long) seg_sp);
    ss.ss_flags = SS_DISABLE;
    sigaltstack(&ss, NULL);
    install_segv(0);
}

/* L: an atomic read-modify-write on a read-only page */
static void test_atomic(void) {
    void *page = map(PROT_READ);
    fix_page = page;
    seg_fix = FIX_PROTECT_RW;
    reset();
    long old = __atomic_fetch_add((long *) page, 3, __ATOMIC_SEQ_CST);
    CHECK(seg_count == 1 && old == 0 && *(volatile long *) page == 3 && seg_code == SEGV_ACCERR,
          "L: atomic add on a read-only page faults, retried after mprotect (value %ld, faults %d)", *(volatile long *) page, seg_count);
    munmap(page, page_size);
}

int mem_run_all(void) {
    failures = 0;
    checks = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    page_size = (size_t) sysconf(_SC_PAGESIZE);
    install_segv(0);
    test_write_retry();
    test_read_retry();
    test_probe();
    test_exec();
    test_precise();
    test_bad_pointer();
    test_nested();
    test_stack_overflow();
    test_atomic();
    signal(SIGSEGV, SIG_DFL);
    printf("%d/%d checks failed\n", failures, checks);
    return failures;
}

/* I: a fault in a worker thread is handled on that thread */
static volatile int worker_tid, worker_value;

static void *fault_worker(void *arg) {
    (void) arg;
    worker_tid = gettid();
    *(volatile uint32_t *) fix_page = 99;
    worker_value = *(volatile uint32_t *) fix_page;
    return NULL;
}

int mem_run_threads(void) {
    failures = 0;
    checks = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    page_size = (size_t) sysconf(_SC_PAGESIZE);
    install_segv(0);
    void *page = map(PROT_NONE);
    fix_page = page;
    seg_fix = FIX_PROTECT_RW;
    reset();
    pthread_t t;
    pthread_create(&t, NULL, fault_worker, NULL);
    pthread_join(t, NULL);
    CHECK(seg_count == 1 && seg_tid == worker_tid && worker_value == 99, "I: fault in a worker: handled on it (tid %d/%d), store retried (%d)",
          seg_tid, worker_tid, worker_value);
    munmap(page, page_size);
    signal(SIGSEGV, SIG_DFL);
    printf("%d/%d thread checks failed\n", failures, checks);
    return failures;
}

int mem_fault_unfixed(void) {
    page_size = (size_t) sysconf(_SC_PAGESIZE);
    install_segv(0);
    seg_fix = FIX_NONE;
    void *page = map(PROT_NONE);
    *(volatile int *) page = 1;
    return 1234;
}

int mem_probe_once(void) {
    install_segv(0);
    seg_fix = FIX_LONGJMP;
    if (sigsetjmp(jump_back, 1) == 0) {
        volatile int v = *(volatile int *) 0x10;
        (void) v;
        return 1;
    }
    return 1234;
}

int mem_fault_no_handler(void) {
    signal(SIGSEGV, SIG_DFL);
    *(volatile int *) 0x10 = 1;
    return 1234;
}
