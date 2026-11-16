/*
 * Signal semantics checked the way apps rely on them (doc/signal-delivery-fidelity.md, acceptance table), through real
 * bionic: sigaction, raise/pthread_kill/kill, rt_sigqueueinfo, sigprocmask, sigsuspend, sigtimedwait, sigpending,
 * sigaltstack. Every expectation is a Linux rule, so the library behaves the same on a real arm64 Android device.
 *
 * sig_run_all()      single thread; returns the number of failed checks
 * sig_run_threads()  needs the thread dispatcher; returns the number of failed checks
 * sig_stress(n)      n rounds of mixed signal traffic; returns the number of failed checks
 * sig_kill_default() raise(SIGTERM) without a handler: the process dies, the function never returns 1234
 * sig_kill_after_sigreturn() SIGTERM raised while blocked by a handler's sa_mask, released by its rt_sigreturn: dies too
 */
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
#include <sys/ucontext.h>
#include <time.h>
#include <unistd.h>

static int failures;
static int checks;

#define CHECK(cond, ...) do { \
    checks++; \
    if (cond) { printf("ok   "); } else { printf("FAIL "); failures++; } \
    printf(__VA_ARGS__); \
    printf("\n"); \
} while (0)

static void reset_handlers(void) {
    for (int sig = 1; sig < 32; sig++) {
        if (sig != SIGKILL && sig != SIGSTOP) {
            signal(sig, SIG_DFL);
        }
    }
    signal(SIGRTMAX, SIG_DFL);
    signal(SIGRTMAX - 1, SIG_DFL);
    sigset_t none;
    sigemptyset(&none);
    sigprocmask(SIG_SETMASK, &none, NULL);
}

static int install(int sig, void (*handler)(int, siginfo_t *, void *), int flags, int mask_sig) {
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    sigemptyset(&act.sa_mask);
    if (mask_sig) {
        sigaddset(&act.sa_mask, mask_sig);
    }
    act.sa_sigaction = handler;
    act.sa_flags = SA_SIGINFO | flags;
    return sigaction(sig, &act, NULL);
}

static int is_blocked(int sig) {
    sigset_t cur;
    sigprocmask(SIG_BLOCK, NULL, &cur);
    return sigismember(&cur, sig);
}

static void block(int sig) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, sig);
    sigprocmask(SIG_BLOCK, &set, NULL);
}

static void unblock(int sig) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, sig);
    sigprocmask(SIG_UNBLOCK, &set, NULL);
}

/* ---- self-directed signals run before raise() returns (CLAUDE.md item 4) ---- */

static volatile int flag;
static volatile int counter;
static volatile int last_code;
static volatile int last_pid;
static volatile intptr_t last_value;
static volatile uintptr_t handler_lr;
static volatile uintptr_t handler_sp;
static volatile uintptr_t frame_info;
static volatile uintptr_t interrupted_sp;
static volatile int mask_has_self, mask_has_usr2;
static volatile int trace[16];
static volatile int trace_len;

static void flag_handler(int sig, siginfo_t *info, void *ctx) {
    ucontext_t *uc = (ucontext_t *) ctx;
    flag = 1;
    counter++;
    last_code = info->si_code;
    last_pid = info->si_pid;
    last_value = (intptr_t) info->si_value.sival_ptr;
    __asm__ volatile("mov %0, x30" : "=r"(handler_lr));
    __asm__ volatile("mov %0, sp" : "=r"(handler_sp));
    frame_info = (uintptr_t) info;
    interrupted_sp = uc->uc_mcontext.sp;
    mask_has_self = is_blocked(sig);
    mask_has_usr2 = is_blocked(SIGUSR2);
}

static void test_self_delivery(void) {
    CHECK(install(SIGUSR1, flag_handler, 0, SIGUSR2) == 0, "sigaction(SIGUSR1, sa_mask={SIGUSR2})");

    flag = 0;
    CHECK(raise(SIGUSR1) == 0 && flag == 1, "raise(): handler ran before raise() returned");
    CHECK(last_code == SI_TKILL && last_pid == getpid(), "raise(): si_code=SI_TKILL(%d) si_pid=getpid (%d, %d)", last_code, last_pid, getpid());
    CHECK(mask_has_self && mask_has_usr2, "handler runs with sa_mask | {signo} blocked (self=%d usr2=%d)", mask_has_self, mask_has_usr2);
    CHECK(!is_blocked(SIGUSR1) && !is_blocked(SIGUSR2), "mask restored after the handler returned");

    char here;
    CHECK(interrupted_sp > (uintptr_t) &here - 0x10000 && interrupted_sp < (uintptr_t) &here + 0x10000 &&
          handler_sp < interrupted_sp && frame_info < interrupted_sp && interrupted_sp - handler_sp < 0x4000,
          "frame on the interrupted thread's stack (sp=0x%lx handler sp=0x%lx)", (unsigned long) interrupted_sp, (unsigned long) handler_sp);
    const uint32_t *ret = (const uint32_t *) handler_lr;
    CHECK(handler_lr != 0x7ffff0000 && ret[0] == 0xd2801168 && ret[1] == 0xd4000001,
          "handler returns into an rt_sigreturn trampoline (x30=0x%lx)", (unsigned long) handler_lr);

    /* tgkill to itself with a busy wait on the flag: must terminate */
    flag = 0;
    syscall(__NR_tgkill, getpid(), gettid(), SIGUSR1);
    int spins = 0;
    while (!flag && spins < 1000000) {
        spins++;
    }
    CHECK(flag && spins == 0, "tgkill(self) + busy wait finishes (spins=%d)", spins);

    flag = 0;
    CHECK(kill(getpid(), SIGUSR1) == 0 && flag == 1 && last_code == SI_USER, "kill(getpid()): si_code=SI_USER (%d)", last_code);

    flag = 0;
    pthread_kill(pthread_self(), SIGUSR1);
    CHECK(flag == 1, "pthread_kill(self)");
}

/* ---- B: block -> raise -> unblock delivers exactly once, at the unblock ---- */

static void test_block_unblock(void) {
    install(SIGUSR1, flag_handler, 0, 0);
    counter = 0;
    block(SIGUSR1);
    raise(SIGUSR1);
    raise(SIGUSR1); /* standard signals do not queue */
    int during = counter;
    sigset_t pending;
    sigpending(&pending);
    int is_pending = sigismember(&pending, SIGUSR1);
    unblock(SIGUSR1);
    CHECK(((during << 8) | counter) == 0x0001 && is_pending, "B: (during << 8) | after = 0x%04x, sigpending saw it", (during << 8) | counter);

    /* SIG_SETMASK restoring the old mask with a signal pending: delivered */
    sigset_t old, set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    counter = 0;
    sigprocmask(SIG_BLOCK, &set, &old);
    raise(SIGUSR1);
    sigprocmask(SIG_SETMASK, &old, NULL);
    CHECK(counter == 1, "SIG_SETMASK back to the old mask delivers the pending signal (count=%d)", counter);

    /* oldset is written even when no mask was ever set */
    sigset_t probe;
    memset(&probe, 0xa5, sizeof(probe));
    sigprocmask(SIG_BLOCK, NULL, &probe);
    CHECK(!sigismember(&probe, SIGUSR1) && !sigismember(&probe, SIGUSR2), "sigprocmask(NULL, &old) reports the mask");
}

/* ---- E1/E2/E3: nesting ---- */

static void trace_push(int v) {
    if (trace_len < 16) {
        trace[trace_len++] = v;
    }
}

static void usr2_trace(int sig, siginfo_t *info, void *ctx) {
    (void) sig; (void) info; (void) ctx;
    trace_push(3);
}

static void usr1_raises_usr2(int sig, siginfo_t *info, void *ctx) {
    (void) sig; (void) info; (void) ctx;
    trace_push(1);
    raise(SIGUSR2);
    trace_push(2);
}

static volatile int depth;

static void usr1_raises_usr1(int sig, siginfo_t *info, void *ctx) {
    (void) info; (void) ctx;
    trace_push(4);
    if (depth++ == 0) {
        raise(sig);
    }
    trace_push(5);
}

static int trace_value(void) {
    int v = 0;
    for (int i = 0; i < trace_len; i++) {
        v = v * 10 + trace[i];
    }
    return v;
}

static void test_nesting(void) {
    install(SIGUSR1, usr1_raises_usr2, 0, 0);
    install(SIGUSR2, usr2_trace, 0, 0);
    trace_len = 0;
    raise(SIGUSR1);
    CHECK(trace_value() == 132, "E1: other signal inside a handler nests: %d", trace_value());

    install(SIGUSR1, usr1_raises_usr1, 0, 0);
    trace_len = 0;
    depth = 0;
    raise(SIGUSR1);
    CHECK(trace_value() == 4545, "E2: same signal stays pending until the handler returns: %d", trace_value());

    install(SIGUSR1, usr1_raises_usr1, SA_NODEFER, 0);
    trace_len = 0;
    depth = 0;
    raise(SIGUSR1);
    CHECK(trace_value() == 4455, "E3: SA_NODEFER nests the same signal: %d", trace_value());
}

/* ---- flags: SA_RESETHAND, SA_ONSTACK ---- */

static volatile uintptr_t onstack_sp;

static void onstack_handler(int sig, siginfo_t *info, void *ctx) {
    (void) sig; (void) info; (void) ctx;
    __asm__ volatile("mov %0, sp" : "=r"(onstack_sp));
}

static char altstack[64 * 1024] __attribute__((aligned(16)));

static void test_flags(void) {
    install(SIGUSR1, flag_handler, SA_RESETHAND, 0);
    flag = 0;
    raise(SIGUSR1);
    struct sigaction now;
    sigaction(SIGUSR1, NULL, &now);
    CHECK(flag == 1 && now.sa_handler == SIG_DFL, "SA_RESETHAND: handled once, disposition back to SIG_DFL");

    install(SIGUSR1, flag_handler, 0, 0);
    struct sigaction query;
    sigaction(SIGUSR1, NULL, &query);
    flag = 0;
    raise(SIGUSR1);
    CHECK(query.sa_sigaction == flag_handler && flag == 1, "sigaction(sig, NULL, &old) only queries");

    stack_t ss, old;
    memset(&ss, 0, sizeof(ss));
    ss.ss_sp = altstack;
    ss.ss_size = sizeof(altstack);
    CHECK(sigaltstack(&ss, NULL) == 0, "sigaltstack set");
    install(SIGUSR2, onstack_handler, SA_ONSTACK, 0);
    onstack_sp = 0;
    raise(SIGUSR2);
    CHECK(onstack_sp > (uintptr_t) altstack && onstack_sp <= (uintptr_t) altstack + sizeof(altstack),
          "H3 SA_ONSTACK: handler sp 0x%lx inside the sigaltstack", (unsigned long) onstack_sp);
    sigaltstack(NULL, &old);
    CHECK(old.ss_sp == altstack && old.ss_size == sizeof(altstack) && old.ss_flags == 0, "sigaltstack query");
    ss.ss_flags = SS_DISABLE;
    sigaltstack(&ss, NULL);
    sigaltstack(NULL, &old);
    CHECK(old.ss_flags == SS_DISABLE, "sigaltstack disabled");
    ss.ss_flags = 0;
    ss.ss_size = 1024;
    CHECK(sigaltstack(&ss, NULL) == -1 && errno == ENOMEM, "sigaltstack below MINSIGSTKSZ: ENOMEM");
}

/* ---- H4: rt_sigqueueinfo keeps si_value / si_code; real-time signals queue ---- */

static volatile int rt_values[8];
static volatile int rt_count;

static void rt_handler(int sig, siginfo_t *info, void *ctx) {
    (void) sig; (void) ctx;
    if (rt_count < 8) {
        rt_values[rt_count++] = info->si_value.sival_int;
    }
    last_code = info->si_code;
}

static int queue_signal(int sig, int value) {
    siginfo_t info;
    memset(&info, 0, sizeof(info));
    info.si_signo = sig;
    info.si_code = SI_QUEUE;
    info.si_pid = getpid();
    info.si_uid = getuid();
    info.si_value.sival_int = value;
    return (int) syscall(__NR_rt_sigqueueinfo, getpid(), sig, &info);
}

static void test_queue(void) {
    install(SIGRTMAX, rt_handler, 0, 0);
    rt_count = 0;
    errno = 1234;
    int ret = queue_signal(SIGRTMAX, 77);
    CHECK(ret == 0 && rt_count == 1 && rt_values[0] == 77 && last_code == SI_QUEUE && errno == 1234,
          "H4 rt_sigqueueinfo: si_value=%d si_code=%d ret=%d, errno untouched", rt_values[0], last_code, ret);

    block(SIGRTMAX);
    rt_count = 0;
    queue_signal(SIGRTMAX, 1);
    queue_signal(SIGRTMAX, 2);
    queue_signal(SIGRTMAX, 3);
    unblock(SIGRTMAX);
    CHECK(rt_count == 3 && rt_values[0] == 1 && rt_values[1] == 2 && rt_values[2] == 3,
          "real-time signals queue in order: %d [%d %d %d]", rt_count, rt_values[0], rt_values[1], rt_values[2]);

    /* setting SIG_IGN discards a pending signal */
    block(SIGUSR2);
    raise(SIGUSR2);
    signal(SIGUSR2, SIG_IGN);
    sigset_t pending;
    sigpending(&pending);
    CHECK(!sigismember(&pending, SIGUSR2), "SIG_IGN discards the pending signal");
    unblock(SIGUSR2);
}

/* ---- waiting: sigsuspend, sigtimedwait ---- */

static void test_wait(void) {
    install(SIGUSR1, flag_handler, 0, 0);
    block(SIGUSR1);
    raise(SIGUSR1);
    sigset_t none;
    sigemptyset(&none);
    flag = 0;
    int ret = sigsuspend(&none);
    CHECK(ret == -1 && errno == EINTR && flag == 1 && is_blocked(SIGUSR1),
          "sigsuspend: handler ran, -1/EINTR, original mask back (ret=%d errno=%d)", ret, errno);
    unblock(SIGUSR1);

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    block(SIGUSR2);
    raise(SIGUSR2);
    siginfo_t info;
    memset(&info, 0, sizeof(info));
    /* sigwaitinfo/sigtimedwait are API 23+ in bionic: use the system call they wrap */
    int sig = (int) syscall(__NR_rt_sigtimedwait, &set, &info, NULL, sizeof(set));
    sigset_t pending;
    sigpending(&pending);
    CHECK(sig == SIGUSR2 && info.si_signo == SIGUSR2 && info.si_code == SI_TKILL && !sigismember(&pending, SIGUSR2),
          "rt_sigtimedwait takes the pending signal: %d code=%d", sig, info.si_code);
    struct timespec zero = {0, 0};
    CHECK(syscall(__NR_rt_sigtimedwait, &set, &info, &zero, sizeof(set)) == -1 && errno == EAGAIN,
          "rt_sigtimedwait with nothing pending: EAGAIN");
    unblock(SIGUSR2);
}

/* ---- the frame: the handler sees and edits the interrupted registers ---- */

static volatile uint64_t seen_x19;

static void edit_regs_handler(int sig, siginfo_t *info, void *ctx) {
    (void) sig; (void) info;
    ucontext_t *uc = (ucontext_t *) ctx;
    seen_x19 = uc->uc_mcontext.regs[19];
    uc->uc_mcontext.regs[19] = 0x1919;
    uc->uc_mcontext.pc += 4;
}

/* x19 = 0x77, then an EL1 register read that faults; the handler edits x19 and skips the instruction */
__attribute__((naked, noinline)) static uint64_t fault_and_read_x19(void) {
    __asm__ volatile(
            "stp x19, x30, [sp, #-16]!\n"
            "mov x19, #0x77\n"
            ".inst 0xd538d089\n" /* mrs x9, tpidr_el1 */
            "mov x0, x19\n"
            "ldp x19, x30, [sp], #16\n"
            "ret");
}

static void test_frame(void) {
    install(SIGILL, edit_regs_handler, 0, 0);
    uint64_t x19 = fault_and_read_x19();
    CHECK(seen_x19 == 0x77 && x19 == 0x1919, "uc_mcontext holds the interrupted registers (x19=0x%llx) and rt_sigreturn applies edits (x19=0x%llx)",
          (unsigned long long) seen_x19, (unsigned long long) x19);
}

/* ---- details: tkill arguments, sigaltstack flags, the frame's sve_context ---- */

#ifndef SS_AUTODISARM
#define SS_AUTODISARM (1U << 31)
#endif
#ifndef HWCAP_SVE
#define HWCAP_SVE (1 << 22)
#endif
#define SVE_MAGIC_VALUE 0x53564501

static volatile int handler_ss_flags, handler_ss_set_ret, sve_record_found;

static void autodisarm_handler(int sig, siginfo_t *info, void *ctx) {
    (void) sig; (void) info; (void) ctx;
    stack_t cur, other;
    sigaltstack(NULL, &cur);
    handler_ss_flags = cur.ss_flags;
    memset(&other, 0, sizeof(other));
    other.ss_flags = SS_DISABLE;
    handler_ss_set_ret = sigaltstack(&other, NULL); /* allowed: the stack was disarmed on entry */
}

static void sve_record_handler(int sig, siginfo_t *info, void *ctx) {
    (void) sig; (void) info;
    ucontext_t *uc = (ucontext_t *) ctx;
    unsigned char *p = (unsigned char *) uc->uc_mcontext.__reserved;
    sve_record_found = 0;
    for (int off = 0; off + 8 <= (int) sizeof(uc->uc_mcontext.__reserved);) {
        uint32_t magic = *(uint32_t *) (p + off), size = *(uint32_t *) (p + off + 4);
        if (magic == 0 || size == 0) {
            break;
        }
        if (magic == SVE_MAGIC_VALUE) {
            sve_record_found = 1;
        }
        off += size;
    }
}

static void test_details(void) {
    errno = 0;
    CHECK(syscall(__NR_tkill, 0, SIGUSR1) == -1 && errno == EINVAL, "tkill(0, sig): EINVAL (errno %d)", errno);

    stack_t ss, old;
    memset(&ss, 0, sizeof(ss));
    ss.ss_sp = altstack;
    ss.ss_size = sizeof(altstack);
    ss.ss_flags = SS_ONSTACK;
    CHECK(sigaltstack(&ss, NULL) == 0, "sigaltstack accepts ss_flags = SS_ONSTACK");
    install(SIGUSR2, onstack_handler, SA_ONSTACK, 0);
    onstack_sp = 0;
    raise(SIGUSR2);
    CHECK(onstack_sp > (uintptr_t) altstack && onstack_sp <= (uintptr_t) altstack + sizeof(altstack), "SA_ONSTACK uses it");

    ss.ss_flags = SS_AUTODISARM;
    sigaltstack(&ss, NULL);
    install(SIGUSR2, autodisarm_handler, SA_ONSTACK, 0);
    raise(SIGUSR2);
    sigaltstack(NULL, &old);
    CHECK((handler_ss_flags & SS_DISABLE) && handler_ss_set_ret == 0 && old.ss_sp == altstack && !(old.ss_flags & SS_DISABLE),
          "SS_AUTODISARM: disarmed in the handler (flags 0x%x, sigaltstack %d), restored by rt_sigreturn", handler_ss_flags, handler_ss_set_ret);
    ss.ss_flags = SS_DISABLE;
    sigaltstack(&ss, NULL);

    install(SIGUSR1, sve_record_handler, 0, 0);
    raise(SIGUSR1);
    int sve = (getauxval(AT_HWCAP) & HWCAP_SVE) != 0;
    CHECK(sve_record_found == sve, "frame has an sve_context record exactly when HWCAP_SVE is set (sve=%d, record=%d)", sve, sve_record_found);
}

int sig_run_all(void) {
    failures = 0;
    checks = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    reset_handlers();
    test_self_delivery();
    test_block_unblock();
    test_nesting();
    test_flags();
    test_queue();
    test_wait();
    test_frame();
    test_details();
    reset_handlers();
    printf("%d/%d checks failed\n", failures, checks);
    return failures;
}

/* ---- threads ---- */

static volatile pid_t worker_tid;
static volatile int worker_ready, worker_stop, worker_got, worker_got_on;
static volatile int sleep_ret, sleep_errno;
static volatile long sleep_rem_ns;

static void thread_handler(int sig, siginfo_t *info, void *ctx) {
    (void) sig; (void) info; (void) ctx;
    worker_got++;
    worker_got_on = gettid();
}

static void *worker(void *arg) {
    (void) arg;
    worker_tid = gettid();
    worker_ready = 1;
    while (!worker_stop) {
        sched_yield();
    }
    return NULL;
}

static void *sleeper(void *arg) {
    (void) arg;
    worker_tid = gettid();
    worker_ready = 1;
    struct timespec req = {5, 0}, rem = {0, 0};
    sleep_ret = nanosleep(&req, &rem);
    sleep_errno = errno;
    sleep_rem_ns = rem.tv_sec * 1000000000L + rem.tv_nsec;
    return NULL;
}

static volatile int inherited_blocked;

static void *process_sender(void *arg) {
    (void) arg;
    kill(getpid(), SIGUSR1);
    worker_ready = 1;
    return NULL;
}

static volatile int coalesce_sent;

static void *coalesce_worker(void *arg) {
    (void) arg;
    block(SIGUSR1);
    worker_tid = gettid();
    worker_ready = 1;
    while (!coalesce_sent) {
        sched_yield();
    }
    unblock(SIGUSR1);
    return NULL;
}

static pthread_mutex_t cond_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static volatile int cond_go;

static void *cond_waiter(void *arg) {
    (void) arg;
    pthread_mutex_lock(&cond_lock);
    worker_tid = gettid();
    worker_ready = 1;
    while (!cond_go) {
        pthread_cond_wait(&cond, &cond_lock);
    }
    pthread_mutex_unlock(&cond_lock);
    return NULL;
}

static volatile int poll_got, poll_rounds;

static void *timed_poller(void *arg) {
    (void) arg;
    block(SIGUSR2);
    worker_tid = gettid();
    worker_ready = 1;
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    struct timespec ts = {0, 10 * 1000 * 1000};
    for (poll_rounds = 0; poll_rounds < 1000; poll_rounds++) {
        if (syscall(__NR_rt_sigtimedwait, &set, NULL, &ts, sizeof(set)) == SIGUSR2) {
            poll_got = 1;
            break;
        }
    }
    return NULL;
}

static void *mask_reporter(void *arg) {
    (void) arg;
    inherited_blocked = is_blocked(SIGUSR2);
    return NULL;
}

int sig_run_threads(void) {
    failures = 0;
    checks = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    reset_handlers();
    install(SIGUSR1, thread_handler, 0, 0);

    pthread_t t;
    worker_ready = worker_stop = worker_got = 0;
    pthread_create(&t, NULL, worker, NULL);
    while (!worker_ready) {
        sched_yield();
    }
    pthread_kill(t, SIGUSR1);
    for (int i = 0; i < 1000 && !worker_got; i++) {
        sched_yield();
    }
    CHECK(worker_got == 1 && worker_got_on == worker_tid, "pthread_kill(other): handler ran on that thread (tid %d, got %d)", worker_got_on, worker_got);

    /* process-directed while the main thread blocks it: another thread takes it */
    worker_got = 0;
    block(SIGUSR1);
    kill(getpid(), SIGUSR1);
    for (int i = 0; i < 1000 && !worker_got; i++) {
        sched_yield();
    }
    CHECK(worker_got == 1 && worker_got_on == worker_tid, "kill(getpid()) with SIGUSR1 blocked in main: delivered to the worker");
    unblock(SIGUSR1);
    worker_stop = 1;
    pthread_join(t, NULL);

    /* nanosleep interrupted by a signal: -1/EINTR, rem written */
    worker_ready = 0;
    pthread_create(&t, NULL, sleeper, NULL);
    while (!worker_ready) {
        sched_yield();
    }
    sched_yield();
    pthread_kill(t, SIGUSR1);
    pthread_join(t, NULL);
    CHECK(sleep_ret == -1 && sleep_errno == EINTR && sleep_rem_ns > 0, "nanosleep interrupted: ret=%d errno=%d rem=%ldns",
          sleep_ret, sleep_errno, sleep_rem_ns);

    /* process-directed with nobody blocking it: the main thread takes it (complete_signal) */
    worker_got = 0;
    worker_ready = 0;
    pthread_create(&t, NULL, process_sender, NULL);
    for (int i = 0; i < 100000 && !worker_got; i++) {
        sched_yield();
    }
    pthread_join(t, NULL);
    CHECK(worker_got == 1 && worker_got_on == getpid(), "kill(getpid()) from a worker: handled by the main thread (tid %d)", worker_got_on);

    /* a standard signal sent twice while blocked by its target is delivered once */
    worker_got = 0;
    worker_ready = 0;
    coalesce_sent = 0;
    pthread_create(&t, NULL, coalesce_worker, NULL);
    while (!worker_ready) {
        sched_yield();
    }
    pthread_kill(t, SIGUSR1);
    pthread_kill(t, SIGUSR1);
    coalesce_sent = 1;
    pthread_join(t, NULL);
    CHECK(worker_got == 1, "two pthread_kill of a blocked standard signal: one delivery (%d)", worker_got);

    /* a thread waiting on a condition variable (futex) runs the handler when signalled, then waits on */
    worker_got = 0;
    worker_ready = 0;
    cond_go = 0;
    pthread_create(&t, NULL, cond_waiter, NULL);
    while (!worker_ready) {
        sched_yield();
    }
    pthread_mutex_lock(&cond_lock); /* the waiter is inside pthread_cond_wait */
    pthread_mutex_unlock(&cond_lock);
    pthread_kill(t, SIGUSR1);
    int spins = 0;
    while (!worker_got && spins < 100000) {
        sched_yield();
        spins++;
    }
    int got_while_waiting = worker_got;
    pthread_mutex_lock(&cond_lock);
    cond_go = 1;
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&cond_lock);
    pthread_join(t, NULL);
    CHECK(got_while_waiting == 1 && worker_got_on == worker_tid, "signal to a thread in pthread_cond_wait: handler ran while it waited");

    /* a worker polling with a timed sigtimedwait lets the sender run */
    worker_ready = 0;
    poll_got = 0;
    pthread_create(&t, NULL, timed_poller, NULL);
    while (!worker_ready) {
        sched_yield();
    }
    pthread_kill(t, SIGUSR2);
    pthread_join(t, NULL);
    CHECK(poll_got == 1, "timed sigtimedwait in a loop receives the signal another thread sends (after %d rounds)", poll_rounds);

    /* H5: a new thread inherits the creator's mask */
    block(SIGUSR2);
    pthread_create(&t, NULL, mask_reporter, NULL);
    pthread_join(t, NULL);
    CHECK(inherited_blocked, "H5: new thread inherits the blocked mask");
    unblock(SIGUSR2);

    reset_handlers();
    printf("%d/%d thread checks failed\n", failures, checks);
    return failures;
}

/* ---- stress: many signals, nested and queued, then the stack and mask must be exactly as before ---- */

static volatile long stress_count;

static void stress_handler(int sig, siginfo_t *info, void *ctx) {
    (void) info; (void) ctx;
    stress_count++;
    if (sig == SIGUSR1 && (stress_count & 7) == 0) {
        raise(SIGUSR2);
    }
}

int sig_stress(int rounds) {
    failures = 0;
    checks = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    reset_handlers();
    install(SIGUSR1, stress_handler, 0, 0);
    install(SIGUSR2, stress_handler, 0, 0);
    install(SIGRTMAX, stress_handler, 0, 0);
    uintptr_t sp_before;
    __asm__ volatile("mov %0, sp" : "=r"(sp_before));
    stress_count = 0;
    long expected = 0;
    for (int i = 0; i < rounds; i++) {
        raise(SIGUSR1);
        expected++;
        if ((expected & 7) == 0) {
            expected++; /* the nested SIGUSR2 */
        }
        if ((i & 15) == 0) {
            block(SIGRTMAX);
            queue_signal(SIGRTMAX, i);
            queue_signal(SIGRTMAX, i + 1);
            unblock(SIGRTMAX);
            expected += 2;
        }
    }
    uintptr_t sp_after;
    __asm__ volatile("mov %0, sp" : "=r"(sp_after));
    sigset_t cur;
    sigprocmask(SIG_BLOCK, NULL, &cur);
    int clean = !sigismember(&cur, SIGUSR1) && !sigismember(&cur, SIGUSR2) && !sigismember(&cur, SIGRTMAX);
    CHECK(stress_count == expected && sp_before == sp_after && clean,
          "stress %d rounds: %ld handlers (expected %ld), stack and mask unchanged", rounds, stress_count, expected);
    reset_handlers();
    return failures;
}

int sig_kill_default(void) {
    reset_handlers();
    raise(SIGTERM);
    return 1234;
}

static void raise_sigterm_handler(int sig, siginfo_t *info, void *ctx) {
    (void) sig; (void) info; (void) ctx;
    raise(SIGTERM); /* blocked by sa_mask: pending until this handler returns */
}

int sig_kill_after_sigreturn(void) {
    reset_handlers();
    install(SIGUSR1, raise_sigterm_handler, 0, SIGTERM);
    raise(SIGUSR1);
    return 1234;
}
