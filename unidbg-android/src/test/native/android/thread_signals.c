/*
 * Threads and signals together, the way apps combine them. Every expectation is a Linux rule, so the library behaves
 * the same on a real arm64 Android device.
 *
 * ts_signal_test(i)  signal delivery between threads, test i (needs the thread dispatcher); returns the failed checks,
 *                    -1 past the last test
 * ts_thread_test(i)  plain threading, test i: create/join, mutex, condvar, rwlock, semaphore, once, TLS, keys, detach,
 *                    errno, nesting, stack size, sleeping, identity; -1 past the last test
 * ts_sequential_threads(n)  n threads created and joined one after another in one call; returns how many completed
 * ts_run_spin()      a thread spinning on a flag another thread sets, without any syscall in the loop
 * Each test runs in its own call (unidbg frees the stacks of finished threads only when the call returns).
 */
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
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

#define WAIT_UNTIL(cond) do { for (int _i = 0; _i < 200000 && !(cond); _i++) sched_yield(); } while (0)

static void block(int sig) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, sig);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
}

static void unblock(int sig) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, sig);
    pthread_sigmask(SIG_UNBLOCK, &set, NULL);
}

static void install(int sig, void (*fn)(int, siginfo_t *, void *)) {
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    sigemptyset(&act.sa_mask);
    act.sa_sigaction = fn;
    act.sa_flags = SA_SIGINFO;
    sigaction(sig, &act, NULL);
}

/* ======================================================================== signals between threads */

#define WORKERS 4

static volatile int handled_count;
static volatile pid_t handled_on[64];
static volatile int stop_workers;

static void record_handler(int sig, siginfo_t *info, void *ctx) {
    (void) sig; (void) ctx;
    int n = __atomic_fetch_add(&handled_count, 1, __ATOMIC_SEQ_CST);
    if (n < 64) {
        handled_on[n] = gettid();
    }
    (void) info;
}

static volatile pid_t worker_tids[WORKERS];
static volatile int workers_ready;

static void *idle_worker(void *arg) {
    int index = (int) (intptr_t) arg;
    worker_tids[index] = gettid();
    __atomic_fetch_add(&workers_ready, 1, __ATOMIC_SEQ_CST);
    while (!stop_workers) {
        sched_yield();
    }
    return NULL;
}

static void start_workers(pthread_t *threads, int n) {
    workers_ready = 0;
    stop_workers = 0;
    for (int i = 0; i < n; i++) {
        pthread_create(&threads[i], NULL, idle_worker, (void *) (intptr_t) i);
    }
    WAIT_UNTIL(workers_ready == n);
}

static void stop_and_join(pthread_t *threads, int n) {
    stop_workers = 1;
    for (int i = 0; i < n; i++) {
        pthread_join(threads[i], NULL);
    }
}

/* S1: one signal to each worker: every handler runs on its own thread */
static void test_each_worker(void) {
    pthread_t threads[WORKERS];
    install(SIGUSR1, record_handler);
    handled_count = 0;
    start_workers(threads, WORKERS);
    for (int i = 0; i < WORKERS; i++) {
        pthread_kill(threads[i], SIGUSR1);
    }
    WAIT_UNTIL(handled_count == WORKERS);
    int matched = 0;
    for (int i = 0; i < WORKERS; i++) {
        for (int j = 0; j < handled_count && j < 64; j++) {
            if (handled_on[j] == worker_tids[i]) {
                matched++;
                break;
            }
        }
    }
    stop_and_join(threads, WORKERS);
    CHECK(handled_count == WORKERS && matched == WORKERS, "S1: pthread_kill to %d workers: each handled once on its own thread (%d handled, %d matched)",
          WORKERS, handled_count, matched);
}

/* S2: a process-directed signal is delivered once, to one thread that does not block it */
static void test_process_once(void) {
    pthread_t threads[3];
    install(SIGUSR1, record_handler);
    handled_count = 0;
    start_workers(threads, 3); /* before blocking: a new thread inherits the creator's mask */
    block(SIGUSR1); /* the main thread blocks it: one of the workers takes it */
    kill(getpid(), SIGUSR1);
    WAIT_UNTIL(handled_count > 0);
    for (int i = 0; i < 100; i++) {
        sched_yield();
    }
    int on_worker = 0;
    for (int i = 0; i < 3; i++) {
        on_worker |= handled_count > 0 && handled_on[0] == worker_tids[i];
    }
    stop_and_join(threads, 3);
    unblock(SIGUSR1);
    CHECK(handled_count == 1 && on_worker, "S2: kill(getpid()) with 3 workers and main blocking: delivered exactly once, to a worker (%d)", handled_count);
}

/* S3: a thread waiting in pthread_join runs its handler, then the join completes */
static volatile pid_t main_tid;
static volatile int joiner_handled;

static void joiner_handler(int sig, siginfo_t *info, void *ctx) {
    (void) sig; (void) info; (void) ctx;
    joiner_handled = gettid() == main_tid;
}

static void *signal_main_then_exit(void *arg) {
    (void) arg;
    for (int i = 0; i < 50; i++) {
        sched_yield(); /* let the main thread reach pthread_join */
    }
    syscall(__NR_tgkill, getpid(), main_tid, SIGUSR1);
    for (int i = 0; i < 1000 && !joiner_handled; i++) {
        sched_yield();
    }
    return (void *) 77;
}

static void test_join_interrupted(void) {
    install(SIGUSR1, joiner_handler);
    main_tid = gettid();
    joiner_handled = 0;
    pthread_t t;
    pthread_create(&t, NULL, signal_main_then_exit, NULL);
    void *ret = NULL;
    int r = pthread_join(t, &ret);
    CHECK(r == 0 && ret == (void *) 77 && joiner_handled, "S3: signal to the main thread inside pthread_join: handler ran on main, join returned 77 (%ld)", (long) ret);
}

/* S4: a thread waiting for a contended mutex runs its handler, then gets the mutex */
static pthread_mutex_t contended = PTHREAD_MUTEX_INITIALIZER;
static volatile int locker_started, locker_got, locker_handled;
static volatile pid_t locker_tid;

static void locker_handler(int sig, siginfo_t *info, void *ctx) {
    (void) sig; (void) info; (void) ctx;
    locker_handled = gettid() == locker_tid;
}

static void *locker(void *arg) {
    (void) arg;
    locker_tid = gettid();
    locker_started = 1;
    pthread_mutex_lock(&contended);
    locker_got = 1;
    pthread_mutex_unlock(&contended);
    return NULL;
}

static void test_mutex_interrupted(void) {
    install(SIGUSR1, locker_handler);
    locker_started = locker_got = locker_handled = 0;
    pthread_mutex_lock(&contended);
    pthread_t t;
    pthread_create(&t, NULL, locker, NULL);
    WAIT_UNTIL(locker_started);
    for (int i = 0; i < 20; i++) {
        sched_yield(); /* the locker is now waiting on the mutex */
    }
    pthread_kill(t, SIGUSR1);
    WAIT_UNTIL(locker_handled);
    int handled_while_waiting = locker_handled && !locker_got;
    pthread_mutex_unlock(&contended);
    pthread_join(t, NULL);
    CHECK(handled_while_waiting && locker_got, "S4: signal to a thread waiting for a mutex: handler ran while it waited, then it got the mutex");
}

/* S5: sigsuspend in a worker ends when another thread signals it */
static volatile int suspend_ret, suspend_errno, suspend_handled, suspend_ready;

static void suspend_handler(int sig, siginfo_t *info, void *ctx) {
    (void) sig; (void) info; (void) ctx;
    suspend_handled = 1;
}

static void *suspender(void *arg) {
    (void) arg;
    block(SIGUSR1);
    sigset_t none;
    sigemptyset(&none);
    suspend_ready = 1;
    suspend_ret = sigsuspend(&none);
    suspend_errno = errno;
    return NULL;
}

static void test_sigsuspend_thread(void) {
    install(SIGUSR1, suspend_handler);
    suspend_ready = suspend_handled = 0;
    pthread_t t;
    pthread_create(&t, NULL, suspender, NULL);
    WAIT_UNTIL(suspend_ready);
    sched_yield();
    pthread_kill(t, SIGUSR1);
    pthread_join(t, NULL);
    CHECK(suspend_ret == -1 && suspend_errno == EINTR && suspend_handled, "S5: sigsuspend in a worker woken by pthread_kill: handler ran, -1/EINTR");
}

/* S6/S7: sigwait for a thread-directed and a process-directed signal */
static volatile int waited_sig, wait_ready, wait_handler_ran;

static void wait_handler(int sig, siginfo_t *info, void *ctx) {
    (void) sig; (void) info; (void) ctx;
    wait_handler_ran = 1;
}

static void *waiter(void *arg) {
    (void) arg;
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    int sig = 0;
    wait_ready = 1;
    sigwait(&set, &sig);
    waited_sig = sig;
    return NULL;
}

static void test_sigwait(void) {
    install(SIGUSR2, wait_handler);
    block(SIGUSR2); /* inherited by the waiter */
    pthread_t t;
    waited_sig = wait_ready = wait_handler_ran = 0;
    pthread_create(&t, NULL, waiter, NULL);
    WAIT_UNTIL(wait_ready);
    sched_yield();
    pthread_kill(t, SIGUSR2);
    pthread_join(t, NULL);
    CHECK(waited_sig == SIGUSR2 && !wait_handler_ran, "S6: sigwait in a worker receives pthread_kill(SIGUSR2), no handler runs (%d)", waited_sig);

    waited_sig = wait_ready = wait_handler_ran = 0;
    pthread_create(&t, NULL, waiter, NULL);
    WAIT_UNTIL(wait_ready);
    sched_yield();
    kill(getpid(), SIGUSR2); /* every thread blocks it: the one waiting for it takes it */
    pthread_join(t, NULL);
    CHECK(waited_sig == SIGUSR2 && !wait_handler_ran, "S7: sigwait in a worker receives kill(getpid(), SIGUSR2) (%d)", waited_sig);
    unblock(SIGUSR2);
}

/* S8: 50 real-time signals queued to a worker that blocks them arrive in order with their values */
#define RT_COUNT 50
static volatile int rt_values[RT_COUNT], rt_received, rt_ready, rt_release;
static volatile pid_t rt_tid;

static void rt_handler(int sig, siginfo_t *info, void *ctx) {
    (void) sig; (void) ctx;
    if (rt_received < RT_COUNT) {
        rt_values[rt_received] = info->si_value.sival_int;
    }
    rt_received++;
}

static void *rt_receiver(void *arg) {
    (void) arg;
    block(SIGRTMIN + 1);
    rt_tid = gettid();
    rt_ready = 1;
    while (!rt_release) {
        sched_yield();
    }
    unblock(SIGRTMIN + 1);
    return NULL;
}

static void test_rt_queue_to_thread(void) {
    install(SIGRTMIN + 1, rt_handler);
    rt_received = rt_ready = rt_release = 0;
    pthread_t t;
    pthread_create(&t, NULL, rt_receiver, NULL);
    WAIT_UNTIL(rt_ready);
    for (int i = 0; i < RT_COUNT; i++) {
        siginfo_t info;
        memset(&info, 0, sizeof(info));
        info.si_signo = SIGRTMIN + 1;
        info.si_code = SI_QUEUE;
        info.si_pid = getpid();
        info.si_value.sival_int = i;
        syscall(__NR_rt_tgsigqueueinfo, getpid(), rt_tid, SIGRTMIN + 1, &info);
    }
    rt_release = 1;
    pthread_join(t, NULL);
    int ordered = rt_received == RT_COUNT;
    for (int i = 0; ordered && i < RT_COUNT; i++) {
        ordered = rt_values[i] == i;
    }
    CHECK(ordered, "S8: %d real-time signals queued to a blocking worker: all delivered in order after it unblocks (%d)", RT_COUNT, rt_received);
}

/* S9: per-thread masks: a signal for the main thread waits while main blocks it, the worker does not take it */
static volatile int s9_on_main;

static void s9_handler(int sig, siginfo_t *info, void *ctx) {
    (void) sig; (void) info; (void) ctx;
    s9_on_main = gettid() == main_tid ? 1 : -1;
}

static void *send_to_main(void *arg) {
    (void) arg;
    syscall(__NR_tgkill, getpid(), main_tid, SIGUSR1);
    return NULL;
}

static void test_per_thread_mask(void) {
    install(SIGUSR1, s9_handler);
    main_tid = gettid();
    s9_on_main = 0;
    block(SIGUSR1);
    pthread_t t;
    pthread_create(&t, NULL, send_to_main, NULL);
    pthread_join(t, NULL);
    int pending_while_blocked = s9_on_main == 0;
    unblock(SIGUSR1);
    CHECK(pending_while_blocked && s9_on_main == 1, "S9: tgkill(main) while main blocks it: pending, then handled on main when unblocked");
}

/* S10: raise() in a worker runs the handler on that worker */
static volatile pid_t raise_tid, raise_handled_on;

static void raise_handler(int sig, siginfo_t *info, void *ctx) {
    (void) sig; (void) info; (void) ctx;
    raise_handled_on = gettid();
}

static void *raiser(void *arg) {
    (void) arg;
    raise_tid = gettid();
    raise(SIGUSR1);
    return NULL;
}

static void test_raise_in_worker(void) {
    install(SIGUSR1, raise_handler);
    raise_handled_on = 0;
    pthread_t t;
    pthread_create(&t, NULL, raiser, NULL);
    pthread_join(t, NULL);
    CHECK(raise_handled_on == raise_tid && raise_tid != gettid(), "S10: raise() in a worker: handled on the worker");
}

/* S11: two threads inside their handlers at the same time, each with its own frame and mask */
static volatile int main_in, worker_in, both_seen_main, both_seen_worker;
static volatile pid_t overlap_worker_tid;

static void overlap_handler(int sig, siginfo_t *info, void *ctx) {
    (void) sig; (void) info; (void) ctx;
    if (gettid() == main_tid) {
        main_in = 1;
        for (int i = 0; i < 100000 && !worker_in; i++) sched_yield();
        both_seen_main = worker_in;
    } else {
        worker_in = 1;
        for (int i = 0; i < 100000 && !main_in; i++) sched_yield();
        both_seen_worker = main_in;
    }
}

static void *overlap_worker(void *arg) {
    (void) arg;
    overlap_worker_tid = gettid();
    while (!worker_in) {
        sched_yield();
    }
    return NULL;
}

static void test_overlapping_handlers(void) {
    install(SIGUSR1, overlap_handler);
    main_tid = gettid();
    main_in = worker_in = both_seen_main = both_seen_worker = 0;
    pthread_t t;
    pthread_create(&t, NULL, overlap_worker, NULL);
    WAIT_UNTIL(overlap_worker_tid != 0);
    pthread_kill(t, SIGUSR1);
    raise(SIGUSR1);
    pthread_join(t, NULL);
    CHECK(both_seen_main && both_seen_worker, "S11: handlers running on two threads at the same time");
}

/* S12: a worker exits with a signal still pending: nothing breaks */
static void *exit_with_pending(void *arg) {
    (void) arg;
    block(SIGUSR1);
    raise(SIGUSR1); /* pending, never delivered */
    return (void *) 5;
}

static void test_exit_with_pending(void) {
    install(SIGUSR1, record_handler);
    handled_count = 0;
    pthread_t t;
    pthread_create(&t, NULL, exit_with_pending, NULL);
    void *ret = NULL;
    pthread_join(t, &ret);
    raise(SIGUSR1); /* the main thread still works */
    CHECK(ret == (void *) 5 && handled_count == 1 && handled_on[0] == gettid(), "S12: a worker exiting with a pending signal: discarded with it, main unaffected");
}

/* S13: pthread_cond_timedwait interrupted by a signal, then signalled */
static pthread_mutex_t tw_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t tw_cond = PTHREAD_COND_INITIALIZER;
static volatile int tw_go, tw_ready, tw_handled, tw_result = -1;

static void tw_handler(int sig, siginfo_t *info, void *ctx) {
    (void) sig; (void) info; (void) ctx;
    tw_handled = 1;
}

static void *timed_waiter(void *arg) {
    (void) arg;
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 30;
    pthread_mutex_lock(&tw_lock);
    tw_ready = 1;
    int r = 0;
    while (!tw_go && r == 0) {
        r = pthread_cond_timedwait(&tw_cond, &tw_lock, &deadline);
    }
    tw_result = r;
    pthread_mutex_unlock(&tw_lock);
    return NULL;
}

static void test_timedwait_interrupted(void) {
    install(SIGUSR1, tw_handler);
    tw_go = tw_ready = tw_handled = 0;
    pthread_t t;
    pthread_create(&t, NULL, timed_waiter, NULL);
    WAIT_UNTIL(tw_ready);
    pthread_mutex_lock(&tw_lock);
    pthread_mutex_unlock(&tw_lock);
    pthread_kill(t, SIGUSR1);
    WAIT_UNTIL(tw_handled);
    pthread_mutex_lock(&tw_lock);
    tw_go = 1;
    pthread_cond_signal(&tw_cond);
    pthread_mutex_unlock(&tw_lock);
    pthread_join(t, NULL);
    CHECK(tw_handled && tw_result == 0, "S13: pthread_cond_timedwait: handler ran during the wait, then the signal woke it (result %d)", tw_result);
}

static void (*const signal_tests[])(void) = {
        test_each_worker, test_process_once, test_join_interrupted, test_mutex_interrupted, test_sigsuspend_thread,
        test_sigwait, test_rt_queue_to_thread, test_per_thread_mask, test_raise_in_worker, test_overlapping_handlers,
        test_exit_with_pending, test_timedwait_interrupted,
};

int ts_signal_test(int index) {
    if (index < 0 || index >= (int) (sizeof(signal_tests) / sizeof(signal_tests[0]))) {
        return -1;
    }
    failures = 0;
    checks = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    signal_tests[index]();
    signal(SIGUSR1, SIG_DFL);
    signal(SIGUSR2, SIG_DFL);
    signal(SIGRTMIN + 1, SIG_DFL);
    return failures;
}

/* ======================================================================== plain threading */

static void *return_index(void *arg) {
    return arg;
}

static void test_create_join(void) {
    pthread_t t[12];
    for (int i = 0; i < 12; i++) {
        pthread_create(&t[i], NULL, return_index, (void *) (intptr_t) (i + 100));
    }
    int ok = 1;
    for (int i = 0; i < 12; i++) {
        void *ret = NULL;
        ok &= pthread_join(t[i], &ret) == 0 && ret == (void *) (intptr_t) (i + 100);
    }
    CHECK(ok, "T1: 12 threads alive at once, joined, each returned its value");
}

static pthread_mutex_t counter_lock = PTHREAD_MUTEX_INITIALIZER;
static long locked_counter, atomic_counter;

static void *count_up(void *arg) {
    (void) arg;
    for (int i = 0; i < 1000; i++) {
        pthread_mutex_lock(&counter_lock);
        long v = locked_counter;
        if ((i & 63) == 0) {
            sched_yield(); /* switch while holding the lock */
        }
        locked_counter = v + 1;
        pthread_mutex_unlock(&counter_lock);
        __atomic_fetch_add(&atomic_counter, 1, __ATOMIC_SEQ_CST);
    }
    return NULL;
}

static void test_mutex_and_atomics(void) {
    pthread_t t[8];
    locked_counter = atomic_counter = 0;
    for (int i = 0; i < 8; i++) {
        pthread_create(&t[i], NULL, count_up, NULL);
    }
    for (int i = 0; i < 8; i++) {
        pthread_join(t[i], NULL);
    }
    CHECK(locked_counter == 8000 && atomic_counter == 8000, "T2: 8 threads x 1000 increments: mutex %ld, atomic %ld", locked_counter, atomic_counter);
}

#define QUEUE_ITEMS 200
static pthread_mutex_t q_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t q_not_empty = PTHREAD_COND_INITIALIZER;
static pthread_cond_t q_not_full = PTHREAD_COND_INITIALIZER;
static int q_buf[8], q_head, q_tail, q_size, q_done;
static long consumed_sum, consumed_count;

static void *producer(void *arg) {
    (void) arg;
    for (int i = 1; i <= QUEUE_ITEMS; i++) {
        pthread_mutex_lock(&q_lock);
        while (q_size == 8) {
            pthread_cond_wait(&q_not_full, &q_lock);
        }
        q_buf[q_tail] = i;
        q_tail = (q_tail + 1) & 7;
        q_size++;
        pthread_cond_signal(&q_not_empty);
        pthread_mutex_unlock(&q_lock);
    }
    pthread_mutex_lock(&q_lock);
    q_done = 1;
    pthread_cond_broadcast(&q_not_empty);
    pthread_mutex_unlock(&q_lock);
    return NULL;
}

static void *consumer(void *arg) {
    (void) arg;
    for (;;) {
        pthread_mutex_lock(&q_lock);
        while (q_size == 0 && !q_done) {
            pthread_cond_wait(&q_not_empty, &q_lock);
        }
        if (q_size == 0) {
            pthread_mutex_unlock(&q_lock);
            return NULL;
        }
        int v = q_buf[q_head];
        q_head = (q_head + 1) & 7;
        q_size--;
        consumed_sum += v;
        consumed_count++;
        pthread_cond_signal(&q_not_full);
        pthread_mutex_unlock(&q_lock);
    }
}

static void test_producer_consumer(void) {
    pthread_t p, c1, c2;
    q_head = q_tail = q_size = q_done = 0;
    consumed_sum = consumed_count = 0;
    pthread_create(&c1, NULL, consumer, NULL);
    pthread_create(&c2, NULL, consumer, NULL);
    pthread_create(&p, NULL, producer, NULL);
    pthread_join(p, NULL);
    pthread_join(c1, NULL);
    pthread_join(c2, NULL);
    CHECK(consumed_count == QUEUE_ITEMS && consumed_sum == QUEUE_ITEMS * (QUEUE_ITEMS + 1) / 2,
          "T3: condvar producer/2 consumers through an 8-slot queue: %ld items, sum %ld", consumed_count, consumed_sum);
}

static pthread_rwlock_t rw = PTHREAD_RWLOCK_INITIALIZER;
static long rw_value, rw_bad_reads;

static void *rw_writer(void *arg) {
    (void) arg;
    for (int i = 0; i < 200; i++) {
        pthread_rwlock_wrlock(&rw);
        rw_value++;
        sched_yield();
        rw_value++;
        pthread_rwlock_unlock(&rw);
    }
    return NULL;
}

static void *rw_reader(void *arg) {
    (void) arg;
    for (int i = 0; i < 200; i++) {
        pthread_rwlock_rdlock(&rw);
        if (rw_value & 1) {
            rw_bad_reads++; /* a writer was half way */
        }
        pthread_rwlock_unlock(&rw);
        sched_yield();
    }
    return NULL;
}

static void test_rwlock(void) {
    pthread_t w, r1, r2;
    rw_value = rw_bad_reads = 0;
    pthread_create(&w, NULL, rw_writer, NULL);
    pthread_create(&r1, NULL, rw_reader, NULL);
    pthread_create(&r2, NULL, rw_reader, NULL);
    pthread_join(w, NULL);
    pthread_join(r1, NULL);
    pthread_join(r2, NULL);
    CHECK(rw_value == 400 && rw_bad_reads == 0, "T4: rwlock: writer 400, readers never saw a half update (%ld)", rw_bad_reads);
}

static sem_t sem;
static volatile int sem_taken;

static void *sem_taker(void *arg) {
    (void) arg;
    for (int i = 0; i < 10; i++) {
        sem_wait(&sem);
        __atomic_fetch_add(&sem_taken, 1, __ATOMIC_SEQ_CST);
    }
    return NULL;
}

static void test_semaphore(void) {
    sem_init(&sem, 0, 0);
    sem_taken = 0;
    pthread_t t1, t2;
    pthread_create(&t1, NULL, sem_taker, NULL);
    pthread_create(&t2, NULL, sem_taker, NULL);
    for (int i = 0; i < 20; i++) {
        sem_post(&sem);
        sched_yield();
    }
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    CHECK(sem_taken == 20, "T5: semaphore: 20 posts, 20 waits satisfied across 2 threads (%d)", sem_taken);
    sem_destroy(&sem);
}

static pthread_once_t once = PTHREAD_ONCE_INIT;
static volatile int once_runs;

static void once_init(void) {
    once_runs++;
    sched_yield();
}

static void *call_once(void *arg) {
    (void) arg;
    pthread_once(&once, once_init);
    return NULL;
}

static void test_once(void) {
    pthread_t t[5];
    for (int i = 0; i < 5; i++) {
        pthread_create(&t[i], NULL, call_once, NULL);
    }
    for (int i = 0; i < 5; i++) {
        pthread_join(t[i], NULL);
    }
    CHECK(once_runs == 1, "T6: pthread_once from 5 threads ran the initializer once (%d)", once_runs);
}

static pthread_key_t key;
static volatile int destructor_calls;
static __thread int tls_value;
static volatile int tls_mismatch, key_mismatch;

static void key_destructor(void *value) {
    (void) value;
    __atomic_fetch_add(&destructor_calls, 1, __ATOMIC_SEQ_CST);
}

static void *tls_user(void *arg) {
    int id = (int) (intptr_t) arg;
    tls_value = id;
    pthread_setspecific(key, (void *) (intptr_t) (id * 10));
    for (int i = 0; i < 10; i++) {
        sched_yield();
        if (tls_value != id) {
            tls_mismatch++;
        }
        if (pthread_getspecific(key) != (void *) (intptr_t) (id * 10)) {
            key_mismatch++;
        }
    }
    return NULL;
}

static void test_tls(void) {
    pthread_key_create(&key, key_destructor);
    destructor_calls = tls_mismatch = key_mismatch = 0;
    tls_value = -1;
    pthread_t t[4];
    for (int i = 0; i < 4; i++) {
        pthread_create(&t[i], NULL, tls_user, (void *) (intptr_t) (i + 1));
    }
    for (int i = 0; i < 4; i++) {
        pthread_join(t[i], NULL);
    }
    CHECK(!tls_mismatch && !key_mismatch && tls_value == -1, "T7: __thread and pthread_getspecific values stay per thread (main still %d)", tls_value);
    CHECK(destructor_calls == 4, "T7: pthread_key destructor ran for each exiting thread (%d)", destructor_calls);
    pthread_key_delete(key);
}

static volatile int detached_done;

static void *detached_body(void *arg) {
    (void) arg;
    sched_yield();
    detached_done = 1;
    return NULL;
}

static void test_detached(void) {
    pthread_t t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    detached_done = 0;
    pthread_create(&t, &attr, detached_body, NULL);
    pthread_attr_destroy(&attr);
    WAIT_UNTIL(detached_done);
    CHECK(detached_done, "T8: a detached thread runs to completion");
}

static void *inner(void *arg) {
    return (void *) ((intptr_t) arg + 1);
}

static void *outer(void *arg) {
    pthread_t t;
    void *ret = NULL;
    pthread_create(&t, NULL, inner, arg);
    pthread_join(t, &ret);
    return ret;
}

static void test_nested_threads(void) {
    pthread_t t;
    void *ret = NULL;
    pthread_create(&t, NULL, outer, (void *) 41);
    pthread_join(t, &ret);
    CHECK(ret == (void *) 42, "T9: a thread creating and joining its own thread (%ld)", (long) ret);
}

static volatile int errno_seen_in_thread;

static void *set_errno(void *arg) {
    (void) arg;
    errno = 77;
    sched_yield();
    errno_seen_in_thread = errno;
    return NULL;
}

static void test_errno(void) {
    errno = 5;
    pthread_t t;
    pthread_create(&t, NULL, set_errno, NULL);
    pthread_join(t, NULL);
    CHECK(errno == 5 && errno_seen_in_thread == 77, "T10: errno is per thread (main %d, thread %d)", errno, errno_seen_in_thread);
}

static volatile int deep_stack_ok;

static void *use_stack(void *arg) {
    (void) arg;
    volatile char buf[32 * 1024];
    for (int i = 0; i < (int) sizeof(buf); i += 512) {
        buf[i] = (char) i;
    }
    deep_stack_ok = buf[512] == (char) 512;
    return NULL;
}

static void test_stack_size(void) {
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 128 * 1024);
    pthread_t t;
    deep_stack_ok = 0;
    pthread_create(&t, &attr, use_stack, NULL);
    pthread_join(t, NULL);
    pthread_attr_destroy(&attr);
    CHECK(deep_stack_ok, "T11: a 128 KB stack thread uses 32 KB of stack");
}

static volatile int slept;

static void *sleeper(void *arg) {
    (void) arg;
    struct timespec req = {0, 20 * 1000 * 1000};
    nanosleep(&req, NULL);
    slept = 1;
    return NULL;
}

static void test_sleep(void) {
    slept = 0;
    pthread_t t;
    pthread_create(&t, NULL, sleeper, NULL);
    int spins = 0;
    while (!slept && spins < 1000000) {
        sched_yield();
        spins++;
    }
    pthread_join(t, NULL);
    CHECK(slept, "T12: a thread in nanosleep(20 ms) wakes while main keeps running");
}

static void *ident(void *arg) {
    pid_t *out = (pid_t *) arg;
    *out = gettid();
    return (void *) pthread_self();
}

static void test_identity(void) {
    pid_t tids[3];
    pthread_t t[3];
    for (int i = 0; i < 3; i++) {
        pthread_create(&t[i], NULL, ident, &tids[i]);
    }
    int ok = 1;
    for (int i = 0; i < 3; i++) {
        void *self = NULL;
        pthread_join(t[i], &self);
        ok &= (pthread_t) self == t[i] && tids[i] != gettid();
    }
    ok &= tids[0] != tids[1] && tids[1] != tids[2] && tids[0] != tids[2];
    CHECK(ok, "T13: pthread_self matches the creator's handle, every thread has its own tid");
}

static void (*const thread_tests[])(void) = {
        test_create_join, test_mutex_and_atomics, test_producer_consumer, test_rwlock, test_semaphore, test_once,
        test_tls, test_detached, test_nested_threads, test_errno, test_stack_size, test_sleep, test_identity,
};

int ts_thread_test(int index) {
    if (index < 0 || index >= (int) (sizeof(thread_tests) / sizeof(thread_tests[0]))) {
        return -1;
    }
    failures = 0;
    checks = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    thread_tests[index]();
    return failures;
}

int ts_sequential_threads(int n) {
    int completed = 0;
    for (int i = 0; i < n; i++) {
        pthread_t t;
        void *ret = NULL;
        if (pthread_create(&t, NULL, return_index, (void *) (intptr_t) i) != 0) {
            break;
        }
        if (pthread_join(t, &ret) == 0 && ret == (void *) (intptr_t) i) {
            completed++;
        }
    }
    return completed;
}

/* a pure spin wait: on a device the scheduler preempts the spinner; a cooperative scheduler never switches */
static volatile int spin_flag;

static void *set_flag(void *arg) {
    (void) arg;
    spin_flag = 1;
    return NULL;
}

int ts_run_spin(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    spin_flag = 0;
    pthread_t t;
    pthread_create(&t, NULL, set_flag, NULL);
    long spins = 0;
    while (!spin_flag && spins < 50000000L) {
        spins++;
    }
    int seen = spin_flag;
    pthread_join(t, NULL);
    printf("%s spin wait without syscalls: flag %s after %ld iterations\n", seen ? "ok  " : "info", seen ? "seen" : "never set", spins);
    return seen ? 0 : 1;
}
