/*
 * The guest's clocks (CLAUDE.md item 3). Every expectation is a Linux rule, so the library behaves the same on a real
 * arm64 Android device, where time is one clock: CNTVCT_EL0, CLOCK_MONOTONIC and CLOCK_REALTIME agree, and a sleep
 * or a timed wait takes its time on it.
 *
 * vc_run_all()         single-thread checks; returns the failed checks
 * vc_run_threads()     waits in threads (needs the thread dispatcher); returns the failed checks
 * vc_gap(cb)           CLOCK_MONOTONIC ns across a call of cb (the host may take its time in cb)
 * vc_gap_counter(cb)   the same with CNTVCT_EL0, in ns
 * vc_mono(), vc_real() clock_gettime(CLOCK_MONOTONIC / CLOCK_REALTIME) in ns
 * vc_gettimeofday_us() gettimeofday in us
 * vc_trace()           a fixed computation read on both clocks; returns a hash of the deltas (the same run reads the
 *                      same times)
 */
#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static int failures;

#define CHECK(cond, ...) do { \
    if (cond) { printf("ok   "); } else { printf("FAIL "); failures++; } \
    printf(__VA_ARGS__); \
    printf("\n"); \
} while (0)

#define MS 1000000LL

static int64_t clock_ns(clockid_t id) {
    struct timespec ts;
    clock_gettime(id, &ts);
    return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

int64_t vc_mono(void) {
    return clock_ns(CLOCK_MONOTONIC);
}

int64_t vc_real(void) {
    return clock_ns(CLOCK_REALTIME);
}

int64_t vc_gettimeofday_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000LL + tv.tv_usec;
}

static inline uint64_t counter(void) {
    uint64_t v;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(v));
    return v;
}

static inline uint64_t frequency(void) {
    uint64_t v;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(v));
    return v;
}

static int64_t counter_ns(uint64_t ticks) {
    uint64_t f = frequency();
    return (int64_t) (ticks / f * 1000000000ULL + ticks % f * 1000000000ULL / f);
}

int64_t vc_gap(void (*cb)(void)) {
    int64_t t0 = vc_mono();
    cb();
    return vc_mono() - t0;
}

int64_t vc_gap_counter(void (*cb)(void)) {
    uint64_t c0 = counter();
    cb();
    return counter_ns(counter() - c0);
}

static volatile uint64_t sink;

static void work(int n) {
    for (int i = 0; i < n; i++) {
        sink += (uint64_t) i * 2654435761u;
    }
}

int64_t vc_trace(void) {
    int64_t m0 = vc_mono();
    uint64_t c0 = counter();
    uint64_t hash = 1469598103934665603ULL;
    for (int round = 1; round <= 50; round++) {
        work(round * 1000);
        hash = (hash ^ (uint64_t) (vc_mono() - m0)) * 1099511628211ULL;
        hash = (hash ^ (counter() - c0)) * 1099511628211ULL;
    }
    return (int64_t) hash;
}

/* ======================================================================== single thread */

static void counter_agrees_with_monotonic(void) {
    int64_t tick = counter_ns(1) > 0 ? counter_ns(1) : 1;
    int outside = 0, back = 0;
    uint64_t last = 0;
    int64_t worst = 0;
    for (int i = 0; i < 2000; i++) {
        int64_t before = vc_mono();
        uint64_t c = counter();
        int64_t after = vc_mono();
        int64_t ns = counter_ns(c);
        if (ns < before - tick || ns > after + tick) {
            outside++;
            int64_t off = ns < before ? before - ns : ns - after;
            if (off > worst) {
                worst = off;
            }
        }
        if (c <= last) {
            back++;
        }
        last = c;
        if (i % 100 == 0) {
            work(i * 10);
        }
    }
    CHECK(outside == 0, "CNTVCT/CNTFRQ lies between the CLOCK_MONOTONIC reads around it, 2000 times (outside %d, worst %lld ns)",
          outside, (long long) worst);
    CHECK(back == 0, "CNTVCT strictly increases between reads (%d not)", back);

    uint64_t a = counter(), b = counter(), c = counter();
    CHECK(a < b && b < c, "back-to-back CNTVCT reads strictly increase (%llu %llu %llu)",
          (unsigned long long) a, (unsigned long long) b, (unsigned long long) c);

    int64_t m0 = vc_mono();
    uint64_t c0 = counter();
    work(200000);
    int64_t dm = vc_mono() - m0;
    int64_t dc = counter_ns(counter() - c0);
    int64_t diff = dm > dc ? dm - dc : dc - dm;
    CHECK(diff <= 2 * tick, "a computation takes the same time on CNTVCT and CLOCK_MONOTONIC (%lld vs %lld ns)",
          (long long) dc, (long long) dm);
}

static void realtime_follows_monotonic(void) {
    int64_t r0 = vc_real(), m0 = vc_mono();
    work(100000);
    int64_t r1 = vc_real(), m1 = vc_mono();
    int64_t skew = (r1 - r0) - (m1 - m0);
    CHECK(skew > -10000 && skew < 10000, "CLOCK_REALTIME and CLOCK_MONOTONIC advance together (%lld vs %lld ns)",
          (long long) (r1 - r0), (long long) (m1 - m0));
    int64_t tv = vc_gettimeofday_us(), rt = vc_real() / 1000;
    CHECK(rt - tv >= 0 && rt - tv < 2000, "gettimeofday agrees with CLOCK_REALTIME (%lld us apart)", (long long) (rt - tv));
}

static void sleeps(void) {
    int64_t t0 = vc_mono();
    struct timespec req = {0, 50 * MS};
    int ret = nanosleep(&req, NULL);
    int64_t slept = vc_mono() - t0;
    CHECK(ret == 0 && slept >= 50 * MS && slept < 51 * MS, "nanosleep(50 ms) takes 50 ms (%lld ns)", (long long) slept);

    uint64_t c0 = counter();
    usleep(10000);
    int64_t counted = counter_ns(counter() - c0);
    CHECK(counted >= 10 * MS && counted < 11 * MS, "usleep(10 ms) takes 10 ms on CNTVCT too (%lld ns)", (long long) counted);

    int rounds = 0;
    int64_t until = vc_mono() + 20 * MS;
    while (vc_mono() < until && rounds < 1000) {
        usleep(1000);
        rounds++;
    }
    CHECK(rounds == 20, "waiting 20 ms in usleep(1 ms) steps takes 20 rounds (%d)", rounds);
}

static void timed_waits(void) {
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    struct timespec abs;
    clock_gettime(CLOCK_REALTIME, &abs);
    abs.tv_nsec += 100 * MS;
    if (abs.tv_nsec >= 1000000000L) {
        abs.tv_sec++;
        abs.tv_nsec -= 1000000000L;
    }
    int64_t t0 = vc_mono();
    pthread_mutex_lock(&mutex);
    int ret = pthread_cond_timedwait(&cond, &mutex, &abs);
    pthread_mutex_unlock(&mutex);
    int64_t waited = vc_mono() - t0;
    CHECK(ret == ETIMEDOUT && waited >= 100 * MS && waited < 101 * MS,
          "pthread_cond_timedwait(100 ms) nothing signals: ETIMEDOUT after 100 ms (ret %d, %lld ns)", ret, (long long) waited);

    t0 = vc_mono();
    ret = poll(NULL, 0, 30);
    waited = vc_mono() - t0;
    CHECK(ret == 0 && waited >= 30 * MS && waited < 31 * MS, "poll(NULL, 0, 30 ms) takes 30 ms (%lld ns)", (long long) waited);

    int fds[2];
    pipe(fds);
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(fds[0], &readfds);
    struct timeval tv = {0, 40000};
    t0 = vc_mono();
    ret = select(fds[0] + 1, &readfds, NULL, NULL, &tv);
    waited = vc_mono() - t0;
    CHECK(ret == 0 && waited >= 40 * MS && waited < 41 * MS, "select on an empty pipe, 40 ms timeout: 0 after 40 ms (%lld ns)",
          (long long) waited);
    close(fds[0]);
    close(fds[1]);

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    struct timespec timeout = {0, 25 * MS};
    t0 = vc_mono();
    long r = syscall(__NR_rt_sigtimedwait, &set, NULL, &timeout, 8);
    int err = errno;
    waited = vc_mono() - t0;
    CHECK(r == -1 && err == EAGAIN && waited >= 25 * MS && waited < 26 * MS,
          "rt_sigtimedwait(25 ms) nothing pending: EAGAIN after 25 ms (%lld ns)", (long long) waited);
}

static void computation_time(void) {
    int64_t t0 = vc_mono();
    work(1000000);
    int64_t took = vc_mono() - t0;
    CHECK(took > 100000 && took < 50 * MS, "1M loop iterations take a CPU's time, not the emulator's (%lld ns)", (long long) took);
}

int vc_run_all(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    failures = 0;
    counter_agrees_with_monotonic();
    realtime_follows_monotonic();
    sleeps();
    timed_waits();
    computation_time();
    printf("%d single-thread checks failed\n", failures);
    return failures;
}

/* ======================================================================== threads */

static void *sleeper(void *arg) {
    struct timespec req = {0, 20 * MS};
    nanosleep(&req, NULL);
    return arg;
}

static pthread_mutex_t wait_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wait_cond = PTHREAD_COND_INITIALIZER;

static void *timed_waiter(void *arg) {
    struct timespec abs;
    clock_gettime(CLOCK_REALTIME, &abs);
    abs.tv_nsec += 30 * MS;
    if (abs.tv_nsec >= 1000000000L) {
        abs.tv_sec++;
        abs.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&wait_mutex);
    int ret = pthread_cond_timedwait(&wait_cond, &wait_mutex, &abs);
    pthread_mutex_unlock(&wait_mutex);
    *(int *) arg = ret;
    return NULL;
}

int vc_run_threads(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    failures = 0;

    pthread_t thread;
    int64_t t0 = vc_mono();
    pthread_create(&thread, NULL, sleeper, NULL);
    pthread_join(thread, NULL);
    int64_t took = vc_mono() - t0;
    CHECK(took >= 20 * MS && took < 25 * MS, "joining a thread in nanosleep(20 ms) takes 20 ms (%lld ns)", (long long) took);

    int ret = -1;
    t0 = vc_mono();
    pthread_create(&thread, NULL, timed_waiter, &ret);
    pthread_join(thread, NULL);
    took = vc_mono() - t0;
    CHECK(ret == ETIMEDOUT && took >= 30 * MS && took < 35 * MS,
          "a thread's pthread_cond_timedwait(30 ms) nothing signals: ETIMEDOUT after 30 ms (ret %d, %lld ns)", ret, (long long) took);

    printf("%d thread checks failed\n", failures);
    return failures;
}
