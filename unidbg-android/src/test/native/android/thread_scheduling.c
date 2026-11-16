/*
 * Code that needs its threads, the ways libraries rely on them. Every expectation is what a device does.
 *
 * sch_timed_handoff(rounds, ms) main hands a job to a worker (which makes syscalls while it works) and waits for the
 *                               result with pthread_cond_timedwait(1 s); 0 if the result came in time, else ETIMEDOUT.
 *                               *ms = the CLOCK_MONOTONIC ms the job took.
 * sch_periodic(ms_per_tick)     a timer thread ticks every ms_per_tick while main sleeps 1 s; returns the ticks
 * sch_start_background()        starts a worker that fills a table, returns at once
 * sch_background_ready()        1 once that worker has finished
 * sch_sequential_threads(n)     n threads created and joined one after another; returns how many ran
 * sch_spin_handoff(max)         main spins (no syscall) until a worker sets a flag; returns the spins, -1 if never set
 * sch_deadlock()                main joins a thread that waits for a condition nobody signals: never returns
 */
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

static int64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}

static volatile uint32_t table[4096];

static void work(long rounds, int syscalls) {
    uint32_t h = 2166136261u;
    for (long r = 0; r < rounds; r++) {
        if (syscalls) {
            sched_yield(); /* stands for the syscalls real work makes (malloc, logging, file reads) */
        }
        for (int i = 0; i < 4096; i++) {
            h = (h ^ table[i]) * 16777619u;
            table[i] = h;
        }
    }
}

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static int job_done;
static long job_rounds;
static int64_t job_ms;

static void *job(void *arg) {
    (void) arg;
    int64_t t0 = mono_ms();
    work(job_rounds, 1);
    pthread_mutex_lock(&lock);
    job_ms = mono_ms() - t0;
    job_done = 1;
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&lock);
    return NULL;
}

int sch_timed_handoff(long rounds, int64_t *ms) {
    pthread_t t;
    job_done = 0;
    job_rounds = rounds;
    pthread_create(&t, NULL, job, NULL);
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 1;
    int ret = 0;
    pthread_mutex_lock(&lock);
    while (!job_done && ret == 0) {
        ret = pthread_cond_timedwait(&cond, &lock, &deadline);
    }
    int done = job_done;
    pthread_mutex_unlock(&lock);
    pthread_join(t, NULL);
    *ms = job_ms;
    return done ? 0 : ETIMEDOUT;
}

static volatile int timer_stop, timer_ticks;
static int timer_period_ms;

static void *timer(void *arg) {
    (void) arg;
    while (!timer_stop) {
        usleep(timer_period_ms * 1000);
        if (!timer_stop) {
            timer_ticks++;
        }
    }
    return NULL;
}

int sch_periodic(int ms_per_tick) {
    pthread_t t;
    timer_stop = 0;
    timer_ticks = 0;
    timer_period_ms = ms_per_tick;
    pthread_create(&t, NULL, timer, NULL);
    struct timespec req = {1, 0};
    nanosleep(&req, NULL);
    timer_stop = 1;
    pthread_join(t, NULL);
    return timer_ticks;
}

static volatile int background_ready;

static void *background(void *arg) {
    (void) arg;
    work(50, 0);
    background_ready = 1;
    return NULL;
}

int sch_start_background(void) {
    pthread_t t;
    background_ready = 0;
    pthread_create(&t, NULL, background, NULL);
    pthread_detach(t);
    return 0;
}

int sch_background_ready(void) {
    return background_ready;
}

static void *one(void *arg) {
    return arg;
}

int sch_sequential_threads(int n) {
    int ran = 0;
    for (int i = 0; i < n; i++) {
        pthread_t t;
        void *ret = NULL;
        if (pthread_create(&t, NULL, one, (void *) (intptr_t) (i + 1)) == 0 && pthread_join(t, &ret) == 0 && ret == (void *) (intptr_t) (i + 1)) {
            ran++;
        }
    }
    return ran;
}

static volatile int flag;

static void *setter(void *arg) {
    (void) arg;
    flag = 1;
    return NULL;
}

long sch_spin_handoff(long max) {
    pthread_t t;
    flag = 0;
    pthread_create(&t, NULL, setter, NULL);
    long spins = 0;
    while (!flag && spins < max) {
        spins++;
    }
    long seen = flag ? spins : -1;
    pthread_join(t, NULL);
    return seen;
}

static pthread_mutex_t never_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t never_cond = PTHREAD_COND_INITIALIZER;

static void *waits_forever(void *arg) {
    (void) arg;
    pthread_mutex_lock(&never_lock);
    pthread_cond_wait(&never_cond, &never_lock);
    pthread_mutex_unlock(&never_lock);
    return NULL;
}

/* a deadlock: main joins a thread that waits for a condition nobody signals; never returns */
int sch_deadlock(void) {
    pthread_t t;
    pthread_create(&t, NULL, waits_forever, NULL);
    pthread_join(t, NULL);
    return 0;
}
