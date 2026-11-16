/*
 * Operations unidbg did not support although it has their answer (GapFillE2ETest): clocks it threw for, *at syscalls
 * by a directory fd, futex with a bitset. The checks that matter as much: a path that does not exist still fails.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

static long ns(clockid_t id) {
    struct timespec ts;
    if (clock_gettime(id, &ts) != 0) {
        return -errno;
    }
    return ts.tv_sec * 1000000000L + ts.tv_nsec;
}

long gf_clock(int id) {
    return ns(id);
}

long gf_libc_clock(void) {
    return (long) clock();
}

/* CPU time during a 100 ms sleep: (monotonic ms << 32) | cpu us */
long gf_cpu_during_sleep(void) {
    long c0 = ns(CLOCK_PROCESS_CPUTIME_ID), m0 = ns(CLOCK_MONOTONIC);
    struct timespec t = {0, 100000000};
    nanosleep(&t, NULL);
    long c1 = ns(CLOCK_PROCESS_CPUTIME_ID), m1 = ns(CLOCK_MONOTONIC);
    return ((m1 - m0) / 1000000) << 32 | ((c1 - c0) / 1000);
}

/* CPU time of a loop, in us */
long gf_cpu_during_work(void) {
    long c0 = ns(CLOCK_PROCESS_CPUTIME_ID);
    volatile long x = 0;
    for (long i = 0; i < 1000000; i++) {
        x += i;
    }
    return (ns(CLOCK_PROCESS_CPUTIME_ID) - c0) / 1000;
}

/*
 * By the fd of dir, which holds file.txt ("hello") and sub/inner.txt; the rootfs' root holds decoy.txt. A bit per
 * check that held.
 */
long gf_dir(const char *dir) {
    struct stat st;
    char buf[8] = {0};
    long bits = 0;
    int d = open(dir, O_RDONLY | O_DIRECTORY);
    if (d < 0) {
        return -1000 - errno;
    }
    int fd = openat(d, "file.txt", O_RDONLY);
    if (fd >= 0 && read(fd, buf, 5) == 5 && memcmp(buf, "hello", 5) == 0) {
        bits |= 1;
    }
    if (fd >= 0) {
        close(fd);
    }
    if (openat(d, "missing.txt", O_RDONLY) < 0) {
        bits |= 2;
    }
    if (fstatat(d, "file.txt", &st, 0) == 0 && st.st_size == 5) {
        bits |= 4;
    }
    if (fstatat(d, "missing.txt", &st, 0) != 0) {
        bits |= 8;
    }
    if (faccessat(d, "file.txt", F_OK, 0) == 0) {
        bits |= 16;
    }
    if (faccessat(d, "missing.txt", F_OK, 0) != 0) {
        bits |= 32;
    }
    if (fstatat(d, "../dir/file.txt", &st, 0) == 0 && st.st_size == 5) {
        bits |= 64;
    }
    int sub = openat(d, "sub", O_RDONLY | O_DIRECTORY);
    if (sub >= 0) {
        if (faccessat(sub, "inner.txt", F_OK, 0) == 0) {
            bits |= 128;
        }
        close(sub);
    }
    if (faccessat(d, "decoy.txt", F_OK, 0) != 0) {
        bits |= 256; /* not the decoy.txt at the rootfs' root */
    }
    close(d);
    return bits;
}

/* an fd scan: readlinkat on the /proc/self/fd directory's entry of an open file; 1 if it names the file */
long gf_fd_scan(const char *path) {
    char name[16], buf[128];
    int fd = open(path, O_RDONLY);
    int d = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
    if (fd < 0 || d < 0) {
        return -1000 - errno;
    }
    snprintf(name, sizeof(name), "%d", fd);
    ssize_t n = readlinkat(d, name, buf, sizeof(buf));
    close(d);
    close(fd);
    if (n < 0) {
        return -errno;
    }
    return n == (ssize_t) strlen(path) && memcmp(buf, path, n) == 0 ? 1 : -2000 - n;
}

static long futex(int *uaddr, int op, int val, const struct timespec *ts, unsigned val3) {
    long r = syscall(SYS_futex, uaddr, op, val, ts, NULL, val3);
    return r == -1 ? -errno : r;
}

long gf_futex_eagain(void) {
    int word = 1;
    return futex(&word, FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG, 0, NULL, FUTEX_BITSET_MATCH_ANY);
}

/* an absolute timeout already past */
long gf_futex_past(void) {
    int word = 0;
    struct timespec ts = {0, 0};
    return futex(&word, FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG, 0, &ts, FUTEX_BITSET_MATCH_ANY);
}

/* an absolute timeout 50 ms ahead, on CLOCK_MONOTONIC or CLOCK_REALTIME: the ms CLOCK_MONOTONIC moved, or -errno */
long gf_futex_timeout(int realtime) {
    int word = 0;
    struct timespec ts;
    clock_gettime(realtime ? CLOCK_REALTIME : CLOCK_MONOTONIC, &ts);
    ts.tv_nsec += 50000000;
    if (ts.tv_nsec >= 1000000000) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000;
    }
    long m0 = ns(CLOCK_MONOTONIC);
    long r = futex(&word, FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG | (realtime ? FUTEX_CLOCK_REALTIME : 0), 0, &ts, FUTEX_BITSET_MATCH_ANY);
    long m1 = ns(CLOCK_MONOTONIC);
    return r == -ETIMEDOUT ? (m1 - m0) / 1000000 : r;
}

long gf_futex_wake_none(void) {
    int word = 0;
    return futex(&word, FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG, 1, NULL, FUTEX_BITSET_MATCH_ANY);
}

static int shared_word;
static long woke;

static void *waiter(void *arg) {
    woke = futex(&shared_word, FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG, 0, NULL, FUTEX_BITSET_MATCH_ANY) == 0 ? 1 : -1;
    return arg;
}

/* a thread waits with FUTEX_WAIT_BITSET, main wakes it with FUTEX_WAKE_BITSET: (woken count << 8) | 1 if it returned 0 */
long gf_futex_wake_thread(void) {
    pthread_t t;
    struct timespec pause = {0, 10000000};
    shared_word = 0;
    woke = 0;
    pthread_create(&t, NULL, waiter, NULL);
    nanosleep(&pause, NULL);
    shared_word = 1;
    long n = futex(&shared_word, FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG, 1, NULL, FUTEX_BITSET_MATCH_ANY);
    pthread_join(t, NULL);
    return n << 8 | (woke & 0xff);
}

/* CLOCK_REALTIME, CLOCK_REALTIME_COARSE, CLOCK_TAI read one after another: (coarse - realtime us << 32) | (tai - coarse us) */
long gf_realtime_clocks(void) {
    long real = ns(CLOCK_REALTIME), coarse = ns(CLOCK_REALTIME_COARSE), tai = ns(CLOCK_TAI);
    if (real < 0 || coarse < 0 || tai < 0) {
        return -1;
    }
    return ((coarse - real) / 1000) << 32 | ((tai - coarse) / 1000);
}
