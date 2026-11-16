/*
 * The pattern behind CLAUDE.md item 4: a thread installs a handler, sends itself a signal with tgkill and busy-waits
 * for the handler's side effect. On a device the handler runs before tgkill() returns, so the loop ends at once.
 * Original unidbg never runs the handler, so the loop never ends; the loop is bounded here only to report that instead
 * of hanging. TgkillSelfTest runs it on every backend.
 */
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

static volatile int handled;
static volatile int handled_tid;

static void on_signal(int sig) {
    handled = 1;
    handled_tid = gettid();
}

/*
 * @return the number of loop iterations before the handler's flag was seen (0 = it ran before tgkill returned, as on
 * a device), or -1 if the handler never ran within max_spins iterations (the original bug: an endless loop)
 */
long tgkill_self(long max_spins) {
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_handler = on_signal;
    sigaction(SIGUSR1, &act, NULL);

    handled = 0;
    handled_tid = 0;
    int ret = (int) syscall(__NR_tgkill, getpid(), gettid(), SIGUSR1);
    printf("tgkill(%d, %d, SIGUSR1) = %d, handler ran before return: %s, on tid %d\n",
           getpid(), gettid(), ret, handled ? "yes" : "no", handled_tid);
    fflush(stdout);

    long spins = 0;
    while (!handled) {
        if (++spins >= max_spins) {
            return -1;
        }
    }
    return spins;
}

/* the same with raise(), which bionic implements with tgkill */
long raise_self(long max_spins) {
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_handler = on_signal;
    sigaction(SIGUSR2, &act, NULL);

    handled = 0;
    raise(SIGUSR2);
    long spins = 0;
    while (!handled) {
        if (++spins >= max_spins) {
            return -1;
        }
    }
    return spins;
}
