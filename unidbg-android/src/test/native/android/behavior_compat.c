/*
 * Behaviour compatibility demo: the situations where unidbg reports something to the user (unimplemented JNI,
 * unknown syscall, unsupported kill, brk/udf without a guest handler...). BehaviorCompatTest runs every case on each
 * backend, on the HEAD baseline and on the working tree; the reports must stay the same unless a case is listed as
 * new support of the unicorn2 backend.
 */
#include <jni.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

/* JNI call to a Java method the test does not implement: AbstractJni throws UnsupportedOperationException */
JNIEXPORT jint JNICALL Java_com_github_unidbg_android_compat_Native_callMissing(JNIEnv *env, jclass clazz) {
    jclass missing = (*env)->FindClass(env, "com/github/unidbg/android/compat/Missing");
    jmethodID method = (*env)->GetStaticMethodID(env, missing, "notImplemented", "(I)I");
    return (*env)->CallStaticIntMethod(env, missing, method, 7) + 1000;
}

/* a syscall unidbg does not implement (io_destroy) */
long compat_unknown_syscall(void) {
    return syscall(__NR_io_destroy, 0);
}

/* kill() to another process: unsupported in unidbg */
int compat_kill_other(void) {
    return kill(1, SIGTERM);
}

/* brk without a SIGTRAP handler: unidbg's debugger (Breaker.brk) */
int compat_brk(void) {
    __asm__ volatile("brk #0x3e8");
    return 1;
}

/* udf without a SIGILL handler: unidbg's debugger (Breaker.debug) */
int compat_udf(void) {
    __asm__ volatile("udf #0");
    return 2;
}

/* a read of unmapped memory without a SIGSEGV handler */
int compat_read_unmapped(void) {
    signal(SIGSEGV, SIG_DFL);
    return *(volatile int *) 0x10;
}

/* EL1 system register read from user code */
long compat_el1_sysreg(void) {
    long value = 0x1234;
    __asm__ volatile("mrs %0, sctlr_el1" : "+r"(value));
    return value;
}

/* tgkill to a thread that does not exist */
int compat_tgkill_unknown(void) {
    errno = 0;
    int ret = (int) syscall(__NR_tgkill, getpid(), 0x7ff0, SIGUSR2);
    return ret == 0 ? 0 : -errno;
}

/* untimed sigtimedwait with nothing pending in a single thread: blocks forever on a device */
int compat_sigtimedwait_forever(void) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGUSR2);
    return (int) syscall(__NR_rt_sigtimedwait, &set, NULL, NULL, sizeof(set));
}

/* sigaction(SIGKILL, act) is refused */
int compat_sigaction_sigkill(void) {
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_handler = SIG_IGN;
    errno = 0;
    int ret = sigaction(SIGKILL, &act, NULL);
    return ret == 0 ? 0 : -errno;
}

/* raise() of a terminating signal without a handler */
int compat_raise_default(void) {
    signal(SIGTERM, SIG_DFL);
    raise(SIGTERM);
    return 1234;
}
