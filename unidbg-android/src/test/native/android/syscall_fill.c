/*
 * Syscalls unidbg had no arm64 implementation of (SyscallFillE2ETest): dup, fsync, getgid/getegid, process_vm_readv
 * on the process itself, an unknown syscall, and mmap of a procfs file; and how readlink writes its buffer. Each
 * function returns a value the test checks; failures return -errno.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

#ifndef __NR_process_vm_readv
#define __NR_process_vm_readv 270
#endif
#ifndef __NR_kcmp
#define __NR_kcmp 272
#endif

static long pvr(int pid, struct iovec *local, unsigned long nlocal, struct iovec *remote, unsigned long nremote) {
    long ret = syscall(__NR_process_vm_readv, pid, local, nlocal, remote, nremote, 0);
    return ret == -1 ? -errno : ret;
}

/* dup of an open file reads the file; returns the new fd */
long sf_dup(const char *path) {
    char buf[4] = {0};
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1000 - errno;
    }
    int d = dup(fd);
    close(fd);
    if (d < 0) {
        return -errno;
    }
    long n = read(d, buf, sizeof(buf));
    close(d);
    return n == 4 && memcmp(buf, "data", 4) == 0 ? d : -2000;
}

long sf_dup_bad(void) {
    return dup(9999) == -1 ? -errno : 0;
}

long sf_fsync(const char *path) {
    int fd = open(path, O_CREAT | O_RDWR, 0600);
    if (fd < 0) {
        return -1000 - errno;
    }
    long ret = write(fd, "data", 4) == 4 ? fsync(fd) : -2000;
    if (ret == -1) {
        ret = -errno;
    }
    close(fd);
    return ret;
}

long sf_fsync_bad(void) {
    return fsync(9999) == -1 ? -errno : 0;
}

/* getgid, getegid: (gid << 16) | egid, with 0xffff when they differ from getuid, geteuid */
long sf_gid(void) {
    long gid = getgid(), egid = getegid();
    if (gid != (long) getuid() || egid != (long) geteuid()) {
        return 0xffff;
    }
    return gid << 16 | egid;
}

/* process_vm_readv of a heap string into a stack buffer: the byte count, -1 if the bytes differ */
long sf_pvr_self(void) {
    static const char text[] = "hello, process_vm_readv";
    char out[64] = {0};
    struct iovec local = {out, sizeof(out)};
    struct iovec remote = {(void *) text, sizeof(text)};
    long n = pvr(getpid(), &local, 1, &remote, 1);
    return n == (long) sizeof(text) && memcmp(out, text, sizeof(text)) != 0 ? -1 : n;
}

/* the source is on the stack (unidbg maps the stack outside its memory map), split over two local elements */
long sf_pvr_stack(void) {
    char text[32];
    char a[10], b[22];
    for (int i = 0; i < 32; i++) {
        text[i] = (char) ('a' + i % 26);
    }
    struct iovec local[2] = {{a, sizeof(a)}, {b, sizeof(b)}};
    struct iovec remote = {text, sizeof(text)};
    long n = pvr(getpid(), local, 2, &remote, 1);
    return n == 32 && (memcmp(a, text, 10) != 0 || memcmp(b, text + 10, 22) != 0) ? -1 : n;
}

long sf_pvr_unmapped(void) {
    char out[16];
    struct iovec local = {out, sizeof(out)};
    struct iovec remote = {(void *) 0x10, 8};
    return pvr(getpid(), &local, 1, &remote, 1);
}

/* the first element is readable, the second is not: only the first is transferred */
long sf_pvr_partial(void) {
    static const char text[] = "1234";
    char out[16];
    struct iovec local = {out, sizeof(out)};
    struct iovec remote[2] = {{(void *) text, 4}, {(void *) 0x10, 8}};
    return pvr(getpid(), &local, 1, remote, 2);
}

/* a mapped page without read permission */
long sf_pvr_prot_none(void) {
    char out[16];
    void *page = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        return -1000 - errno;
    }
    struct iovec local = {out, sizeof(out)};
    struct iovec remote = {page, 8};
    long ret = pvr(getpid(), &local, 1, &remote, 1);
    munmap(page, 4096);
    return ret;
}

long sf_pvr_bad_flags(void) {
    char out[4];
    struct iovec iov = {out, sizeof(out)};
    long ret = syscall(__NR_process_vm_readv, getpid(), &iov, 1, &iov, 1, 1);
    return ret == -1 ? -errno : ret;
}

/* another process: not modelled */
long sf_pvr_other(void) {
    char out[4];
    struct iovec iov = {out, sizeof(out)};
    return pvr(getpid() + 1000, &iov, 1, &iov, 1);
}

/* a syscall unidbg does not have; its first argument is a pid, what x0 still held before */
long sf_unknown(void) {
    long ret = syscall(__NR_kcmp, getpid(), getpid(), 0, 0, 0);
    return ret == -1 ? -errno : ret;
}

/* mmap of an open file: 1 if it was mapped and holds what read() returns */
long sf_mmap_file(const char *path) {
    char head[8] = {0};
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1000 - errno;
    }
    if (read(fd, head, sizeof(head)) <= 0) {
        close(fd);
        return -2000;
    }
    void *p = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (p == MAP_FAILED) {
        return -errno;
    }
    long same = memcmp(p, head, sizeof(head)) == 0;
    munmap(p, 4096);
    return same;
}

/* readlink into a 64-byte buffer of 0xaa with the given bufsiz: (bytes written << 16) | return value, or -errno */
long sf_readlink(const char *path, int bufsiz) {
    unsigned char buf[64];
    memset(buf, 0xaa, sizeof(buf));
    ssize_t n = readlink(path, (char *) buf, bufsiz);
    if (n < 0) {
        return -errno;
    }
    long written = 0;
    for (int i = 0; i < (int) sizeof(buf); i++) {
        if (buf[i] != 0xaa) {
            written = i + 1;
        }
    }
    return written << 16 | n;
}

/* readlink of /proc/self/fd/<fd>, or /proc/<pid>/fd/<fd> (the form an APK check uses), of an open file: 1 if it reads
 * back the path, without a NUL after it */
long sf_readlink_fd(const char *path, int by_pid) {
    char link[32];
    unsigned char buf[128];
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1000 - errno;
    }
    if (by_pid) {
        snprintf(link, sizeof(link), "/proc/%d/fd/%d", getpid(), fd);
    } else {
        snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    }
    memset(buf, 0xaa, sizeof(buf));
    ssize_t n = readlink(link, (char *) buf, sizeof(buf));
    close(fd);
    if (n < 0) {
        return -errno;
    }
    return n == (ssize_t) strlen(path) && memcmp(buf, path, n) == 0 && buf[n] == 0xaa ? 1 : -2000 - n;
}

/* stat of the fd directory written with a trailing slash: 1 for a directory */
long sf_stat_fd_dir(void) {
    char path[32];
    struct stat st;
    snprintf(path, sizeof(path), "/proc/%d/fd/", getpid());
    if (stat(path, &st) != 0) {
        return -errno;
    }
    return S_ISDIR(st.st_mode) ? 1 : -3000;
}
