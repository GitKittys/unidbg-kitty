package com.bytedance.mobsec.metasec.ml;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.github.unidbg.Emulator;
import com.github.unidbg.arm.ARMEmulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.file.linux.IOConstants;
import com.github.unidbg.linux.ARM64SyscallHandler;
import com.github.unidbg.linux.file.NetLinkSocket;
import com.github.unidbg.linux.file.NetworkIF;
import com.github.unidbg.linux.file.UdpSocket;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.unix.IO;
import com.github.unidbg.unix.UnixEmulator;
import com.sun.jna.Pointer;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import unicorn.Arm64Const;

import java.io.File;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * The syscalls this test patches, the usual unidbg way (a handler subclass): ones unidbg has no answer for, that metasec's
 * collection threads make and that do not feed the sign. Without them such a thread dies on unidbg's UnsupportedOperationException.
 */
class MetasecSyscalls extends ARM64SyscallHandler {

    private static final int NR_STATFS = 43;
    private static final int NR_FACCESSAT = 48;
    private static final int NR_OPENAT = 56;
    private static final int NR_READLINKAT = 78;
    private static final int NR_NEWFSTATAT = 79;
    private static final int NR_PRCTL = 167;
    private static final int NR_CLOCK_GETTIME = 113;
    private static final int NR_READ = 63;
    private static final int NR_SOCKET = 198;
    /** libmetasec_ml.so+0x1e4280: reads its own memory (the pid argument is getpid(), symbol at GOT 0x4f3cc0) */
    private static final int NR_PROCESS_VM_READV = 270;
    /** libmetasec_ml.so+0x20c550, import `sysinfo` at GOT 0x4f3e60: the collection thread's memory figure (totalram * mem_unit) */
    private static final int NR_SYSINFO = 179;
    private static final int NR_PTRACE = 117;
    private static final int PTRACE_TRACEME = 0;
    private static final int NR_UNAME = 160;
    private static final int PR_SET_NAME = 15;
    private static final int PR_GET_NAME = 16;
    private static final int UTS_FIELD = 65;
    private static final int CLOCK_REALTIME = 0;
    private static final int PR_GET_DUMPABLE = 3;
    private static final int PR_GET_NO_NEW_PRIVS = 39;
    // a forked child up to its execve
    private static final int NR_DUP = 23;
    private static final int NR_DUP3 = 24;
    private static final int NR_FCNTL = 25;
    private static final int NR_CLOSE = 57;
    private static final int NR_EXIT = 93;
    private static final int NR_EXIT_GROUP = 94;
    private static final int NR_RT_SIGACTION = 134;
    private static final int NR_RT_SIGPROCMASK = 135;
    private static final int NR_SETPGID = 154;
    private static final int NR_SETSID = 157;
    private static final int NR_GETPID = 172;
    private static final int NR_GETPPID = 173;
    private static final int NR_GETTID = 178;
    private static final int NR_GETUID = 174;
    private static final int NR_GETEUID = 175;
    private static final int NR_GETEGID = 177;
    private static final int NR_EXECVE = 221;
    private static final int NR_WAIT4 = 260;
    private static final int CLONE_VM = 0x100;
    private static final int CLONE_CHILD_SETTID = 0x01000000;
    private static final int SIGCHLD = 17;
    private static final int F_DUPFD = 0;
    private static final int F_GETFD = 1;
    private static final int F_SETFD = 2;
    private static final int F_DUPFD_CLOEXEC = 1030;
    private static final int EBADF = 9;
    private static final int EPIPE = 32;
    private static final int S_IFIFO = 0x1000;
    // unicorn2 register ids beyond the unicorn1 Arm64Const set
    private static final int UC_ARM64_REG_FPCR = 291;
    private static final int UC_ARM64_REG_FPSR = 292;

    /** bytes the guest read from /dev/urandom, in order (diagnostics: X-Perseus takes its nonce from the guest's randomness) */
    final java.io.ByteArrayOutputStream urandom = new java.io.ByteArrayOutputStream();
    private int urandomFd = -1;

    /** the last CLOCK_REALTIME the guest itself read (epoch seconds), 0 before it read one */
    private volatile long lastRealtimeSec;

    /** the paths the guest looked up (open, access, stat, readlink, statfs) and what it got: 0 or an fd, else -errno */
    final Map<String, Long> files = new TreeMap<>();

    /** the device: the profile's sysinfo / network / uname sections and its files; all null for a run without a profile */
    private JSONObject sysinfoValues, network, uname, statfsValues;
    private MetasecStartup.ProfileFs fs;
    /** thread names the guest set (prctl PR_SET_NAME), by tid; unidbg accepts the call and keeps nothing */
    private final Map<Integer, String> threadNames = new java.util.concurrent.ConcurrentHashMap<>();
    /** the process name, which a thread has until it names itself (Linux: a new thread inherits its creator's comm) */
    private String comm;
    /** what each shell command printed and returned on the device (the profile's shell_commands), by command line */
    private final Map<String, JSONObject> shellRuns = new java.util.HashMap<>();
    /** a forked child while it runs up to its execve or exit; null otherwise */
    private ForkChild child;
    /** children that exited and were not waited for yet: pid -> wait status */
    private final Map<Integer, Integer> zombies = new java.util.LinkedHashMap<>();
    /**
     * the process's ids from the profile's /proc/self/status (Uid:/Gid: real, effective, saved, fs); null without one. unidbg
     * answers getuid/geteuid/getgid/getegid with 0, root, where the app runs as its own uid (u0_a275 = 10275)
     */
    private int[] uids, gids;
    /** the fsuid/fsgid, which own what the process creates (0 without a profile, as unidbg's getuid) */
    private int uid, gid;
    /** the SIGCHLD handler the guest installed (0 SIG_DFL, 1 SIG_IGN) */
    private long sigchldHandler;

    MetasecSyscalls(SvcMemory svcMemory) {
        super(svcMemory);
    }

    /** diagnostic (-Dmetasec.traceFn): while set, every syscall and system-register read is printed */
    volatile boolean tracing;

    @Override
    public boolean hook(Backend backend, int insn, int op0, int op1, int crn, int crm, int op2, long[] val, Object user_data) {
        boolean handled = super.hook(backend, insn, op0, op1, crn, crm, op2, val, user_data);
        if (tracing) {
            System.out.printf("  [trace]   sysreg op0=%d op1=%d CRn=%d CRm=%d op2=%d -> 0x%x%n", op0, op1, crn, crm, op2,
                    val != null && val.length > 0 ? val[0] : 0);
        }
        return handled;
    }

    /** the device this handler answers for (sysinfo, the network interface, uname, links and denied paths) */
    void device(DeviceProfile profile, MetasecStartup.ProfileFs fs) {
        this.sysinfoValues = (JSONObject) profile.section("sysinfo");
        this.statfsValues = (JSONObject) profile.section("statfs");
        this.network = (JSONObject) profile.section("network");
        this.uname = (JSONObject) profile.section("uname");
        this.fs = fs;
        Object process = profile.section("process");
        if (process instanceof JSONObject && ((JSONObject) process).getString("status") != null) {
            for (String line : ((JSONObject) process).getString("status").split("\n")) {
                String[] ids = line.trim().split("\\s+"); // "Uid:  real  effective  saved  fs"
                if (ids.length == 5 && ("Uid:".equals(ids[0]) || "Gid:".equals(ids[0]))) {
                    int[] values = new int[4];
                    for (int i = 0; i < 4; i++) {
                        values[i] = Integer.parseInt(ids[i + 1]);
                    }
                    if ("Uid:".equals(ids[0])) {
                        uids = values;
                        uid = values[3];
                    } else {
                        gids = values;
                        gid = values[3];
                    }
                }
            }
        }
        Object shell = profile.section("shell_commands");
        if (shell instanceof com.alibaba.fastjson.JSONArray) {
            for (Object item : (com.alibaba.fastjson.JSONArray) shell) {
                JSONObject run = (JSONObject) item;
                if (run.getString("cmd") != null && run.getJSONObject("replay") != null && !shellRuns.containsKey(run.getString("cmd"))) {
                    shellRuns.put(run.getString("cmd"), run);
                }
            }
        }
    }

    /** the name of the process, for threads that never named themselves */
    void processName(String comm) {
        this.comm = comm;
    }

    /** the name a guest thread gave itself, or null */
    String threadName(int tid) {
        return threadNames.get(tid);
    }

    private int currentTid(Emulator<?> emulator) {
        com.github.unidbg.thread.Task task = emulator.get(com.github.unidbg.thread.Task.TASK_KEY);
        return task == null ? emulator.getPid() : task.getId();
    }

    /**
     * {@code -Dmetasec.fixedTime=<ms>} pins the guest clock. metasec seeds its init chain from the clock it reads at startup
     * ({@code d350 = seed ^ k}), so pinning it is what makes a run reproduce a recorded chain — and with it {@code fl} and
     * the decimal digits that decide X-Medusa's length.
     */
    @Override
    protected long currentTimeMillis() {
        long fixed = Long.getLong("metasec.fixedTime", 0);
        return fixed != 0 ? fixed : super.currentTimeMillis();
    }

    /**
     * The guest's CLOCK_REALTIME in milliseconds (what the guest's time() reads). Outside a call the guest clock has not been
     * started yet and reads 0; then the host's time is what the next call starts from.
     */
    long guestTimeMillis() {
        long time = currentTimeMillis(), host = System.currentTimeMillis();
        return time <= 0 || Math.abs(time - host) > 86400000L ? host : time;
    }

    /** the CLOCK_REALTIME the guest last read through clock_gettime, epoch seconds (0: it has not read one) */
    long lastRealtimeSec() {
        return lastRealtimeSec;
    }

    @Override
    public void hook(Backend backend, int intno, int swi, Object user) {
        Emulator<?> emulator = (Emulator<?>) user;
        if (child != null) {
            if (intno == ARMEmulator.EXCP_SWI) {
                child.syscall(backend, emulator);
            } else {
                child.abort(backend, emulator, "exception " + intno);
            }
            return;
        }
        String path = intno == ARMEmulator.EXCP_SWI ? path(backend, emulator) : null;
        if (intno == ARMEmulator.EXCP_SWI && patched(backend, emulator)) {
            looked(path, backend);
            return;
        }
        int nr = intno == ARMEmulator.EXCP_SWI ? backend.reg_read(Arm64Const.UC_ARM64_REG_X8).intValue() : 0;
        if (tracing && intno == ARMEmulator.EXCP_SWI) {
            System.out.printf("  [trace]   svc %d x0=0x%x x1=0x%x x2=0x%x lr=0x%x%s%n", nr, backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue(),
                    backend.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue(), backend.reg_read(Arm64Const.UC_ARM64_REG_X2).longValue(),
                    backend.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue(), path == null ? "" : " " + path);
        }
        boolean socket = nr == NR_SOCKET, realtime = nr == NR_CLOCK_GETTIME && backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue() == CLOCK_REALTIME;
        long clock = nr == NR_CLOCK_GETTIME ? backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue() : -1;
        // CLOCK_MONOTONIC / _RAW / _COARSE / BOOTTIME count from the device's boot, not from the emulator's creation (unidbg's
        // clock starts at 0): -Dmetasec.uptime=true adds the profile's uptime (sysinfo), so boot time = now - uptime as on it
        boolean sinceBoot = (clock == 1 || clock == 4 || clock == 6 || clock == 7) && Boolean.getBoolean("metasec.uptime")
                && sysinfoValues != null;
        long timespecAt = sinceBoot ? backend.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue() : 0;
        boolean urandomRead = nr == NR_READ && backend.reg_read(Arm64Const.UC_ARM64_REG_X0).intValue() == urandomFd;
        long readBuffer = urandomRead ? backend.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue() : 0;
        int readCount = urandomRead ? backend.reg_read(Arm64Const.UC_ARM64_REG_X2).intValue() : 0;
        super.hook(backend, intno, swi, user);
        if ((nr == NR_FACCESSAT || nr == NR_NEWFSTATAT) && backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue() == -1) {
            // unidbg returns -1 with errno set; the syscall itself returns -errno (on the device: -2 ENOENT, -13 EACCES)
            int errno = emulator.getMemory().getLastErrno();
            backend.reg_write(Arm64Const.UC_ARM64_REG_X0, -(errno > 0 ? errno : UnixEmulator.ENOENT));
        }
        if (nr == NR_OPENAT && backend.reg_read(Arm64Const.UC_ARM64_REG_X0).intValue() >= 0) {
            if ("/dev/urandom".equals(path)) {
                urandomFd = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).intValue();
            }
        }
        if (urandomRead && readBuffer != 0) {
            long got = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
            if (got > 0) {
                // -Dmetasec.urandom=<hex> pins the source: every read is served from this repeating stream, so the session
                // UUID (and therefore pd/fkd) stops changing between runs. It is *our* UUID, not the device's.
                String pinned = System.getProperty("metasec.urandom");
                if (pinned != null && !pinned.isEmpty()) {
                    try {
                        byte[] stream = Hex.decodeHex(pinned.toCharArray());
                        int length = (int) Math.min(got, readCount);
                        byte[] fill = new byte[length];
                        for (int i = 0; i < length; i++) {
                            fill[i] = stream[i % stream.length];
                        }
                        UnidbgPointer.pointer(emulator, readBuffer).write(0, fill, 0, length);
                        urandom.write(fill, 0, fill.length);
                        looked(path, backend);
                        return;
                    } catch (org.apache.commons.codec.DecoderException e) {
                        throw new IllegalArgumentException("metasec.urandom: " + e.getMessage(), e);
                    }
                }
                byte[] bytes = UnidbgPointer.pointer(emulator, readBuffer).getByteArray(0, (int) Math.min(got, Math.min(readCount, 64)));
                urandom.write(bytes, 0, bytes.length);
            }
        }
        if (sinceBoot && timespecAt != 0 && backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue() == 0) {
            UnidbgPointer timespec = UnidbgPointer.pointer(emulator, timespecAt);
            timespec.setLong(0, timespec.getLong(0) + sysinfoValues.getLongValue("uptime"));
        }
        if (realtime) {
            UnidbgPointer timespec = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
            if (timespec != null && backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue() == 0) {
                lastRealtimeSec = timespec.getLong(0);
            }
        }
        looked(path, backend);
        if (socket) {
            int fd = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).intValue();
            if (fdMap.get(fd) instanceof NetLinkSocket) {
                fdMap.put(fd, new RouteDumpNetLink(emulator, network));
            } else if (fdMap.get(fd) instanceof UdpSocket && network != null) {
                fdMap.put(fd, new DeviceUdpSocket(emulator, network)); // otherwise SIOCGIFCONF would answer with the host's adapters
            }
        }
    }

    private static String path(Backend backend, Emulator<?> emulator) {
        int nr = backend.reg_read(Arm64Const.UC_ARM64_REG_X8).intValue();
        if (nr != NR_OPENAT && nr != NR_FACCESSAT && nr != NR_NEWFSTATAT && nr != NR_READLINKAT && nr != NR_STATFS) {
            return null;
        }
        int register = nr == NR_STATFS ? Arm64Const.UC_ARM64_REG_X0 : Arm64Const.UC_ARM64_REG_X1;
        UnidbgPointer pointer = UnidbgPointer.register(emulator, register);
        return pointer == null ? null : pointer.getString(0);
    }

    private void looked(String path, Backend backend) {
        if (path != null) {
            files.put(path, backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue());
        }
    }

    private boolean patched(Backend backend, Emulator<?> emulator) {
        int nr = backend.reg_read(Arm64Const.UC_ARM64_REG_X8).intValue();
        long x0 = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
        if (nr == NR_RT_SIGACTION && x0 == SIGCHLD && backend.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue() != 0) {
            sigchldHandler = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).getLong(0); // the call itself is unidbg's
        }
        if (nr >= NR_GETUID && nr <= NR_GETEGID && uids != null && gids != null) {
            // getuid, geteuid, getgid, getegid: the real and effective ids of the device's process
            int[] ids = nr <= NR_GETEUID ? uids : gids;
            backend.reg_write(Arm64Const.UC_ARM64_REG_X0, ids[(nr - NR_GETUID) % 2]);
            return true;
        }
        if (nr == NR_WAIT4) {
            Long ret = wait4(backend, emulator);
            if (ret != null) {
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, ret);
                return true;
            }
        }
        if (nr == NR_PRCTL && x0 == PR_SET_NAME) {
            // remember it (the task view shows it); unidbg still answers the call itself
            UnidbgPointer name = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
            if (name != null) {
                String value = name.getString(0);
                threadNames.put(currentTid(emulator), value.length() > 15 ? value.substring(0, 15) : value);
            }
        }
        if (nr == NR_PRCTL && x0 == PR_GET_NAME && comm != null) {
            // the kernel copies the 16-byte comm (NUL-padded); unidbg does not implement PR_GET_NAME
            UnidbgPointer buffer = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
            if (buffer == null) {
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, -UnixEmulator.EFAULT);
                return true;
            }
            String name = threadNames.containsKey(currentTid(emulator)) ? threadNames.get(currentTid(emulator)) : comm;
            byte[] value = new byte[16];
            byte[] text = name.getBytes(StandardCharsets.UTF_8);
            System.arraycopy(text, 0, value, 0, Math.min(text.length, 15));
            buffer.write(0, value, 0, 16);
            backend.reg_write(Arm64Const.UC_ARM64_REG_X0, 0);
            return true;
        }
        if (nr == NR_UNAME && uname != null) {
            // unidbg answers release "1.0.0-unidbg"; the device's own struct utsname comes from the profile
            backend.reg_write(Arm64Const.UC_ARM64_REG_X0, uname(emulator, x0));
            return true;
        }
        if (fs != null && (nr == NR_OPENAT || nr == NR_FACCESSAT || nr == NR_NEWFSTATAT || nr == NR_STATFS)) {
            // a path the device's app is denied (SELinux): every lookup fails with that errno. Answered here and not by the
            // profile's resolver, because unidbg keeps asking the other resolvers after a failure and takes a later success
            // (its bundled android/sdk23/proc/stat would answer /proc/stat)
            String path = path(backend, emulator);
            int denied = path == null ? 0 : fs.errno(path);
            if (denied != 0) {
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, -denied);
                return true;
            }
        }
        if (nr == NR_READLINKAT && fs != null) {
            Long ret = readlinkat(backend, emulator);
            if (ret != null) {
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, ret);
                return true;
            }
        }
        if (nr == NR_PROCESS_VM_READV) {
            backend.reg_write(Arm64Const.UC_ARM64_REG_X0, processVmReadv(backend, emulator));
            return true;
        }
        if (nr == NR_SYSINFO && sysinfoValues != null) {
            backend.reg_write(Arm64Const.UC_ARM64_REG_X0, sysinfo(emulator, x0));
            return true;
        }
        if (nr == NR_STATFS && statfsValues != null) {
            // statfs(path, buf) for a mount the profile has: the device's struct (unidbg answers made-up numbers for a directory,
            // and nothing for one it cannot resolve; libc's statvfs goes through here)
            UnidbgPointer path = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
            UnidbgPointer buf = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
            JSONObject mount = path == null ? null : statfsValues.getJSONObject(path.getString(0));
            if (mount != null && buf != null) {
                writeStatfs(buf, mount);
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, 0);
                return true;
            }
        }
        if (nr == NR_PTRACE && x0 == PTRACE_TRACEME) {
            // an app process cannot make itself traced: the device answers -1 (badger_env1: ptrace(0,0,1,0) = -1); unidbg says 0,
            // which a tracer check reads as "nobody was tracing us before" on a device that never allows it
            backend.reg_write(Arm64Const.UC_ARM64_REG_X0, -UnixEmulator.EPERM);
            return true;
        }
        if (nr == NR_PRCTL && x0 == PR_GET_NO_NEW_PRIVS) {
            // an app process runs under the seccomp filter zygote installs, which needs no_new_privs set
            backend.reg_write(Arm64Const.UC_ARM64_REG_X0, 1);
            return true;
        }
        if (nr == NR_NEWFSTATAT && (int) x0 == IO.AT_FDCWD) {
            String path = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1).getString(0);
            String lookup = FilenameUtils.normalize(path, true); // as unidbg does: "/proc/self/fd/." becomes "/proc/self/fd/"
            if (!lookup.startsWith("/")) {
                lookup = "/" + lookup; // unidbg answers a path relative to the working directory with EACCES (its openat looks it up)
            }
            while (lookup.length() > 1 && lookup.endsWith("/")) {
                lookup = lookup.substring(0, lookup.length() - 1); // unidbg throws NumberFormatException on /proc/<pid>/fd/
            }
            if (!lookup.equals(path)) {
                @SuppressWarnings("unchecked")
                int ret = stat64((Emulator<AndroidFileIO>) emulator, lookup, UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2));
                backend.reg_write(Arm64Const.UC_ARM64_REG_X0, ret == 0 ? 0 : -emulator.getMemory().getLastErrno());
                return true;
            }
        }
        if (nr == NR_PRCTL && x0 == PR_GET_DUMPABLE) {
            // zygote's setresuid to the app's uid clears it; only debuggable/profileable apps set it again (not confirmed on the device)
            backend.reg_write(Arm64Const.UC_ARM64_REG_X0, 0);
            return true;
        }
        return false;
    }

    /**
     * {@code process_vm_readv(pid, local, n, remote, n, 0)}. metasec always passes its own pid (the pid argument comes from
     * the {@code getpid} import), so the read is just a copy inside the guest's address space. unidbg leaves NR 270
     * unanswered, which leaves x0 holding the pid; the libc stub then reports that as the byte count, so every caller's
     * "did I get the whole length" check fails and the memory it wanted never arrives.
     */
    private static long processVmReadv(Backend backend, Emulator<?> emulator) {
        int pid = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).intValue();
        long local = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
        int localCount = backend.reg_read(Arm64Const.UC_ARM64_REG_X2).intValue();
        long remote = backend.reg_read(Arm64Const.UC_ARM64_REG_X3).longValue();
        int remoteCount = backend.reg_read(Arm64Const.UC_ARM64_REG_X4).intValue();
        long flags = backend.reg_read(Arm64Const.UC_ARM64_REG_X5).longValue();
        if (pid != emulator.getPid()) {
            return -UnixEmulator.ESRCH; // another process: the kernel refuses an untrusted app that too
        }
        if (local == 0 || remote == 0 || flags != 0) {
            return -UnixEmulator.EINVAL;
        }
        long total = 0;
        try {
            for (int i = 0; i < Math.min(localCount, remoteCount); i++) {
                UnidbgPointer localIo = UnidbgPointer.pointer(emulator, local + i * 16L);
                UnidbgPointer remoteIo = UnidbgPointer.pointer(emulator, remote + i * 16L);
                long localLength = localIo.getLong(8);
                long remoteLength = remoteIo.getLong(8);
                long length = Math.min(localLength, remoteLength);
                if (length <= 0) {
                    continue;
                }
                if (length > Integer.MAX_VALUE) {
                    return -UnixEmulator.EINVAL;
                }
                byte[] bytes = UnidbgPointer.pointer(emulator, remoteIo.getLong(0)).getByteArray(0, (int) length);
                UnidbgPointer.pointer(emulator, localIo.getLong(0)).write(0, bytes, 0, bytes.length);
                total += bytes.length;
                if (localLength < remoteLength) {
                    break; // the kernel stops at the shorter iovec too
                }
            }
        } catch (RuntimeException e) {
            return -UnixEmulator.EFAULT; // an address the guest cannot read
        }
        return total;
    }

    /**
     * fork / vfork (clone without a stack). unidbg has no second process for a child and fails every fork (ENOSYS), so
     * metasec's shell probes (it forks, execs {@code /system/bin/sh -c <command>} and reads the output from a pipe:
     * {@code pm list features}, {@code pm list libraries}, {@code ls -lZ /dev/pts 2>&1} ...) never got an answer. Here the child
     * runs in the parent's place up to its execve, as a vfork child does: what it writes to memory is put back afterwards
     * (unless CLONE_VM, which shares it), its fd table is its own copy, and the exec is answered with what that command
     * printed and returned on the device (the profile's {@code shell_commands}), written to the child's stdout/stderr. Then
     * the parent goes on with the child's pid, and wait4 reports the device's status. A command the device's record does not
     * have, or a child doing more than set up its fds before the exec, gets unidbg's answer: all the child did is undone and
     * the fork fails as before.
     */
    @Override
    protected long fork(Emulator<?> emulator) {
        if (shellRuns.isEmpty() || child != null) {
            return super.fork(emulator);
        }
        child = new ForkChild(emulator);
        return 0;
    }

    /** wait4 for a child forked here (null: not one of ours, unidbg's answer) */
    private Long wait4(Backend backend, Emulator<?> emulator) {
        int pid = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).intValue();
        long status = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
        long rusage = backend.reg_read(Arm64Const.UC_ARM64_REG_X3).longValue();
        Integer reaped = pid > 0 ? (zombies.containsKey(pid) ? pid : null) : (zombies.isEmpty() ? null : zombies.keySet().iterator().next());
        if (reaped == null) {
            return null;
        }
        if (rusage != 0) {
            // the child's resource usage on the device is not on record
            System.out.printf("  [shell] wait4(%d) asks for the child's rusage, which the device record does not have: unidbg's answer%n", pid);
            return null;
        }
        int wstatus = zombies.remove(reaped);
        if (status != 0) {
            UnidbgPointer.pointer(emulator, status).setInt(0, wstatus);
        }
        return (long) reaped;
    }

    /**
     * A pipe with the kernel's behaviour for a writer that is ahead of the reader. unidbg's pipe is a
     * {@code java.io.PipedInputStream} with a 1 KiB buffer, and its writer waits for a reader on another Java thread, which
     * there is not: more than 1 KiB written before the guest reads hangs the emulator. A forked shell writes its whole output
     * (pm list features: 6403 B) before the parent reads. Reads answer as unidbg's do: what is there, 0 when nothing is.
     * fstat answers too (unidbg's pipe throws, which kills the thread): the kernel's pipefs inode is a FIFO, mode 0600,
     * owned by the process's uid/gid, with PAGE_SIZE blocks and the pipe's creation time; st_dev/st_ino are unidbg's
     * convention for a file it makes (1/1, as ByteArrayFileIO). The reader is stdio's buffer sizing (st_mode, st_blksize).
     */
    @Override
    protected net.dongliu.apk.parser.utils.Pair<AndroidFileIO, AndroidFileIO> getPipePair(Emulator<?> emulator, final int writefd) {
        final java.io.ByteArrayOutputStream[] buffer = {new java.io.ByteArrayOutputStream()};
        final boolean[] readerOpen = {true};
        final long created = guestTimeMillis();
        AndroidFileIO write = new com.github.unidbg.file.linux.BaseAndroidFileIO(IOConstants.O_WRONLY) {
            @Override
            public int write(byte[] data) {
                if (!readerOpen[0]) {
                    return -EPIPE;
                }
                buffer[0].write(data, 0, data.length);
                return data.length;
            }

            @Override
            public void close() {
            }

            @Override
            public int fstat(Emulator<?> emulator, com.github.unidbg.file.linux.StatStructure stat) {
                return pipeStat(emulator, stat, created);
            }

            @Override
            public String toString() {
                return "PipedWrite: " + writefd;
            }
        };
        AndroidFileIO read = new com.github.unidbg.file.linux.BaseAndroidFileIO(IOConstants.O_RDONLY) {
            @Override
            public int read(Backend backend, Pointer pointer, int count) {
                byte[] held = buffer[0].toByteArray();
                int n = Math.min(count, held.length);
                if (n <= 0) {
                    return 0;
                }
                pointer.write(0, held, 0, n);
                buffer[0] = new java.io.ByteArrayOutputStream();
                buffer[0].write(held, n, held.length - n);
                return n;
            }

            @Override
            public boolean canRead() {
                return buffer[0].size() > 0;
            }

            @Override
            public void close() {
                readerOpen[0] = false;
            }

            @Override
            public int fstat(Emulator<?> emulator, com.github.unidbg.file.linux.StatStructure stat) {
                return pipeStat(emulator, stat, created);
            }

            @Override
            public String toString() {
                return "PipedRead: " + writefd;
            }
        };
        return new net.dongliu.apk.parser.utils.Pair<>(write, read);
    }

    private int pipeStat(Emulator<?> emulator, com.github.unidbg.file.linux.StatStructure stat, long created) {
        stat.st_dev = 1;
        stat.setSt_ino(1);
        stat.st_mode = S_IFIFO | 0600;
        stat.st_nlink = 1;
        stat.st_uid = uid;
        stat.st_gid = gid;
        stat.st_rdev = 0;
        stat.st_size = 0;
        stat.st_blksize = emulator.getPageAlign();
        stat.st_blocks = 0;
        stat.setLastModification(created);
        stat.pack();
        return 0;
    }

    /** a forked child, run in the parent's place up to its execve (see {@link #fork}) */
    private final class ForkChild {

        private final int pid;
        /** CLONE_VM (vfork): the child writes the parent's memory, nothing is put back */
        private final boolean sharedMemory;
        private final long[] registers;
        private final byte[][] vectors = new byte[32][];
        private final long fpcr, fpsr;
        private final Map<Integer, AndroidFileIO> fds;
        /** {address, the bytes there before the child wrote}, in order */
        private final List<Object[]> undo = new java.util.ArrayList<>();
        private com.github.unidbg.arm.backend.UnHook journal;

        ForkChild(Emulator<?> emulator) {
            Backend backend = emulator.getBackend();
            long flags = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
            long ctid = backend.reg_read(Arm64Const.UC_ARM64_REG_X4).longValue();
            this.pid = incrementThreadId(emulator); // the next id the emulated kernel hands out
            this.sharedMemory = (flags & CLONE_VM) != 0;
            int[] ids = registerIds();
            this.registers = new long[ids.length];
            for (int i = 0; i < ids.length; i++) {
                registers[i] = backend.reg_read(ids[i]).longValue();
            }
            for (int i = 0; i < 32; i++) {
                vectors[i] = backend.reg_read_vector(Arm64Const.UC_ARM64_REG_Q0 + i);
            }
            this.fpcr = backend.reg_read(UC_ARM64_REG_FPCR).longValue();
            this.fpsr = backend.reg_read(UC_ARM64_REG_FPSR).longValue();
            this.fds = new TreeMap<>(fdMap);
            if (!sharedMemory) {
                backend.hook_add_new(new com.github.unidbg.arm.backend.WriteHook() {
                    @Override
                    public void hook(Backend b, long address, int size, long value, Object user) {
                        undo.add(new Object[]{address, b.mem_read(address, size)});
                    }

                    @Override
                    public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
                        journal = unHook;
                    }

                    @Override
                    public void detach() {
                    }
                }, 1, 0, null);
            }
            if ((flags & CLONE_CHILD_SETTID) != 0 && ctid != 0) {
                write(backend, ctid, ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(pid).array());
            }
        }

        private int[] registerIds() {
            int[] ids = new int[29 + 6];
            for (int i = 0; i <= 28; i++) {
                ids[i] = Arm64Const.UC_ARM64_REG_X0 + i;
            }
            ids[29] = Arm64Const.UC_ARM64_REG_X29;
            ids[30] = Arm64Const.UC_ARM64_REG_X30;
            ids[31] = Arm64Const.UC_ARM64_REG_SP;
            ids[32] = Arm64Const.UC_ARM64_REG_PC;
            ids[33] = Arm64Const.UC_ARM64_REG_NZCV;
            ids[34] = Arm64Const.UC_ARM64_REG_TPIDR_EL0;
            return ids;
        }

        /** a write the kernel makes into the child's memory */
        private void write(Backend backend, long address, byte[] bytes) {
            if (!sharedMemory) {
                undo.add(new Object[]{address, backend.mem_read(address, bytes.length)});
            }
            backend.mem_write(address, bytes);
        }

        void syscall(Backend backend, Emulator<?> emulator) {
            int nr = backend.reg_read(Arm64Const.UC_ARM64_REG_X8).intValue();
            long x0 = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
            long x1 = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).longValue();
            long x2 = backend.reg_read(Arm64Const.UC_ARM64_REG_X2).longValue();
            switch (nr) {
                case NR_GETPID:
                case NR_GETTID:
                case NR_SETSID:
                    answer(backend, pid);
                    return;
                case NR_GETPPID:
                    answer(backend, emulator.getPid());
                    return;
                case NR_SETPGID:
                    answer(backend, 0);
                    return;
                case NR_CLOSE:
                    answer(backend, fdMap.remove((int) x0) == null ? -EBADF : 0); // the parent's file stays open
                    return;
                case NR_DUP3:
                    if (!fdMap.containsKey((int) x0)) {
                        answer(backend, -EBADF);
                    } else if ((int) x0 == (int) x1) {
                        answer(backend, -UnixEmulator.EINVAL);
                    } else {
                        fdMap.put((int) x1, fdMap.get((int) x0));
                        answer(backend, (int) x1);
                    }
                    return;
                case NR_DUP:
                    answer(backend, duplicate((int) x0, 0));
                    return;
                case NR_FCNTL:
                    if ((int) x1 == F_DUPFD || (int) x1 == F_DUPFD_CLOEXEC) {
                        answer(backend, duplicate((int) x0, (int) x2));
                    } else if ((int) x1 == F_GETFD || (int) x1 == F_SETFD) {
                        answer(backend, fdMap.containsKey((int) x0) ? 0 : -EBADF); // close-on-exec: the program is not run
                    } else {
                        abort(backend, emulator, "fcntl cmd " + x1);
                    }
                    return;
                case NR_RT_SIGACTION:
                case NR_RT_SIGPROCMASK:
                    if (x2 == 0) {
                        answer(backend, 0); // the child's own dispositions/mask, which end with the exec
                    } else {
                        abort(backend, emulator, "syscall " + nr + " asking for the old value");
                    }
                    return;
                case NR_EXECVE:
                    exec(backend, emulator);
                    return;
                case NR_EXIT:
                case NR_EXIT_GROUP:
                    end(backend, ((int) x0 & 0xff) << 8);
                    return;
                default:
                    abort(backend, emulator, "syscall " + nr);
            }
        }

        private int duplicate(int fd, int from) {
            if (!fdMap.containsKey(fd)) {
                return -EBADF;
            }
            int to = Math.max(from, 0);
            while (fdMap.containsKey(to)) {
                to++;
            }
            fdMap.put(to, fdMap.get(fd));
            return to;
        }

        private void answer(Backend backend, long value) {
            backend.reg_write(Arm64Const.UC_ARM64_REG_X0, value);
        }

        private void exec(Backend backend, Emulator<?> emulator) {
            UnidbgPointer filename = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X0);
            UnidbgPointer argv = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
            String program = filename == null ? "" : filename.getString(0);
            List<String> args = new java.util.ArrayList<>();
            for (int i = 0; argv != null && argv.getPointer(i * 8L) != null; i++) {
                args.add(argv.getPointer(i * 8L).getString(0));
            }
            // sh -c <command>: the device record has the command line; a program run directly, its argv
            String command = program.endsWith("/sh") && args.size() >= 3 && "-c".equals(args.get(1)) ? args.get(2) : String.join(" ", args);
            JSONObject run = shellRuns.get(command);
            if (run == null) {
                abort(backend, emulator, "exec " + program + " " + args + ": not in the device's record");
                return;
            }
            JSONObject replay = run.getJSONObject("replay");
            byte[] out = String.valueOf(replay.getString("stdout") == null ? "" : replay.getString("stdout")).getBytes(StandardCharsets.UTF_8);
            // with 2>&1 in the command the shell sent stderr to stdout, which is what the record's stdout holds
            String stderr = command.contains("2>&1") || run.getString("stderr") == null ? "" : run.getString("stderr");
            emit(1, out);
            emit(2, stderr.getBytes(StandardCharsets.UTF_8));
            int status = replay.getIntValue("status");
            if (MetasecSign.DEBUG) {
                System.out.printf("  [shell] fork+exec %s %s: %d B on stdout, status %d (device record), pid %d%n", program, args, out.length,
                        status, pid);
            }
            end(backend, status);
        }

        /** what the program wrote on fd: into the pipe (or file) the child put there; unidbg's own console is not the app's */
        private void emit(int fd, byte[] bytes) {
            AndroidFileIO io = fdMap.get(fd);
            if (bytes.length == 0 || io == null || io instanceof com.github.unidbg.linux.file.Stdout) {
                return;
            }
            io.write(bytes);
        }

        /** the child exited with this wait status: the parent goes on with its pid */
        private void end(Backend backend, int status) {
            finish(backend);
            zombies.put(pid, status);
            if (sigchldHandler > 1) {
                System.out.printf("  [shell] child %d exited; the guest's SIGCHLD handler 0x%x is not run (not modelled)%n", pid, sigchldHandler);
            }
            backend.reg_write(Arm64Const.UC_ARM64_REG_X0, pid);
        }

        /** undo the child: the fork fails as unidbg's does */
        void abort(Backend backend, Emulator<?> emulator, String why) {
            finish(backend);
            System.out.printf("  [shell] fork: the child's %s -> undone, the fork fails as unidbg's%n", why);
            backend.reg_write(Arm64Const.UC_ARM64_REG_X0, MetasecSyscalls.super.fork(emulator));
        }

        private void finish(Backend backend) {
            if (journal != null) {
                journal.unhook();
            }
            for (int i = undo.size() - 1; i >= 0; i--) {
                backend.mem_write((Long) undo.get(i)[0], (byte[]) undo.get(i)[1]);
            }
            fdMap.clear();
            fdMap.putAll(fds);
            int[] ids = registerIds();
            for (int i = 0; i < ids.length; i++) {
                backend.reg_write(ids[i], registers[i]);
            }
            for (int i = 0; i < 32; i++) {
                backend.reg_write_vector(Arm64Const.UC_ARM64_REG_Q0 + i, vectors[i]);
            }
            backend.reg_write(UC_ARM64_REG_FPCR, fpcr);
            backend.reg_write(UC_ARM64_REG_FPSR, fpsr);
            child = null;
        }
    }

    /** {@code struct utsname}: six NUL-padded fields of 65 bytes, from the profile's {@code uname} */
    private long uname(Emulator<?> emulator, long pointer) {
        if (pointer == 0) {
            return -UnixEmulator.EFAULT;
        }
        UnidbgPointer struct = UnidbgPointer.pointer(emulator, pointer);
        String[] fields = {"sysname", "nodename", "release", "version", "machine", "domainname"};
        for (int i = 0; i < fields.length; i++) {
            byte[] value = new byte[UTS_FIELD];
            byte[] text = String.valueOf(uname.getString(fields[i])).getBytes(StandardCharsets.UTF_8);
            System.arraycopy(text, 0, value, 0, Math.min(text.length, UTS_FIELD - 1));
            struct.write((long) i * UTS_FIELD, value, 0, UTS_FIELD);
        }
        return 0;
    }

    /**
     * readlink with the kernel's semantics. unidbg writes the path itself back for any path and returns its length + 1, so a
     * probe like readlink("/sys/class/net/tun0") "succeeds" (a VPN interface) and every answer counts a NUL the kernel does not.
     * Here: a symlink of the profile -> its target; /proc/.../fd/N -> the open file's path; a path the app is denied -> -errno;
     * any other existing path -> -EINVAL (not a link); else -ENOENT. Returns null for what is left to unidbg (dirfd != AT_FDCWD).
     */
    private Long readlinkat(Backend backend, Emulator<?> emulator) {
        if ((int) backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue() != IO.AT_FDCWD) {
            return null;
        }
        UnidbgPointer pathname = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X1);
        UnidbgPointer buf = UnidbgPointer.register(emulator, Arm64Const.UC_ARM64_REG_X2);
        int size = backend.reg_read(Arm64Const.UC_ARM64_REG_X3).intValue();
        if (pathname == null || buf == null) {
            return (long) -UnixEmulator.EFAULT;
        }
        String path = pathname.getString(0);
        String target = fs.link(path);
        if (target == null) {
            java.util.regex.Matcher fd = java.util.regex.Pattern.compile("^/proc/(?:self|\\d+)/fd/(\\d+)$").matcher(path);
            if (fd.matches()) {
                com.github.unidbg.file.FileIO io = fdMap.get(Integer.parseInt(fd.group(1)));
                if (io == null) {
                    return (long) -UnixEmulator.ENOENT;
                }
                target = io.getPath();
            }
        }
        if (target == null) {
            int denied = fs.errno(path);
            if (denied != 0) {
                return (long) -denied;
            }
            @SuppressWarnings("unchecked")
            FileResult<AndroidFileIO> found = resolve((Emulator<AndroidFileIO>) emulator, path, IOConstants.O_RDONLY);
            return (long) (found != null && found.isSuccess() ? -UnixEmulator.EINVAL : -UnixEmulator.ENOENT);
        }
        byte[] bytes = target.getBytes(StandardCharsets.UTF_8);
        int n = Math.min(bytes.length, size);
        buf.write(0, bytes, 0, n);
        return (long) n;
    }

    /** {@code struct statfs}, aarch64 (asm-generic, 120 bytes): type, bsize, blocks, bfree, bavail, files, ffree, fsid[2], namelen, frsize, flags, spare[4] */
    private static void writeStatfs(UnidbgPointer buf, JSONObject mount) {
        buf.write(0, new byte[120], 0, 120);
        buf.setLong(0x00, mount.getLongValue("f_type"));
        buf.setLong(0x08, mount.getLongValue("f_bsize"));
        buf.setLong(0x10, mount.getLongValue("f_blocks"));
        buf.setLong(0x18, mount.getLongValue("f_bfree"));
        buf.setLong(0x20, mount.getLongValue("f_bavail"));
        buf.setLong(0x28, mount.getLongValue("f_files"));
        buf.setLong(0x30, mount.getLongValue("f_ffree"));
        buf.setInt(0x38, mount.getJSONArray("f_fsid").getIntValue(0));
        buf.setInt(0x3c, mount.getJSONArray("f_fsid").getIntValue(1));
        buf.setLong(0x40, mount.getLongValue("f_namelen"));
        buf.setLong(0x48, mount.getLongValue("f_frsize"));
        buf.setLong(0x50, mount.getLongValue("f_flags"));
    }

    /** {@code struct sysinfo}, aarch64 layout: 0x00 uptime, 0x08/0x10/0x18 loads, 0x20 totalram, ... , 0x68 mem_unit */
    private long sysinfo(Emulator<?> emulator, long pointer) {
        if (pointer == 0) {
            return -UnixEmulator.EFAULT;
        }
        JSONObject info = sysinfoValues;
        UnidbgPointer struct = UnidbgPointer.pointer(emulator, pointer);
        struct.write(0, new byte[112], 0, 112); // the padding after mem_unit is part of the struct
        struct.setLong(0x00, info.getLongValue("uptime"));
        struct.setLong(0x08, info.getJSONArray("loads").getLongValue(0));
        struct.setLong(0x10, info.getJSONArray("loads").getLongValue(1));
        struct.setLong(0x18, info.getJSONArray("loads").getLongValue(2));
        struct.setLong(0x20, info.getLongValue("totalram"));
        struct.setLong(0x28, info.getLongValue("freeram"));
        struct.setLong(0x30, info.getLongValue("sharedram"));
        struct.setLong(0x38, info.getLongValue("bufferram"));
        struct.setLong(0x40, info.getLongValue("totalswap"));
        struct.setLong(0x48, info.getLongValue("freeswap"));
        struct.setShort(0x50, (short) info.getIntValue("procs"));
        struct.setShort(0x52, (short) 0);
        struct.setLong(0x58, info.getLongValue("totalhigh"));
        struct.setLong(0x60, info.getLongValue("freehigh"));
        struct.setInt(0x68, info.getIntValue("mem_unit"));
        return 0;
    }

    /**
     * SIOCGIFCONF / SIOCGIFFLAGS / SIOCGIFNAME on this socket answer with the device's interface instead of the host's:
     * unidbg's {@code SocketIO.getNetworkIFs} enumerates {@code java.net.NetworkInterface}, which is the machine running the
     * emulator. The one interface is the profile's {@code network}.
     */
    private static class DeviceUdpSocket extends UdpSocket {

        private final JSONObject network;

        DeviceUdpSocket(Emulator<?> emulator, JSONObject network) {
            super(emulator);
            this.network = network;
        }

        @Override
        protected List<NetworkIF> getNetworkIFs(Emulator<?> emulator) throws SocketException {
            return deviceInterfaces(network);
        }

    }

    /**
     * The device's IPv4 interfaces in the kernel's order (registration order: lo first): the profile's {@code network.interfaces},
     * or its one interface for a profile that lists only that
     */
    static List<NetworkIF> deviceInterfaces(JSONObject network) throws SocketException {
        try {
            List<NetworkIF> list = new java.util.ArrayList<>();
            com.alibaba.fastjson.JSONArray interfaces = network.getJSONArray("interfaces");
            for (Object item : interfaces == null ? Arrays.asList((Object) network) : interfaces) {
                JSONObject json = (JSONObject) item;
                Inet4Address ipv4 = (Inet4Address) InetAddress.getByName(json.getString("ipv4"));
                Inet4Address broadcast = json.getString("broadcast") == null ? null : (Inet4Address) InetAddress.getByName(json.getString("broadcast"));
                list.add(new NetworkIF(json.getIntValue("index"), json.getString("name"), ipv4, broadcast));
            }
            return list;
        } catch (IOException e) {
            throw new SocketException(e.getMessage());
        }
    }

    /**
     * unidbg's netlink answers address dumps (from the host's adapters) and nothing else. Here an address dump answers with the
     * device's interfaces, and an IPv4 route dump (RTM_GETROUTE, which an app may make: it is nlmsg_read; bind and RTM_GETLINK are
     * what Android denies) with the routes the kernel and netd keep for them, in the kernel's dump order (tables by id &amp; 255,
     * routes by destination) and attribute order (fib_dump_info: RTA_TABLE, RTA_DST, RTA_PREFSRC, RTA_GATEWAY, RTA_OIF):
     * <ul>
     *   <li>the network's table (netd: 1000 + ifindex): {@code default via <gateway> proto static},
     *       {@code <subnet> proto static scope link};</li>
     *   <li>main: {@code <subnet> proto kernel scope link src <address>} (the prefix route of the address);</li>
     *   <li>local (fib_add_ifaddr): {@code local <subnet>} (lo), {@code local <address>} scope host, {@code broadcast <subnet|~mask>} scope link.</li>
     * </ul>
     * The gateway and the prefixes are the profile's ({@code network.gateway}, {@code interfaces[].prefix}). An IPv6 dump stays
     * empty: the device's IPv6 addresses are not on record.
     */
    private static class RouteDumpNetLink extends NetLinkSocket {

        private static final short RTM_NEWROUTE = 24;
        private static final short RTM_GETROUTE = 0x1a;
        private static final short NLMSG_DONE = 3;
        private static final short NLM_F_MULTI = 2;
        private static final int AF_INET = 2;
        private static final int AF_UNSPEC = 0;
        private static final short RTA_DST = 1, RTA_OIF = 4, RTA_GATEWAY = 5, RTA_PREFSRC = 7, RTA_TABLE = 15;
        private static final int RTN_UNICAST = 1, RTN_LOCAL = 2, RTN_BROADCAST = 3;
        private static final int RTPROT_KERNEL = 2, RTPROT_STATIC = 4;
        private static final int RT_SCOPE_UNIVERSE = 0, RT_SCOPE_LINK = 253, RT_SCOPE_HOST = 254;
        private static final int RT_TABLE_COMPAT = 252, RT_TABLE_MAIN = 254, RT_TABLE_LOCAL = 255;
        private static final int NETD_TABLE_OFFSET = 1000;

        private final Emulator<?> emulator;
        private final JSONObject network;
        private int seq = -1;
        private int family;
        private byte[] pending;

        RouteDumpNetLink(Emulator<?> emulator, JSONObject network) {
            super(emulator);
            this.emulator = emulator;
            this.network = network;
        }

        @Override
        protected List<NetworkIF> getNetworkIFs(Emulator<?> emulator) throws SocketException {
            return network == null ? super.getNetworkIFs(emulator) : deviceInterfaces(network);
        }

        @Override
        public int write(byte[] data) {
            seq = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN).getInt(8);
            family = data.length > 16 ? data[16] & 0xff : AF_UNSPEC;
            pending = null;
            return super.write(data);
        }

        @Override
        protected int handleType(Pointer buffer, int count, short netlinkType) {
            if (netlinkType != RTM_GETROUTE || seq == -1) {
                return super.handleType(buffer, count, netlinkType);
            }
            if (pending == null) {
                pending = routes();
                if (pending.length > 0 && pending.length <= count) {
                    buffer.write(0, pending, 0, pending.length); // the routes; NLMSG_DONE comes with the next read, as the kernel's dump
                    return pending.length;
                }
            }
            ByteBuffer done = ByteBuffer.allocate(20).order(ByteOrder.LITTLE_ENDIAN);
            done.putInt(20).putShort(NLMSG_DONE).putShort(NLM_F_MULTI).putInt(seq).putInt(emulator.getPid()).putInt(0);
            buffer.write(0, done.array(), 0, 20);
            seq = -1;
            pending = null;
            return 20;
        }

        private byte[] routes() {
            if (network == null || network.getString("gateway") == null || (family != AF_INET && family != AF_UNSPEC)) {
                return new byte[0];
            }
            try {
                com.alibaba.fastjson.JSONArray interfaces = network.getJSONArray("interfaces");
                List<NetworkIF> ifs = deviceInterfaces(network);
                byte[] gateway = InetAddress.getByName(network.getString("gateway")).getAddress();
                Map<Integer, java.io.ByteArrayOutputStream> tables = new TreeMap<>();
                for (int i = 0; i < ifs.size(); i++) {
                    NetworkIF nif = ifs.get(i);
                    int prefix = interfaces == null ? network.getIntValue("prefix") : interfaces.getJSONObject(i).getIntValue("prefix");
                    byte[] address = nif.ipv4.getAddress();
                    byte[] subnet = subnet(address, prefix);
                    if (nif.isLoopback()) {
                        route(table(tables, RT_TABLE_LOCAL), RT_TABLE_LOCAL, prefix, subnet, RTN_LOCAL, RTPROT_KERNEL, RT_SCOPE_HOST, address, null, nif.index);
                    } else {
                        int table = NETD_TABLE_OFFSET + nif.index;
                        if (Arrays.equals(subnet, subnet(gateway, prefix))) {
                            route(table(tables, table), table, 0, null, RTN_UNICAST, RTPROT_STATIC, RT_SCOPE_UNIVERSE, null, gateway, nif.index);
                        }
                        route(table(tables, table), table, prefix, subnet, RTN_UNICAST, RTPROT_STATIC, RT_SCOPE_LINK, null, null, nif.index);
                        route(table(tables, RT_TABLE_MAIN), RT_TABLE_MAIN, prefix, subnet, RTN_UNICAST, RTPROT_KERNEL, RT_SCOPE_LINK, address, null, nif.index);
                    }
                    route(table(tables, RT_TABLE_LOCAL), RT_TABLE_LOCAL, 32, address, RTN_LOCAL, RTPROT_KERNEL, RT_SCOPE_HOST, address, null, nif.index);
                    if (prefix < 31) { // fib_add_ifaddr: the network's broadcast, prefix | ~mask (lo has no broadcast address, but this route)
                        byte[] broadcast = ByteBuffer.allocate(4).putInt(ByteBuffer.wrap(subnet).getInt() | ~(prefix == 0 ? 0 : -1 << (32 - prefix))).array();
                        route(table(tables, RT_TABLE_LOCAL), RT_TABLE_LOCAL, 32, broadcast, RTN_BROADCAST, RTPROT_KERNEL, RT_SCOPE_LINK, address, null, nif.index);
                    }
                }
                // the kernel walks the table hash (bucket = id & 255), each table's routes in its trie's key order
                Map<Integer, Integer> order = new TreeMap<>();
                for (int id : tables.keySet()) {
                    order.put(id & 0xff, id);
                }
                java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
                for (int id : order.values()) {
                    out.write(sorted(tables.get(id).toByteArray()));
                }
                return out.toByteArray();
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }

        private static java.io.ByteArrayOutputStream table(Map<Integer, java.io.ByteArrayOutputStream> tables, int id) {
            java.io.ByteArrayOutputStream table = tables.get(id);
            if (table == null) {
                tables.put(id, table = new java.io.ByteArrayOutputStream());
            }
            return table;
        }

        /** a table's messages in the trie's order: by destination, then prefix length */
        private static byte[] sorted(byte[] messages) {
            List<byte[]> list = new java.util.ArrayList<>();
            ByteBuffer buffer = ByteBuffer.wrap(messages).order(ByteOrder.LITTLE_ENDIAN);
            while (buffer.remaining() > 0) {
                byte[] message = new byte[buffer.getInt(buffer.position())];
                buffer.get(message);
                list.add(message);
            }
            list.sort((a, b) -> {
                long ka = key(a), kb = key(b);
                return ka != kb ? Long.compare(ka, kb) : Integer.compare(a[17] & 0xff, b[17] & 0xff);
            });
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            for (byte[] message : list) {
                out.write(message, 0, message.length);
            }
            return out.toByteArray();
        }

        /** the destination of a route message (0 for the default route) */
        private static long key(byte[] message) {
            ByteBuffer buffer = ByteBuffer.wrap(message).order(ByteOrder.LITTLE_ENDIAN);
            for (int at = 28; at + 4 <= message.length; at += (buffer.getShort(at) + 3) & ~3) {
                if (buffer.getShort(at + 2) == RTA_DST) {
                    return ByteBuffer.wrap(message, at + 4, 4).getInt() & 0xffffffffL;
                }
            }
            return 0;
        }

        private void route(java.io.ByteArrayOutputStream out, int table, int prefix, byte[] dst, int type, int protocol, int scope,
                           byte[] prefsrc, byte[] gateway, int oif) {
            int length = 16 + 12 + 8 + (prefix > 0 ? 8 : 0) + (prefsrc != null ? 8 : 0) + (gateway != null ? 8 : 0) + 8;
            ByteBuffer message = ByteBuffer.allocate(length).order(ByteOrder.LITTLE_ENDIAN);
            message.putInt(length).putShort(RTM_NEWROUTE).putShort(NLM_F_MULTI).putInt(seq).putInt(emulator.getPid());
            message.put((byte) AF_INET).put((byte) prefix).put((byte) 0).put((byte) 0) // family, dst_len, src_len, tos
                    .put((byte) (table < 256 ? table : RT_TABLE_COMPAT)).put((byte) protocol).put((byte) scope).put((byte) type).putInt(0);
            message.putShort((short) 8).putShort(RTA_TABLE).putInt(table);
            if (prefix > 0) {
                message.putShort((short) 8).putShort(RTA_DST).put(dst);
            }
            if (prefsrc != null) {
                message.putShort((short) 8).putShort(RTA_PREFSRC).put(prefsrc);
            }
            if (gateway != null) {
                message.putShort((short) 8).putShort(RTA_GATEWAY).put(gateway);
            }
            message.putShort((short) 8).putShort(RTA_OIF).putInt(oif);
            out.write(message.array(), 0, length);
        }

        private static byte[] subnet(byte[] address, int prefix) {
            int value = ByteBuffer.wrap(address).getInt() & (prefix == 0 ? 0 : -1 << (32 - prefix));
            return ByteBuffer.allocate(4).putInt(value).array();
        }

    }
}
