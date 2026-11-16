package com.github.unidbg.android;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.BackendFactory;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.ARM64SyscallHandler;
import com.github.unidbg.linux.android.AndroidARM64Emulator;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.listener.TraceSystemMemoryWriteListener;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.unix.UnixSyscallHandler;
import org.apache.log4j.AppenderSkeleton;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.LoggingEvent;
import unicorn.Arm64Const;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Syscalls unidbg had no arm64 implementation of (native/android/syscall_fill.c, built by native/android/build.sh), on
 * unicorn2: dup, fsync, getgid/getegid and process_vm_readv on the process itself answer as the kernel does; a syscall
 * unidbg does not have still logs its warning and returns -ENOSYS instead of what x0 held; mapping a procfs file warns
 * and maps as before; readlink writes at most bufsiz bytes, without a NUL. A subclass's handleUnknownSyscall and
 * readlink still come first, and the default backend is unchanged.
 */
public class SyscallFillE2ETest {

    private static final File LIBRARY = new File("unidbg-android/src/test/native/android/libs_syscall/arm64-v8a/libsyscall_fill.so");

    private static final int EBADF = 9, EFAULT = 14, EINVAL = 22, ENOSYS = 38;

    private static int failures;

    private static final List<String> warnings = new ArrayList<>();
    private static final List<String> infos = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        Logger.getLogger(ARM64SyscallHandler.class).addAppender(new AppenderSkeleton() {
            @Override
            protected void append(LoggingEvent event) {
                if (event.getLevel() == Level.WARN) {
                    warnings.add(String.valueOf(event.getMessage()));
                } else if (event.getLevel() == Level.INFO) {
                    infos.add(String.valueOf(event.getMessage()));
                }
            }

            @Override
            public void close() {
            }

            @Override
            public boolean requiresLayout() {
                return false;
            }
        });

        File root = Files.createTempDirectory("syscall_fill").toFile();
        AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit().setRootDir(root).addBackendFactory(new Unicorn2Factory(false)).build();
        emulator.getMemory().setLibraryResolver(new AndroidResolver(23));
        Module module = emulator.loadLibrary(LIBRARY);

        new File(root, "data/local/tmp").mkdirs();
        warnings.clear();
        check(call(module, emulator, "sf_fsync", "/data/local/tmp/sf.txt") == 0, "fsync of a written file: 0");
        check(call(module, emulator, "sf_fsync_bad") == -EBADF, "fsync of a bad fd: EBADF");
        long fd = call(module, emulator, "sf_dup", "/data/local/tmp/sf.txt");
        check(fd > 2 && warnings.isEmpty(), "dup of an open file reads the file: new fd %d %s", fd, warnings);
        check(call(module, emulator, "sf_dup_bad") == -EBADF, "dup of a bad fd: EBADF");
        check(call(module, emulator, "sf_gid") == 0, "getgid and getegid agree with getuid and geteuid (0)");

        // the copy is a system write into the guest's buffer, reported by setTraceSystemMemoryWrite, and the call is logged
        final List<String> systemWrites = new ArrayList<>();
        emulator.setTraceSystemMemoryWrite(0, Long.MAX_VALUE, new TraceSystemMemoryWriteListener() {
            @Override
            public void onWrite(Emulator<?> emulator, long address, byte[] buf) {
                systemWrites.add(new String(buf, java.nio.charset.StandardCharsets.ISO_8859_1));
            }
        });
        infos.clear();
        check(call(module, emulator, "sf_pvr_self") == 24, "process_vm_readv of a string into a stack buffer: 24 bytes, the same bytes");
        boolean traced = false;
        for (String write : systemWrites) {
            traced |= write.startsWith("hello, process_vm_readv");
        }
        boolean logged = false;
        for (String info : infos) {
            logged |= info.startsWith("process_vm_readv of its own memory: 1 element(s)") && info.contains("24 bytes copied");
        }
        check(traced && logged, "process_vm_readv: the copy is reported by setTraceSystemMemoryWrite (%s) and the call logged (%s)", traced, logged);
        emulator.setTraceSystemMemoryWrite(0, 0, null);
        check(call(module, emulator, "sf_pvr_stack") == 32, "process_vm_readv from the stack into two elements: 32 bytes");
        check(call(module, emulator, "sf_pvr_unmapped") == -EFAULT, "process_vm_readv of unmapped memory: EFAULT");
        check(call(module, emulator, "sf_pvr_partial") == 4, "process_vm_readv of a readable then an unmapped element: 4 bytes");
        check(call(module, emulator, "sf_pvr_prot_none") == -EFAULT, "process_vm_readv of a PROT_NONE page: EFAULT");
        check(call(module, emulator, "sf_pvr_bad_flags") == -EINVAL, "process_vm_readv with flags: EINVAL");

        warnings.clear();
        long other = call(module, emulator, "sf_pvr_other");
        check(other == -ENOSYS && warned("NR=270"), "process_vm_readv of another process: not modelled, the unknown syscall warning (%d, %s)", other, warnings);
        warnings.clear();
        long unknown = call(module, emulator, "sf_unknown");
        check(unknown == -ENOSYS && warned("handleInterrupt intno=2, NR=272"), "kcmp, which unidbg does not have: warned as before, then ENOSYS (%d)", unknown);

        // a /proc file the user supplies (here in the rootfs): a device cannot map it
        File status = new File(root, "proc/self/status");
        status.getParentFile().mkdirs();
        Files.write(status.toPath(), "Name:\tsyscall_fill\nTracerPid:\t0\n".getBytes());
        warnings.clear();
        long proc = call(module, emulator, "sf_mmap_file", "/proc/self/status");
        check(proc == 1 && warnings.size() == 1 && warned("mmap of /proc/self/status"), "mmap of /proc/self/status: warned, mapped as before (%d, %s)", proc, warnings);
        warnings.clear();
        long regular = call(module, emulator, "sf_mmap_file", "/data/local/tmp/sf.txt");
        check(regular == 1 && warnings.isEmpty(), "mmap of a regular file: mapped, no warning (%d, %s)", regular, warnings);

        // readlink writes at most bufsiz bytes, without a NUL, and returns that count (which link a path has is unchanged)
        String file = "/data/local/tmp/sf.txt"; // 22 bytes
        long small = call(module, emulator, "sf_readlink", file, 4);
        check(small == (4 << 16 | 4), "readlink with bufsiz 4: 4 bytes written, 4 returned (%d written, %d returned)", small >> 16, small & 0xffff);
        long large = call(module, emulator, "sf_readlink", file, 64);
        check(large == (22 << 16 | 22), "readlink with bufsiz 64: the 22 bytes, no NUL, 22 returned (%d written, %d returned)", large >> 16, large & 0xffff);
        check(call(module, emulator, "sf_readlink", file, 0) == -EINVAL, "readlink with bufsiz 0: EINVAL");
        check(call(module, emulator, "sf_readlink_fd", file, 0) == 1, "readlink of /proc/self/fd/<fd>: the open file's path, as before");
        long byPid = call(module, emulator, "sf_readlink_fd", file, 1);
        check(byPid == 1, "readlink of /proc/<pid>/fd/<fd>: the open file's path too (%d)", byPid);
        long dir = call(module, emulator, "sf_stat_fd_dir");
        check(dir == 1, "stat of /proc/<pid>/fd/ with a trailing slash: the fd directory (%d)", dir);
        emulator.close();

        // a subclass's handleUnknownSyscall comes first for the syscalls unidbg did not have
        AndroidEmulator custom = new AndroidARM64Emulator("syscall_fill", null, Collections.<BackendFactory>singleton(new Unicorn2Factory(false))) {
            @Override
            protected UnixSyscallHandler<AndroidFileIO> createSyscallHandler(SvcMemory svcMemory) {
                return new ARM64SyscallHandler(svcMemory) {
                    @Override
                    protected boolean handleUnknownSyscall(Emulator<?> emulator, int NR) {
                        if (NR == 270 || NR == 272) {
                            emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_X0, 777);
                            return true;
                        }
                        return super.handleUnknownSyscall(emulator, NR);
                    }

                    @Override
                    protected int readlink(Emulator<?> emulator, String path, com.sun.jna.Pointer buf, int bufSize) {
                        buf.setString(0, "/x");
                        return 99;
                    }
                };
            }
        };
        custom.getMemory().setLibraryResolver(new AndroidResolver(23));
        Module customModule = custom.loadLibrary(LIBRARY);
        warnings.clear();
        long pvr = call(customModule, custom, "sf_pvr_self");
        long kcmp = call(customModule, custom, "sf_unknown");
        check(pvr == 777 && kcmp == 777 && warnings.isEmpty(), "a subclass's handleUnknownSyscall answers process_vm_readv and kcmp (%d, %d)", pvr, kcmp);
        long own = call(customModule, custom, "sf_readlink", "/any", 4);
        check(own == (3 << 16 | 99), "a subclass's readlink is used as it is (%d written, %d returned)", own >> 16, own & 0xffff);
        custom.close();

        // the default backend keeps unidbg's original behaviour
        AndroidEmulator original = AndroidEmulatorBuilder.for64Bit().build();
        original.getMemory().setLibraryResolver(new AndroidResolver(23));
        Module originalModule = original.loadLibrary(LIBRARY);
        warnings.clear();
        long kept = call(originalModule, original, "sf_unknown");
        check(kept > 0 && warned("NR=272"), "default backend: kcmp warned and left x0 as it was, the pid (%d)", kept);
        long whole = call(originalModule, original, "sf_readlink", "/data/local/tmp/sf.txt", 4);
        check(whole == (23 << 16 | 23), "default backend: readlink as before, the path and its NUL whatever bufsiz (%d written, %d returned)", whole >> 16, whole & 0xffff);
        long originalDir = call(originalModule, original, "sf_stat_fd_dir");
        check(originalDir == 1, "default backend too: stat of /proc/<pid>/fd/ no longer throws NumberFormatException (%d)", originalDir);
        original.close();

        System.out.println(failures == 0 ? "PASS" : "FAIL " + failures);
    }

    private static long call(Module module, AndroidEmulator emulator, String symbol, Object... args) {
        return module.callFunction(emulator, symbol, args).longValue();
    }

    private static boolean warned(String text) {
        for (String warning : warnings) {
            if (warning.contains(text)) {
                return true;
            }
        }
        return false;
    }

    private static void check(boolean ok, String format, Object... args) {
        if (!ok) {
            failures++;
        }
        System.out.printf("%s %s%n", ok ? "ok  " : "FAIL", String.format(format, args));
    }

}
