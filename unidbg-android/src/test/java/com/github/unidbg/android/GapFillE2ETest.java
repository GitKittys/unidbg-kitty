package com.github.unidbg.android;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.file.FileIO;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.unix.FileListener;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/**
 * Operations unidbg did not support although it has their answer (native/android/gap_fill.c, built by
 * native/android/build.sh), on unicorn2: clock() and the clocks it threw for, openat/fstatat/faccessat/readlinkat by a
 * directory fd, FUTEX_WAIT_BITSET/FUTEX_WAKE_BITSET with every bit set. A path that does not exist still fails, the
 * IOResolvers and the FileListener see the whole path, and the default backend is unchanged.
 */
public class GapFillE2ETest {

    private static final File LIBRARY = new File("unidbg-android/src/test/native/android/libs_gap/arm64-v8a/libgap_fill.so");

    private static final int CLOCK_MONOTONIC = 1, CLOCK_PROCESS_CPUTIME_ID = 2;
    private static final int EAGAIN = 11, ETIMEDOUT = 110;
    private static final String DIR = "/data/local/tmp/dir";

    private static int failures;

    public static void main(String[] args) throws Exception {
        File root = Files.createTempDirectory("gap_fill").toFile();
        File dir = new File(root, DIR.substring(1));
        new File(dir, "sub").mkdirs();
        Files.write(new File(dir, "file.txt").toPath(), "hello".getBytes());
        Files.write(new File(dir, "sub/inner.txt").toPath(), "inner".getBytes());
        Files.write(new File(root, "decoy.txt").toPath(), "decoy".getBytes()); // a relative name looked up from the root would find it

        AndroidEmulator emulator = create(true, false, root);
        final List<String> resolved = new ArrayList<>(), opened = new ArrayList<>();
        emulator.getSyscallHandler().addIOResolver(new IOResolver<AndroidFileIO>() {
            @Override
            public FileResult<AndroidFileIO> resolve(Emulator<AndroidFileIO> emulator, String pathname, int oflags) {
                resolved.add(pathname);
                return null;
            }
        });
        emulator.getSyscallHandler().setFileListener(new FileListener() {
            @Override
            public void onOpenSuccess(Emulator<?> emulator, String pathname, FileIO io) {
                opened.add(pathname);
            }

            @Override
            public void onRead(Emulator<?> emulator, String pathname, byte[] bytes) {
            }

            @Override
            public void onWrite(Emulator<?> emulator, String pathname, byte[] bytes) {
            }

            @Override
            public void onClose(Emulator<?> emulator, FileIO io) {
            }
        });
        Module module = emulator.loadLibrary(LIBRARY);

        // clocks
        long clock = call(module, emulator, "gf_libc_clock");
        long cpu = call(module, emulator, "gf_clock", CLOCK_PROCESS_CPUTIME_ID);
        long mono = call(module, emulator, "gf_clock", CLOCK_MONOTONIC);
        check(clock >= 0 && cpu > 0 && cpu <= mono, "clock() %d us, CLOCK_PROCESS_CPUTIME_ID %d ns, not above CLOCK_MONOTONIC %d ns", clock, cpu, mono);
        long sleep = call(module, emulator, "gf_cpu_during_sleep");
        check((sleep >> 32) >= 100 && (sleep & 0xffffffffL) < 5000, "a 100 ms sleep: CLOCK_MONOTONIC +%d ms, CPU time +%d us", sleep >> 32, sleep & 0xffffffffL);
        long work = call(module, emulator, "gf_cpu_during_work");
        check(work > 0, "a loop of a million additions: CPU time +%d us", work);
        long realtime = call(module, emulator, "gf_realtime_clocks"); // in one call: CLOCK_REALTIME catches up with the host's between calls
        check(realtime >= 0 && (realtime >> 32) < 1000 && (realtime & 0xffffffffL) < 1000,
                "CLOCK_REALTIME_COARSE and CLOCK_TAI follow CLOCK_REALTIME (+%d us, +%d us)", realtime >> 32, realtime & 0xffffffffL);

        // *at by a directory fd
        resolved.clear();
        opened.clear();
        long bits = call(module, emulator, "gf_dir", DIR);
        check(bits == 511, "by a directory fd: openat, fstatat, faccessat find file.txt, ../dir/file.txt and sub/inner.txt; missing.txt and the root's decoy.txt are not found (0x%x)", bits);
        check(resolved.contains(DIR + "/file.txt") && resolved.contains(DIR + "/missing.txt") && resolved.contains(DIR + "/decoy.txt") && !resolved.contains("file.txt"),
                "the IOResolvers see the whole paths %s", resolved);
        check(opened.contains(DIR + "/file.txt") && !opened.contains(DIR + "/missing.txt"), "the FileListener sees the file opened by the directory fd %s", opened);
        long scan = call(module, emulator, "gf_fd_scan", DIR + "/file.txt");
        check(scan == 1, "readlinkat on the /proc/self/fd entry of an open file: its path (%d)", scan);

        // futex with every bit set
        check(call(module, emulator, "gf_futex_eagain") == -EAGAIN, "FUTEX_WAIT_BITSET, the word not the value: EAGAIN");
        check(call(module, emulator, "gf_futex_past") == -ETIMEDOUT, "FUTEX_WAIT_BITSET, an absolute timeout already past: ETIMEDOUT");
        long monoWait = call(module, emulator, "gf_futex_timeout", 0);
        long realWait = call(module, emulator, "gf_futex_timeout", 1);
        check(monoWait >= 50 && monoWait < 60 && realWait >= 50 && realWait < 60,
                "FUTEX_WAIT_BITSET until 50 ms ahead on CLOCK_MONOTONIC / CLOCK_REALTIME: times out after %d / %d ms of the guest's time", monoWait, realWait);
        check(call(module, emulator, "gf_futex_wake_none") == 0, "FUTEX_WAKE_BITSET, nobody waiting: 0");
        emulator.close();

        AndroidEmulator threads = create(true, true, root);
        Module threadModule = threads.loadLibrary(LIBRARY);
        long threadWait = call(threadModule, threads, "gf_futex_timeout", 0);
        check(threadWait >= 50 && threadWait < 60, "with the thread dispatcher: FUTEX_WAIT_BITSET times out after %d ms", threadWait);
        long wake = call(threadModule, threads, "gf_futex_wake_thread");
        check(wake == (1 << 8 | 1), "a thread waiting with FUTEX_WAIT_BITSET is woken by FUTEX_WAKE_BITSET (woken %d, waiter got %d)", wake >> 8, wake & 0xff);
        threads.close();

        // the default backend keeps unidbg's original handling
        AndroidEmulator original = create(false, false, root);
        Module originalModule = original.loadLibrary(LIBRARY);
        System.out.printf("info default backend: clock() %d, gf_dir 0x%x (each -1 is an exception that ended the call, as before)%n",
                call(originalModule, original, "gf_libc_clock"), call(originalModule, original, "gf_dir", DIR));
        original.close();

        System.out.println(failures == 0 ? "PASS" : "FAIL " + failures);
    }

    private static AndroidEmulator create(boolean unicorn2, boolean threads, File root) {
        AndroidEmulatorBuilder builder = AndroidEmulatorBuilder.for64Bit();
        builder.setRootDir(root);
        if (unicorn2) {
            builder.addBackendFactory(new Unicorn2Factory(false));
        }
        AndroidEmulator emulator = builder.build();
        emulator.getSyscallHandler().setEnableThreadDispatcher(threads);
        emulator.getMemory().setLibraryResolver(new AndroidResolver(23));
        return emulator;
    }

    private static long call(Module module, AndroidEmulator emulator, String symbol, Object... args) {
        return module.callFunction(emulator, symbol, args).longValue();
    }

    private static void check(boolean ok, String format, Object... args) {
        if (!ok) {
            failures++;
        }
        System.out.printf("%s %s%n", ok ? "ok  " : "FAIL", String.format(format, args));
    }

}
