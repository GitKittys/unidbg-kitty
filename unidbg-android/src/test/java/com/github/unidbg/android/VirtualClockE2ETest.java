package com.github.unidbg.android;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.backend.BackendFactory;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.ARM64SyscallHandler;
import com.github.unidbg.linux.android.AndroidARM64Emulator;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.unix.UnixSyscallHandler;

import java.io.File;
import java.util.Collections;

/**
 * CLAUDE.md item 3: the guest's clocks on unicorn2. Loads native/android/virtual_clock.c (built by
 * native/android/build.sh): CNTVCT_EL0, CLOCK_MONOTONIC and CLOCK_REALTIME agree, sleeps and timed waits take their
 * time on the clock; then, from the host side: the host sleeping (in a callback, between calls) does not move the
 * guest's clock, the same run reads the same times, and a subclass that pins currentTimeMillis() keeps its time.
 */
public class VirtualClockE2ETest {

    private static final File LIBRARY = new File("unidbg-android/src/test/native/android/libs_clock/arm64-v8a/libvirtual_clock.so");

    private static final long MS = 1000000L;

    private static int failures;

    public static void main(String[] args) throws Exception {
        AndroidEmulator emulator = createEmulator(false);
        Module module = emulator.loadLibrary(LIBRARY);
        failures += module.callFunction(emulator, "vc_run_all").intValue();

        AndroidEmulator threaded = createEmulator(true);
        failures += threaded.loadLibrary(LIBRARY).callFunction(threaded, "vc_run_threads").intValue();

        // the host takes 300 ms inside a call (a slow hook, a debugger): the guest does not see it
        UnidbgPointer hostSleep = emulator.getSvcMemory().registerSvc(new Arm64Svc() {
            @Override
            public long handle(Emulator<?> emulator) {
                try {
                    Thread.sleep(300);
                } catch (InterruptedException e) {
                    throw new IllegalStateException(e);
                }
                return 0;
            }
        });
        long gap = module.callFunction(emulator, "vc_gap", hostSleep).longValue();
        check(gap >= 0 && gap < MS, "the host sleeping 300 ms in a callback: CLOCK_MONOTONIC moved %d ns", gap);
        gap = module.callFunction(emulator, "vc_gap_counter", hostSleep).longValue();
        check(gap >= 0 && gap < MS, "the host sleeping 300 ms in a callback: CNTVCT moved %d ns", gap);

        // between calls the guest does not run: CLOCK_MONOTONIC stays, CLOCK_REALTIME catches up with the wall clock
        long mono = module.callFunction(emulator, "vc_mono").longValue();
        long real = module.callFunction(emulator, "vc_real").longValue();
        Thread.sleep(300);
        long mono2 = module.callFunction(emulator, "vc_mono").longValue();
        long real2 = module.callFunction(emulator, "vc_real").longValue();
        long wall = System.currentTimeMillis() * MS;
        check(mono2 - mono >= 0 && mono2 - mono < MS, "the host sleeping 300 ms between calls: CLOCK_MONOTONIC moved %d ns", mono2 - mono);
        check(real2 - real >= 300 * MS && Math.abs(wall - real2) < 100 * MS,
                "between calls CLOCK_REALTIME caught up with the wall clock (moved %d ms, %d ms from the host's)",
                (real2 - real) / MS, (wall - real2) / MS);

        // the same run reads the same times
        long trace1 = createEmulator(false).loadLibrary(LIBRARY).callFunction(lastEmulator, "vc_trace").longValue();
        long trace2 = createEmulator(false).loadLibrary(LIBRARY).callFunction(lastEmulator, "vc_trace").longValue();
        check(trace1 == trace2, "two emulators, the same computation: the same CLOCK_MONOTONIC and CNTVCT readings (%x, %x)", trace1, trace2);

        // a subclass that pins the wall time keeps it
        final long pinned = 1600000000000L;
        AndroidEmulator fixed = new AndroidARM64Emulator("clock", null, Collections.<BackendFactory>singleton(new Unicorn2Factory(false))) {
            @Override
            protected UnixSyscallHandler<AndroidFileIO> createSyscallHandler(SvcMemory svcMemory) {
                return new ARM64SyscallHandler(svcMemory) {
                    @Override
                    protected long currentTimeMillis() {
                        return pinned;
                    }
                };
            }
        };
        fixed.getMemory().setLibraryResolver(new AndroidResolver(23));
        Module fixedModule = fixed.loadLibrary(LIBRARY);
        long r1 = fixedModule.callFunction(fixed, "vc_real").longValue();
        long m1 = fixedModule.callFunction(fixed, "vc_mono").longValue();
        Thread.sleep(50);
        long r2 = fixedModule.callFunction(fixed, "vc_real").longValue();
        long tv = fixedModule.callFunction(fixed, "vc_gettimeofday_us").longValue();
        long m2 = fixedModule.callFunction(fixed, "vc_mono").longValue();
        check(r1 == pinned * MS && r2 == pinned * MS && tv == pinned * 1000,
                "currentTimeMillis() pinned by a subclass: CLOCK_REALTIME %d and %d ns, gettimeofday %d us", r1, r2, tv);
        check(m2 > m1, "with the wall time pinned, CLOCK_MONOTONIC still runs (%d -> %d ns)", m1, m2);

        System.out.println(failures == 0 ? "PASS" : "FAILED: " + failures);
        System.exit(failures == 0 ? 0 : 1);
    }

    private static void check(boolean ok, String format, Object... args) {
        if (!ok) {
            failures++;
        }
        System.out.println((ok ? "ok   " : "FAIL ") + String.format(format, args));
    }

    private static AndroidEmulator lastEmulator;

    private static AndroidEmulator createEmulator(boolean threads) {
        AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit()
                .addBackendFactory(new Unicorn2Factory(false))
                .build();
        emulator.getSyscallHandler().setEnableThreadDispatcher(threads);
        emulator.getMemory().setLibraryResolver(new AndroidResolver(23));
        lastEmulator = emulator;
        return emulator;
    }

}
