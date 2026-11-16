package com.github.unidbg.android;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.BackendFactory;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.ARM64SyscallHandler;
import com.github.unidbg.linux.android.AndroidARM64Emulator;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.unix.UnixSyscallHandler;

import java.io.File;
import java.util.Collections;

/**
 * CLAUDE.md item 4: a handler is installed, the thread sends itself SIGUSR1 with tgkill and busy-waits for the
 * handler's flag. Runs native/android/tgkill_self.c on one backend (args[0]: unicorn, dynarmic or unicorn2), with the
 * thread dispatcher off and on. Original unidbg never runs the handler, so the wait never ends (bounded here, reported
 * as "handler never ran"); with the signal model (unicorn2) the handler runs before tgkill returns, as on a device.
 */
public class TgkillSelfTest {

    private static final long MAX_SPINS = 20_000_000L;

    public static void main(String[] args) {
        String backend = args.length > 0 ? args[0] : "unicorn2";
        int failures = 0;
        for (boolean threads : new boolean[]{false, true}) {
            AndroidEmulatorBuilder builder = AndroidEmulatorBuilder.for64Bit();
            BackendFactory factory = "dynarmic".equals(backend) ? new DynarmicFactory(false) :
                    "unicorn2".equals(backend) ? new Unicorn2Factory(false) : null;
            if (factory != null) {
                builder.addBackendFactory(factory);
            }
            AndroidEmulator emulator = builder.build();
            emulator.getSyscallHandler().setEnableThreadDispatcher(threads);
            emulator.getMemory().setLibraryResolver(new AndroidResolver(23));
            Module module = emulator.loadLibrary(new File("unidbg-android/src/test/native/android/libs_compat/arm64-v8a/libtgkill_self.so"));
            System.out.printf("== %s, thread dispatcher %s%n", emulator.getBackend().getClass().getSimpleName(), threads ? "on" : "off");
            for (String function : new String[]{"tgkill_self", "raise_self"}) {
                long start = System.nanoTime();
                long spins = module.callFunction(emulator, function, MAX_SPINS).longValue();
                long ms = (System.nanoTime() - start) / 1000000;
                if (spins < 0) {
                    failures++;
                    System.out.printf("  %s: handler never ran, the busy wait would loop forever (gave up after %d spins, %d ms)%n", function, MAX_SPINS, ms);
                } else {
                    System.out.printf("  %s: handler ran, busy wait ended after %d spins (%d ms)%n", function, spins, ms);
                }
            }
        }
        if ("unicorn2".equals(backend)) {
            failures += userOverrideKeepsTgkill();
        }
        System.out.println(failures == 0 ? "PASS" : "FAILED: " + failures + " (the original tgkill self-signal bug)");
        System.exit(failures == 0 ? 0 : 1);
    }

    private static int overrideCalls;

    /**
     * A syscall handler subclass that overrides unidbg's tgkill() keeps the syscall: its override runs instead of the
     * signal model (here it calls the original, which with the dispatcher off never runs the handler).
     */
    private static int userOverrideKeepsTgkill() {
        AndroidEmulator emulator = new AndroidARM64Emulator("tgkill", null, Collections.<BackendFactory>singleton(new Unicorn2Factory(false))) {
            @Override
            protected UnixSyscallHandler<AndroidFileIO> createSyscallHandler(SvcMemory svcMemory) {
                return new ARM64SyscallHandler(svcMemory) {
                    @Override
                    protected int tgkill(Emulator<?> emulator) {
                        overrideCalls++;
                        return super.tgkill(emulator);
                    }
                };
            }
        };
        emulator.getMemory().setLibraryResolver(new AndroidResolver(23));
        Module module = emulator.loadLibrary(new File("unidbg-android/src/test/native/android/libs_compat/arm64-v8a/libtgkill_self.so"));
        long spins = module.callFunction(emulator, "tgkill_self", 1_000_000L).longValue();
        boolean ok = overrideCalls == 1 && spins < 0;
        System.out.printf("== user subclass overriding tgkill(): override called %d time(s), %s -> %s%n", overrideCalls,
                spins < 0 ? "handler not run (the override's decision)" : "handler ran", ok ? "ok" : "FAIL");
        return ok ? 0 : 1;
    }

}
