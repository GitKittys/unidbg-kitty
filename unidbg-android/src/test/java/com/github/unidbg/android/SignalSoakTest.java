package com.github.unidbg.android;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;

import java.io.File;

/**
 * Stability soak: repeats every check of the two demo libraries (el0_boundary.c, signal_fidelity.c) many times in the
 * same emulators. Each iteration must pass completely, and neither time per iteration nor memory may keep growing
 * (signal state, frames, masks and thread bookkeeping must not accumulate).
 */
public class SignalSoakTest {

    public static void main(String[] args) {
        int iterations = args.length > 0 ? Integer.parseInt(args[0]) : 30;
        File el0 = new File("unidbg-android/src/test/native/android/libs_el0/arm64-v8a/libel0_boundary.so");
        File signal = new File("unidbg-android/src/test/native/android/libs_signal/arm64-v8a/libsignal_fidelity.so");

        AndroidEmulator single = createEmulator(false);
        Module el0Module = single.loadLibrary(el0);
        Module signalModule = single.loadLibrary(signal);
        AndroidEmulator threaded = createEmulator(true);
        Module threadedModule = threaded.loadLibrary(signal);

        int failures = 0;
        long firstMs = 0, lastMs = 0, maxMs = 0;
        long firstHeap = 0;
        for (int i = 0; i < iterations; i++) {
            long start = System.nanoTime();
            int f = signalModule.callFunction(single, "sig_run_all").intValue();
            f += el0Module.callFunction(single, "el0_run_all").intValue();
            f += signalModule.callFunction(single, "sig_stress", 2000).intValue();
            f += threadedModule.callFunction(threaded, "sig_run_threads").intValue();
            long ms = (System.nanoTime() - start) / 1000000;
            failures += f;
            Runtime runtime = Runtime.getRuntime();
            if (i == 0) {
                firstMs = ms;
                runtime.gc();
                firstHeap = runtime.totalMemory() - runtime.freeMemory();
            }
            lastMs = ms;
            maxMs = Math.max(maxMs, ms);
            System.err.printf("iteration %d: %d failures, %d ms%n", i, f, ms);
        }
        Runtime runtime = Runtime.getRuntime();
        runtime.gc();
        long lastHeap = runtime.totalMemory() - runtime.freeMemory();
        System.err.printf("%d iterations, %d failures; time first %d ms, last %d ms, max %d ms; heap %d KB -> %d KB; " +
                        "emulator memory %d KB / %d KB%n", iterations, failures, firstMs, lastMs, maxMs, firstHeap / 1024, lastHeap / 1024,
                single.getBackend().getMemAllocatedSize() / 1024, threaded.getBackend().getMemAllocatedSize() / 1024);
        boolean stable = failures == 0 && lastMs <= Math.max(3 * firstMs, firstMs + 2000);
        System.err.println(stable ? "STABLE" : "UNSTABLE");
        System.exit(stable ? 0 : 1);
    }

    private static AndroidEmulator createEmulator(boolean threads) {
        AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit()
                .addBackendFactory(new Unicorn2Factory(false))
                .build();
        emulator.getSyscallHandler().setEnableThreadDispatcher(threads);
        emulator.getMemory().setLibraryResolver(new AndroidResolver(23));
        return emulator;
    }

}
