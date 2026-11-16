package com.github.unidbg.android;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.BackendFactory;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;

import java.io.File;

/**
 * Runs native/android/thread_signals.c with the thread dispatcher on: signal delivery between threads, plain threading,
 * and two known limitations of unidbg's thread scheduling, reported but not counted (more than 16 threads in one call;
 * a spin wait without syscalls). Each test runs in its own call. args[0]: unicorn2 (default), unicorn or dynarmic;
 * args[1]: all (default), signals, threads or limits. Uses public API only, so it also runs on the HEAD baseline.
 */
public class ThreadSignalE2ETest {

    private static final File LIBRARY = new File("unidbg-android/src/test/native/android/libs_threads/arm64-v8a/libthread_signals.so");

    public static void main(String[] args) {
        String backend = args.length > 0 ? args[0] : "unicorn2";
        String part = args.length > 1 ? args[1] : "all";
        AndroidEmulator emulator = createEmulator(backend);
        Module module = emulator.loadLibrary(LIBRARY);
        System.out.println("backend " + emulator.getBackend().getClass().getSimpleName());

        int failures = 0;
        if ("all".equals(part) || "signals".equals(part)) {
            failures += runAll(emulator, module, "ts_signal_test");
        }
        if ("all".equals(part) || "threads".equals(part)) {
            failures += runAll(emulator, module, "ts_thread_test");
        }
        if ("all".equals(part) || "limits".equals(part)) {
            // known limitations of unidbg's thread scheduling, each in a fresh emulator: reported, not counted
            AndroidEmulator spin = createEmulator(backend);
            spin.loadLibrary(LIBRARY).callFunction(spin, "ts_run_spin");
            AndroidEmulator many = createEmulator(backend);
            String completed;
            try {
                completed = String.valueOf(many.loadLibrary(LIBRARY).callFunction(many, "ts_sequential_threads", 20));
            } catch (RuntimeException e) {
                completed = e.toString();
            }
            System.out.println(("20".equals(completed) ? "ok   " : "info ") + "20 threads one after another in one call: " + completed);
        }
        System.out.println(failures == 0 ? "PASS" : "FAILED: " + failures);
        System.exit(failures == 0 ? 0 : 1);
    }

    private static int runAll(AndroidEmulator emulator, Module module, String function) {
        int failures = 0;
        for (int i = 0; ; i++) {
            int result;
            try {
                result = module.callFunction(emulator, function, i).intValue();
            } catch (RuntimeException e) {
                System.out.println("FAIL " + function + "(" + i + "): " + e);
                failures++;
                continue;
            }
            if (result == -1) {
                return failures;
            }
            failures += result;
        }
    }

    private static AndroidEmulator createEmulator(String backend) {
        AndroidEmulatorBuilder builder = AndroidEmulatorBuilder.for64Bit();
        BackendFactory factory = "dynarmic".equals(backend) ? new DynarmicFactory(false) :
                "unicorn2".equals(backend) ? new Unicorn2Factory(false) : null;
        if (factory != null) {
            builder.addBackendFactory(factory);
        }
        AndroidEmulator emulator = builder.build();
        emulator.getSyscallHandler().setEnableThreadDispatcher(true);
        emulator.getMemory().setLibraryResolver(new AndroidResolver(23));
        return emulator;
    }

}
