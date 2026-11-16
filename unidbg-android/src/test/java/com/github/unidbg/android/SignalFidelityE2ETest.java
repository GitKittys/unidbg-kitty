package com.github.unidbg.android;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;

import java.io.File;

/**
 * Loads native/android/signal_fidelity.c (built by native/android/build.sh) and runs its checks through bionic:
 * self-directed delivery, masks and pending signals, nesting, SA_* flags, sigaltstack, rt_sigqueueinfo, real-time
 * queueing, sigsuspend/rt_sigtimedwait, frame contents, threads, a stress run, and SIG_DFL termination.
 * Every expectation is a Linux rule; the library passes on a real arm64 Android device too.
 */
public class SignalFidelityE2ETest {

    private static final File LIBRARY = new File("unidbg-android/src/test/native/android/libs_signal/arm64-v8a/libsignal_fidelity.so");

    public static void main(String[] args) {
        int rounds = args.length > 0 ? Integer.parseInt(args[0]) : 20000;
        int failures = 0;

        AndroidEmulator emulator = createEmulator(false);
        Module module = emulator.loadLibrary(LIBRARY);
        failures += module.callFunction(emulator, "sig_run_all").intValue();

        long start = System.nanoTime();
        failures += module.callFunction(emulator, "sig_stress", rounds).intValue();
        System.out.printf("stress: %d rounds in %.1f ms%n", rounds, (System.nanoTime() - start) / 1e6);

        // SIG_DFL of a terminating signal ends the process: the code after raise() must not run
        Number killed = module.callFunction(emulator, "sig_kill_default");
        if (killed.intValue() == 1234) {
            failures++;
            System.out.println("FAIL raise(SIGTERM) without a handler did not terminate");
        } else {
            System.out.println("ok   raise(SIGTERM) without a handler terminated the emulation");
        }
        // the same when the signal was blocked by a handler's sa_mask and released by its rt_sigreturn
        Number killedLater = module.callFunction(emulator, "sig_kill_after_sigreturn");
        if (killedLater.intValue() == 1234) {
            failures++;
            System.out.println("FAIL SIGTERM released by rt_sigreturn did not terminate");
        } else {
            System.out.println("ok   SIGTERM released by rt_sigreturn terminated the emulation");
        }

        AndroidEmulator threaded = createEmulator(true);
        Module threadedModule = threaded.loadLibrary(LIBRARY);
        failures += threadedModule.callFunction(threaded, "sig_run_threads").intValue();

        System.out.println(failures == 0 ? "PASS" : "FAILED: " + failures);
        System.exit(failures == 0 ? 0 : 1);
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
