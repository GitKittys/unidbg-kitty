package com.github.unidbg.android;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;

import java.io.File;

/**
 * Loads native/android/memory_fault.c (built by native/android/build.sh) and runs its checks through bionic: SIGSEGV
 * for unmapped and protected memory with the kernel's siginfo/ucontext, retry after the handler repairs the mapping,
 * sigsetjmp/siglongjmp probes, instruction fetch faults, precise faults, a fault inside another handler, a stack
 * overflow caught on the alternate stack, an atomic on a read-only page, a fault in a worker thread; then a handler that
 * never repairs its fault (stopped instead of hanging) and a fault without a handler (unidbg's original error).
 */
public class MemoryFaultE2ETest {

    private static final File LIBRARY = new File("unidbg-android/src/test/native/android/libs_memfault/arm64-v8a/libmemory_fault.so");

    public static void main(String[] args) {
        int failures = 0;

        AndroidEmulator emulator = createEmulator(false);
        Module module = emulator.loadLibrary(LIBRARY);
        failures += module.callFunction(emulator, "mem_run_all").intValue();

        AndroidEmulator threaded = createEmulator(true);
        failures += threaded.loadLibrary(LIBRARY).callFunction(threaded, "mem_run_threads").intValue();

        long start = System.nanoTime();
        int unfixed = createAndLoad().callFunction(emulatorOf(), "mem_fault_unfixed").intValue();
        long ms = (System.nanoTime() - start) / 1000000;
        if (unfixed == 1234) {
            failures++;
            System.out.println("FAIL a handler that never repairs its fault: execution went on past the fault");
        } else {
            System.out.printf("ok   a handler that never repairs its fault: emulation stopped after %d ms (on a device it loops forever)%n", ms);
        }

        int noHandler = createAndLoad().callFunction(emulatorOf(), "mem_fault_no_handler").intValue();
        if (noHandler == 1234) {
            failures++;
            System.out.println("FAIL SIGSEGV without a handler: execution went on past the fault");
        } else {
            System.out.println("ok   SIGSEGV without a handler: unidbg's original invalid-memory error (" + noHandler + ")");
        }

        // the default (no setMemoryFaultSignals): the fault stays unidbg's emulation error even with a guest handler
        AndroidEmulator byDefault = AndroidEmulatorBuilder.for64Bit()
                .addBackendFactory(new Unicorn2Factory(false))
                .build();
        byDefault.getMemory().setLibraryResolver(new AndroidResolver(23));
        int probe = byDefault.loadLibrary(LIBRARY).callFunction(byDefault, "mem_probe_once").intValue();
        if (probe == 1234) {
            failures++;
            System.out.println("FAIL memory fault signals off by default: the guest handler took the fault");
        } else {
            System.out.println("ok   memory fault signals off by default: unidbg's original invalid-memory error (" + probe + ")");
        }

        System.out.println(failures == 0 ? "PASS" : "FAILED: " + failures);
        System.exit(failures == 0 ? 0 : 1);
    }

    private static AndroidEmulator last;

    private static Module createAndLoad() {
        last = createEmulator(false);
        return last.loadLibrary(LIBRARY);
    }

    private static AndroidEmulator emulatorOf() {
        return last;
    }

    private static AndroidEmulator createEmulator(boolean threads) {
        AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit()
                .addBackendFactory(new Unicorn2Factory(false).setMemoryFaultSignals(true))
                .build();
        emulator.getSyscallHandler().setEnableThreadDispatcher(threads);
        emulator.getMemory().setLibraryResolver(new AndroidResolver(23));
        return emulator;
    }

}
