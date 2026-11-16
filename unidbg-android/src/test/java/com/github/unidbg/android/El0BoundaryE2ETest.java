package com.github.unidbg.android;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.debugger.Breaker;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.pointer.UnidbgPointer;
import unicorn.Arm64Const;

import java.io.File;

/**
 * Runs native/android/el0_boundary.c (build with native/android/build.sh) through bionic: real sigaction,
 * sigsetjmp/siglongjmp, ucontext-editing handlers, getauxval. The library checks Linux/architecture rules only, so it
 * passes on a real arm64 Android device as well; here it must pass on the unicorn2 backend.
 */
public class El0BoundaryE2ETest {

    public static void main(String[] args) {
        File library = new File("unidbg-android/src/test/native/android/libs_el0/arm64-v8a/libel0_boundary.so");
        AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit()
                .addBackendFactory(new Unicorn2Factory(false))
                .build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        Module module = emulator.loadLibrary(library);

        int failures = module.callFunction(emulator, "el0_run_all").intValue();

        // No SIGILL handler: on a device the process is killed; unidbg reports the fatal fault to the debugger.
        final Backend backend = emulator.getBackend();
        final String[] fatal = new String[1];
        emulator.getSyscallHandler().setBreaker(new Breaker() {
            @Override
            public void debug(String reason) {
                fatal[0] = reason;
                long pc = backend.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue();
                backend.reg_write(Arm64Const.UC_ARM64_REG_PC, pc + 4);
            }

            @Override
            public void brk(UnidbgPointer pc, int svcNumber) {
                debug("brk at " + pc);
            }
        });
        module.callFunction(emulator, "el0_no_handler");
        if (fatal[0] == null) {
            failures++;
            System.out.println("FAIL privileged instruction without a SIGILL handler was not treated as fatal");
        } else {
            System.out.println("ok   no SIGILL handler -> fatal fault reported: " + fatal[0]);
        }

        // Pointer authentication switched off at the factory: the library must see a core without it (no HWCAP_PACA,
        // ID_AA64ISAR1 APA/API = 0) and still pass every check.
        AndroidEmulator noPac = AndroidEmulatorBuilder.for64Bit()
                .addBackendFactory(new Unicorn2Factory(false).setPointerAuthentication(false))
                .build();
        noPac.getMemory().setLibraryResolver(new AndroidResolver(23));
        int noPacFailures = noPac.loadLibrary(library).callFunction(noPac, "el0_run_all").intValue();
        System.out.println((noPacFailures == 0 ? "ok   " : "FAIL ") + "pointer authentication off: " + noPacFailures + " failures");
        failures += noPacFailures;

        System.out.println(failures == 0 ? "PASS" : "FAILED: " + failures);
        System.exit(failures == 0 ? 0 : 1);
    }

}
