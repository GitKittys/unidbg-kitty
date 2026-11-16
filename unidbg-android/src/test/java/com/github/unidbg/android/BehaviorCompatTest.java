package com.github.unidbg.android;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BackendFactory;
import com.github.unidbg.arm.backend.DynarmicFactory;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.debugger.Breaker;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.pointer.UnidbgPointer;
import unicorn.Arm64Const;

import java.io.File;

/**
 * Runs native/android/behavior_compat.c on one backend (args[0]: unicorn, dynarmic or unicorn2) and prints what unidbg
 * reports for each case. Run it on the HEAD baseline and on the working tree and compare: what unidbg tells the user
 * about unimplemented things (JNI, syscalls, kill to other processes, brk/udf without a handler) must not change.
 * Uses public API only, so the same class runs on both trees.
 */
public class BehaviorCompatTest {

    public static void main(String[] args) {
        String backend = args.length > 0 ? args[0] : "unicorn2";
        AndroidEmulatorBuilder builder = AndroidEmulatorBuilder.for64Bit();
        BackendFactory factory = "dynarmic".equals(backend) ? new DynarmicFactory(false) :
                "unicorn2".equals(backend) ? new Unicorn2Factory(false) : null;
        if (factory != null) {
            builder.addBackendFactory(factory);
        }
        AndroidEmulator emulator = builder.build();
        emulator.getMemory().setLibraryResolver(new AndroidResolver(23));
        // a non-interactive stand-in for the debugger: records the report, then steps over the instruction the way a
        // user would before continuing (the engine stays on a brk/udf after the interrupt)
        emulator.getSyscallHandler().setBreaker(new Breaker() {
            @Override
            public void debug(String reason) {
                System.out.println("  BREAKER debug: " + reason);
                if (reason != null && reason.contains("EXCP_UDEF")) {
                    skipInstruction(emulator);
                }
            }

            @Override
            public void brk(UnidbgPointer pc, int svcNumber) {
                System.out.println("  BREAKER brk: pc=" + pc + ", imm=0x" + Integer.toHexString(svcNumber));
                skipInstruction(emulator);
            }
        });
        System.out.println("backend " + emulator.getBackend().getClass().getSimpleName());

        VM vm = emulator.createDalvikVM();
        vm.setJni(new AbstractJni() {
        });
        DalvikModule dm = vm.loadLibrary(new File("unidbg-android/src/test/native/android/libs_compat/arm64-v8a/libbehavior_compat.so"), false);
        Module module = dm.getModule();

        System.out.println("== jni: call an unimplemented Java method");
        try {
            DvmClass cls = vm.resolveClass("com/github/unidbg/android/compat/Native");
            System.out.println("  result=" + cls.callStaticJniMethodInt(emulator, "callMissing()I"));
        } catch (Throwable t) {
            System.out.println("  exception " + t);
        }
        call(emulator, module, "unknown syscall (io_destroy)", "compat_unknown_syscall");
        call(emulator, module, "kill(1, SIGTERM)", "compat_kill_other");
        call(emulator, module, "tgkill to an unknown thread", "compat_tgkill_unknown");
        call(emulator, module, "rt_sigtimedwait forever, single thread", "compat_sigtimedwait_forever");
        call(emulator, module, "sigaction(SIGKILL, act)", "compat_sigaction_sigkill");
        call(emulator, module, "read of unmapped memory without a handler", "compat_read_unmapped");
        // last: dynarmic stops at these (an EL1 register or brk; the same before and after the change)
        call(emulator, module, "mrs sctlr_el1 (EL1 register)", "compat_el1_sysreg");
        call(emulator, module, "udf without SIGILL handler", "compat_udf");
        call(emulator, module, "brk without SIGTRAP handler", "compat_brk");
        call(emulator, module, "raise(SIGTERM) without handler", "compat_raise_default");
        System.out.println("done");
    }

    private static void skipInstruction(AndroidEmulator emulator) {
        Backend backend = emulator.getBackend();
        backend.reg_write(Arm64Const.UC_ARM64_REG_PC, backend.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue() + 4);
    }

    private static void call(AndroidEmulator emulator, Module module, String name, String symbol) {
        System.out.println("== " + name);
        try {
            Number result = module.callFunction(emulator, symbol);
            System.out.println("  result=" + (result == null ? null : "0x" + Long.toHexString(result.longValue())));
        } catch (Throwable t) {
            System.out.println("  exception " + t);
        }
    }

}
