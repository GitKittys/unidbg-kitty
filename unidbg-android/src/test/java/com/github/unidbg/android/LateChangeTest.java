package com.github.unidbg.android;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.BlockHook;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.ReadHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.arm.backend.WriteHook;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.pointer.UnidbgPointer;
import unicorn.Arm64Const;
import unicorn.UnicornConst;

import java.io.File;

/**
 * The usual unidbg workflow on unicorn2 (doc/diff-07-translated-code.md): call a function once, then patch it, hook it,
 * set a breakpoint, or unmap and map new code at the same address, and run it again. The engine keeps the code it
 * translated; before the fix none of these changes took effect once the code had run.
 */
public class LateChangeTest {

    private static final File LIBRARY = new File("unidbg-android/src/test/native/android/libs_scheduling/arm64-v8a/libthread_scheduling.so");
    private static final long CODE = 0x50000000L;
    private static final long DATA = 0x50010000L;
    private static final long RETURN = 0x50020000L;

    private static int failures;

    public static void main(String[] args) throws Exception {
        library();
        backend();
        System.out.println(failures == 0 ? "PASS" : "FAIL " + failures);
    }

    /** sch_background_ready is "adrp x8, ...; ldr w0, [x8, #...]; ret" */
    private static void library() throws Exception {
        AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit().addBackendFactory(new Unicorn2Factory(false)).build();
        emulator.getMemory().setLibraryResolver(new AndroidResolver(23));
        Module module = emulator.loadLibrary(LIBRARY);
        long fn = module.findSymbolByName("sch_background_ready", false).getAddress();
        int first = module.callFunction(emulator, "sch_background_ready").intValue();

        final int[] reads = {0};
        emulator.getBackend().hook_add_new(new ReadHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                reads[0]++;
            }

            @Override
            public void onAttach(UnHook unHook) {
            }

            @Override
            public void detach() {
            }
        }, module.base, module.base + module.size - 1, null);
        int again = module.callFunction(emulator, "sch_background_ready").intValue();
        check(reads[0] == 1 && again == first, "read hook added after the code ran: %d hit(s), expected 1", reads[0]);

        UnidbgPointer insn = UnidbgPointer.pointer(emulator, fn + 4);
        check((insn.getInt(0) & 0xffc003ff) == 0xb9400100, "fn+4 is ldr w0, [x8, #imm]");
        insn.setInt(0, 0x528000e0); // mov w0, #7
        int patched = module.callFunction(emulator, "sch_background_ready").intValue();
        check(patched == 7, "ldr patched to mov w0, #7 after the code ran: returns %d", patched);

        final int[] hits = {0};
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                hits[0]++;
            }

            @Override
            public void onAttach(UnHook unHook) {
            }

            @Override
            public void detach() {
            }
        }, fn + 4, fn + 4, null);
        module.callFunction(emulator, "sch_background_ready");
        check(hits[0] == 1, "code hook added after the code ran: %d hit(s), expected 1", hits[0]);

        final int[] bp = {0};
        emulator.attach().addBreakPoint(fn + 4, (emu, address) -> {
            bp[0]++;
            return true; // no debugger console
        });
        module.callFunction(emulator, "sch_background_ready");
        check(bp[0] == 1, "breakpoint set after the code ran: %d hit(s), expected 1", bp[0]);
        emulator.close();
    }

    /** "mov x0, #n; str x0, [x1]; str x0, [x1, #8]; ret" run straight on the backend, returning to a nop elsewhere as a call does */
    private static void backend() throws Exception {
        AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit().addBackendFactory(new Unicorn2Factory(false)).build();
        Backend backend = emulator.getBackend();
        backend.mem_map(CODE, 0x1000, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC);
        backend.mem_map(DATA, 0x1000, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_WRITE);
        backend.mem_map(RETURN, 0x1000, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC);
        backend.mem_write(RETURN, new byte[]{0x1f, 0x20, 0x03, (byte) 0xd5}); // nop
        backend.mem_write(CODE, code(1));
        check(run(backend) == 1, "first run stores 1");

        final int[] writes = {0};
        backend.hook_add_new(new WriteHook() {
            @Override
            public void hook(Backend backend, long address, int size, long value, Object user) {
                writes[0]++;
            }

            @Override
            public void onAttach(UnHook unHook) {
            }

            @Override
            public void detach() {
            }
        }, DATA, DATA + 15, null);
        final int[] blocks = {0};
        backend.hook_add_new(new BlockHook() {
            @Override
            public void hookBlock(Backend backend, long address, int size, Object user) {
                blocks[0]++;
            }

            @Override
            public void onAttach(UnHook unHook) {
            }

            @Override
            public void detach() {
            }
        }, CODE, CODE + 0xfff, null);
        run(backend);
        check(writes[0] == 2, "write hook added after the code ran: %d hit(s), expected 2", writes[0]);
        check(blocks[0] == 1, "block hook added after the code ran: %d hit(s), expected 1", blocks[0]);

        backend.mem_write(CODE, code(2));
        long stored = run(backend);
        check(stored == 2, "code rewritten by the host: stores %d, expected 2", stored);

        backend.mem_unmap(CODE, 0x1000);
        backend.mem_map(CODE, 0x1000, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC);
        backend.mem_write(CODE, code(3));
        stored = run(backend);
        check(stored == 3, "unmapped, new code mapped at the same address: stores %d, expected 3", stored);
        emulator.close();
    }

    private static long run(Backend backend) {
        backend.reg_write(Arm64Const.UC_ARM64_REG_X1, DATA);
        backend.reg_write(Arm64Const.UC_ARM64_REG_LR, RETURN);
        // the stop address must not be in the code under test: a block that holds it is not kept
        backend.emu_start(CODE, RETURN, 0, 0);
        byte[] b = backend.mem_read(DATA, 8);
        return (b[0] & 0xff) | (b[1] & 0xff) << 8;
    }

    private static byte[] code(int n) {
        int[] insns = {0xd2800000 | n << 5, 0xf9000020, 0xf9000420, 0xd65f03c0}; // mov x0, #n; str x0, [x1]; str x0, [x1, #8]; ret
        byte[] b = new byte[insns.length * 4];
        for (int i = 0; i < insns.length; i++) {
            for (int j = 0; j < 4; j++) {
                b[i * 4 + j] = (byte) (insns[i] >> (8 * j));
            }
        }
        return b;
    }

    private static void check(boolean ok, String format, Object... args) {
        if (!ok) {
            failures++;
        }
        System.out.printf("%s %s%n", ok ? "ok  " : "FAIL", String.format(format, args));
    }

}
