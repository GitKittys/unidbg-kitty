package com.github.unidbg.android;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import unicorn.Arm64Const;
import unicorn.UnicornConst;

/**
 * The unicorn2 engine's own memory handling under load (doc/diff-06-mingw-vfree.md): the translation-block hash
 * table growing several times in one engine, then engines created and closed one after another in one JVM. With the
 * Windows library built before the MinGW qemu_vfree fix both crash the JVM (qht_do_resize_reset, ntdll free).
 */
public class EngineHeapStressTest {

    private static final long CODE = 0x40000000L;

    public static void main(String[] args) throws Exception {
        long start = System.currentTimeMillis();
        run(1500000); // about 1.5M translation blocks: the table grows from 8192 buckets several times
        System.out.printf("ok   1.5M translation blocks in one engine (%d ms)%n", System.currentTimeMillis() - start);
        start = System.currentTimeMillis();
        for (int i = 0; i < 10; i++) {
            run(50000);
        }
        System.out.printf("ok   10 engines created, used and closed one after another (%d ms)%n", System.currentTimeMillis() - start);
        System.out.println("PASS");
    }

    /** n blocks of "add x0, x0, #1; b next": n distinct translation blocks, run twice, then the engine is closed */
    private static void run(int n) throws Exception {
        AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit().addBackendFactory(new Unicorn2Factory(false)).build();
        Backend backend = emulator.getBackend();
        long size = ((long) n * 8 + 4 + 0xfff) & ~0xfffL;
        backend.mem_map(CODE, size, UnicornConst.UC_PROT_READ | UnicornConst.UC_PROT_EXEC);
        byte[] code = new byte[n * 8 + 4];
        for (int i = 0; i < n; i++) {
            put(code, i * 8, 0x91000400); // add x0, x0, #1
            put(code, i * 8 + 4, 0x14000001); // b .+4
        }
        put(code, n * 8, 0xd503201f); // nop
        backend.mem_write(CODE, code);
        for (int round = 0; round < 2; round++) {
            backend.reg_write(Arm64Const.UC_ARM64_REG_X0, 0);
            backend.emu_start(CODE, CODE + (long) n * 8, 0, 0);
            long x0 = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
            if (x0 != n) {
                throw new IllegalStateException("x0=" + x0 + ", expected " + n);
            }
        }
        emulator.close();
    }

    private static void put(byte[] b, int off, int insn) {
        b[off] = (byte) insn;
        b[off + 1] = (byte) (insn >> 8);
        b[off + 2] = (byte) (insn >> 16);
        b[off + 3] = (byte) (insn >> 24);
    }

}
