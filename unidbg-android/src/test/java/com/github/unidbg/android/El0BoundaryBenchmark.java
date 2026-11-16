package com.github.unidbg.android;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.BackendFactory;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;

import java.io.File;

/**
 * Cost of the EL0 boundary hooks: a loop of "mrs tpidr_el0" (TLS reads are everywhere in libc) next to a plain loop,
 * on the unicorn2 backend (system instruction hooks) and the default backend (none).
 */
public class El0BoundaryBenchmark {

    public static void main(String[] args) {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 1000000;
        run("unicorn2", new Unicorn2Factory(false), n);
        run("default ", null, n);
        System.exit(0);
    }

    private static void run(String name, BackendFactory factory, int n) {
        AndroidEmulatorBuilder builder = AndroidEmulatorBuilder.for64Bit();
        if (factory != null) {
            builder.addBackendFactory(factory);
        }
        AndroidEmulator emulator = builder.build();
        emulator.getMemory().setLibraryResolver(new AndroidResolver(23));
        Module module = emulator.loadLibrary(new File("unidbg-android/src/test/native/android/libs_el0/arm64-v8a/libel0_boundary.so"));
        module.callFunction(emulator, "el0_bench_tls", 1000);
        module.callFunction(emulator, "el0_bench_loop", 1000);
        long start = System.nanoTime();
        module.callFunction(emulator, "el0_bench_tls", n);
        long tls = System.nanoTime() - start;
        start = System.nanoTime();
        module.callFunction(emulator, "el0_bench_loop", n);
        long loop = System.nanoTime() - start;
        System.out.printf("%s %d iterations: mrs tpidr_el0 loop %.1f ms (%.0f ns/iter), plain loop %.1f ms (%.0f ns/iter)%n",
                name, n, tls / 1e6, (double) tls / n, loop / 1e6, (double) loop / n);
    }

}
