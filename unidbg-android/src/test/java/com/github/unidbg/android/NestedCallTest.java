package com.github.unidbg.android;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;

import java.io.File;

/**
 * A call made from a hook while a call runs (doc/unidbg-bugs-observed.md §1): unidbg refuses it with
 * IllegalStateException("running"). Before the fix its task was added first, so the running call's task list changed
 * under its iteration (ConcurrentModificationException instead of the error) and the task stayed for later calls.
 * On unicorn2 the call is refused before its task is added; the default backend is unchanged.
 */
public class NestedCallTest {

    private static final File LIBRARY = new File("unidbg-android/src/test/native/android/libs_scheduling/arm64-v8a/libthread_scheduling.so");

    private static int failures;

    public static void main(String[] args) {
        for (boolean threads : new boolean[]{false, true}) {
            for (boolean catching : new boolean[]{true, false}) {
                run(true, threads, catching);
            }
        }
        run(false, false, true); // the default backend, for comparison
        System.out.println(failures == 0 ? "PASS" : "FAIL " + failures);
    }

    private static void run(boolean unicorn2, boolean threads, boolean catching) {
        AndroidEmulatorBuilder builder = AndroidEmulatorBuilder.for64Bit();
        if (unicorn2) {
            builder.addBackendFactory(new Unicorn2Factory(false));
        }
        final AndroidEmulator emulator = builder.build();
        emulator.getSyscallHandler().setEnableThreadDispatcher(threads);
        emulator.getMemory().setLibraryResolver(new AndroidResolver(23));
        final Module module = emulator.loadLibrary(LIBRARY);
        long fn = module.findSymbolByName("sch_background_ready", false).getAddress();
        final Throwable[] nested = new Throwable[1];
        final boolean[] once = {false};
        emulator.getBackend().hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                if (once[0]) {
                    return;
                }
                once[0] = true;
                try {
                    module.callFunction(emulator, "sch_background_ready");
                } catch (RuntimeException e) {
                    nested[0] = e;
                    if (!catching) {
                        throw e;
                    }
                }
            }

            @Override
            public void onAttach(UnHook unHook) {
            }

            @Override
            public void detach() {
            }
        }, fn, fn, null);

        String outer;
        try {
            outer = "returned " + module.callFunction(emulator, "sch_background_ready");
        } catch (RuntimeException e) {
            outer = "threw " + e;
        }
        int left = emulator.getThreadDispatcher().getTaskCount();
        String next;
        try {
            next = "returned " + module.callFunction(emulator, "sch_background_ready");
        } catch (RuntimeException e) {
            next = "threw " + e;
        }
        String what = String.format("%s, dispatcher %s, hook %s the error: nested call %s; the running call %s; %d task(s) left; next call %s",
                unicorn2 ? "unicorn2" : "default backend", threads ? "on" : "off", catching ? "catches" : "rethrows",
                nested[0], outer, left, next);
        if (unicorn2) {
            check(nested[0] instanceof IllegalStateException && "running".equals(nested[0].getMessage())
                    && !outer.contains("ConcurrentModification") && left == 0 && "returned 0".equals(next), what);
        } else {
            System.out.println("info " + what);
        }
    }

    private static void check(boolean ok, String what) {
        if (!ok) {
            failures++;
        }
        System.out.println((ok ? "ok   " : "FAIL ") + what);
    }

}
