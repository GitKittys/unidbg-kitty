package com.github.unidbg.android;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.ARM64SyscallHandler;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.memory.MemoryBlock;
import org.apache.log4j.AppenderSkeleton;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.spi.LoggingEvent;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Libraries that need their threads (native/android/thread_scheduling.c, built by native/android/build.sh), on
 * unicorn2 with the thread dispatcher on: timed waits last as long as on a device however slow the emulation is,
 * waiting threads let the guest's time move on instead of the host waiting, background work runs until the threads
 * are idle, finished threads release their stacks at once, and preemption by instruction count (registerEmuCountHook)
 * lets a spinning thread see another thread's progress.
 */
public class ThreadSchedulingE2ETest {

    private static final File LIBRARY = new File("unidbg-android/src/test/native/android/libs_scheduling/arm64-v8a/libthread_scheduling.so");

    private static int failures;

    public static void main(String[] args) {
        AndroidEmulator emulator = createEmulator();
        Module module = emulator.loadLibrary(LIBRARY);

        // a worker that makes syscalls while it works: the main thread's timeout is not cut short by the emulation's speed
        MemoryBlock block = emulator.getMemory().malloc(8, true);
        long start = System.currentTimeMillis();
        int ret = module.callFunction(emulator, "sch_timed_handoff", 1500L, block.getPointer()).intValue();
        long jobMs = block.getPointer().getLong(0);
        check(ret == 0 && jobMs < 1000, "job handed to a worker, main waits up to 1 s: result in time (job %d ms on the guest's clock, %d ms on the host)",
                jobMs, System.currentTimeMillis() - start);

        // the main thread sleeps 1 s while a timer thread ticks every 100 ms: the guest's time moves on, the host does not wait
        start = System.currentTimeMillis();
        int ticks = module.callFunction(emulator, "sch_periodic", 100).intValue();
        long hostMs = System.currentTimeMillis() - start;
        check(ticks >= 9 && ticks <= 10 && hostMs < 1000, "timer every 100 ms while main sleeps 1 s: %d ticks, %d ms on the host", ticks, hostMs);
        int again = module.callFunction(emulator, "sch_periodic", 100).intValue();
        check(again == ticks, "the same run ticks the same way (%d, %d)", ticks, again);

        // background work started by one call: run the threads until they are idle, no guessing how long
        module.callFunction(emulator, "sch_start_background");
        int before = module.callFunction(emulator, "sch_background_ready").intValue();
        emulator.getThreadDispatcher().runThreadsUntilIdle();
        int after = module.callFunction(emulator, "sch_background_ready").intValue();
        check(before == 0 && after == 1, "background worker: not done right after the call (%d), done after runThreadsUntilIdle (%d)", before, after);

        // finished threads release their stacks at once: more than the 16 stack slots in one call
        int ran = module.callFunction(emulator, "sch_sequential_threads", 40).intValue();
        check(ran == 40, "40 threads created and joined one after another in one call: %d ran", ran);

        // preemption by instruction count: a thread spinning without syscalls sees another thread's progress
        AndroidEmulator preemptive = createEmulator();
        preemptive.getBackend().registerEmuCountHook(10000);
        Module spin = preemptive.loadLibrary(LIBRARY);
        long spins = spin.callFunction(preemptive, "sch_spin_handoff", 100_000_000L).longValue();
        check(spins >= 0 && spins < 1_000_000, "registerEmuCountHook(10000): main spinning on a flag sees the worker set it after %d spins", spins);
        long without = module.callFunction(emulator, "sch_spin_handoff", 1_000_000L).longValue();
        System.out.printf("info without registerEmuCountHook the spin never sees the flag (%d): the dispatcher switches threads at syscalls only%n", without);

        // a deadlock: the call can never finish (unidbg keeps waiting, as before), but it says why, once
        final List<String> warnings = new ArrayList<>();
        Logger.getLogger(ARM64SyscallHandler.class).addAppender(new AppenderSkeleton() {
            @Override
            protected void append(LoggingEvent event) {
                if (event.getLevel() == Level.WARN) {
                    warnings.add(String.valueOf(event.getMessage()));
                }
            }

            @Override
            public void close() {
            }

            @Override
            public boolean requiresLayout() {
                return false;
            }
        });
        final AndroidEmulator stuck = createEmulator();
        final Module stuckModule = stuck.loadLibrary(LIBRARY);
        Thread call = new Thread(() -> stuckModule.callFunction(stuck, "sch_deadlock"));
        call.setDaemon(true);
        call.start();
        try {
            call.join(2000);
        } catch (InterruptedException e) {
            throw new IllegalStateException(e);
        }
        check(call.isAlive() && warnings.size() == 1 && warnings.get(0).contains("nothing can wake them up"),
                "deadlock: the call still waits, reported once: %s", warnings);

        System.out.println(failures == 0 ? "PASS" : "FAILED: " + failures);
        System.exit(failures == 0 ? 0 : 1);
    }

    private static AndroidEmulator createEmulator() {
        AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit()
                .addBackendFactory(new Unicorn2Factory(false))
                .build();
        emulator.getSyscallHandler().setEnableThreadDispatcher(true);
        emulator.getMemory().setLibraryResolver(new AndroidResolver(23));
        return emulator;
    }

    private static void check(boolean ok, String format, Object... args) {
        if (!ok) {
            failures++;
        }
        System.out.println((ok ? "ok   " : "FAIL ") + String.format(format, args));
    }

}
