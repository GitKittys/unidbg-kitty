package com.bytedance.mobsec.metasec.ml;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Emulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.Arm64Svc;
import com.github.unidbg.arm.backend.BackendFactory;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.file.linux.AndroidFileIO;
import com.github.unidbg.linux.android.AndroidARM64Emulator;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.ElfLibraryFile;
import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmClassFactory;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.wrapper.DvmBoolean;
import com.github.unidbg.linux.android.dvm.wrapper.DvmInteger;
import com.github.unidbg.linux.android.dvm.wrapper.DvmLong;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.memory.SvcMemory;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.unix.UnixSyscallHandler;
import com.github.unidbg.virtualmodule.android.AndroidModule;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Local test of the framework with douyin 39.4.0's libmetasec_ml.so and one device's recorded values: the app's init calls are
 * made in the order the device made them (README_初始化流程 2/9; the calls and their arguments come from the recording), then the
 * sign entry the network library registered is called once, and each step is checked against what the device showed: f3.a's
 * results, the init flags (0x4 after JNI_OnLoad, 0xc after 0x1000003, 0x7f once the sign callbacks are registered, 0x1ff after a
 * sign), the check chain d350..d360 recomputed from seed/k with the README formula, the instance's config fields, the sdi token
 * metasec loads from the persisted state, and the sign output against the block the device returned for the same request.
 * <p>
 * The device is data, not code, and it is one file: the profile ({@code device/fp_values_full.json}, or {@code -Dmetasec.profile})
 * holds the recorded calls and values, the system properties, every file the app sees that is this device's ({@code fs}: /proc,
 * /sys, the app's persisted state, the APK ranges metasec reads, what SELinux denies), struct sysinfo, uname, the network interface
 * and the shell commands' output. {@code src/test/resources/example_binaries/metasec/rootfs} is only the system skeleton with the
 * app's libraries; {@code session.json} is the calls to make and {@code sign_request.json} the request to sign. Another device =
 * another profile. Each run copies the rootfs to {@code target/rootfs/metasec-<n>}, writes the profile's files and the property
 * area into it. Run from the repository root.
 * args: [-v] (unidbg's JNI trace)
 */
public class MetasecSign {

    /** -Dchain.debug=true: extra tracing while bringing the library up (same switch the replay tools use) */
    static final boolean DEBUG = Boolean.getBoolean("chain.debug");

    private static final File RESOURCES = Build.RESOURCES;
    /**
     * One rootfs per instance: concurrent instances must not share (nor delete) each other's files. The counter alone is not
     * enough once two JVMs run at the same time — each would start at 1 and the second would delete the first's rootfs while
     * it was in use — so the process's own pid comes first. {@code -Dmetasec.rootfs=<name>} picks one explicitly.
     */
    private static final java.util.concurrent.atomic.AtomicInteger RUNS = new java.util.concurrent.atomic.AtomicInteger();
    private static final String PROCESS = java.lang.management.ManagementFactory.getRuntimeMXBean().getName()
            .replaceAll("\\W", "_");
    private final File ROOT_DIR = new File("target/rootfs/" + System.getProperty("metasec.rootfs",
            "metasec-" + PROCESS + "-" + RUNS.incrementAndGet()));
    /** the rendered /proc/self/{status,stat,task}, kept for -Dmetasec.dumpProcess */
    private MetasecStartup.ProcessView processView;
    private static final String F3_A = "a(IIJLjava/lang/String;Ljava/lang/Object;)Ljava/lang/Object;";


    private final List<String> failures = new ArrayList<>();
    private final List<String> differences = new ArrayList<>();
    private final long[] signEntries = new long[2];
    private final Map<String, DvmObject<?>> instances = new HashMap<>();

    private AndroidEmulator emulator;
    private final java.util.concurrent.atomic.AtomicBoolean closed = new java.util.concurrent.atomic.AtomicBoolean();
    private MetasecSyscalls syscalls;
    private VM vm;
    private DvmClass f3;
    private Module libc;
    private DeviceProfile profile;
    private Build build;
    private ProfileJni jni;
    private long base;
    private MetasecState state;
    private Keva keva;
    private long handle;
    private String appId;
    /** the sdi token the persisted state held before the run (what the Keva file has) */
    private String persistedSdiToken;
    private boolean recordedNetwork;
    private UnidbgPointer[] setters;
    /** the moment of the recording (ms) the run has reached */
    private long timeline;
    private ArrayObject callbacks;

    public static void main(String[] args) throws Exception {
        boolean verbose = args.length > 0 && "-v".equals(args[0]);
        MetasecSign test = new MetasecSign();
        for (int attempt = 1; ; attempt++) {
            try {
                test.run(verbose, true); // the test signs the recorded reference request and checks it
            } catch (RuntimeException e) {
                e.printStackTrace(System.out);
                test.failures.add("stopped: " + e);
            }
            boolean flake = test.failures.toString().contains("expected 0x1ff");
            if (!flake || attempt >= 3) {
                break;
            }
            // the component init occasionally does not take the registering path at the recorded sign moment (see
            // doc/metasec-local-test.md "已知缺口"): one more attempt with a fresh emulator
            System.out.println("== the sign call did nothing (flags stayed 0x7f), attempt " + attempt + " of 3");
            test = new MetasecSign();
        }
        System.exit(test.report() ? 0 : 1);
    }

    /**
     * Brings metasec up the way the device did and makes the recorded calls.
     *
     * @param referenceSign also sign the recorded request and check it (the test); the request tool signs its own URL instead
     */
    /** -Dmetasec.phases=true: how long each stage of the init took, for finding where a run's time goes */
    private final boolean phases = Boolean.getBoolean("metasec.phases");
    private long phaseStart = System.nanoTime();

    private void phase(String what) {
        if (phases) {
            long now = System.nanoTime();
            System.out.printf("  [phase] %-34s %6.0f ms%n", what, (now - phaseStart) / 1e6);
            phaseStart = now;
        }
    }

    void run(boolean verbose, boolean referenceSign) throws Exception {
        FileUtils.deleteDirectory(ROOT_DIR);
        FileUtils.copyDirectory(new File(RESOURCES, "rootfs"), ROOT_DIR);
        phase("rootfs copy");
        // -Dmetasec.profile=<file> picks another recorded session (e.g. the mask-215 one, which signs with 0x290c5c
        // and answers six headers instead of seven)
        profile = new DeviceProfile(new File(System.getProperty("metasec.profile",
                new File(RESOURCES, "device/fp_values_full.json").getPath())));
        build = new Build(new File(RESOURCES, "device/metasec.json"));
        // 设备的文件全部来自档案的 fs（/proc、/sys、App 的持久化、APK……）；rootfs 只是系统骨架 + App 的 so
        final MetasecStartup.ProfileFs fs = new MetasecStartup.ProfileFs(profile.fs(), profile.dir(), new File(RESOURCES, "device"));
        fs.materialize(ROOT_DIR);
        phase("profile fs materialize");
        JSONObject session = json(System.getProperty("metasec.session", "device/session.json"));
        FileUtils.writeByteArrayToFile(new File(ROOT_DIR, "dev/__properties__"), MetasecStartup.PropertyArea.build(profile.properties()));

        emulator = new AndroidARM64Emulator(build.packageName(), ROOT_DIR, Collections.<BackendFactory>singleton(new Unicorn2Factory(false))) {
            @Override
            protected UnixSyscallHandler<AndroidFileIO> createSyscallHandler(SvcMemory svcMemory) {
                return syscalls = new MetasecSyscalls(svcMemory);
            }
        };
        emulator.getSyscallHandler().setEnableThreadDispatcher(true);
        syscalls.device(profile, fs);
        Memory memory = emulator.getMemory();
        // popen/system answered from the device's own recorded output
        Object shell = profile.section("shell_commands");
        memory.addHookListener(new MetasecStartup.ShellReplay(emulator, shell == null ? new JSONArray() : (JSONArray) shell));
        final String libraryPath = devicePath(build.library());
        // both native libraries live in the same emulator: the encryptor is loaded on top of the metasec init
        memory.setLibraryResolver(new MetasecStartup.RootfsLibraryResolver(new AndroidResolver(23), ROOT_DIR, libraryPath,
                build.encryptor()));
        emulator.getSyscallHandler().addIOResolver(new MetasecStartup.ProcSelf(ROOT_DIR));
        emulator.getSyscallHandler().addIOResolver(new MetasecStartup.DataDataAlias(ROOT_DIR));
        emulator.getSyscallHandler().addIOResolver(fs); // registered late = asked early: denied paths, links, recorded stat
        String mapsExtra = System.getProperty("metasec.mapsExtra");
        String dumpMaps = System.getProperty("metasec.dumpMaps");
        MetasecStartup.MapsView maps = new MetasecStartup.MapsView(
                mapsExtra == null ? null : FileUtils.readFileToString(new File(mapsExtra), StandardCharsets.UTF_8),
                dumpMaps == null ? null : new File(dumpMaps));
        Object mapped = profile.section("mapped_files");
        if (mapped instanceof JSONObject) {
            maps.mapFiles(emulator, (JSONObject) mapped, profile.fs(), ROOT_DIR);
        }
        if (maps.active()) {
            emulator.getSyscallHandler().addIOResolver(maps);
        }
        Object process = profile.section("process");
        if (process != null) {
            // /proc/self/{status,stat,task}: the emulator's own pid and threads in the device's process (asked first)
            MetasecStartup.ProcessView view = new MetasecStartup.ProcessView((JSONObject) process, emulator, syscalls);
            syscalls.processName(view.comm());
            emulator.getSyscallHandler().addIOResolver(view);
            processView = view;
        }

        if (System.getProperty("metasec.watch") != null) {
            // diagnostic: every guest write to this address (the instruction, its caller, the value, the guest clock)
            final long watched = Long.decode(System.getProperty("metasec.watch"));
            emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.WriteHook() {
                private int writes;

                @Override
                public void hook(com.github.unidbg.arm.backend.Backend b, long address, int size, long value, Object user) {
                    long pc = b.reg_read(unicorn.Arm64Const.UC_ARM64_REG_PC).longValue();
                    long lr = b.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue();
                    com.github.unidbg.thread.Task task = emulator.get(com.github.unidbg.thread.Task.TASK_KEY);
                    if (++writes <= 200 || writes % 1000 == 0) {
                        System.out.printf("  [watch] #%d pc=0x%x lr=0x%x size=%d value=%d task=%s t=%d ms%n", writes,
                                base == 0 ? pc : pc - base, base == 0 ? lr : lr - base, size, value,
                                task == null ? "-" : String.valueOf(task.getId()), syscalls.guestTimeMillis());
                    }
                }

                @Override
                public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
                }

                @Override
                public void detach() {
                }
            }, watched, watched + 3, null);
        }
        libc = memory.dlopen("libc.so");
        MetasecStartup.cpuCount(emulator, libc, profile.fs());
        checkProperties();
        // the process environment beyond unidbg's: what the device's process had from zygote and the framework (the profile's
        // environ), then what the app sets before System.loadLibrary("metasec_ml") (d3.LIZIZ, README 2 #0)
        List<String> inherited = new ArrayList<>();
        List<String[]> environment = new ArrayList<>();
        Object environ = profile.section("environ");
        if (environ instanceof JSONObject) {
            JSONArray from = ((JSONObject) environ).getJSONArray("inherited");
            for (int i = 0; from != null && i < from.size(); i++) {
                inherited.add(from.getString(i));
            }
            JSONArray set = ((JSONObject) environ).getJSONArray("set");
            for (int i = 0; set != null && i < set.size(); i++) {
                String entry = set.getString(i);
                environment.add(new String[]{entry.substring(0, entry.indexOf('=')), entry.substring(entry.indexOf('=') + 1)});
            }
        }
        environment.add(build.environment());
        MetasecStartup.environment(emulator, libc, inherited, environment);

        phase("emulator + libc up");
        vm = emulator.createDalvikVM();
        phase("createDalvikVM");
        // JNI method/field ids as ART's (addresses laid out per launch), set before any class is resolved;
        // -Dmetasec.artSeed=<n> pins the layout for comparison runs
        Long artSeed = Long.getLong("metasec.artSeed");
        vm.setHashFunction(new MetasecStartup.ArtIds(artSeed != null ? artSeed : new java.security.SecureRandom().nextLong()));
        vm.setVerbose(verbose);
        // metasec calls methods through the method IDs of superclasses (Object.getClass, ClassLoader.loadClass...): unidbg finds
        // them through the class hierarchy, so classes get the superclass the recording shows, else Object
        final DvmClass object = vm.resolveClass("java/lang/Object");
        final Map<String, String> supertypes = profile.supertypes();
        vm.setDvmClassFactory(new DvmClassFactory() {
            @Override
            public DvmClass createClass(BaseVM vm, String className, DvmClass superClass, DvmClass[] interfaceClasses) {
                String recorded = supertypes.get(className.replace('/', '.'));
                if (superClass == null) {
                    superClass = recorded == null ? object : vm.resolveClass(recorded);
                }
                return vm.createClass(vm, className, superClass, interfaceClasses);
            }
        });
        f3 = vm.resolveClass("ms/bd/c/f3");
        DvmClass m2 = vm.resolveClass("ms/bd/c/m2", f3);
        vm.resolveClass("com/bytedance/mobsec/metasec/ml/MS", m2);
        Map<Integer, Object> msbOverrides = new HashMap<>();
        for (Map.Entry<String, Object> entry : session.getJSONObject("msb").entrySet()) {
            msbOverrides.put(Long.decode(entry.getKey()).intValue(), entry.getValue());
        }
        keva = new Keva(new File(ROOT_DIR, "data/user/0/" + build.packageName() + "/files/keva/repo"));
        // metasec 自己的 keva（sdi token、计数、kd 键）来自档案的 keva_read——录制里 metasec 读过的键全在里面；
        // 没列出的键 = 不存在。metasec 运行中写入的值照常覆盖
        for (Map.Entry<String, String> entry : profile.kevaRead().entrySet()) {
            keva.put(build.kevaRepo(), entry.getKey(), entry.getValue());
        }
        String network = System.getProperty("metasec.network", session.getString("network"));
        recordedNetwork = "recorded".equals(network);
        jni = new ProfileJni(profile, keva, msbOverrides, recordedNetwork, () -> syscalls.guestTimeMillis());
        // This install's own accelerometer. metasec polls for samples every 10 s and reports them as a series, so replaying
        // the recorded answers makes the device read as one that was left on a table and whose sensor then stopped
        // (the replay clamps to the last recorded answer). The behaviour is data (device/motion.json,
        // device/dynamic.json); the code holds the clock and the invariants. Seeded from this install's id so one install
        // stays one phone across its launches while a cohort is a cohort of different phones. Without
        // -Dmetasec.motion every recorded answer is replayed exactly as before.
        String motionSeed = System.getProperty("metasec.motion");
        if (motionSeed != null && !motionSeed.isEmpty()) {
            jni.motion(new Motion(data(System.getProperty("metasec.motionData", "device/motion.json")), seeded(motionSeed)));
            // what the last launch left behind, for the answers that have to carry over
            JSONObject ledger = null;
            String statePath = System.getProperty("metasec.state");
            if (statePath != null && !statePath.isEmpty()) {
                ledger = DeviceState.read(new File(statePath)).values();
            }
            jni.dynamic(new DynamicValues(data(System.getProperty("metasec.dynamicData", "device/dynamic.json")),
                    seeded(motionSeed), ledger));
        }
        if ("live".equals(network)) {
            // Sending metasec's own mssdk traffic for real needs a recorded channel (device/mssdk_http.json) and the
            // sender that drives it; neither ships with this example, which signs and reports offline.
            throw new IllegalStateException("metasec.network=live is not available in this example: it signs offline. "
                    + "Use the default (recorded) network, or supply your own channel.");
        }
        vm.setJni(jni);
        new AndroidModule(emulator, vm).register(memory);
        setters = new UnidbgPointer[]{setter(0), setter(1)};

        final String library = libraryPath;
        step("dlopen(" + library + ") like System.loadLibrary + JNI_OnLoad");
        Module module = memory.dlopen(library); // unidbg's ld entry: the resolver above reads it from the rootfs by device path
        if (module == null) {
            System.out.println("  dlopen resolved nothing, loading the file directly");
            module = memory.load(new ElfLibraryFile(new File(ROOT_DIR, library), true) {
                @Override
                public String getPath() {
                    return library;
                }
            }, true);
        } else {
            System.out.printf("  dlopen %s -> module at 0x%x%n", module.name, module.base);
        }
        base = module.base;
        moduleSize = module.size;
        state = new MetasecState(emulator, base, build);
        for (final String name : new String[]{"pthread_cond_wait", "pthread_cond_timedwait", "pthread_cond_signal", "pthread_cond_broadcast"}) {
            final com.github.unidbg.Symbol symbol = libc.findSymbolByName(name, false);
            if (symbol == null) {
                System.out.println("  [wait] " + name + ": not in libc");
                continue;
            }
            final int[] count = new int[1];
            waitCounts.put(name, count);
            emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                @Override
                public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                    count[0]++;
                    long cond = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue();
                    com.github.unidbg.thread.Task task = emulator.get(com.github.unidbg.thread.Task.TASK_KEY);
                    if (count[0] <= 3 || count[0] % 50 == 0) {
                        System.out.printf("  [wait] %-24s #%d t=%d task=%s cond=0x%x%n", name, count[0], System.currentTimeMillis(),
                                task == null ? "-" : String.valueOf(task.getId()), cond);
                    }
                }

                @Override
                public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
                }

                @Override
                public void detach() {
                }
            }, symbol.getAddress(), symbol.getAddress(), null);
        }
        for (String text : System.getProperty("metasec.probeThreads", "").split(",")) {
            if (text.trim().isEmpty()) {
                continue;
            }
            final long offset = Long.decode(text.trim());
            final int[] count = new int[1];
            counts.put(offset, count);
            emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                @Override
                public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                    if (++count[0] <= 3) {
                        if (offset == 0x4a1998) {
                            long p = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X1).longValue();
                            try {
                                System.out.printf("    [cond] x0=0x%x x1=0x%x [x1]=0x%x [x1+8]=0x%x  (now ms=%d)%n", 
                                        backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue(), p,
                                        UnidbgPointer.pointer(emulator, p).getLong(0), UnidbgPointer.pointer(emulator, p + 8).getLong(0),
                                        syscalls.guestTimeMillis());
                            } catch (RuntimeException ignored) {
                            }
                        }
                        com.github.unidbg.thread.Task task = emulator.get(com.github.unidbg.thread.Task.TASK_KEY);
                        System.out.printf("  [threads] metasec+0x%x hit #%d task=%s lr=metasec+0x%x x0=0x%x x1=0x%x%n", offset, count[0],
                                task == null ? "-" : String.valueOf(task.getId()),
                                backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue() - base,
                                backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue(),
                                backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X1).longValue());
                    }
                }

                @Override
                public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
                }

                @Override
                public void detach() {
                }
            }, base + offset, base + offset, null);
        }

        if (System.getProperty("metasec.traceFn") != null) {
            // diagnostic: what a function of libmetasec reads while it runs (syscalls, system registers) and what it returns
            final long fn = base + Long.decode(System.getProperty("metasec.traceFn"));
            final com.github.unidbg.arm.backend.Backend backend = emulator.getBackend();
            backend.hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                private int calls;

                @Override
                public void hook(com.github.unidbg.arm.backend.Backend b, long address, int size, Object user) {
                    final long lr = b.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue();
                    final int call = ++calls;
                    System.out.printf("  [trace] enter 0x%x #%d (lr 0x%x) x0=0x%x x1=0x%x%n", fn - base, call, lr - base,
                            b.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue(),
                            b.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X1).longValue());
                    syscalls.tracing = true;
                    vm.setVerbose(true); // unidbg prints each JNI call while the function runs
                    b.hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                        private boolean done;

                        @Override
                        public void hook(com.github.unidbg.arm.backend.Backend b2, long at, int sz, Object u) {
                            if (done) {
                                return;
                            }
                            done = true;
                            syscalls.tracing = false;
                            vm.setVerbose(false);
                            byte[] d0 = b2.reg_read_vector(unicorn.Arm64Const.UC_ARM64_REG_Q0);
                            double value = java.nio.ByteBuffer.wrap(d0, 0, 8).order(java.nio.ByteOrder.LITTLE_ENDIAN).getDouble();
                            System.out.printf("  [trace] leave #%d x0=0x%x d0=%s%n", call,
                                    b2.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue(), value);
                        }

                        @Override
                        public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
                        }

                        @Override
                        public void detach() {
                        }
                    }, lr, lr, null);
                    b.removeJitCodeCache(lr, lr + 4);
                }

                @Override
                public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
                }

                @Override
                public void detach() {
                }
            }, fn, fn, null);
            backend.removeJitCodeCache(fn, fn + 4);
        }
        if (Boolean.getBoolean("metasec.patchContainer")) {
            new ContainerPatch(emulator, base, new File(RESOURCES, "device/mssdk_descs.json"),
                    new File(System.getProperty("metasec.patchFile", new File(RESOURCES, "device/mssdk_patch.json").getPath())))
                    .install(0x265244L);
        }
        if (System.getProperty("metasec.sts") != null || System.getProperty("metasec.dyn") != null) {
            installSignalOverrides();
        }
        if (Boolean.getBoolean("metasec.dumpVmSlots")) {
            installVmSlotDump();
        }
        if (Boolean.getBoolean("metasec.probeVm")) {
            // 215 变体是六个独立的 VM 程序，都由 sub_173BA4(blob, args, table1, table2, cb) 跑起来；
            // 记下每次的 x0(blob)/x1/x2(参数)，并按调用顺序编号
            final int[] calls = {0};
            final int[] medusaCalls = {0};
            emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                @Override
                public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                    int index = calls[0]++;
                    long blob = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue();
                    long a1 = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X1).longValue();
                    long a2 = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X2).longValue();
                    long lr = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue();
                    System.out.printf("  [vm] #%d blob=0x%x a1=0x%x a2=0x%x lr=+0x%x%n", index, blob, a1, a2, lr - base);
                    boolean medusa = (lr - base) == 0x295be0L;
                    if (medusa && a1 != 0 && medusaCalls[0]++ < 2) {
                        com.github.unidbg.pointer.UnidbgPointer args = com.github.unidbg.pointer.UnidbgPointer.pointer(emulator, a1);
                        for (int i = 0; i < 8; i++) {
                            long target = args.getLong(i * 8L);
                            if (target == 0) {
                                continue;
                            }
                            try {
                                byte[] head = com.github.unidbg.pointer.UnidbgPointer.pointer(emulator, target).getByteArray(0, 32);
                                StringBuilder hex = new StringBuilder();
                                for (byte value : head) {
                                    hex.append(String.format("%02x", value));
                                }
                                System.out.printf("      a1[%d] -> 0x%x: %s%n", i, target, hex);
                            } catch (RuntimeException e) {
                                System.out.printf("      a1[%d] -> 0x%x: unreadable%n", i, target);
                            }
                        }
                    }
                    if (false) {
                        com.github.unidbg.pointer.UnidbgPointer table = com.github.unidbg.pointer.UnidbgPointer.pointer(emulator, a2);
                        for (int i = 0; i < 8; i++) {
                            long target = table.getLong(i * 8L);
                            if (target == 0) {
                                continue;
                            }
                            try {
                                byte[] head = com.github.unidbg.pointer.UnidbgPointer.pointer(emulator, target).getByteArray(0, 32);
                                StringBuilder hex = new StringBuilder();
                                for (byte value : head) {
                                    hex.append(String.format("%02x", value));
                                }
                                System.out.printf("      a2[%d] -> 0x%x: %s%n", i, target, hex);
                            } catch (RuntimeException e) {
                                System.out.printf("      a2[%d] -> 0x%x: unreadable%n", i, target);
                            }
                        }
                    }
                    for (long pointer : new long[]{blob, a1, a2}) {
                        if (pointer == 0) {
                            continue;
                        }
                        try {
                            int width = (pointer == a1 || pointer == a2) ? (medusa ? 128 : 32) : 32;
                            byte[] head = com.github.unidbg.pointer.UnidbgPointer.pointer(emulator, pointer).getByteArray(0, width);
                            StringBuilder hex = new StringBuilder();
                            for (byte value : head) {
                                hex.append(String.format("%02x", value));
                            }
                            System.out.printf("      0x%x: %s%n", pointer, hex);
                        } catch (RuntimeException e) {
                            System.out.printf("      0x%x: unreadable%n", pointer);
                        }
                    }
                }

                @Override
                public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
                }

                @Override
                public void detach() {
                }
            }, base + 0x173ba4L, base + 0x173ba4L, null);
        }
        if (Boolean.getBoolean("metasec.dumpFrame")) {
            // byte 趟的帧：x24 是帧基址，frame[10]=key 指针、frame[11]=明文指针、frame[13]=长度
            // （sign/bytepass_gen_extract.py 的布局；循环起点 4291697，来自 INNER_CIPHER_NOTES）
            final com.github.unidbg.arm.backend.UnHook[] frameHook = new com.github.unidbg.arm.backend.UnHook[1];
            emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                @Override
                public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                    try {
                        long frame = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X24).longValue();
                        if (frame == 0) {
                            return;
                        }
                        com.github.unidbg.pointer.UnidbgPointer slots = com.github.unidbg.pointer.UnidbgPointer.pointer(emulator, frame);
                        long key = slots.getLong(10 * 8);
                        long plain = slots.getLong(11 * 8);
                        long length = slots.getLong(13 * 8);
                        System.out.printf("  [frame] x24=0x%x key=0x%x plain=0x%x len=%d%n", frame, key, plain, length);
                        if (key != 0) {
                            FileUtils.writeByteArrayToFile(new File("target/metasec-medusa-key.bin"),
                                    com.github.unidbg.pointer.UnidbgPointer.pointer(emulator, key).getByteArray(0, 32));
                        }
                        if (plain != 0 && length > 0 && length < 8192) {
                            FileUtils.writeByteArrayToFile(new File("target/metasec-medusa-plaintext.bin"),
                                    com.github.unidbg.pointer.UnidbgPointer.pointer(emulator, plain).getByteArray(0, (int) length));
                        }
                    } catch (RuntimeException | java.io.IOException e) {
                        // not the shape we expected at this hit
                    }
                    if (frameHook[0] != null) {
                        frameHook[0].unhook();
                    }
                }

                @Override
                public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
                    frameHook[0] = unHook;
                }

                @Override
                public void detach() {
                }
            }, base + 4291697L, base + 4291697L, null);
        }
        // dlopen 已经跑过构造函数（operator new、rand 这些早就翻译进缓存了）：不作废缓存，后加的 hook 对已缓存的翻译块不生效
        if (Boolean.getBoolean("metasec.dumpVmSlots") || Boolean.getBoolean("metasec.probeVm")
                || System.getProperty("metasec.sts") != null || System.getProperty("metasec.dyn") != null) {
            flushJit("debug probes installed");
        }
        if (Boolean.getBoolean("metasec.inspectContainer")) {
            // the dev message is recognised by its model string, so take that from the profile, not from a literal here
            final String expectedModel = profile.properties().get("ro.product.model");
            emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                @Override
                public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                    long msg = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue();
                    if (msg == 0 || seen[0]++ > 60) {
                        return;
                    }
                    try {
                        long dev = UnidbgPointer.pointer(emulator, msg + 24).getLong(0);
                        if (dev == 0 || dev == 0x10) {
                            return;
                        }
                        long model = UnidbgPointer.pointer(emulator, dev + 40).getLong(0);
                        String text = model == 0 ? null : UnidbgPointer.pointer(emulator, model).getString(0);
                        if (expectedModel == null || !expectedModel.equals(text)) {
                            return;
                        }
                        System.out.printf("  [inspect] CONTAINER msg=0x%x devmsg=0x%x%n", msg, dev);
                        System.out.printf("    dev+24=0x%x dev+28=0x%x dev+32=0x%x dev+36=0x%x%n",
                                UnidbgPointer.pointer(emulator, dev + 24).getInt(0), UnidbgPointer.pointer(emulator, dev + 28).getInt(0),
                                UnidbgPointer.pointer(emulator, dev + 32).getLong(0), UnidbgPointer.pointer(emulator, dev + 36).getInt(0));
                        for (int off : new int[]{128, 136, 144, 216, 272, 424, 1072}) {
                            long value = UnidbgPointer.pointer(emulator, dev + off).getLong(0);
                            System.out.printf("    dev+%d = 0x%x (has@%d=0x%x)%n", off, value, off - 8,
                                    UnidbgPointer.pointer(emulator, dev + off - 8).getInt(0));
                        }
                    } catch (RuntimeException e) {
                        // not this message
                    }
                }

                @Override
                public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
                }

                @Override
                public void detach() {
                }
            }, base + 0x265244, base + 0x265244, null);
        }
        if (System.getProperty("metasec.argStrings") != null) {
            // diagnostic: the C strings in x0/x1 at each entry of a function of libmetasec (and its caller)
            final long fn = base + Long.decode(System.getProperty("metasec.argStrings"));
            final int[] hits = new int[1];
            emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                @Override
                public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                    if (hits[0]++ > 400) {
                        return;
                    }
                    System.out.printf("  [args] lr=0x%x x0=%s x1=%s%n", backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue() - base,
                            string(backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue()),
                            string(backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X1).longValue()));
                }

                private String string(long address) {
                    try {
                        return address == 0 ? "null" : "\"" + UnidbgPointer.pointer(emulator, address).getString(0) + "\"";
                    } catch (RuntimeException e) {
                        return String.format("0x%x", address);
                    }
                }

                @Override
                public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
                }

                @Override
                public void detach() {
                }
            }, fn, fn, null);
        }
        if (System.getProperty("metasec.dumpPack") != null) {
            // diagnostic: the plaintext metasec packs for each mssdk container (protobuf-c pack at 0x265244, the call the device's
            // pack_NNN_<descriptor>.bin dumps were taken at), as <dir>/pack_NNN_<descriptor>.bin
            final File dir = new File(System.getProperty("metasec.dumpPack"));
            final int[] packs = new int[1];
            emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                @Override
                public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                    final long msg = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue();
                    final long out = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X1).longValue();
                    final long lr = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue();
                    final long sp = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_SP).longValue();
                    final long descriptor = msg == 0 ? 0 : UnidbgPointer.pointer(emulator, msg).getLong(0) - base;
                    if (descriptor != 0x4cb7f0 && descriptor != 0x4d0fc0 && descriptor != 0x4c7e60 && descriptor != 0x4c8df0) {
                        return; // a sub-message (pack recurses) or another message
                    }
                    backend.hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                        private com.github.unidbg.arm.backend.UnHook self;

                        @Override
                        public void hook(com.github.unidbg.arm.backend.Backend b, long at, int sz, Object u) {
                            if (b.reg_read(unicorn.Arm64Const.UC_ARM64_REG_SP).longValue() != sp || self == null) {
                                return;
                            }
                            long length = b.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue();
                            try {
                                FileUtils.writeByteArrayToFile(new File(dir, String.format("pack_%03d_%x.bin", ++packs[0], descriptor)),
                                        b.mem_read(out, length));
                            } catch (IOException e) {
                                throw new IllegalStateException(e);
                            }
                            self.unhook();
                            self = null;
                        }

                        @Override
                        public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
                            self = unHook;
                        }

                        @Override
                        public void detach() {
                        }
                    }, lr, lr, null);
                }

                @Override
                public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
                }

                @Override
                public void detach() {
                }
            }, base + 0x265244, base + 0x265244, null);
        }
        for (String text : System.getProperty("metasec.probePack", "").split(",")) {
            if (text.trim().isEmpty()) {
                continue;
            }
            final long offset = Long.decode(text.trim());
            System.out.printf("  [pack] hooking metasec+0x%x (base 0x%x)%n", offset, base);
            final int[] hits = new int[1];
            emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                @Override
                public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                    // entry: x1 = output buffer, x30 = where it returns to
                    final long buf = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X1).longValue();
                    if (Boolean.getBoolean("metasec.probePackDebug") && hits[0] < 2) {
                        System.out.printf("  [pack entry metasec+0x%x] x0=0x%x x1=0x%x x2=0x%x lr=0x%x%n", offset,
                                backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue(), buf,
                                backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X2).longValue(),
                                backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue());
                    }
                    final long returnAddress = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue() & ~3L;
                    if (buf == 0) {
                        return;
                    }
                    emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                        @Override
                        public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                            long length = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue();
                            if (length <= 0 || length > 0x100000) {
                                return;
                            }
                            try {
                                byte[] data = UnidbgPointer.pointer(emulator, buf).getByteArray(0, (int) length);
                                File dir = new File("target/mssdk");
                                dir.mkdirs();
                                FileUtils.writeByteArrayToFile(new File(dir, String.format("pack-%x-%d.bin", offset, ++hits[0])), data);
                                System.out.printf("  [pack metasec+0x%x] %d bytes%n", offset, length);
                            } catch (IOException e) {
                                throw new IllegalStateException(e);
                            }
                        }

                        @Override
                        public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
                        }

                        @Override
                        public void detach() {
                        }
                    }, returnAddress, returnAddress, null);
                }

                @Override
                public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
                }

                @Override
                public void detach() {
                }
            }, base + offset, base + offset, null);
        }

        vm.callJNI_OnLoad(emulator, module);
        System.out.printf("  mask 0x%x%n", UnidbgPointer.pointer(emulator, base + build.mask()).getLong(0));
        expectFlags(0x4);

        long deviceInstance = 0; // the instance handle f3.a(0x4000002) returned on the device
        for (JSONObject created : profile.f3a(0x4000002)) {
            String ret = created.getString("ret");
            if (ret != null && ret.startsWith("Long:")) {
                deviceInstance = Long.parseLong(ret.substring(5));
                break;
            }
        }
        List<Long> signs = session.getJSONArray("signs_at_ms").toJavaList(Long.class);
        int next = 0;
        for (Object step : session.getJSONArray("flow")) {
            JSONObject call = (JSONObject) step;
            for (; next < signs.size() && signs.get(next) < call.getLongValue("t_ms"); next++) {
                sign();
            }
            int cmd = Long.decode(call.getString("cmd")).intValue();
            JSONObject recorded = profile.f3a(cmd).get(call.getIntValue("record"));
            // the instance handle goes where the session marks it, and wherever the device itself passed its instance
            // (recorded l = what f3.a(0x4000002) returned on the device): a session written without the marks would
            // otherwise call with 0, and metasec drops the call (set4: did, iid, session and the lifecycle events)
            boolean instance = "handle".equals(call.getString("l"))
                    || (deviceInstance != 0 && recorded.getString("l") != null && Long.decode(recorded.getString("l")) == deviceInstance);
            if (DeviceProfile.pending(recorded.getString("s"))) {
                // a first launch: the app hands metasec the did/iid only once device_register has answered (installed())
                deferred.add(new Object[]{cmd, recorded, instance});
                System.out.printf("  f3.a(0x%x, %s) waits for device_register%n", cmd, recorded.getString("s"));
                continue;
            }
            call(cmd, recorded, instance ? handle : 0);
        }
        phase("the recorded f3.a calls");
        for (; next < signs.size(); next++) {
            sign();
        }
        phase("the recorded signs");
        long runUntil = Long.getLong("metasec.runUntil", 0);
        if (runUntil > 0) { // metasec's own threads keep reporting while the app runs: let the guest live that long
            passTime(runUntil);
            emulator.getThreadDispatcher().runThreadsUntilIdle();
            System.out.printf("  ran to %d ms of the recording, %d threads left%n", runUntil,
                    emulator.getThreadDispatcher().getTaskCount());
            for (com.github.unidbg.thread.Task task : emulator.getThreadDispatcher().getTaskList()) {
                System.out.printf("    task %d %s%s%n", task.getId(), task.isMainThread() ? "main" : "thread",
                        task.isFinish() ? " finished" : "");
            }
        }
    }

    /**
     * f3.a(cmd, p1, l, s, o) with the arguments of a recorded call, the result compared with the recorded one.
     * <p>
     * The calls are made one after another, not at the moments the recording has for them. Waiting for those moments cost the
     * whole recorded span of the init — 101 seconds of sleeping, which the emulator's own pace stretched to about 150 — and it
     * bought nothing: the library reads the clock itself when it signs, so its timestamps are of the moment it ran, and they
     * cannot run ahead of a request that is signed afterwards.
     */
    private void call(int cmd, JSONObject call, long l) throws DecoderException {
        int p1 = Long.decode(call.getString("p1")).intValue();
        String s = DeviceProfile.resolve(call.getString("s"));
        DvmObject<?> o = argument(call.get("o"));
        step(String.format("f3.a(0x%x, 0x%x, 0x%x, %s, %s) [recorded on %s at %d ms, %s]", cmd, p1, l, abbreviate(s), o,
                call.getString("thread"), call.getLongValue("t_ms"), call.getString("src")));
        long began = System.nanoTime();
        DvmObject<?> ret = f3.callStaticJniMethodObject(emulator, F3_A, cmd, p1, l, s, o);
        if (phases) {
            long took = (System.nanoTime() - began) / 1000000L;
            if (took >= 50) {
                System.out.printf("  [phase] f3.a(0x%x) %d ms%n", cmd, took);
            }
        }

        Object recorded = call.get("ret");
        String got = ret == null ? null : ret instanceof DvmInteger ? "Integer:" + ret.getValue() : ret instanceof DvmBoolean ?
                "Boolean:" + ret.getValue() : ret instanceof DvmLong ? "Long:" + ret.getValue() : String.valueOf(ret.getValue());
        if (cmd == 0x4000002) {
            System.out.printf("  -> %s (the instance; device %s)%n", got, recorded);
        } else if (Objects.equals(recorded, got)) {
            System.out.println("  -> " + got);
        } else {
            System.out.printf("  -> %s, device %s%n", got, recorded);
            differences.add(String.format("f3.a(0x%x): %s, device %s", cmd, got, recorded));
        }
        if (cmd == 0x1000003) {
            expectFlags(0xc);
        }
        if (o != null && o == callbacks) {
            expectFlags(0x7f);
            boolean masked = (UnidbgPointer.pointer(emulator, base + build.mask()).getLong(0) & 0x200) != 0;
            long[] entries = build.signEntries(masked);
            if (signEntries[0] != 0) {
                expect("http sign entry", base + entries[0], signEntries[0]);
                expect("ws sign entry", base + entries[1], signEntries[1]);
            }
        }
        checkConfig(cmd, s, ret);
    }

    /**
     * Lets the app's time pass up to a moment of the recording: the calling thread sleeps in the guest, so metasec's threads run
     * what their timers start meanwhile (while all of them wait, the guest's clock moves on to the next deadline)
     */
    private void passTime(long until) {
        if (until > timeline) {
            if (Boolean.getBoolean("metasec.realtime")) {
                // live mssdk: the host waits as long as the guest, so metasec's requests leave at the recorded pace, not in a burst.
                // The guest goes first, a second at a time, and the host then waits out that second: each call starts with the
                // guest's CLOCK_REALTIME caught up with the wall clock (unidbg's VirtualClock), so a sleep before the guest's wait
                // would put the guest ahead by the wait (X-Khronos ahead of the request's own ts/_rticket by the startup waits)
                for (long left = until - timeline; left > 0; ) {
                    long slice = Math.min(1000, left), started = System.currentTimeMillis();
                    libc.callFunction(emulator, "usleep", slice * 1000);
                    try {
                        Thread.sleep(Math.max(0, slice - (System.currentTimeMillis() - started)));
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    left -= slice;
                }
            } else {
                libc.callFunction(emulator, "usleep", (until - timeline) * 1000);
            }
            timeline = until;
        }
    }

    /** f3.a calls of a first launch that carry the did/iid, held until device_register answers: {cmd, record, with the instance} */
    private final List<Object[]> deferred = new ArrayList<>();

    /**
     * device_register answered: the app gives metasec the install's ids, in the order the recording made those calls
     * (f3.a 0x200000e, 0x2000002 did, 0x2000003 iid)
     */
    void installed(String did, String iid) throws DecoderException {
        DeviceProfile.INSTALL.put("did", did);
        DeviceProfile.INSTALL.put("iid", iid);
        for (Object[] call : deferred) {
            call((Integer) call[0], (JSONObject) call[1], (Boolean) call[2] ? handle : 0);
        }
        deferred.clear();
    }

    /** see the {@code "live".equals(network)} branch: this example signs offline and ships no live mssdk channel */
    void goLive() throws IOException {
        throw new IllegalStateException("the live mssdk channel is not part of this example: it signs offline");
    }

    /** no live channel here, so there is nothing to park */
    void holdMssdk(boolean on) {
    }

    /** the app runs on for this long: the main thread sleeps in the guest, metasec's threads run their timers meanwhile */
    void passGuest(long ms) {
        if (ms > 0) {
            libc.callFunction(emulator, "usleep", ms * 1000);
        }
    }

    /** what the call stored where the sign reads it (README 5) */
    private void checkConfig(int cmd, String s, DvmObject<?> ret) throws DecoderException {
        switch (cmd) {
            case 0x4000001: // the config JSON array: [appID, , , license, SDK version, ...]
                appId = JSON.parseArray(s).getString(0);
                break;
            case 0x4000002:
                handle = ((DvmLong) ret).getValue();
                persistedSdiToken = MetasecState.persistedSdiToken(build.sdiKey(appId), keva.get(build.kevaRepo(), build.sdiKey(appId)));
                expect("config appID", appId, state.config(handle, "app_id"));
                break;
            case 0x2000002:
                expect("config did", s, state.config(handle, "did"));
                break;
            case 0x2000003:
                expect("config iid", s, state.config(handle, "iid"));
                break;
            case 0x2000004:
                expect("config session", s, state.config(handle, "session"));
                break;
            default:
                break;
        }
    }

    /** what the app passes in: one instance per class (the Application, the SwitchManager...), the sign callbacks of this run */
    private DvmObject<?> argument(Object recorded) {
        if (recorded instanceof JSONObject) {
            JSONObject object = (JSONObject) recorded;
            JSONArray values = object.getJSONArray("v");
            if (values != null && values.contains("http_callback")) {
                // the network library hands over its setters as decimal addresses (README 1): ours stand in for them
                String[] array = values.toArray(new String[0]);
                for (int i = 0; i + 1 < array.length; i += 2) {
                    array[i + 1] = Long.toString(setters["ws_callback".equals(array[i]) ? 1 : 0].peer);
                }
                return callbacks = ArrayObject.newStringArray(vm, array);
            }
            String cls = object.getString("cls");
            if (values == null && !object.containsKey("hex") && !cls.startsWith("[")) {
                DvmObject<?> instance = instances.get(cls);
                if (instance == null) {
                    instance = vm.resolveClass(cls.replace('.', '/')).newObject(recorded);
                    instances.put(cls, instance);
                }
                return instance;
            }
        }
        return jni.value(vm, recorded);
    }

    /** a setter like the network library's: metasec calls it with the sign entry in x0 and ignores its result */
    private UnidbgPointer setter(final int which) {
        return emulator.getSvcMemory().registerSvc(new Arm64Svc("sign_setter_" + which) {
            @Override
            public long handle(Emulator<?> emulator) {
                signEntries[which] = emulator.getContext().getLongArg(0);
                return 0;
            }
        });
    }

    /** sign a request through the registered entry: the "name\r\nvalue..." block metasec produced (its own copy is freed) */
    String signRaw(String urlText, String headerBlob) {
        return signEntry(signEntries[0], urlText, headerBlob);
    }

    /**
     * WS sign entry selected by URL scheme, as sscronet does on the real device (真机初始化时序_run2.txt: 0x5000001 installs
     * http_setter=metasec+0x290c5c and ws_setter=metasec+0x291324).
     * ★ signature differs from the http entry (static evidence 2026-11-02):
     *   http call site  sscronet+0x3609e8: MOV X0,url ; MOV X1,blob ; BLR X23   (X23 = LDAR qword_4D4E80)
     *   ws  call site  sscronet+0x396070: MOV X0,blob ; BLR X27             (X27 = LDAR qword_4D48E8)
     *   ws  setter     sscronet+0x39D65C: STLR X0,[qword_4D48E8] ; RET   (stores only the fn ptr)
     * → the ws entry takes the service/method kv blob as its ONLY argument (no URL). Calling it with the URL in x0
     * makes it parse "wss://..." as kv pairs and bail to 0 — that was the room16 "ws entry NULL for every blob".
     */
    String signWsRaw(String headerBlob) {
        if (signEntries[1] == 0) {
            throw new IllegalStateException("the ws sign entry was not registered on this run (0x5000001 ws_callback missing)");
        }
        return signEntryBlob(signEntries[1], headerBlob);
    }

    /** diagnostic (room16): sign the same URL+blob through each registered entry, to attribute the frame-sign 0 to an entry.
     *  entry[0] gets (url, blob); entry[1] gets blob only — the real sscronet call shapes (see signWsRaw). */
    String[][] signBothEntries(String urlText, String headerBlob) {
        String[][] out = new String[2][];
        for (int i = 0; i < 2; i++) {
            if (signEntries[i] == 0) {
                out[i] = new String[]{"(not registered)", null};
            } else {
                String answer = null;
                try {
                    answer = i == 0 ? signEntry(signEntries[i], urlText, headerBlob)
                            : signEntryBlob(signEntries[i], headerBlob);
                } catch (RuntimeException e) {
                    answer = null;
                }
                out[i] = new String[]{String.format("metasec+0x%x", signEntries[i] - base), answer};
            }
        }
        return out;
    }

    /** the ws entry's real signature: f(kv_blob) -> header block (char*), no URL argument (sscronet+0x396074) */
    private String signEntryBlob(long entry, String headerBlob) {
        MemoryBlock blob = cString(headerBlob);
        try {
            Number ret = Module.emulateFunction(emulator, entry, blob.getPointer());
            if (ret.longValue() == 0) {
                return null;
            }
            String block = UnidbgPointer.pointer(emulator, ret.longValue()).getString(0);
            libc.callFunction(emulator, "free", ret.longValue());
            return block;
        } finally {
            blob.free();
        }
    }

    private String signEntry(long entry, String urlText, String headerBlob) {
        if (entry == 0) {
            // the callbacks were not registered on this run (component init took another path): call the entry the mask selects
            boolean masked = (UnidbgPointer.pointer(emulator, base + build.mask()).getLong(0) & 0x200) != 0;
            entry = base + build.signEntries(masked)[0];
            System.out.printf("  sign entry not registered, calling metasec+0x%x directly%n", entry - base);
        }
        MemoryBlock url = cString(urlText), blob = cString(headerBlob);
        final java.util.List<long[]> allocations = new java.util.ArrayList<>();
        final boolean find = Boolean.getBoolean("metasec.findPlaintext");
        if (find) {
            installAllocationProbe(allocations);
        }
        final boolean aligned = Boolean.getBoolean("metasec.aligned");
        if (aligned) {
            randoms.clear();
            lastSlot0 = null;
            if (!randomsHooked) {
                captureRandoms();
                randomsHooked = true;
                flushJit("rand() hook installed");
            }
        }
        try {
            Number ret = Module.emulateFunction(emulator, entry, url.getPointer(), blob.getPointer());
            if (ret.longValue() == 0) {
                return null;
            }
            String block = UnidbgPointer.pointer(emulator, ret.longValue()).getString(0);
            libc.callFunction(emulator, "free", ret.longValue());
            if (aligned) {
                writeAligned(urlText, block);
            }
            return block;
        } finally {
            url.free();
            blob.free();
            if (find) {
                dumpAllocations(allocations);
            }
            String needle = System.getProperty("metasec.searchPlaintext", "");
            if (!needle.isEmpty()) {
                searchMemory(needle.getBytes(java.nio.charset.StandardCharsets.US_ASCII), "ascii:" + needle);
            }
            if (vmBufferBase != 0) {
                try {
                    byte[] whole = UnidbgPointer.pointer(emulator, vmBufferBase).getByteArray(0, 0x4000);
                    File out = new File("target/vmslots/medusa_16k_after_sign.bin");
                    out.getParentFile().mkdirs();
                    FileUtils.writeByteArrayToFile(out, whole);
                    System.out.printf("  [vmslot] %s (the whole 16 KB after the sign)%n", out.getName());
                } catch (RuntimeException | java.io.IOException e) {
                    // gone
                }
            }
            String hexNeedle = System.getProperty("metasec.searchHex", "");
            if (!hexNeedle.isEmpty()) {
                try {
                    searchMemory(org.apache.commons.codec.binary.Hex.decodeHex(hexNeedle.toCharArray()), "hex:" + hexNeedle);
                } catch (org.apache.commons.codec.DecoderException e) {
                    throw new IllegalArgumentException("metasec.searchHex: " + e.getMessage(), e);
                }
            }
        }
    }

    /**
     * {@code -Dmetasec.aligned=true}：同一次签名的四样东西放进一个目录 {@code target/aligned/}，保证彼此对得上——
     * 签名输出（含 X-Medusa 的 base64 与解码后字节）、初始化 VM 写完的 slot0、这次 rand() 的返回值、
     * 签完后内存里那份设备信号 JSON。
     */
    private void writeAligned(String urlText, String block) {
        try {
            File dir = new File("target/aligned");
            FileUtils.deleteDirectory(dir);
            dir.mkdirs();
            Map<String, String> output = new LinkedHashMap<>();
            String[] lines = block.split("\r\n", -1);
            for (int i = 0; i + 1 < lines.length; i += 2) {
                output.put(lines[i], lines[i + 1]);
            }
            JSONObject manifest = new JSONObject(true);
            manifest.put("url", urlText);
            manifest.put("guest_time_ms", syscalls.guestTimeMillis());
            JSONObject heads = new JSONObject(true);
            for (Map.Entry<String, String> entry : output.entrySet()) {
                byte[] raw = java.util.Base64.getDecoder().decode(entry.getValue());
                JSONObject head = new JSONObject(true);
                head.put("chars", entry.getValue().length());
                head.put("bytes", raw.length);
                head.put("value", entry.getValue());
                heads.put(entry.getKey(), head);
                if ("X-Medusa".equals(entry.getKey())) {
                    FileUtils.writeByteArrayToFile(new File(dir, "medusa.bin"), raw);
                }
            }
            manifest.put("heads", heads);
            JSONArray rand = new JSONArray();
            for (long value : randoms) {
                rand.add(String.format("%08x", value));
            }
            manifest.put("rand", rand);
            if (lastSlot0 != null) {
                FileUtils.writeByteArrayToFile(new File(dir, "slot0.bin"), lastSlot0);
                manifest.put("slot0", "slot0.bin (" + lastSlot0.length + " B, after sub_295AF8)");
            }
            String signal = findSignalJson();
            if (signal != null) {
                FileUtils.writeStringToFile(new File(dir, "signal.json"), signal, StandardCharsets.UTF_8);
                manifest.put("signal", JSON.parseObject(signal, com.alibaba.fastjson.parser.Feature.OrderedField));
            }
            FileUtils.writeStringToFile(new File(dir, "manifest.json"), JSON.toJSONString(manifest, true), StandardCharsets.UTF_8);
            System.out.printf("  [aligned] target/aligned: X-Medusa %d B, slot0 %s, rand() x%d, signal %s%n",
                    heads.containsKey("X-Medusa") ? heads.getJSONObject("X-Medusa").getIntValue("bytes") : -1,
                    lastSlot0 == null ? "missing" : lastSlot0.length + " B", randoms.size(),
                    signal == null ? "missing" : signal.length() + " chars");
        } catch (IOException | RuntimeException e) {
            System.out.println("  [aligned] failed: " + e);
        }
    }

    /** 签完后内存里第一份 {"cmr":...} 的设备信号 JSON（以 '}' 结尾的完整对象） */
    private String findSignalJson() {
        byte[] pattern = "{\"cmr\":".getBytes(StandardCharsets.US_ASCII);
        for (com.github.unidbg.memory.MemoryMap map : emulator.getMemory().getMemoryMap()) {
            if ((map.prot & 1) == 0 || map.size <= 0 || map.size > 64L * 1024 * 1024) {
                continue;
            }
            byte[] region;
            try {
                region = UnidbgPointer.pointer(emulator, map.base).getByteArray(0, (int) map.size);
            } catch (RuntimeException e) {
                continue;
            }
            outer:
            for (int i = 0; i + pattern.length < region.length; i++) {
                for (int k = 0; k < pattern.length; k++) {
                    if (region[i + k] != pattern[k]) {
                        continue outer;
                    }
                }
                for (int end = i; end < region.length && end < i + 4096; end++) {
                    if (region[end] == 0) {
                        String text = new String(region, i, end - i, StandardCharsets.UTF_8);
                        if (text.endsWith("}")) {
                            return text;
                        }
                        break;
                    }
                }
            }
        }
        return null;
    }

    /**
     * 差分实验：{@code -Dmetasec.sts=<n>} 让风控 JSON 的 sts 读到 n（在 sub_2684E8 执行 {@code ldar w0,[ctx+0x138]} 之前改那 4 字节）；
     * {@code -Dmetasec.dyn=<串>} 让 sub_268268(ctx, "fa4c0a5b…") 返回这个串（在它返回处改写 sret 里的 libc++ std::string，
     * 只支持 ≤22 字节的短串）。用来证明输出长度随我们改的数值精确变化，没有隐藏分支。
     */
    private void installSignalOverrides() {
        final String sts = System.getProperty("metasec.sts");
        final String dyn = System.getProperty("metasec.dyn");
        if (sts != null) {
            final int value = Integer.parseInt(sts);
            final int[] hits = {0};
            emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                @Override
                public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                    long ctx = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue();
                    UnidbgPointer field = UnidbgPointer.pointer(emulator, ctx + 0x138);
                    int before = field.getInt(0);
                    field.setInt(0, value);
                    if (hits[0]++ < 4) {
                        System.out.printf("  [override] sts: ctx=0x%x, %d -> %d%n", ctx, before, value);
                    }
                }

                @Override
                public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
                }

                @Override
                public void detach() {
                }
            }, base + 0x2684e8L, base + 0x2684e8L, null);
        }
        if (dyn != null) {
            final byte[] value = dyn.getBytes(StandardCharsets.UTF_8);
            if (value.length > 22) {
                throw new IllegalArgumentException("metasec.dyn: at most 22 bytes (a libc++ short string)");
            }
            final byte[] key = "fa4c0a5bbd8dcedf5ee28719c5bb1df1".getBytes(StandardCharsets.US_ASCII);
            final int[] dynCalls = {0};
            // heap[0] = 用掉几块，heap[1..] = 事先 malloc 的块（每次注入一块，避免两次 free 同一指针）
            final long[] heap = new long[9];
            for (int i = 1; i < heap.length; i++) {
                heap[i] = libc.callFunction(emulator, "malloc", 64).longValue();
            }
            emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                @Override
                public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                    long keyArg = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X1).longValue();
                    final long sret = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X8).longValue();
                    long lr = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue();
                    if (dynCalls[0]++ < 6) {
                        String raw;
                        try {
                            raw = org.apache.commons.codec.binary.Hex.encodeHexString(
                                    UnidbgPointer.pointer(emulator, keyArg).getByteArray(0, 32));
                        } catch (RuntimeException e) {
                            raw = "unreadable";
                        }
                        System.out.printf("  [override] sub_268268 call from +0x%x, x1=%s (%s)%n", lr - base, raw, describeString(keyArg));
                    }
                    // the JSON builder sub_2A2804 asks for dyn from +0x2a4298 (the key is not a plain std::string there)
                    if (!isKey(keyArg, key) && (lr - base) != 0x2a4298L) {
                        return;
                    }
                    final com.github.unidbg.arm.backend.UnHook[] ref = new com.github.unidbg.arm.backend.UnHook[1];
                    emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                        @Override
                        public void hook(com.github.unidbg.arm.backend.Backend b, long a, int s, Object u) {
                            try {
                                // metasec 自己的串类型：+0 头、+8 int cap(含 NUL)、+12 int len、+16 数据指针（key 参数就是这个布局）
                                UnidbgPointer string = UnidbgPointer.pointer(emulator, sret);
                                System.out.printf("  [override] dyn sret before: %s%n",
                                        org.apache.commons.codec.binary.Hex.encodeHexString(string.getByteArray(0, 24)));
                                // 数据放在事先用 guest 的 malloc 申请的块里：metasec 之后会按自己的方式 free 它
                                if (heap[0] >= heap.length - 1) {
                                    return;
                                }
                                UnidbgPointer data = UnidbgPointer.pointer(emulator, heap[1 + (int) heap[0]++]);
                                data.write(0, value, 0, value.length);
                                data.setByte(value.length, (byte) 0);
                                string.setInt(8, value.length + 1);
                                string.setInt(12, value.length);
                                string.setPointer(16, data);
                                System.out.printf("  [override] dyn -> \"%s\" (sret 0x%x)%n", dyn, sret);
                            } finally {
                                if (ref[0] != null) {
                                    ref[0].unhook();
                                }
                            }
                        }

                        @Override
                        public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
                            ref[0] = unHook;
                        }

                        @Override
                        public void detach() {
                        }
                    }, lr, lr, null);
                }

                @Override
                public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
                }

                @Override
                public void detach() {
                }
            }, base + 0x268268L, base + 0x268268L, null);
        }
    }

    private String describeString(long pointer) {
        try {
            UnidbgPointer p = UnidbgPointer.pointer(emulator, pointer);
            int flag = p.getByte(0) & 0xff;
            byte[] text;
            if ((flag & 1) != 0) {
                long length = Math.min(p.getLong(8), 48);
                text = UnidbgPointer.pointer(emulator, p.getLong(16)).getByteArray(0, (int) length);
                return "long \"" + new String(text, StandardCharsets.ISO_8859_1) + "\"";
            }
            text = p.getByteArray(1, Math.min(flag >> 1, 22));
            return "short \"" + new String(text, StandardCharsets.ISO_8859_1) + "\"";
        } catch (RuntimeException e) {
            return "unreadable";
        }
    }

    /** x1 是 C 串还是 libc++ std::string（短串：byte0=len<<1；长串：+8 长度、+16 指针），内容等于 key 就算 */
    private boolean isKey(long pointer, byte[] key) {
        if (pointer == 0) {
            return false;
        }
        try {
            UnidbgPointer p = UnidbgPointer.pointer(emulator, pointer);
            if (java.util.Arrays.equals(p.getByteArray(0, key.length), key)) {
                return true;
            }
            int flag = p.getByte(0) & 0xff;
            if ((flag & 1) != 0) {
                long length = p.getLong(8);
                long data = p.getLong(16);
                return length == key.length
                        && java.util.Arrays.equals(UnidbgPointer.pointer(emulator, data).getByteArray(0, key.length), key);
            }
            return (flag >> 1) == key.length && java.util.Arrays.equals(p.getByteArray(1, key.length), key);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * 内存搜索：钩住 guest 的 {@code malloc}，对"像是明文/密钥缓冲"的分配（600–1200 B）记下返回指针，
     * 签名结束后把每个候选缓冲落盘，供人工判断哪一个是 Medusa 的明文。
     */
    private void installAllocationProbe(final java.util.List<long[]> out) {
        com.github.unidbg.Symbol malloc = libc.findSymbolByName("malloc", false);
        if (malloc == null) {
            System.out.println("  [find] malloc not found in libc");
            return;
        }
        emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
            @Override
            public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                final long length = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue();
                final long lr = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue();
                if (lr == 0 || length < 0x2000 || length > 0x8000 || out.size() > 200) {
                    System.out.printf("  [malloc] size=0x%x caller=+0x%x%n", length, lr - base);
                    return;
                }
                final com.github.unidbg.arm.backend.UnHook[] ref = new com.github.unidbg.arm.backend.UnHook[1];
                emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                    @Override
                    public void hook(com.github.unidbg.arm.backend.Backend b, long a, int s, Object u) {
                        try {
                            long pointer = b.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue();
                            if (pointer != 0) {
                                out.add(new long[]{pointer, length, lr - base});
                            }
                        } finally {
                            if (ref[0] != null) {
                                ref[0].unhook();
                            }
                        }
                    }

                    @Override
                    public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
                        ref[0] = unHook;
                    }

                    @Override
                    public void detach() {
                    }
                }, lr, lr, null);
            }

            @Override
            public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
            }

            @Override
            public void detach() {
            }
        }, malloc.getAddress(), malloc.getAddress(), null);
    }

    /**
     * 内存搜索：签名结束后在可写映射里找一串 ASCII（{@code -Dmetasec.searchPlaintext=<needle>}），
     * 把命中点前后各 {@value #SEARCH_WINDOW} 字节落盘。用来定位"没有固定分配点"的中间缓冲（Medusa 明文一类）。
     */
    /** Medusa 驱动那块 16 KB 的基址（0x295a2c 处捕获），供签名后 dump 用 */
    private long vmBufferBase;
    /** 本次签名里初始化 VM（sub_295AF8）写完的 slot0，0x295ab8 处取的 */
    private byte[] lastSlot0;
    private boolean randomsHooked;
    private long moduleSize;

    /**
     * unicorn2 只在"翻译时"把 code hook 织进翻译块：hook 装上之前已经执行过、留在缓存里的代码不会触发它
     * （0x4a2614 的 16 KB 分配、libc 的 rand() 都因此漏过）。装完调试 hook 后作废 metasec 与 libc 的缓存。
     */
    private void flushJit(String why) {
        emulator.getBackend().removeJitCodeCache(base, base + moduleSize);
        emulator.getBackend().removeJitCodeCache(libc.base, libc.base + libc.size);
        System.out.printf("  [jit] translation cache dropped (%s)%n", why);
    }

    private static final int SEARCH_WINDOW = Integer.getInteger("metasec.searchWindow", 700);

    private void searchMemory(byte[] pattern, String label) {
        System.out.printf("  [search] %s over writable memory%n", label);
        File dir = new File("target/search");
        dir.mkdirs();
        int hits = 0;
        for (com.github.unidbg.memory.MemoryMap map : emulator.getMemory().getMemoryMap()) {
            if ((map.prot & 1) == 0 || map.size <= 0 || map.size > 64L * 1024 * 1024 || hits >= 20) {
                continue;
            }
            byte[] region;
            try {
                region = UnidbgPointer.pointer(emulator, map.base).getByteArray(0, (int) map.size);
            } catch (RuntimeException e) {
                continue;
            }
            for (int i = 0; i + pattern.length < region.length && hits < 20; i++) {
                boolean match = true;
                for (int k = 0; k < pattern.length; k++) {
                    if (region[i + k] != pattern[k]) {
                        match = false;
                        break;
                    }
                }
                if (!match) {
                    continue;
                }
                int from = Math.max(0, i - SEARCH_WINDOW);
                byte[] dump = java.util.Arrays.copyOfRange(region, from, Math.min(region.length, i + SEARCH_WINDOW));
                File out = new File(dir, String.format("hit%02d_0x%x_%d.bin", hits, map.base + i, dump.length));
                try {
                    FileUtils.writeByteArrayToFile(out, dump);
                } catch (java.io.IOException e) {
                    continue;
                }
                System.out.printf("    %s (map 0x%x, hit at +0x%x)%n", out.getName(), map.base, i);
                hits++;
            }
        }
        System.out.printf("  [search] %d hit(s)%n", hits);
    }

    private void dumpAllocations(java.util.List<long[]> allocations) {
        System.out.printf("  [find] %d candidate allocation(s) of 600-1200 B during the sign%n", allocations.size());
        File dir = new File("target/findplain");
        dir.mkdirs();
        int index = 0;
        for (long[] allocation : allocations) {
            try {
                byte[] bytes = UnidbgPointer.pointer(emulator, allocation[0]).getByteArray(0, (int) allocation[1]);
                File out = new File(dir, String.format("%03d_%d_at_0x%x.bin", index++, bytes.length, allocation[2]));
                FileUtils.writeByteArrayToFile(out, bytes);
                StringBuilder head = new StringBuilder();
                for (int i = 0; i < Math.min(16, bytes.length); i++) {
                    head.append(String.format("%02x", bytes[i]));
                }
                System.out.printf("    %s  head=%s%n", out.getName(), head);
            } catch (RuntimeException | java.io.IOException e) {
                // the buffer is gone
            }
        }
    }


    /**
     * 215 变体：Medusa 的程序是 blob 0x122b69f0，调用点 lr=+0x295be0。明文不在帧里（727 的证据：明文是独立 malloc 的
     * 651 B 缓冲，帧里只有指针），所以这里在<b>调用返回后</b>把 a1[0] 指向的 0x1000 槽整体落盘，并把槽里每个可读 qword
     * 当指针再跟 256 字节；同时挂 metasec 内部分配器 0x4a2614，记下 600–1200 B 的分配。
     */
    private void installVmSlotDump() throws Exception {
        final long vmEntry = base + 0x173ba4L;
        final long medusaLr = base + 0x295be0L;
        final File dir = new File("target/vmslots");
        dir.mkdirs();

        final long allocator = base + 0x4a2614L;
        final long[] medusaBuffer = new long[1];
        this.vmBufferBase = 0;
        emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
            @Override
            public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                System.out.printf("  [driver] metasec+0x295a18 entered (x0=0x%x)%n",
                        backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue());
            }

            @Override
            public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
            }

            @Override
            public void detach() {
            }
        }, base + 0x295a18L, base + 0x295a18L, null);

        emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
            @Override
            public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                System.out.printf("  [thunk] 0x4a2680 x0=0x%x lr=+0x%x%n",
                        backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue(),
                        backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue() - base);
            }

            @Override
            public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
            }

            @Override
            public void detach() {
            }
        }, base + 0x4a2680L, base + 0x4a2684L, null);

        emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
            @Override
            public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                System.out.printf("  [thunk-b] +0x%x x0=0x%x lr=+0x%x%n", address - base,
                        backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue(),
                        backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue() - base);
            }

            @Override
            public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
            }

            @Override
            public void detach() {
            }
        }, base + 0x4a2684L, base + 0x4a2684L, null);

        emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
            @Override
            public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                com.github.unidbg.thread.Task task = emulator.get(com.github.unidbg.thread.Task.TASK_KEY);
                System.out.printf("  [bl] task=%s +0x%x x0=0x%x lr=+0x%x%n", task == null ? "-" : task.getId(), address - base,
                        backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue(),
                        backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue() - base);
                if ((address - base) == 0x295a28L) {
                    byte[] thunk = com.github.unidbg.pointer.UnidbgPointer.pointer(emulator, base + 0x4a2680L).getByteArray(0, 16);
                    StringBuilder hex = new StringBuilder();
                    for (byte value : thunk) {
                        hex.append(String.format("%02x", value));
                    }
                    System.out.printf("       in-memory @0x4a2680: %s%n", hex);
                }
            }

            @Override
            public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
            }

            @Override
            public void detach() {
            }
        }, base + 0x295a28L, base + 0x295a2cL, null);

        emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
            @Override
            public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                byte[] code = com.github.unidbg.pointer.UnidbgPointer.pointer(emulator, address).getByteArray(0, 16);
                StringBuilder hex = new StringBuilder();
                for (byte value : code) {
                    hex.append(String.format("%02x", value));
                }
                System.out.printf("  [drv] reached +0x295a24; in-memory code: %s%n", hex);
            }

            @Override
            public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
            }

            @Override
            public void detach() {
            }
        }, base + 0x295a24L, base + 0x295a24L, null);

        // BL 在 0x295a28，返回后 x0 就是那块 16 KB 的基址（0x4a2614 上的 hook 在这个地址上不触发）
        emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
            @Override
            public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                long returned = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue();
                if (returned != 0) {
                    medusaBuffer[0] = returned;
                    vmBufferBase = returned;
                    System.out.printf("  [drv] 16 KB buffer at 0x%x%n", returned);
                }
            }

            @Override
            public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
            }

            @Override
            public void detach() {
            }
        }, base + 0x295a2cL, base + 0x295a2cL, null);
        final int[] allocHits = {0};
        emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
            @Override
            public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                final long length = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue();
                final long lr = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue();
                if (length >= 0x1000) {
                    com.github.unidbg.thread.Task allocTask = emulator.get(com.github.unidbg.thread.Task.TASK_KEY);
                    System.out.printf("  [alloc-lr] task=%s size=0x%x from +0x%x%n",
                            allocTask == null ? "-" : allocTask.getId(), length, lr - base);
                }
                if (length == 0x4000L) {
                    System.out.printf("  [alloc] size=0x%x caller=+0x%x%n", length, lr - base);
                }
                if (lr == 0 || length != 0x4000L) {
                    return;
                }
                final com.github.unidbg.arm.backend.UnHook[] ref = new com.github.unidbg.arm.backend.UnHook[1];
                emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                    @Override
                    public void hook(com.github.unidbg.arm.backend.Backend b, long a, int s, Object u) {
                        try {
                            long pointer = b.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue();
                            if (pointer != 0) {
                                byte[] bytes = UnidbgPointer.pointer(emulator, pointer).getByteArray(0, (int) length);
                                File out = new File(dir, String.format("alloc_%d_%d_at_0x%x.bin", length, lr - base, pointer));
                                FileUtils.writeByteArrayToFile(out, bytes);
                                if ((lr - base) == 0x295a2cL) {
                                    medusaBuffer[0] = pointer;
                                }
                                System.out.printf("  [vmslot] alloc %d B at 0x%x (caller +0x%x) -> %s%n", length, pointer, lr - base, out.getName());
                            }
                        } catch (RuntimeException | java.io.IOException e) {
                            // gone
                        } finally {
                            if (ref[0] != null) {
                                ref[0].unhook();
                            }
                        }
                    }

                    @Override
                    public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
                        ref[0] = unHook;
                    }

                    @Override
                    public void detach() {
                    }
                }, lr, lr, null);
            }

            @Override
            public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
            }

            @Override
            public void detach() {
            }
        }, allocator, allocator, null);

        emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
            @Override
            public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                // sub_295AF8 返回处：初始化 VM 程序刚把 slot0 写完，这就是明文的候选
                if (medusaBuffer[0] == 0) {
                    return;
                }
                try {
                    byte[] slot0 = UnidbgPointer.pointer(emulator, medusaBuffer[0]).getByteArray(0, 0x800);
                    lastSlot0 = slot0;
                    File out = new File(dir, String.format("medusa_slot0_at_init_0x%x.bin", medusaBuffer[0]));
                    FileUtils.writeByteArrayToFile(out, slot0);
                    System.out.printf("  [vmslot] %s (slot0 after the init VM)%n", out.getName());
                } catch (RuntimeException | java.io.IOException e) {
                    // gone
                }
            }

            @Override
            public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
            }

            @Override
            public void detach() {
            }
        }, base + 0x295ab8L, base + 0x295ab8L, null);

        emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
            @Override
            public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                long lr = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue();
                if (lr != medusaLr) {
                    return;
                }
                final long a1 = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X1).longValue();
                if (a1 == 0) {
                    return;
                }
                final long slot = UnidbgPointer.pointer(emulator, a1).getLong(0);
                if (slot == 0) {
                    return;
                }
                final com.github.unidbg.arm.backend.UnHook[] ref = new com.github.unidbg.arm.backend.UnHook[1];
                emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                    @Override
                    public void hook(com.github.unidbg.arm.backend.Backend b, long a, int s, Object u) {
                        try {
                            dumpSlot(new File(dir, String.format("medusa_slot_0x%x.bin", slot)), slot);
                        } catch (RuntimeException | java.io.IOException e) {
                            // not readable
                        } finally {
                            if (ref[0] != null) {
                                ref[0].unhook();
                            }
                        }
                    }

                    @Override
                    public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
                        ref[0] = unHook;
                    }

                    @Override
                    public void detach() {
                    }
                }, lr, lr, null);
            }

            @Override
            public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
            }

            @Override
            public void detach() {
            }
        }, vmEntry, vmEntry, null);
    }

    private void dumpSlot(File out, long slot) throws java.io.IOException {
        UnidbgPointer pointer = UnidbgPointer.pointer(emulator, slot);
        byte[] bytes = pointer.getByteArray(0, 0x1000);
        FileUtils.writeByteArrayToFile(out, bytes);
        System.out.printf("  [vmslot] %s (%d B)%n", out.getName(), bytes.length);
        for (int i = 0; i < 0x1000; i += 8) {
            long value = pointer.getLong(i);
            if (value < 0x10000 || value > 0xf0000000L) {
                continue;
            }
            try {
                byte[] target = UnidbgPointer.pointer(emulator, value).getByteArray(0, 256);
                File follow = new File(out.getParentFile(), out.getName() + String.format("_q%03x_0x%x.bin", i, value));
                FileUtils.writeByteArrayToFile(follow, target);
                System.out.printf("    [q+0x%03x] -> 0x%x: %s%n", i, value, follow.getName());
            } catch (RuntimeException e) {
                // not a pointer
            }
        }
    }

    /** the syscall layer, for the request test (it reads the guest clock) */
    MetasecSyscalls syscalls() {
        return syscalls;
    }

    /** the emulator the init ran in: {@link MetasecEmulator} adds libEncryptor on top */
    AndroidEmulator emulator() {
        return emulator;
    }

    VM vm() {
        return vm;
    }

    /** the device's answers to Java calls (the profile): another native library of the app asks the same device */
    ProfileJni jni() {
        return jni;
    }

    /** this run's copy of the device's file system (the app's data dir, its lib dir) */
    File rootDir() {
        return ROOT_DIR;
    }

    void close() throws java.io.IOException {
        if (emulator != null && closed.compareAndSet(false, true)) {
            emulator.close();
        }
    }

    /**
     * char *sign(const char *url, const char *headers) through the registered entry, as the network library calls it: headers =
     * lower-case name\r\nvalue pairs joined by \r\n, the result likewise, malloc'ed
     */
    private void sign() throws IOException, DecoderException {
        step("threads until idle");
        long start = System.currentTimeMillis();
        emulator.getThreadDispatcher().runThreadsUntilIdle();
        System.out.printf("  %d ms, %d threads%n", System.currentTimeMillis() - start, emulator.getThreadDispatcher().getTaskCount());

        JSONObject request = json("device/sign_request.json");
        StringBuilder headers = new StringBuilder();
        for (Object pair : request.getJSONArray("headers")) {
            JSONArray header = (JSONArray) pair;
            headers.append(headers.length() == 0 ? "" : "\r\n").append(header.getString(0)).append("\r\n").append(header.getString(1));
        }
        // diagnostics: the inner cipher's VM handler (sign/续做指令_X-Perseus内层.md: metasec+0x2cfaf4)
        if (Boolean.getBoolean("metasec.dumpPlaintext")) {
            final int[] hits = {0};
            emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                @Override
                public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                    if (hits[0]++ < 3) {
                        StringBuilder sb = new StringBuilder();
                        for (int r = 0; r <= 7; r++) {
                            sb.append(String.format(" x%d=0x%x", r, backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0 + r).longValue()));
                        }
                        System.out.println("  [inner cipher handler] pc=0x" + Long.toHexString(address) + sb);
                    }
                }

                @Override
                public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
                }

                @Override
                public void detach() {
                }
            }, base + 0x2cfaf4, base + 0x2cfaf4, null);
        }
        dumpPlaintext("before"); // only with -Dmetasec.dumpPlaintext=true
        if (Boolean.getBoolean("metasec.dumpPlaintext")) {
            captureRandoms();
        }
        if (Boolean.getBoolean("metasec.dumpPlaintext")) {
            for (com.github.unidbg.thread.Task task : emulator.getThreadDispatcher().getTaskList()) {
                System.out.printf("  task %d %s%s%n", task.getId(), task.isMainThread() ? "main" : "thread", task.isFinish() ? " finished" : "");
            }
        }
        step("sign " + abbreviate(request.getString("url")));
        MemoryBlock url = cString(request.getString("url")), blob = cString(headers.toString());
        long realtime = syscalls.guestTimeMillis() / 1000; // the guest's CLOCK_REALTIME (s), before the call
        start = System.currentTimeMillis();
        Number ret = Module.emulateFunction(emulator, signEntries[0], url.getPointer(), blob.getPointer());
        System.out.printf("  %d ms%n", System.currentTimeMillis() - start);
        dumpPlaintext("after");
        dumpPlaintextBuffer("after");
        if (Boolean.getBoolean("metasec.probeCipher")) {
            probeCipher();
            return;
        }
        if (!randoms.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            for (long random : randoms) {
                sb.append(String.format("%08x ", random));
            }
            System.out.println("  rand() during the sign: " + sb);
            FileUtils.writeStringToFile(new File("target/metasec-randoms.txt"), sb.toString().trim(), StandardCharsets.UTF_8);
        }
        if (Boolean.getBoolean("metasec.dumpPlaintext") && syscalls.urandom.size() > 0) {
            FileUtils.writeByteArrayToFile(new File("target/metasec-urandom.bin"), syscalls.urandom.toByteArray());
            System.out.printf("  /dev/urandom bytes read: %d -> target/metasec-urandom.bin%n", syscalls.urandom.size());
        }
        url.free();
        blob.free();
        expectFlags(0x1ff);
        // the sign loads the sdi token the first time it needs it: from the persisted multi-backend KV (Keva, .msp_, .msf3_)
        String now = MetasecState.persistedSdiToken(build.sdiKey(appId), keva.get(build.kevaRepo(), build.sdiKey(appId)));
        if (recordedNetwork) {
            // the mssdk round trip ran: the recorded get_token response is the same session's, so its token equals the persisted one
            if (now == null) {
                failures.add("mssdk: no sdi token after the get_token round trip");
            } else {
                System.out.printf("  mssdk get_token: token %s (%s the persisted one)%n", now,
                        now.equals(persistedSdiToken) ? "same as" : "replaced");
            }
        }
        expect("sdi token (the persisted one)", now, state.sdiToken());
        checkPerseus();
        if (ret.longValue() == 0) {
            failures.add("sign returned NULL");
            return;
        }
        String[] parts = UnidbgPointer.pointer(emulator, ret.longValue()).getString(0).split("\r\n", -1);
        libc.callFunction(emulator, "free", ret.longValue());
        Map<String, String> output = new LinkedHashMap<>();
        for (int i = 0; i + 1 < parts.length; i += 2) {
            output.put(parts[i], parts[i + 1]);
        }
        FileUtils.writeStringToFile(new File("target/metasec-sign-output.json"),
                JSON.toJSONString(output, true), StandardCharsets.UTF_8); // the full values, next to the device's in sign_request.json
        List<String> device = new ArrayList<>();
        for (Object pair : request.getJSONArray("output")) {
            JSONArray header = (JSONArray) pair;
            device.add(header.getString(0));
            String value = output.get(header.getString(0));
            System.out.printf("  %-10s %4s chars (device %4d): %s%n", header.getString(0), value == null ? "-" : String.valueOf(value.length()),
                    header.getString(1).length(), value == null ? "" : abbreviate(value));
        }
        expect("output headers", device, new ArrayList<>(output.keySet()));
        String khronos = output.get("X-Khronos");
        if (khronos != null) {
            // X-Khronos = the guest's REALTIME + the server offset metasec keeps (server_tsp_diff -2043 ms for the recorded state;
            // a replayed mssdk response carries the server time of its own session and moves it)
            long host = System.currentTimeMillis() / 1000, read = syscalls.lastRealtimeSec(); // what the sign itself read
            if (read == 0 || Math.abs(read - host) > 86400) {
                read = host; // outside a call the guest clock is not the epoch yet
            }
            long offset = Long.parseLong(khronos) - read;
            System.out.printf("  X-Khronos - guest time before the call = %+d s%s%n", offset,
                    recordedNetwork ? " (a replayed response set the server offset; only the offline run checks it)" : "");
            if (!recordedNetwork && Math.abs(offset) > 7 * 24 * 3600L) {
                failures.add("X-Khronos is " + offset + " s off the guest's time");
            }
        }
    }

    /**
     * X-Perseus signs the device-signal record metasec built (README_初始化流程 6): a protobuf whose JSON part holds the device
     * and anti-fraud values. The record is checked where metasec still has it in memory after the sign: the JSON keys and order,
     * the values that describe this app on this device (device id, app id, SDK version, the "!notset" slots), and "fl", which
     * carries the init check chain d350..d360. The anti-fraud probes (kd, sts, un_h, fkd, pd, lp) report what the kernel and the
     * frameworks look like to the app; they are printed, not compared: the device's own values come from a session with an
     * instrumented framework attached, a clean emulator has others (kd=0 is "nothing detected").
     */
    private final List<Long> randoms = new ArrayList<>();

    /**
     * Diagnostic (metasec.dumpPlaintext): records what the guest's rand() returns while the sign runs. X-Perseus derives its cipher
     * key from SM3(secret + rand() output + secret) (sign/X-Perseus_密钥派生_完整结论.md), so with the returned value and the
     * plaintext captured from memory the header can be decrypted / re-encrypted offline to check it.
     */
    private void captureRandoms() {
        final com.github.unidbg.Symbol rand = libc.findSymbolByName("rand", false);
        System.out.println("  rand symbol: " + (rand == null ? "not found" : "0x" + Long.toHexString(rand.getAddress())));
        if (rand == null) {
            return;
        }
        final java.util.Set<Long> hooked = new HashSet<>();
        emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
            @Override
            public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                final long lr = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue() & ~3L;
                if (!hooked.add(lr)) {
                    return;
                }
                emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                    @Override
                    public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                        randoms.add(backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue() & 0xffffffffL);
                        System.out.printf("  rand() = 0x%x%n", randoms.get(randoms.size() - 1));
                    }

                    @Override
                    public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
                    }

                    @Override
                    public void detach() {
                    }
                }, lr, lr, null);
            }

            @Override
            public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
            }

            @Override
            public void detach() {
            }
        }, rand.getAddress(), rand.getAddress(), null);
    }

    private void checkPerseus() throws DecoderException, IOException {
        String json = findDeviceSignals();
        if (json == null) {
            failures.add("the device-signal record X-Perseus signs was not found in memory after the sign");
            return;
        }
        com.alibaba.fastjson.JSONObject record = JSON.parseObject(json, com.alibaba.fastjson.parser.Feature.OrderedField);
        List<String> keys = new ArrayList<>(record.keySet());
        expect("device-signal JSON keys", Arrays.asList("cmr", "cmr2", "un_h", "vpn", "sts", "kd", "fkd", "pd", "do", "lp", "fl", "tk"), keys);
        expect("no VPN", 0, record.getIntValue("vpn"));
        // the fields a device capture shows to be stable and that mean the same on any device (device/xperseus_expected.json)
        JSONObject expected = json("device/xperseus_expected.json").getJSONObject("expected");
        for (Map.Entry<String, Object> entry : expected.entrySet()) {
            expect("X-Perseus " + entry.getKey(), String.valueOf(entry.getValue()), String.valueOf(record.get(entry.getKey())));
        }
        int doFlag = record.getIntValue("do");
        expect("tk", true, record.getBooleanValue("tk"));
        String[] fl = record.getString("fl").split("\\|", -1);
        long[] chain = state.chain();
        expect("fl length", 10, fl.length);
        if (fl.length == 10) {
            for (int i = 0; i < 5; i++) { // "0|0|d350|d354|d358|d35C|d360|0|0|..."
                expect("fl[" + (2 + i) + "] = d" + Integer.toHexString(0x350 + 4 * i), Long.toString(chain[i]), fl[2 + i]);
            }
            expect("fl[0], fl[1]", "0,0", fl[0] + "," + fl[1]);
            expect("fl[7], fl[8]", "0,0", fl[7] + "," + fl[8]);
        }
        String[] lp = record.getString("lp").split("\\|", -1);
        expect("lp length", 5, lp.length);
        if (lp.length == 5) {
            expect("lp[0]", "2", lp[0]);
        }
        // kd is the persisted event counter the KV keeps (read at init, written back by the work threads), not a detection result
        String key = build.eventKey(appId);
        String persisted = MetasecState.persistedValue(key, keva.get(build.kevaRepo(), key));
        expect("kd (the persisted event counter)", persisted == null ? 0L : Long.parseLong(persisted.trim()), record.getLongValue("kd"));
        String uuid = state.uuid();
        if (uuid == null) {
            failures.add("the session UUID was not in memory after the sign");
        } else {
            // pd = crc32(UUID), fkd = crc32(md5hex(UUID + kd)) (the user's kd_source.md)
            expect("pd (crc32 of the session UUID)", crc32(uuid), record.getLongValue("pd"));
            expect("fkd (crc32 of md5hex(UUID + kd))", crc32(DigestUtils.md5Hex(uuid + record.getLongValue("kd"))), record.getLongValue("fkd"));
        }
        if (DEBUG) {
            System.out.printf("  per-session probes (not compared, see device/xperseus_expected.json): un_h=%d pd=%d fkd=%d lp=%s%n",
                    record.getLongValue("un_h"), record.getLongValue("pd"), record.getLongValue("fkd"), record.getString("lp"));
        }
    }

    /** the JSON part of the device-signal record metasec built, scanned from the heap after the sign */
    private String findDeviceSignals() {
        for (com.github.unidbg.memory.MemoryMap map : emulator.getMemory().getMemoryMap()) {
            if ((map.prot & 1) == 0 || map.base < 0x10000000L || map.base >= 0x14000000L || map.size <= 0 || map.size > 64L * 1024 * 1024) {
                continue;
            }
            byte[] region;
            try {
                region = UnidbgPointer.pointer(emulator, map.base).getByteArray(0, (int) map.size);
            } catch (RuntimeException e) {
                continue;
            }
            int i = indexOf(region, "{\"cmr\"".getBytes(StandardCharsets.US_ASCII));
            if (i >= 0) {
                int end = i;
                while (end < region.length && region[end] != '}') {
                    end++;
                }
                return new String(region, i, end - i + 1, StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    private static long crc32(String text) {
        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        crc.update(text.getBytes(StandardCharsets.UTF_8));
        return crc.getValue();
    }

    private static int indexOf(byte[] region, byte[] pattern) {
        for (int i = 0; i + pattern.length <= region.length; i++) {
            boolean match = true;
            for (int j = 0; j < pattern.length && match; j++) {
                match = region[i + j] == pattern[j];
            }
            if (match) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Diagnostic (metasec.probeCipher): watches the buffers metasec allocates while it signs and names the offsets that read them,
     * so the same offset can be hooked on the device (the plaintext is complete there).
     */
    private boolean probed;
    private final Map<Long, int[]> counts = new java.util.concurrent.ConcurrentHashMap<>();
    private final Map<String, int[]> waitCounts = new java.util.concurrent.ConcurrentHashMap<>();
    private final int[] seen = new int[1];

    /**
     * Diagnostic (metasec.probeOffsets=0x..,0x..): prints the registers where the given module offsets execute during a sign — the
     * offsets that read the device-signal buffer, so the same place can be hooked on the device with Frida.
     */
    private void probeCipher() throws IOException, DecoderException {
        if (probed) {
            return;
        }
        probed = true;
        final Map<Long, Integer> hits = new HashMap<>();
        for (String text : System.getProperty("metasec.probeOffsets", "").split(",")) {
            if (text.trim().isEmpty()) {
                continue;
            }
            final long offset = Long.decode(text.trim());
            emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                @Override
                public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                    int n = hits.merge(offset, 1, Integer::sum);
                    if (n > 3) {
                        return;
                    }
                    StringBuilder sb = new StringBuilder();
                    for (int r = 0; r <= 7; r++) {
                        sb.append(String.format(" x%d=0x%x", r, backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0 + r).longValue()));
                    }
                    System.out.printf("  [offset metasec+0x%x] lr=0x%x%s%n", offset,
                            backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue(), sb);
                }

                @Override
                public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
                }

                @Override
                public void detach() {
                }
            }, base + offset, base + offset, null);
        }
        // and every memcpy/memmove of a device-signal-sized block: the copy that carries the plaintext names the caller
        for (String name : new String[]{"memcpy", "memmove"}) {
            final com.github.unidbg.Symbol symbol = libc.findSymbolByName(name, false);
            if (symbol == null) {
                continue;
            }
            final String call = name;
            emulator.getBackend().hook_add_new(new com.github.unidbg.arm.backend.CodeHook() {
                @Override
                public void hook(com.github.unidbg.arm.backend.Backend backend, long address, int size, Object user) {
                    long dst = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X0).longValue();
                    long src = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X1).longValue();
                    long length = backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_X2).longValue();
                    if (length < 400 || length > 2048 || src < 0x10000 || dst < 0x10000) {
                        return;
                    }
                    byte[] head;
                    try {
                        head = UnidbgPointer.pointer(emulator, src).getByteArray(0, (int) Math.min(length, 512));
                    } catch (RuntimeException e) {
                        return;
                    }
                    if (indexOf(head, "{\"cmr\"".getBytes(StandardCharsets.US_ASCII)) < 0
                            && !(head.length > 2 && head[0] == 8 && head[1] == 1)) {
                        return;
                    }
                    System.out.printf("  [memcpy] %s(dst=0x%x, src=0x%x, %d) from metasec+0x%x lr=metasec+0x%x (%s)%n",
                            call, dst, src, length, backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_PC).longValue() - base,
                            backend.reg_read(unicorn.Arm64Const.UC_ARM64_REG_LR).longValue() - base,
                            new String(head, 0, Math.min(24, head.length), StandardCharsets.ISO_8859_1).replaceAll("[^ -~]", "."));
                }

                @Override
                public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {
                }

                @Override
                public void detach() {
                }
            }, symbol.getAddress(), symbol.getAddress(), null);
        }
        sign();
    }

    /**
     * Diagnostic (-Dmetasec.dumpPlaintext=true): finds the device-signal protobuf metasec fed to the inner cipher (it starts with
     * field #1 = 1 and carries the "cmr" record) and dumps it, so the Python engine can be run on the same bytes
     */
    private int dumpPlaintextBuffer(String when) throws IOException {
        if (!Boolean.getBoolean("metasec.dumpPlaintext")) {
            return 0;
        }
        byte[] start = {8, 1, 0x1a}, json = "{\"cmr\"".getBytes(StandardCharsets.US_ASCII);
        int found = 0;
        for (com.github.unidbg.memory.MemoryMap map : emulator.getMemory().getMemoryMap()) {
            if ((map.prot & 1) == 0 || map.size <= 0 || map.size > 64L * 1024 * 1024) {
                continue;
            }
            byte[] region;
            try {
                region = UnidbgPointer.pointer(emulator, map.base).getByteArray(0, (int) map.size);
            } catch (RuntimeException e) {
                continue;
            }
            for (int i = 0; i + 700 < region.length; i++) {
                if (region[i] == start[0] && region[i + 1] == start[1] && region[i + 2] == start[2]
                        && indexOf(java.util.Arrays.copyOfRange(region, i, Math.min(region.length, i + 900)), json) > 0) {
                    byte[] dump = java.util.Arrays.copyOfRange(region, i, Math.min(region.length, i + 700));
                    File out = new File("target/metasec-plaintextbuf-" + when + "-" + (found++) + ".bin");
                    FileUtils.writeByteArrayToFile(out, dump);
                    System.out.printf("  plaintext protobuf? 0x%x -> %s%n", map.base + i, out);
                }
            }
        }
        System.out.println("  plaintext protobuf dumps (" + when + "): " + found);
        return found;
    }

    /**
     * Diagnostic (-Dmetasec.dumpPlaintext=true): finds the device-signal plaintext in memory by the JSON string it carries (the
     * "cmr" record) and dumps the protobuf around it, to compare with the device's plaintext_devbuf.bin
     */
    private void dumpPlaintext(String when) throws IOException {
        if (!Boolean.getBoolean("metasec.dumpPlaintext")) {
            return;
        }
        byte[] pattern = "{\"cmr\"".getBytes(StandardCharsets.US_ASCII);
        int found = 0;
        for (com.github.unidbg.memory.MemoryMap map : emulator.getMemory().getMemoryMap()) {
            if ((map.prot & 1) == 0 || map.size <= 0 || map.size > 64L * 1024 * 1024) {
                continue;
            }
            byte[] region;
            try {
                region = UnidbgPointer.pointer(emulator, map.base).getByteArray(0, (int) map.size);
            } catch (RuntimeException e) {
                continue;
            }
            for (int i = 0; i + pattern.length < region.length; i++) {
                if (region[i] == '{' && region[i + 1] == '"' && region[i + 2] == 'c' && region[i + 3] == 'm' && region[i + 4] == 'r') {
                    int from = Math.max(0, i - 700);
                    byte[] dump = java.util.Arrays.copyOfRange(region, from, Math.min(region.length, i + 600));
                    File out = new File("target/metasec-plaintext-" + when + "-" + (found++) + ".bin");
                    FileUtils.writeByteArrayToFile(out, dump);
                    System.out.printf("  plaintext? 0x%x -> %s (%d bytes in front of the JSON)%n", map.base + i, out, i - from);
                    break;
                }
            }
        }
        System.out.println("  plaintext dumps (" + when + "): " + found);
    }

    private MemoryBlock cString(String text) {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        MemoryBlock block = emulator.getMemory().malloc(bytes.length + 1, true);
        block.getPointer().write(0, bytes, 0, bytes.length);
        block.getPointer().setByte(bytes.length, (byte) 0);
        return block;
    }

    /** the property area as the guest's libc sees it: every recorded value, and nothing where the device had nothing */
    private void checkProperties() {
        MemoryBlock buffer = emulator.getMemory().malloc(92, true);
        int present = 0, absent = 0;
        for (Map.Entry<String, String> entry : profile.properties().entrySet()) {
            long info = libc.callFunction(emulator, "__system_property_find", entry.getKey()).longValue();
            int length = libc.callFunction(emulator, "__system_property_get", entry.getKey(), buffer.getPointer()).intValue();
            String value = entry.getValue() == null ? null : buffer.getPointer().getString(0);
            if (entry.getValue() == null ? info != 0 || length != 0 : info == 0 || !entry.getValue().equals(value)) {
                failures.add("property " + entry.getKey() + ": libc sees find=0x" + Long.toHexString(info) + " value=" + value + ", device " + entry.getValue());
            }
            if (entry.getValue() == null) {
                absent++;
            } else {
                present++;
            }
        }
        buffer.free();
        System.out.printf("properties through libc: %d present, %d absent, as recorded%n", present, absent);
    }

    /** the device path of a file in the rootfs, found by name under data/app (where the package manager installed the app) */
    private String devicePath(String name) {
        java.util.Collection<File> found = FileUtils.listFiles(new File(ROOT_DIR, "data/app"), new String[]{"so"}, true);
        for (File file : found) {
            if (file.getName().equals(name)) {
                return file.getAbsolutePath().substring(ROOT_DIR.getAbsolutePath().length()).replace(File.separatorChar, '/');
            }
        }
        throw new IllegalStateException(name + " is not in the rootfs under data/app");
    }

    private void expectFlags(long flags) {
        long actual = state.flags();
        long[] chain = state.chain(), expected = state.expectedChain();
        System.out.printf("  flags 0x%x seed 0x%x k 0x%x chain %s%n", actual, state.seed(), state.k(), hex(chain));
        expect("flags", "0x" + Long.toHexString(flags), "0x" + Long.toHexString(actual));
        for (int i = 0; i < chain.length; i++) {
            if (chain[i] != 0 && chain[i] != expected[i]) {
                failures.add(String.format("d%x = 0x%x, the README formula gives 0x%x", 0x350 + 4 * i, chain[i], expected[i]));
            }
        }
    }

    private static JSONObject json(String path) throws IOException {
        return JSON.parseObject(FileUtils.readFileToString(new File(RESOURCES, path), StandardCharsets.UTF_8));
    }

    /** a data file under the resources, or wherever an override points (so a test can feed its own) */
    private static File data(String path) {
        File given = new File(path);
        return given.isAbsolute() ? given : new File(RESOURCES, path);
    }

    /**
     * This install's own draw, from its id.
     *
     * <p>Not {@code new Random(id.hashCode())}: seeded with near-consecutive values, {@code java.util.Random} returns nearly
     * identical first draws (the hashCodes of {@code install-0..install-7} give 0.9130, 0.9126, 0.9125, ... ), so a cohort
     * whose ids differ in one character would share its first drawn value. Real openudids are random hex and spread well, but
     * the seeding should not depend on that - a SHA-256 of the id spreads whatever it is given.
     */
    private static java.util.Random seeded(String id) {
        try {
            byte[] hash = java.security.MessageDigest.getInstance("SHA-256")
                    .digest(id.getBytes(StandardCharsets.UTF_8));
            long seed = 0;
            for (int i = 0; i < 8; i++) {
                seed = (seed << 8) | (hash[i] & 0xffL);
            }
            return new java.util.Random(seed);
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private void step(String name) {
        System.out.println("== " + name);
    }

    private void expect(String what, Object expected, Object actual) {
        boolean ok = Objects.equals(expected, actual);
        System.out.printf("  %s %s: %s%s%n", ok ? "ok  " : "FAIL", what, describe(actual), ok ? "" : " (expected " + describe(expected) + ")");
        if (!ok) {
            failures.add(what + ": " + describe(actual) + ", expected " + describe(expected));
        }
    }

    private boolean report() {
        String dumpProcess = System.getProperty("metasec.dumpProcess");
        if (dumpProcess != null && processView != null) {
            try {
                processView.dump(new File(dumpProcess));
                System.out.println("== the process view as rendered: " + dumpProcess);
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
        if (syscalls != null) {
            System.out.println("== paths metasec looked up, and what unidbg answered (-2 = ENOENT):");
            for (Map.Entry<String, Long> entry : syscalls.files.entrySet()) {
                System.out.printf("  %4d %s%n", entry.getValue(), entry.getKey());
            }
        }
        System.out.println("== results that differ from the device (" + differences.size() + "):");
        for (String difference : differences) {
            System.out.println("  " + difference);
        }
        System.out.println("== not on record (" + (jni == null ? 0 : jni.missing().size()) + "):");
        if (jni != null) {
            for (String missing : jni.missing()) {
                System.out.println("  " + missing);
            }
        }
        if (jni != null && Boolean.getBoolean("metasec.countCalls")) {
            System.out.println("== calls metasec made (top 30):");
            new java.util.TreeMap<>(jni.callCounts).entrySet().stream().sorted((a, b) -> b.getValue() - a.getValue()).limit(30)
                    .forEach(e -> System.out.printf("  %6d %s%n", e.getValue(), e.getKey()));
            System.out.println("== MS.b cmds:");
            new java.util.TreeMap<>(jni.callCounts).entrySet().stream().filter(e -> e.getKey().startsWith("MS.b("))
                    .sorted(java.util.Map.Entry.comparingByKey())
                    .forEach(e -> System.out.printf("  %s=%d ", e.getKey(), e.getValue()));
            System.out.println();
        }
        if (!waitCounts.isEmpty()) {
            System.out.println("== condition variables:");
            waitCounts.forEach((name, count) -> System.out.printf("  %-24s %d%n", name, count[0]));
        }
        if (!counts.isEmpty()) {
            System.out.println("== hook hits:");
            counts.forEach((offset, count) -> System.out.printf("  metasec+0x%x: %d%n", offset, count[0]));
        }
        System.out.println(failures.isEmpty() ? "PASS" : "FAILED: " + failures);
        return failures.isEmpty();
    }

    private static String describe(Object value) {
        return value instanceof Long ? "0x" + Long.toHexString((Long) value) : String.valueOf(value);
    }

    private static String hex(long[] values) {
        StringBuilder sb = new StringBuilder();
        for (long value : values) {
            sb.append(sb.length() == 0 ? "" : " ").append(Long.toHexString(value));
        }
        return sb.toString();
    }

    private static String abbreviate(String text) {
        return text == null || text.length() <= 60 ? text : text.substring(0, 60) + "...";
    }

}
