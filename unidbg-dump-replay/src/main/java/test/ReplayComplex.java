package test;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.debugger.BreakPointCallback;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.memory.Memory;
import unicorn.Arm64Const;
import unicorn.UnicornConst;

import java.io.File;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 用 trace_unidbg_dump 采样出的「复杂例子」dump 包（JNI 指纹 + libc CRC32 校验 + AES）在
 * Unidbg 里回填现场，并把运行中真正遇到的外部符号（symbols.log 记录的地址）patch 到
 * Unidbg 自己 dlopen 出来的 libc.so 对应符号地址 —— 而不是重新拿别的语言实现一遍算法。
 *
 * 已知边界（README 里也写了）：symbols.log 里有 5 条来自 libart.so 的 JNI 调用地址是
 * "<unresolved>"（JNI 函数表调用，不是常规 ELF 导出符号），这几个本例不 patch，命中时
 * 直接停下并报告——因为要接住它们需要在 Unidbg 里另外搭一套 DalvikVM + JNI 环境，这是
 * AndroidPrybar 侧 trace_unidbg_dump v1 明确写清楚的局限，不在这次验证范围内。
 *
 * 用法：
 *   java -jar unidbg-dump-replay/target/unidbg-dump-replay.jar --complex [dumpDir]
 */
public class ReplayComplex {

    static Map<String, Long> readRegs(File dumpDir) throws Exception {
        Map<String, Long> regs = new HashMap<>();
        for (String line : Files.readAllLines(new File(dumpDir, "regs.txt").toPath())) {
            int eq = line.indexOf('=');
            if (eq < 0) continue;
            String key = line.substring(0, eq).trim();
            String val = line.substring(eq + 1).trim();
            if (val.startsWith("0x")) val = val.substring(2);
            if (key.startsWith("Q")) continue;
            try { regs.put(key, Long.parseUnsignedLong(val, 16)); } catch (NumberFormatException ignore) {}
        }
        return regs;
    }

    // __xxx_chk（_FORTIFY_SOURCE 加固变体）、__xxx_2 这类都是编译时优化/加固加出来的符号名，
    // 语义和基础函数一致——不用精确解析后缀规则，直接看符号名里包不包含某个已知基础函数名，
    // 包含就当一样处理去老 libc 里找。列表按更具体的名字在前排（比如 pread 要排在 read 前面，
    // 否则 "__pread_chk" 会先被 "read" 命中）。
    static final String[] KNOWN_BASE_NAMES = {
        "vsnprintf", "snprintf", "strncpy", "pread", "memcpy", "memset",
        "strstr", "strtok", "sscanf", "close", "read", "open",
    };
    static String baseLibcName(String name) {
        for (String base : KNOWN_BASE_NAMES) {
            if (name.contains(base)) return base;
        }
        return name;
    }

    static int copyTree(File src, File dstRoot) throws java.io.IOException {
        int[] count = {0};
        java.nio.file.Path srcPath = src.toPath();
        Files.walk(srcPath).forEach(p -> {
            try {
                File target = new File(dstRoot, srcPath.relativize(p).toString());
                if (Files.isDirectory(p)) {
                    target.mkdirs();
                } else {
                    target.getParentFile().mkdirs();
                    Files.copy(p, target.toPath());
                    count[0]++;
                }
            } catch (java.io.IOException e) {
                throw new RuntimeException(e);
            }
        });
        return count[0];
    }

    public static void main(String[] args) throws Exception {
        File dumpDir = args.length >= 1
                ? new File(args[0])
                : new File("unidbg-dump-replay/sample-dumps/unidbg_dump_complex");
        if (!dumpDir.isDirectory()) dumpDir = new File("sample-dumps/unidbg_dump_complex");

        Map<String, Long> regs = readRegs(dumpDir);
        System.out.println("=== dump 目录: " + dumpDir.getAbsolutePath() + " ===");

        // rootDir：给 Unidbg 一个虚拟文件系统根，把 dump 里的 rootfs/ 整棵树原样搬过去，
        // 这样 patch 后跳进 Unidbg 自己的 open/read 实现时，能读到「当时设备上真实的那些文件」。
        File rootDir = Files.createTempDirectory("unidbg-dump-replay-root").toFile();
        File dumpedRootfs = new File(dumpDir, "rootfs");
        if (dumpedRootfs.isDirectory()) {
            int copied = copyTree(dumpedRootfs, rootDir);
            System.out.println("=== 已把 dump 里的 rootfs/（" + copied + " 个文件）搬进 Unidbg 虚拟根目录 ===");
        }

        AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit().setRootDir(rootDir).build();
        Backend backend = emulator.getBackend();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        // Unidbg 自己 dlopen 出来的 libc.so —— 后面 patch 外部符号时的“真身”来源
        Module libc = memory.dlopen("libc.so", false);
        System.out.println("=== Unidbg 自带 libc.so 已加载，base=0x" + Long.toHexString(libc.base) + " ===");

        // ---- 回填：把所有 <start>_<end>.bin 按原始地址原样映射回去 ----
        Set<Long> mappedPages = new HashSet<>();
        Pattern binName = Pattern.compile("([0-9a-fA-F]+)_([0-9a-fA-F]+)\\.bin");
        File[] files = dumpDir.listFiles();
        int mapped = 0;
        // 记住每段的 (start,end,data)，供下面给「带 tag 的指针」镜像映射时复用，不用重读文件
        java.util.List<long[]> ranges = new java.util.ArrayList<>();
        java.util.List<byte[]> rangeData = new java.util.ArrayList<>();
        if (files != null) {
            for (File f : files) {
                Matcher m = binName.matcher(f.getName());
                if (!m.matches()) continue;
                long start = Long.parseUnsignedLong(m.group(1), 16);
                long end = Long.parseUnsignedLong(m.group(2), 16);
                byte[] data;
                try (RandomAccessFile raf = new RandomAccessFile(f, "r")) {
                    data = new byte[(int) raf.length()];
                    raf.readFully(data);
                }
                backend.mem_map(start, end - start, UnicornConst.UC_PROT_ALL);
                backend.mem_write(start, data);
                for (long p = start; p < end; p += 0x1000) mappedPages.add(p);
                ranges.add(new long[]{start, end});
                rangeData.add(data);
                mapped++;
            }
        }
        System.out.println("=== 共回填 " + mapped + " 段内存 ===");

        // ---- 回填：入口寄存器 ----
        for (int i = 0; i <= 28; i++) {
            Long v = regs.get("X" + i);
            if (v != null) backend.reg_write(Arm64Const.UC_ARM64_REG_X0 + i, v);
        }
        backend.reg_write(Arm64Const.UC_ARM64_REG_X29, regs.get("X29"));
        backend.reg_write(Arm64Const.UC_ARM64_REG_LR,  regs.get("X30"));
        backend.reg_write(Arm64Const.UC_ARM64_REG_SP,  regs.get("SP"));
        backend.reg_write(Arm64Const.UC_ARM64_REG_NZCV, regs.get("NZCV"));

        // ---- JNI：不整体换 env，改成和 libc 符号一样「逐个函数」patch ----
        // X0（JNIEnv*）保持真机原始值不动——它背后的真机 JNINativeInterface 表内容（函数名对应
        // 的真实地址）已经在 jni_table.log 里有完整记录，而且这块内存本身也在 tag 镜像映射范围
        // 内（下面那段扫描），所以 guest 代码正常解引用 env->functions->XXX 读到的就是真机的
        // 真实地址——和 libc 符号一模一样，只需要在每个真实地址上下断点，命中时改 PC 指向
        // Unidbg 自己 DalvikVM 对应函数的实现即可，不需要伪造/替换 env 指针本身。
        //
        // Unidbg 自己 DalvikVM 现造一个真正能用的 JNIEnv，只是用来"借"它内部各函数的实现地址
        // （JNINativeInterface 是 JNI 规范固定的标准表布局，任何 JVM/ART 实现同一版本下
        // 字段顺序都一样，按偏移对齐即可，不需要按名字/地址去猜）。
        com.github.unidbg.linux.android.dvm.VM vm = emulator.createDalvikVM();
        vm.setJni(new com.github.unidbg.linux.android.dvm.AbstractJni() {
            @Override
            public com.github.unidbg.linux.android.dvm.DvmObject<?> getStaticObjectField(
                    com.github.unidbg.linux.android.dvm.BaseVM vm,
                    com.github.unidbg.linux.android.dvm.DvmClass dvmClass, String signature) {
                // 真机上这两个字段的真实值也是 dump 不出来的（活的系统属性），这里用固定值
                // 代替——和教程里固定时间戳的思路一样：不追求"一模一样"，追求"确定、可复现"。
                if ("android/os/Build->MODEL:Ljava/lang/String;".equals(signature)) {
                    return new com.github.unidbg.linux.android.dvm.StringObject(vm, "unidbg-replay");
                }
                if ("android/os/Build->FINGERPRINT:Ljava/lang/String;".equals(signature)) {
                    return new com.github.unidbg.linux.android.dvm.StringObject(vm, "unidbg-replay/fingerprint");
                }
                return super.getStaticObjectField(vm, dvmClass, signature);
            }
        });
        // ---- JNI：X0(env) 整体换成 Unidbg 自己真正认可的 env 地址 ----
        // 试过"保持 X0 真机原值不动，只把它背后那张表的内容原地覆写成 Unidbg 自己的值"
        // （这样调用也能正确路由——guest 解引用 env->functions->XXX 时表里已经是 Unidbg 认识
        // 的值了），单论"跑不跑得通"这一点是可行的。但 Unidbg 自带的 JNI trace（下面的
        // vm.setVerbose(true)）要按 env 地址识别"这是不是我自己发出的调用"才会打印/记录，
        // 只有 X0 真的等于 vm.getJNIEnv() 这个地址本身才能对上号——所以 X0 必须整体替换，
        // 不能只改它指向的表内容。真机 dump 出来的 env 值（以及它背后那张表）在这里就不再
        // 使用了。
        //
        // （也试过更早一版"逐个真机地址下断点、命中时把 PC 改指到 Unidbg 对应函数"：行不通，
        // Unidbg 自己 JNI 表里存的根本不是可执行机器码地址，是它内部 hook 机制识别用的
        // "哨兵值"——实测 getLong(0)=0x0、getLong(8)=0x8、getLong(16)=0x10，正好等于表内
        // 偏移本身，跳过去执行会立刻报 FETCH UNMAPPED。这套"改 PC 跳过去"的手法只对 libc
        // 这种真实 dlopen 出来、函数是真实可执行代码的场景有效，对 JNI 这种 Unidbg 内部
        // hook 机制无效。）
        com.github.unidbg.pointer.UnidbgPointer unidbgEnv = (com.github.unidbg.pointer.UnidbgPointer) vm.getJNIEnv();
        long origX0 = regs.get("X0");
        backend.reg_write(Arm64Const.UC_ARM64_REG_X0, unidbgEnv.peer);
        vm.setVerbose(true);
        System.out.println("=== X0(JNIEnv*) 从真机值 0x" + Long.toHexString(origX0)
                + " 换成 Unidbg 自己的 env 0x" + Long.toHexString(unidbgEnv.peer)
                + "，已开启 vm.setVerbose(true) ===");

        // ---- ART 的堆指针带 top-byte tag（如 0xb4...），AndroidPrybar 的 VCPU（可编程 ARM64 CPU）
        //      会在 hook 触发前自动剥掉 tag 再记页号，所以 dump 出来的 .bin 文件名是「去 tag」
        //      后的地址；但 Unidbg 用的是标准 Unicorn，不会剥 tag，会拿寄存器里的原始带 tag
        //      值去找映射。这里扫一遍入口寄存器，凡是 top byte 非零的，把对应「去 tag」页的内容
        //      在「带 tag」地址上再镜像映射一份，兼容标准 Unicorn 的字面地址匹配语义。
        int aliased = 0;
        for (int i = 0; i <= 30; i++) {
            Long v = (i == 30) ? regs.get("X30") : regs.get("X" + i);
            if (v == null) continue;
            long val = v;
            int tag = (int) ((val >>> 56) & 0xFF);
            if (tag == 0) continue; // 没有 tag，不用镜像
            long stripped = val & 0x00FFFFFFFFFFFFFFL;
            for (int r = 0; r < ranges.size(); r++) {
                long start = ranges.get(r)[0], end = ranges.get(r)[1];
                if (stripped >= start && stripped < end) {
                    long taggedStart = ((long) tag << 56) | start;
                    if (!mappedPages.contains(taggedStart)) {
                        backend.mem_map(taggedStart, end - start, UnicornConst.UC_PROT_ALL);
                        backend.mem_write(taggedStart, rangeData.get(r));
                        for (long p = taggedStart; p < taggedStart + (end - start); p += 0x1000) mappedPages.add(p);
                        aliased++;
                        System.out.println("  tag 镜像映射: 0x" + Long.toHexString(start) + "-0x" + Long.toHexString(end)
                                + " -> 0x" + Long.toHexString(taggedStart) + " (来自 X" + i + "=0x" + Long.toHexString(val) + ")");
                    }
                    break;
                }
            }
        }
        System.out.println("=== 共补了 " + aliased + " 段 tag 镜像映射 ===");

        long pc = regs.get("PC");
        long lr = regs.get("X30");

        // ---- patch：symbols.log 里记录的每一条外部符号调用地址，命中时把 PC 改指到
        //      Unidbg 自己 libc.so 里同名符号的地址，而不是尝试执行原设备地址（那里的机器码
        //      我们从未 dump 过——AndroidPrybar 只记了符号名，没记 libc 内部的指令）----
        File symLog = new File(dumpDir, "symbols.log");
        int patched = 0, skippedJni = 0;
        if (symLog.isFile()) {
            for (String line : Files.readAllLines(symLog.toPath())) {
                line = line.trim();
                if (line.isEmpty()) continue;
                int sp = line.indexOf(' ');
                if (sp < 0) continue;
                long addr = Long.parseUnsignedLong(line.substring(2, sp), 16);
                String name = line.substring(sp + 1).trim();

                if ("<unresolved>".equals(name)) {
                    // libart.so 的 JNI 函数表调用——不需要在这里单独处理：上面已经把整张
                    // JNI 函数表原地覆写成了 Unidbg 自己的值，guest 代码解引用 env->functions
                    // 拿到的直接就是 Unidbg 认识的哨兵值，BLR 过去会自然触发 Unidbg 内部的
                    // hook 分发，不需要针对 symbols.log 里这条记录单独下断点。
                    continue;
                }

                // __xxx_chk / _2 是 _FORTIFY_SOURCE 加固符号名，只是在基础函数外面包了一层参数
                // 校验，语义和基础函数等价；Unidbg 自带的是 Android 6(SDK23) 年代的老 libc，不
                // 一定导出这些加固变体，但一定有基础函数——patch 的目的只是让功能对得上、结果
                // 对得上，不强求符号名字面一致，所以按基础函数名去 findSymbolByName。
                String baseName = baseLibcName(name);
                com.github.unidbg.Symbol sym = libc.findSymbolByName(baseName);
                if (sym == null) {
                    System.out.println("  跳过 patch: 0x" + Long.toHexString(addr) + " (" + name
                            + ") —— Unidbg 自带 libc 里没有这个符号（已知局限）");
                    skippedJni++;
                    continue;
                }

                // 只有确定要 patch 成什么（已解析出符号名）的地址才需要先映射一页占位可执行
                // 内存——这样断点才有机会在真正执行前截住它，把 PC 改到 Unidbg 自己的实现上。
                long page = addr & ~0xFFFL;
                if (!mappedPages.contains(page)) {
                    backend.mem_map(page, 0x1000, UnicornConst.UC_PROT_ALL);
                    mappedPages.add(page);
                }

                final String fname = name, fbase = baseName;
                // 用 emulator.attach().addBreakPoint(...)（Debugger 层）而不是
                // backend.addBreakPoint(...)（Backend 层裸接口）——教程原文用的就是前者。
                // 断点命中的分发（AbstractARMDebugger.onBreak）查的是 Debugger 自己那张
                // breakMap，如果断点是绕过 Debugger 直接注册到 Backend 上的，onBreak 找不到
                // 对应的 callback，会误判成"没人处理"而掉进交互式调试 loop（我们最早踩的死循环
                // 就是这个）。
                emulator.attach().addBreakPoint(addr, new BreakPointCallback() {
                    @Override
                    public boolean onHit(com.github.unidbg.Emulator<?> emulator, long address) {
                      try {
                        com.github.unidbg.Symbol s = libc.findSymbolByName(fbase);
                        if (s == null) {
                            throw new IllegalStateException("符号消失: " + fbase); // 不应该发生，保险
                        }
                        long target = s.getAddress();
                        emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_PC, target);
                        System.out.println("  patch: 0x" + Long.toHexString(address) + " (" + fname
                                + " -> " + fbase + ") -> Unidbg 自带 libc 0x" + Long.toHexString(target));
                        return true; // 不真的停，改完 PC 继续跑
                      } catch (Throwable t) {
                        System.out.println("  !! onHit 内部抛出异常: " + t);
                        t.printStackTrace(System.out);
                        return true; // 即使异常也别让它掉进交互式 debugger 循环
                      }
                    }
                });
                patched++;
            }
        }
        System.out.println("=== 共 patch " + patched + " 个外部符号，" + skippedJni + " 个 JNI 调用未 patch(已知局限) ===");

        // 在真正抛异常之前，先看一眼到底是哪个地址访问失败——比事后读 PC 更可靠
        // （事后读到的 PC 可能已经是 JIT 块边界之后的下一条，不是真正出错那条）。
        backend.hook_add_new(new com.github.unidbg.arm.backend.EventMemHook() {
            @Override
            public boolean hook(Backend backend, long address, int size, long value, Object user, UnmappedType unmappedType) {
                long curPc = backend.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue();
                System.out.println("  !! " + unmappedType + " UNMAPPED addr=0x" + Long.toHexString(address)
                        + " size=" + size + " at PC=0x" + Long.toHexString(curPc));
                return false; // 不代为处理，仍然报错，只是先把地址打出来
            }
            @Override public void onAttach(com.github.unidbg.arm.backend.UnHook unHook) {}
            @Override public void detach() {}
        }, UnicornConst.UC_HOOK_MEM_READ_UNMAPPED | UnicornConst.UC_HOOK_MEM_WRITE_UNMAPPED | UnicornConst.UC_HOOK_MEM_FETCH_UNMAPPED, null);

        System.out.println("=== 开始在 Unidbg 内从 PC=0x" + Long.toHexString(pc) + " 跑 ===");
        try {
            // count 传 0 在某些 Unicorn 版本下会启用一条不重新检查 hook 的 TB 缓存快路径，
            // 已经缓存过的翻译块可能不会再触发新注册的 hook/断点。传一个天文数字般大的
            // 指令数上限（不会真的跑到这么多指令，只是避免触发那条快路径）更稳妥。
            backend.emu_start(pc, lr, 0, 100_000_000_000L);
            System.out.println("=== emu_start 正常跑到 LR 返回 ===");
        } catch (Exception e) {
            // 具体撞在哪个地址、哪个 PC，上面注册的 EventMemHook 已经在异常抛出前打印过了
            // （对应教程里 Unidbg 原生 "FETCH MEMORY FAILED" 那行诊断），这里只报告异常本身。
            System.out.println("=== emu_start 中途停止: " + e + " ===");
        }

        emulator.close();
    }
}
