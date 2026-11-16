package test;

import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.arm.backend.Backend;
import unicorn.Arm64Const;
import unicorn.UnicornConst;

import java.io.File;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 用 AndroidPrybar 的 trace_unidbg_dump 采样出的 dump 包（regs.txt + *.bin），在真正的
 * Unidbg 里回填现场并从目标函数入口（PC）跑到返回（LR）。
 *
 * 目标函数：sha256_raw_2blocks(const uint8_t* input, uint8_t* out32)
 *   —— 纯 ALU 计算，无外部符号调用，回填后不需要 patch 任何外部符号即可直接跑通。
 *
 * 注意：这里只做“回填 + 运行”，不重新拿别的语言实现一遍算法当参考答案 —— dump 法的价值
 * 就在于 Unidbg 直接执行的是真实设备上的那份机器码，跑出来是什么就是什么，不需要另外验证。
 *
 * 用法：
 *   mvn -pl unidbg-dump-replay -am package
 *   java -jar unidbg-dump-replay/target/unidbg-dump-replay.jar [dumpDir]
 *   不传参数时默认用 unidbg-dump-replay/sample-dumps/unidbg_dump（本模块自带的样例数据）。
 */
public class ReplaySha256 {

    static Map<String, Long> readRegs(File dumpDir) throws Exception {
        Map<String, Long> regs = new HashMap<>();
        for (String line : Files.readAllLines(new File(dumpDir, "regs.txt").toPath())) {
            int eq = line.indexOf('=');
            if (eq < 0) continue;
            String key = line.substring(0, eq).trim();
            String val = line.substring(eq + 1).trim();
            if (val.startsWith("0x")) val = val.substring(2);
            if (key.startsWith("Q")) continue; // 向量寄存器本用例不需要
            try {
                regs.put(key, Long.parseUnsignedLong(val, 16));
            } catch (NumberFormatException ignore) {}
        }
        return regs;
    }

    public static void main(String[] args) throws Exception {
        File dumpDir = args.length >= 1
                ? new File(args[0])
                : new File("unidbg-dump-replay/sample-dumps/unidbg_dump");
        if (!dumpDir.isDirectory()) {
            dumpDir = new File("sample-dumps/unidbg_dump");
        }
        Map<String, Long> regs = readRegs(dumpDir);

        System.out.println("=== dump 目录: " + dumpDir.getAbsolutePath() + " ===");
        System.out.println("PC=0x" + Long.toHexString(regs.get("PC")) + " SP=0x" + Long.toHexString(regs.get("SP"))
                + " LR(X30)=0x" + Long.toHexString(regs.get("X30")));

        AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit().build();
        Backend backend = emulator.getBackend();

        // ---- 回填：把所有 <start>_<end>.bin 按原始地址原样映射回去 ----
        Pattern binName = Pattern.compile("([0-9a-fA-F]+)_([0-9a-fA-F]+)\\.bin");
        File[] files = dumpDir.listFiles();
        int mapped = 0;
        long totalBytes = 0;
        if (files != null) {
            for (File f : files) {
                Matcher m = binName.matcher(f.getName());
                if (!m.matches()) continue;
                long start = Long.parseUnsignedLong(m.group(1), 16);
                long end = Long.parseUnsignedLong(m.group(2), 16);
                long size = end - start;
                byte[] data;
                try (RandomAccessFile raf = new RandomAccessFile(f, "r")) {
                    data = new byte[(int) raf.length()];
                    raf.readFully(data);
                }
                backend.mem_map(start, size, UnicornConst.UC_PROT_ALL);
                backend.mem_write(start, data);
                mapped++;
                totalBytes += size;
                System.out.println("  mem_map 0x" + Long.toHexString(start) + " - 0x" + Long.toHexString(end)
                        + " (" + size + " bytes) <- " + f.getName());
            }
        }
        System.out.println("=== 共回填 " + mapped + " 段内存，合计 " + totalBytes + " 字节 ===");

        // ---- 回填：入口寄存器 X0-X28 + X29(FP) + X30(LR) + SP + NZCV ----
        for (int i = 0; i <= 28; i++) {
            Long v = regs.get("X" + i);
            if (v != null) backend.reg_write(Arm64Const.UC_ARM64_REG_X0 + i, v);
        }
        backend.reg_write(Arm64Const.UC_ARM64_REG_X29, regs.get("X29"));
        backend.reg_write(Arm64Const.UC_ARM64_REG_LR,  regs.get("X30"));
        backend.reg_write(Arm64Const.UC_ARM64_REG_SP,  regs.get("SP"));
        backend.reg_write(Arm64Const.UC_ARM64_REG_NZCV, regs.get("NZCV"));

        long pc = regs.get("PC");
        long lr = regs.get("X30");
        long x1 = regs.get("X1"); // out32 指针（第二个入参）

        // 本例无外部符号需要 patch（symbols.log 为空），直接从 PC 跑到 LR
        System.out.println("=== 开始在 Unidbg 内从 PC=0x" + Long.toHexString(pc)
                + " 跑到 LR=0x" + Long.toHexString(lr) + " ===");
        // count 传天文数字大的上限而非 0——避免 Unicorn 某些版本下 TB 缓存快路径跳过 hook 重新
        // 检查（本例没有外部符号/断点，影响不大，但保持和 ReplayComplex 一致的稳妥做法）。
        backend.emu_start(pc, lr, 0, 100_000_000_000L);
        System.out.println("=== emu_start 正常返回 ===");

        byte[] vmOut = backend.mem_read(x1, 32);
        StringBuilder hex = new StringBuilder();
        for (byte b : vmOut) hex.append(String.format("%02x", b));

        System.out.println("Unidbg 回填现场跑出的结果: " + hex);
        System.out.println("====== 回填 + 运行 完成，未重新实现算法做对照 ======");

        emulator.close();
    }
}
