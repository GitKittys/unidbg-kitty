# dump 法完整流程与踩坑记录

（本仓库 `unidbg-dump-replay` 模块实测验证过的完整流程；被 [UNIDBG_GUIDE.md](./UNIDBG_GUIDE.md) 引用，
只在需要具体做 dump 法回填/排查问题时才需要打开这份文档。）

**背景**：目标函数依赖链太深、补环境太痛苦（依赖库找不全，或初始化会报错/死循环）时，不走 Unidbg
的 Loader、不管初始化，直接把**真机上某一时刻已经跑通的内存镜像 + 寄存器状态**原样搬到 Unidbg 里，
从**执行中途**接着跑。用 unicornTrace 的 `trace_unidbg_dump()`/`trace_unidbg_dump_finish()` 在真机上
采样，产出一份 dump 包，再按本文档回填进 Unidbg。

---

## 1. 数据来源：unicornTrace 侧的 `trace_unidbg_dump`

在真机 App 进程里，用 unicornTrace 把目标函数包一层：
```c
auto h = (返回值类型(*)(参数类型...))trace_unidbg_dump((void*)目标函数, dumpDir);
h(真实参数...);              // 真实跑一遍，期间采样（入口寄存器/内存访问/外部符号/JNI表/文件访问）
trace_unidbg_dump_finish((void*)h);   // 落盘 + 释放
```
产出目录：
| 文件 | 内容 |
|---|---|
| `<start>_<end>.bin` | 运行时访问过的内存段（按页对齐合并） |
| `regs.txt` | 入口寄存器快照（X0-X30/SP/PC/NZCV/Q0-Q31...） |
| `args.txt` | 入口参数（X0-X7+SP） |
| `symbols.log` | 这次执行路径实际调用到的外部符号（地址+名字，libart 的 JNI 调用记为 `<unresolved>`） |
| `jni_table.log` | 真机 `JNINativeInterface`（libart 全局函数表，229 项）每项的函数名+真实地址，按 JNI 规范标准字段顺序记录 |
| `maps.log` | `/proc/self/maps` |
| `info.txt` | 模块基址/偏移/SO 路径 |
| `rootfs/` | 目标运行时 open 过的文件，按原路径放好 |
| `files_manifest.txt` | rootfs 里放了哪些文件（含跳过记录） |

## 2. 回填：把 dump 包搬进 Unidbg

不走 `Memory.load()`/Loader，直接用 `Backend` 底层接口：
```java
AndroidEmulator emulator = AndroidEmulatorBuilder.for64Bit().setRootDir(rootDir).build();
Backend backend = emulator.getBackend();

// 1. 内存：所有 <start>_<end>.bin 按文件名里的地址原样映射回去
backend.mem_map(start, end - start, UnicornConst.UC_PROT_ALL);
backend.mem_write(start, data);

// 2. 寄存器：regs.txt 里的 X0-X28/X29(FP)/X30(LR)/SP/NZCV 全部写回去
backend.reg_write(Arm64Const.UC_ARM64_REG_X0 + i, v);
...

// 3. rootDir：dump 包的 rootfs/ 整棵树搬进 Unidbg 的虚拟文件系统根
//    （setRootDir(rootDir)，rootDir 下预先放好 rootfs/ 的内容）

// 4. 从 PC 跑到 LR
backend.emu_start(pc, lr, 0, 100_000_000_000L);   // count 传大数，见第 7 节
```

**为什么不走 Loader**：Loader 要做的事——重定位、依赖解析、初始化——真机在采样那一刻已经全部做完
了。dump 法是直接复用这个"已经做完的结果"（内存镜像+寄存器），不是重新做一遍加载。代价是没有目标
SO 的 `Module` 对象（想再查目标 SO 内部别的符号地址，只能自己拿 `info.txt` 的 `module_base+offset`
手算，不能调 `findSymbolByName`）。

**已排除的方案**：先用 `Loader` 正常加载目标 SO 再合并 dump 数据——技术上行不通（Unidbg 的 Loader
没有公开 API 能指定固定加载基址，`load_base` 是它自己内部 `mmapBaseAddress` 算出来的，加载后的基址
必然和真机不同，"合并"得先做一轮地址重定位），而且方向上和 dump 法的初衷矛盾（dump 法就是为了跳过
补环境/加载依赖，再绕回去用 Loader 加载+补重定位等于把省掉的工作量加回来）。不做。

## 3. ART 堆指针的 top-byte tag 坑

`X0`（JNIEnv*）等寄存器的值形如 `0xb400007339345390`——真机 ART 的堆指针带 top-byte tag。
unicornTrace 自己那个魔改 Unicorn 会在 hook 触发前自动剥掉 tag 再记录页号，所以 dump 出来的 `.bin`
文件名是"去 tag"后的地址；但 Unidbg 用的是标准 Unicorn，**不会剥 tag**，会拿寄存器里的原始带 tag 值
去找映射。

**解法**：扫一遍入口寄存器，凡是 top byte（`(val >>> 56) & 0xFF`）非零的，把对应"去 tag"页的内容在
"带 tag"地址上再镜像映射一份：
```java
for (寄存器 X0..X30) {
    if (top byte != 0) {
        long stripped = val & 0x00FFFFFFFFFFFFFFL;
        // 找到 stripped 落在哪个已回填的 .bin 段范围内
        long taggedStart = (tag << 56) | rangeStart;
        backend.mem_map(taggedStart, size, UC_PROT_ALL);
        backend.mem_write(taggedStart, 同一份 data);
    }
}
```

## 4. libc 符号 patch

`symbols.log` 里记录的外部符号调用，在原设备地址上下断点，命中时把 `PC` 改写成 Unidbg 自己
`dlopen("libc.so")` 出来的同名符号地址：
```java
Module libc = memory.dlopen("libc.so", false);   // 用 Unidbg 自带的 android/sdk23/lib64/libc.so 资源
...
emulator.attach().addBreakPoint(addr, new BreakPointCallback() {
    public boolean onHit(Emulator<?> emulator, long address) {
        long target = libc.findSymbolByName(baseName).getAddress();
        emulator.getBackend().reg_write(Arm64Const.UC_ARM64_REG_PC, target);
        return true;   // 不真的停，改完 PC 继续跑
    }
});
```
**fortify 加固符号名要按基础函数名去找**：`__strncpy_chk`/`__memcpy_chk`/`__open_2` 这类是编译期加了
参数校验的加固变体，语义和基础函数一样，但 Unidbg 自带的是 Android 6(SDK23) 年代的老 libc，不一定
导出这些加固变体。**直接判断符号名里"包不包含"某个已知基础名**（`strncpy`/`memcpy`/`open`...）就按
基础名处理，不用精确解析后缀规则；注意匹配顺序要让更具体的名字排前面（`pread` 要排在 `read` 前面，
否则 `__pread_chk` 会先被 `read` 命中）。

## 5. JNI：`X0` 整体换成 Unidbg 自己的 env（不是 dump 真机 env 内存）

真机那个带 tag 的 `JNIEnv*` 背后是活的 ART 运行时，压根没法 dump 出来在 Unidbg 里用。正确做法：
```java
VM vm = emulator.createDalvikVM();
vm.setJni(new AbstractJni() {
    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        // 真机上这类字段的真实值是活的系统属性，dump 不出来，给固定 mock 值
        // ——和教程固定时间戳的思路一样：不追求"一模一样"，追求"确定、可复现"
        if ("android/os/Build->MODEL:Ljava/lang/String;".equals(signature)) {
            return new StringObject(vm, "unidbg-replay");
        }
        return super.getStaticObjectField(vm, dvmClass, signature);
    }
});
UnidbgPointer unidbgEnv = (UnidbgPointer) vm.getJNIEnv();
backend.reg_write(Arm64Const.UC_ARM64_REG_X0, unidbgEnv.peer);   // 整体替换，不是改内容
vm.setVerbose(true);   // 打开后能看到完整可读的 JNI 调用轨迹
```

**走过的两个弯路（重要，别再踩）**：

1. **"逐个真机地址下断点、命中时把 PC 改指到 Unidbg 对应 JNI 函数地址去跑"**（和 libc 符号一模一样
   的手法）——**行不通**。实测 Unidbg 自己 JNI 表里存的值是 `getLong(0)=0x0`、`getLong(8)=0x8`、
   `getLong(16)=0x10`——正好等于表内偏移本身。说明 Unidbg 内部的 JNI 表存的根本不是可执行机器码
   地址，是它自己 hook 机制识别用的"哨兵值"，没法直接当 PC 跳过去执行（会立刻报 `FETCH UNMAPPED`）。
   这套手法只对 libc 这种真实 dlopen 出来、函数是真实可执行代码的场景有效，对 JNI 这种 Unidbg 内部
   hook 机制无效。
2. **"`X0` 保持真机原值不动，只把它背后那张表（`jni_table.log` 记录的真机地址）的内容原地覆写成
   Unidbg 自己表里对应偏移的值"**——单论"跑不跑得通"是可行的（guest 解引用 `env->functions->XXX`
   拿到的直接是 Unidbg 认识的值，`BLR` 过去正常触发内部 hook 分发），**但拿不到 `vm.setVerbose(true)`
   的可读 trace**——Unidbg 要按 env **地址**识别"这是不是我自己发出的调用"才会打印，只改表内容、
   不改 `X0` 本身，这个身份对不上。要 trace，`X0` 必须真的等于 `vm.getJNIEnv()` 这个地址。

`jni_table.log` 在最终这条路径里没有被用到（`X0` 整体替换后，guest 解引用走的是 Unidbg 自己那张
本来就正确、从未被动过的表），只是采样阶段多留的一份真机侧参考，如果以后要做"不整体换 env、只想
局部纠正个别调用"之类更精细的方案可以再捡回来。

## 6. 断点必须用 `emulator.attach().addBreakPoint()`，不能用 `backend.addBreakPoint()`

**这是本轮踩的最关键的坑**，会导致非交互环境下无限循环刷屏，务必注意。

`Backend.addBreakPoint(addr, callback, thumb)`（Backend 层裸接口）和 `emulator.attach().addBreakPoint
(addr, callback)`（Debugger 层）是**两套不互通的断点注册表**。断点命中的分发逻辑
（`AbstractARMDebugger.onBreak`）查的是 Debugger 自己内部的 `breakMap`；如果断点是绕过 Debugger 直接
注册在 Backend 上的，`onBreak` 根本找不到对应的 callback，会误判成"没人处理这次断点"，从而掉进
`AbstractARMDebugger.loop()`——这是一个**交互式调试 REPL**，内部用 `Scanner` 读 `System.in` 等命令输入。
在非交互（比如批处理/CI）环境下，`scanner.nextLine()` 读不到真实输入，会不断打印
`"debugger break at: ..."` + 全部寄存器状态，且 PC 原地不动、断点反复命中，**无限循环刷屏**（曾经
产出几十万行、90+MB 的输出）。

```java
// ❌ 错误：会导致上述死循环
backend.addBreakPoint(addr, callback, false);

// ✅ 正确：教程原文用的就是这个
emulator.attach().addBreakPoint(addr, callback);
```

## 7. `emu_start` 的 `count` 参数

`backend.emu_start(pc, lr, timeout, count)` 的 `count` 传 `0`（语义上是"无限制"）在某些 Unicorn 版本
下可能会启用一条"不重新检查 hook"的 TB 缓存快路径，导致已经缓存过的翻译块不会再触发新注册的
hook/断点。稳妥起见传一个天文数字般大的值（如 `100_000_000_000L`）而不是 `0`，不会真的跑到这么多
指令，只是避免触发那条快路径。

## 8. 崩溃诊断：先看地址再猜

排查"到底撞在哪"，比事后读 PC 更可靠的做法是提前注册一个 `EventMemHook`：
```java
backend.hook_add_new(new EventMemHook() {
    public boolean hook(Backend backend, long address, int size, long value, Object user, UnmappedType type) {
        long curPc = backend.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue();
        System.out.println("!! " + type + " UNMAPPED addr=0x" + Long.toHexString(address) + " at PC=0x" + Long.toHexString(curPc));
        return false;   // 不代为处理，仍然报错，只是先把地址打出来
    }
    public void onAttach(UnHook unHook) {}
    public void detach() {}
}, UnicornConst.UC_HOOK_MEM_READ_UNMAPPED | UnicornConst.UC_HOOK_MEM_WRITE_UNMAPPED | UnicornConst.UC_HOOK_MEM_FETCH_UNMAPPED, null);
```
事后从 `catch (Exception e)` 里读 `backend.reg_read(PC)` 拿到的地址**不一定可靠**——可能已经是 JIT
块边界之后的下一条，不是真正出错那条指令。用 `emulator.disassemble(addr, size, count)`
（`ArmDisassembler` 接口）可以反汇编一段地址辅助人工判断。

拿到"卡在哪个地址"之后，用 `maps.log` 查这个地址属于哪个模块/段，判断是真的没采样到，还是别的问题
（本轮踩过一个例子：`crc32_buf` 校验 libc r-xp 段时把这段真机代码当**数据**读、被 dump 顺带采样了
下来，但回填时统一用 `UC_PROT_ALL` 把它也映射成了可执行——本该只当数据用的内容被错误映射成可执行
段，执行流意外跳了进去，往下跑到某处访问了真没被采样到的 `.bss` 地址——这不是"漏采样"，是"数据段
误映射为可执行权限"这个独立问题）。

### 8.1 卡住/死循环时：patch 跳出去，不用较真修复根因

定位到卡点之后，不是每次都要去补一个"完全正确"的环境或者去修 Unidbg/Unicorn 本身的 bug——
Unidbg 只是 Unicorn 的一层封装，本身不是完美的，遇到它自己的 bug（比如某些指令模拟跟真机不一致、
某个 hook 时机不对导致卡死循环）是正常情况，没必要陷进去修 Unicorn。实际做法是在卡点前后落一个
断点/`UC_HOOK_CODE`，直接把 PC patch 到应该去的地方，跳过这一段：

- 上面 `crc32_buf` 误跳进数据段的例子，与其去改内存映射权限方案，更直接的办法是在这段代码的
  入口/出口各下一个断点：入口断点直接给出校验应该返回的值（反正这段代码本来就只是读字节算
  checksum，跑不跑都不影响目标函数真正要算的结果），把 PC 直接改到调用者该拿到返回值继续跑的
  地方，完全跳过这段代码，不需要再纠结"到底哪些页该标可执行、哪些不该"。
- 只要**跳过去之后目标函数的最终结果是对的**，中间这段没跑（或者跑的是 patch 出来的假数据）
  完全不影响判断——dump 法本来就不追求"每条指令都物理复现真机"，追求的是最终结果确定、可复现
  （参照 §5 mock `Build.MODEL` 的思路：不追求真实，追求确定）。

## 9. 已知局限

- **路径覆盖**：dump 包只覆盖"这一次具体输入触达的那条执行路径"。一旦回填后改变了输入（比如 patch
  外部符号改变了分支走向），实际执行路径可能偏离原始采样路径，走到未被 dump 覆盖的地址。解法是同一
  目标函数多跑几次 trace_unidbg_dump、合并覆盖范围（增量 union）。
- **数据段误映射为可执行**：回填 `.bin` 段统一用 `UC_PROT_ALL`，有些段实际内容是"被当数据读的真机
  代码字节"，本该保持只读/不可执行，错误的可执行权限可能让执行流意外跳进去。后续可考虑按段的真实
  用途区分权限。
- **JNI**：`X0` 整体换成 Unidbg 自己 env 已完整验证，但真机执行路径中如果引用了"中途才产生、不经过
  `env->functions->XXX` 标准调用路径"的其它 ART 运行时对象（比较少见），仍不在覆盖范围内。
- 只验证过单线程主路径；多线程子路径未覆盖。

---

具体实现参考：`unidbg-dump-replay/src/main/java/test/ReplaySha256.java`（最简单例子，无外部符号）、
`unidbg-dump-replay/src/main/java/test/ReplayComplex.java`（完整例子，libc patch + JNI 处理全套）。
