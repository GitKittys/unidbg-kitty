# Unidbg 使用手册（dump 法 + 常规用法速查）

写给下一个接手这份代码/继续做 Android native 逆向分析的人（或 AI）——目的是不用再把这一轮踩过的坑
重新踩一遍。内容分两大块：**dump 法**（本仓库 `unidbg-dump-replay` 模块实测验证过的完整流程和全部
坑）和**常规 Unidbg 用法速查**（loadso / 虚拟模块 / hook-patch / SVC 定制，来自仓库 `unidbg-android/
src/test/java` 下真实测试用例的核对结果，不是凭印象编的）。

---

## 0. 先搞清楚：什么时候用 dump 法，什么时候用常规 loadso

Unidbg 的"常规工作流"是：加载真实 `.so` 文件（`Module.load()`/`VM.loadLibrary()`）→ 让 Unidbg 自己的
ELF Loader 做重定位、处理依赖、跑 `.init_array`/`JNI_OnLoad` → 从**函数入口**开始调用，参数自己构造。

这条路的前提是：目标函数不太依赖复杂的运行时状态，或者依赖链能一路补全（依赖的 SO 都能找到/伪造，
初始化函数都能跑通）。

**dump 法**是反过来的思路：目标函数依赖链太深、补环境太痛苦（要么依赖库找不全，要么初始化会报错、
死循环），干脆不走 Loader、不管初始化，直接把**真机上某一时刻已经跑通的内存镜像 + 寄存器状态**原样
搬到 Unidbg 里，从**执行中途**接着跑。用 unicornTrace 的 `trace_unidbg_dump()`/`trace_unidbg_dump_finish()`
在真机上采样，产出一份 dump 包，再用 [DUMP_METHOD.md](./DUMP_METHOD.md) 的方法回填进 Unidbg。

两条路不是互斥的：dump 法跑起来之后，如果撞到"这个符号/JNI调用需要处理"这种情况，patch 手法（本
手册第 1.4 节 / [DUMP_METHOD.md 第 5 节](./DUMP_METHOD.md#5-jnix0-整体换成-unidbg-自己的-env不是-dump-真机-env-内存)）在两条路上都用得上。

### 0.1 心态：难补的地方不要硬补，合理用 patch 补数据/补执行流

不管走哪条路，一旦撞上"环境补不出来"（缺的库找不到、初始化跑不通、某个依赖没法在 Unidbg 里
重现）或者"Unidbg/Unicorn 自己的 bug"（模拟出的行为跟真机不一致、卡在某处死循环出不来），
**不要想着把环境彻底补"真"**——目标从来不是让 Unidbg 变成一台完美的真机，而是让目标函数能跑出
和真机一致的**结果**。遇到这种卡点，直接 patch：

- **补数据**：某个值/字段 Unidbg 里天然拿不到（系统属性、ART 内部状态、没 dump 到的内存），
  就在断点/hook 回调里直接把想要的值写回寄存器或内存，不用纠结"这个值本来应该怎么正确地算出来"。
  参见 [DUMP_METHOD.md 第 5 节](./DUMP_METHOD.md#5-jnix0-整体换成-unidbg-自己的-env不是-dump-真机-env-内存)
  mock `Build.MODEL`/`Build.FINGERPRINT` 的做法。
- **补执行流**：某段代码 Unidbg 死活跑不对（比如撞上 Unicorn 自身的 bug、或者根本没必要模拟的分支），
  用断点把 PC 直接改到目标函数执行完之后该到的地方，跳过这一段，不用花时间去让 Unidbg 把这段"正确"
  地模拟一遍。**Unidbg 不是完美的，它只是 Unicorn 的一层封装**，遇到死循环/卡死时，patch 跳出去
  就是最直接的解法，不必较真去修 Unidbg 或 Unicorn 本身的 bug。
- 判断"哪里卡住了"用第 1.4 节的 `UC_HOOK_CODE`/断点先观察（无痕，不影响判断），确认卡点之后再决定
  要不要在这里落一个真正改数据/改执行流的 patch。

---

## 1. 常规用法速查（供对比参考，本仓库主要用的是第 2 节的 dump 法）

### 1.1 标准 loadso 流程

```java
AndroidEmulator emulator = AndroidEmulatorBuilder.for32Bit()   // 或 for64Bit()
        .setProcessName("com.example.app")
        .build();
Memory memory = emulator.getMemory();
memory.setLibraryResolver(new AndroidResolver(23));            // 指定模拟的 Android API Level

VM vm = emulator.createDalvikVM();
vm.setVerbose(true);                                           // 打开 JNI 调用 trace
vm.setJni(this);                                                // this 实现 AbstractJni，覆写需要的 JNI 方法

DalvikModule dm = vm.loadLibrary(new File("libtarget.so"), false);
dm.callJNI_OnLoad(emulator);
Module module = dm.getModule();

// 走 Java 层暴露的 native 方法：
DvmClass cls = vm.resolveClass("com/example/Encrypt");
ByteArray result = cls.callStaticJniMethodObject(emulator, "encrypt([BI)[B", new ByteArray(vm, data), data.length);

// 或者直接调导出函数（不走 JNI）：
Number r = module.callFunction(emulator, "_Z4testv");           // 按符号名
Number r2 = module.callFunction(emulator, 0x7e0 + 1);            // 按偏移（ARM32 注意 +1 表示 thumb）
```
参考：`unidbg-android/src/test/java/com/bytedance/frameworks/core/encrypt/TTEncrypt.java`、
`unidbg-android/src/test/java/com/github/unidbg/android/AndroidTest.java`、
`unidbg-android/src/test/java/org/aeonlucid/AndroidNativeEmuTest.java`。

`vm.setJni(this)` 配 `AbstractJni` 子类覆写方法，是 [DUMP_METHOD.md 第 5 节](./DUMP_METHOD.md#5-jnix0-整体换成-unidbg-自己的-env不是-dump-真机-env-内存)"JNI mock 静态字段"用的同一套机制。

### 1.2 虚拟模块加载（loadVirtualModule）

**用途**：目标 SO 依赖了一个 Unidbg 模拟不了、也没必要真模拟的系统 SO（比如
`libjnigraphics.so`/`libandroid.so`/`libsystemproperties.so`），不需要真的加载它，伪造一个"空壳模块"，
只注册它对外暴露的几个符号地址，让动态链接器能正常做 relocation，不会因为"缺 SO"而加载失败。

```java
// 接口：Loader.loadVirtualModule(String name, Map<String, UnidbgPointer> symbols)
// 标准封装：继承 VirtualModule<T>，覆写 onInitialize 填充 symbols

public class SystemProperties extends VirtualModule<Void> {
    public SystemProperties(Emulator<?> emulator, Void extra) {
        super(emulator, extra, "libsystemproperties.so");
    }
    protected void onInitialize(Emulator<?> emulator, Void extra, Map<String, UnidbgPointer> symbols) {
        SvcMemory svcMemory = emulator.getSvcMemory();
        symbols.put("__system_property_read_callback", svcMemory.registerSvc(new Arm64Hook() {
            @Override
            protected HookStatus hook(Emulator<?> emulator) { ... }
        }));
    }
}

// 调用处：
new SystemProperties(emulator, null).register(memory);
new JniGraphics(emulator, vm).register(memory);
new AndroidModule(emulator, vm).register(memory);
```
参考：`unidbg-api/src/main/java/com/github/unidbg/virtualmodule/VirtualModule.java`、
`unidbg-android/src/main/java/com/github/unidbg/virtualmodule/android/SystemProperties.java`（及同目录
`JniGraphics`/`AndroidModule`/`MediaNdkModule`）。

### 1.3 SVC（系统调用）定制

两个层面：

**(a) 覆写 Linux syscall 处理**——继承 `ARM32SyscallHandler`/`ARM64SyscallHandler`，覆写具体 syscall
方法或 `handleUnknownSyscall(emulator, NR)` 兜底：
```java
class MySyscallHandler extends ARM64SyscallHandler {
    protected boolean handleUnknownSyscall(Emulator<?> emulator, int NR) {
        if (NR == 260) { /* wait4 */ return true; }
        return super.handleUnknownSyscall(emulator, NR);
    }
}
// 装配：自定义 Emulator 子类覆写 createSyscallHandler(SvcMemory)
```

**(b) `SvcMemory.registerSvc(Svc)` 插入自定义 native 回调点**——在一小块可执行内存写入 `svc #N; ret`
桩代码，guest 代码 `blr` 过去触发 svc 异常时回调 Java 端的 `Svc.handle(Emulator)`；`Arm64Hook`/`ArmHook`
是在此基础上封装的"用假实现替代真函数"专用接口，返回 `HookStatus` 决定后续（第 1.2 节
`SystemProperties` 例子就是标准用法）。

参考：`unidbg-android/src/test/java/com/github/unidbg/android/ida/MyARM64SyscallHandler.java`、
`unidbg-api/src/main/java/com/github/unidbg/arm/Arm64Svc.java`。

### 1.4 Hook / Patch 手法（除了断点还有这些）

| 方式 | 用途 | 关键 API |
|---|---|---|
| **HookZz** | 对导出函数做 pre/post 包裹（不改变原逻辑）；对内部子函数做纯观测 | `HookZz.getInstance(emulator)` → `wrap(Symbol, WrapCallback)` / `instrument(addr, InstrumentCallback)` |
| **Dobby** | 真正的 inline hook，可完全替换函数实现，回调里拿到 `originFunction` 决定是否调用原函数 | `Dobby.getInstance(emulator)` → `replace(Symbol, ReplaceCallback, boolean enablePostCall)` |
| **xHook** | 对指定 SO 的**导入表**符号做替换（类似 Android xHook 的 PLT hook） | `XHookImpl.getInstance(emulator)` → `register(soName, symbolName, ReplaceCallback)` + `refresh()` |
| **InlineHook** | 直接 patch 目标地址第一条指令为 `svc #N` 跳转（仅限特定序言，ARM32/Thumb） | `InlineHook.simpleArmHook/simpleThumbHook(emulator, address, HookCallback)` |
| **断点** | 我们这一整轮 dump 法主要用的手法，见 [DUMP_METHOD.md 第 5/6 节](./DUMP_METHOD.md#5-jnix0-整体换成-unidbg-自己的-env不是-dump-真机-env-内存) | `emulator.attach().addBreakPoint(addr, BreakPointCallback)` |
| **UC_HOOK_CODE（Unicorn 原生）** | **唯一无痕的方式**：纯引擎级取指回调，按地址区间过滤，不改写 guest 内存里的任何字节 | `backend.hook_add_new(CodeHook callback, begin, end, user_data)` |

**上面这几种的本质区别（有代价 vs 无痕）**：HookZz/Dobby/xHook/InlineHook 都要往 guest
内存里**实际写入字节**（trampoline、替换指令、改 GOT/PLT 表项、patch 首条指令）——即使这是 Unidbg
模拟出来的内存而非真机内存，写入这个动作本身就是"有代价"的：它改变了该地址处的实际内容，一旦有
代码把这段内存当**数据**读出来做校验（典型例子见 [DUMP_METHOD.md 第 8 节](./DUMP_METHOD.md#8-崩溃诊断先看地址再猜)
里 `crc32_buf` 读 libc 代码段做完整性校验的场景），patch 过的字节就会被读到、校验结果就会和真机不一致。
`emulator.attach().addBreakPoint()` 本身内部也是基于 Unicorn 的地址断点表+hook 分发实现的，同样不
patch 内存，和 `UC_HOOK_CODE` 一样无痕；只有 HookZz/Dobby/xHook/InlineHook 这四种是真的会改字节。
需要"改变执行结果"（比如把外部符号跳转到 Unidbg 自己的实现）时才必须用断点/patch 这类有代价的手法；
只是"观测执行、不改变任何结果"时，优先用 `UC_HOOK_CODE`，不留痕迹。

参考：`unidbg-android/src/test/java/com/bytedance/frameworks/core/encrypt/TTEncrypt.java`（同一个文件里
演示了前三种 hook 方式）。

---

## 2. dump 法（详见独立文档，按需打开）

Unidbg 侧无关，是把 unicornTrace 在真机上采样出的内存镜像+寄存器状态直接回填进 Unidbg、从执行中途
接着跑的一套方法——完整流程、6 个实测踩过的坑（ART 堆指针 tag、libc fortify 符号名匹配、JNI 处理的
两次弯路、断点机制的死循环坑、`emu_start` 的 `count` 陷阱、崩溃诊断方法）和已知局限，都写在单独一份
文档里，**只在需要具体做 dump 法回填/排查问题时才打开**：

👉 **[DUMP_METHOD.md](./DUMP_METHOD.md)**

代码实现在本仓库 `unidbg-dump-replay/src/main/java/test/`（`ReplaySha256.java` 最简单例子，
`ReplayComplex.java` 完整例子含 libc patch + JNI 处理全套）。

---

## 3. 环境搭建注意事项

- **必须用 JDK 8** 编译 `unidbg-api`/`unidbg-android`——源码里未限定的 `Module` 引用在 JDK 9+ 会和
  `java.lang.Module`（JPMS 引入）产生二义性编译错误，只有走 JDK 8 才不会撞名：
  ```bash
  JAVA_HOME=/path/to/jdk8 mvn -pl <你的模块> -am package
  ```
- 只构建需要的模块 + 它的 reactor 依赖，跳过 `unidbg-ios`/`backend/dynarmic`/`backend/hypervisor`/
  `backend/kvm`/`backend/unicorn2` 这些用不上的模块（`-pl <module> -am` 只会连带构建它真正依赖的
  reactor 模块）。
