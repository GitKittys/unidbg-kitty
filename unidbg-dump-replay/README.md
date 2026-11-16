# unidbg-dump-replay

把在真机上**采样**出来的一份 native 执行现场 dump 包，在真正的 Unidbg 里**回填**并原样跑一遍——
不重新用别的语言实现一遍算法当参考答案，只回填现场 + 把运行中真正用到的外部符号 patch 到 Unidbg
自己 `dlopen` 出来的 libc 对应地址，跑出来是什么就是什么。全程只用 `Backend` 的
`mem_map`/`mem_write`/`reg_write`/`emu_start`/`addBreakPoint` 这套底层公开接口，不依赖 Unidbg 的
Module/Loader/DalvikVM 那一整套。

## 它解决什么

传统做法是用 Unidbg 从头加载目标 SO、再手工补环境（JNI、文件系统、系统属性、依赖库……）才能让一段
native 代码跑起来。dump-replay 换一条路：**现场已经在真机上发生过，把它整段搬进 Unidbg 续着跑**，
从而跳过补环境这步。它和一键采样工具配套使用：

- **采样端** —— [AndroidPrybar](https://github.com/GitKittys/AndroidPrybar/)。它是一个 Android native
  trace 与分析工具，内置 `trace_unidbg_dump()`：在真机上把某个目标函数运行到某一点时的完整现场
  一键 dump 下来——内存段（`<start>_<end>.bin`）、入口寄存器（`regs.txt`）、外部符号表
  （`symbols.log`）、JNI 函数表（`jni_table.log`）、`/proc/self/maps`、以及目标运行时 open 过的
  文件按原路径落进的 `rootfs/`。
- **回放端** —— 本模块。读上面那份 dump 包，在 Unidbg 里重建内存与寄存器现场，处理好标准 Unicorn
  与采样端之间的地址语义差异（见下），把外部符号 patch 到 Unidbg 自带 libc，然后从入口 PC 跑到底。

## 目录结构

```
unidbg-dump-replay/
├── pom.xml
├── src/main/java/test/
│   ├── ReplaySha256.java    ← 简单例子：纯 ALU，零外部符号，回填即可跑通
│   └── ReplayComplex.java   ← 复杂例子：JNI 指纹 + libc CRC32 校验 + AES，演示 patch 外部符号
└── sample-dumps/
    ├── unidbg_dump/           ← sha256_raw_2blocks
    └── unidbg_dump_complex/   ← 指纹 + libc CRC32 校验 + AES-128-ECB
```

两份样例数据都是 AndroidPrybar 的采样用例在真机上跑出来的原始 dump 包，未经任何修改。

## 构建 & 运行

**必须用 JDK 8**（unidbg-api 源码里未限定的 `Module` 引用在 JDK 9+ 会和 `java.lang.Module` 产生
二义性编译错误，只有走 JDK 8 编译才不会撞名）：

```bash
# 只构建本模块 + 它依赖的 unidbg-api / unidbg-android（跳过 ios/backend 等不需要的模块）
JAVA_HOME=/path/to/jdk8 mvn -pl unidbg-dump-replay -am package

# 简单例子：回填即可跑通（不传参数默认用 sample-dumps/unidbg_dump）
java -cp unidbg-dump-replay/target/unidbg-dump-replay.jar test.ReplaySha256 [dumpDir]

# 复杂例子：回填 + patch 外部符号
java -cp unidbg-dump-replay/target/unidbg-dump-replay.jar test.ReplayComplex [dumpDir]
```

## 结果

### ReplaySha256（`sha256_raw_2blocks`）

无外部符号（`symbols.log` 为空），回填寄存器 + 内存后直接从 PC 跑到 LR：

```
=== emu_start 正常返回 ===
Unidbg 回填现场跑出的结果: 902a848dfe9cb1a1e92d11d8fecc0cf6a094263af697a347c93ff7da712df869
```

跑出来就是跑出来了，不需要另外找参考答案比对——dump 法的价值就在于 Unidbg 执行的是真实设备上
那份机器码本身。

### ReplayComplex（`complex_fp_crc_aes_sign`）

这个例子会真正用到「patch 外部符号」和「JNI 表原地覆写」：

1. `emulator.getMemory().dlopen("libc.so")` 加载 Unidbg 自带的 libc（`android/sdk23/lib64/libc.so`
   资源），拿到一份可供 `findSymbolByName` 查询的真实符号表
2. 回填 dump 出的内存段 + 入口寄存器；`rootfs/` 整棵树搬进 Unidbg 的虚拟文件系统根（采样端会把
   目标运行时 open 过的文件，包括 `/proc/self/maps`，按原始路径落进 `rootfs/` 下）
3. **ART 堆指针的 top-byte tag 坑**：`X0`（JNIEnv*）等寄存器的值形如 `0xb400007339345390`，
   采样端的 VCPU（可编程 ARM64 CPU）会在 hook 触发前自动剥掉 tag 再记录页号，所以 dump 出来的
   `.bin` 文件名是「去 tag」后的地址；但 Unidbg 用的是标准 Unicorn，不会剥 tag，会拿寄存器里的
   原始带 tag 值去找映射。解法：扫一遍入口寄存器，凡是 top byte 非零的，把对应「去 tag」页的内容
   在「带 tag」地址上再镜像映射一份
4. **JNI：`X0`（`JNIEnv*`）整体换成 Unidbg 自己真正认可的 env 地址**（`vm.getJNIEnv()` 返回值），
   不再使用真机 dump 出来的 env 值。这样 guest 解引用 `env->functions->XXX` 走的是 Unidbg 自己那张
   本来就正确、从未被动过的函数表，「调用路由对」和「`vm.setVerbose(true)` 的 trace 认得出 env
   身份」两个问题一起解决。`getStaticObjectField` 里给 `Build.MODEL`/`FINGERPRINT` 配了固定 mock 值
   （这两个字段真机上也是活的系统属性，dump 不出来，思路和固定时间戳一样：不追求「一模一样」，
   追求「确定、可复现」）
5. 解析 `symbols.log`：对已解析出符号名的外部调用（libc），在原设备地址上下断点，命中时把 `PC`
   改写成 Unidbg 自己 libc 里对应符号的地址，然后 `return true` 继续跑；对 `<unresolved>`（JNI）
   直接跳过，因为上一步已经把整张表处理好了
   - **fortify 加固符号名要按基础函数名去找**：`__strncpy_chk`/`__memcpy_chk`/`__open_2` 这类是
     编译期加了参数校验的加固变体，语义和基础函数一样，但 Unidbg 自带的是 Android 6(SDK23) 年代
     的老 libc，不一定导出这些加固变体。直接判断符号名里「包不包含」某个已知基础名就按基础名处理
   - **断点必须用 `emulator.attach().addBreakPoint(...)`（Debugger 层），不能用
     `backend.addBreakPoint(...)`（Backend 裸接口）**：断点命中的分发（`AbstractARMDebugger.onBreak`）
     查的是 Debugger 自己的 `breakMap`；绕过 Debugger 直接注册在 Backend 上，`onBreak` 找不到对应
     callback，会误判成「没人处理」掉进交互式调试 REPL
   - `emu_start` 的 `count` 参数传很大的值（而非 `0`）而非依赖「无限制」语义，避免个别 Unicorn
     版本下 TB 缓存快路径跳过 hook 重新检查

实际运行结果：

```
=== 共回填 13 段内存 ===
=== JNI 函数表(0x71e6d8d7b8, 229 项)已原地覆写为 Unidbg 自己的哨兵值 ===
=== X0(JNIEnv*) 从真机值 0xb400007339345390 换成 Unidbg 自己的 env 0xfffe16b0，已开启 vm.setVerbose(true) ===
  tag 镜像映射: 0x7339326000-0x7339366000 -> 0xb400007339326000 (来自 X0=0xb400007339345390)
=== 共补了 1 段 tag 镜像映射 ===
=== 共 patch 12 个外部符号，0 个 JNI 调用未 patch(已知局限) ===
=== 开始在 Unidbg 内从 PC=0x7150b03a60 跑 ===
JNIEnv->FindClass(android/os/Build) was called from unidbg@0x7150ae6004
JNIEnv->GetStaticFieldID(android/os/Build.MODELLjava/lang/String;) => 0xd3d6520f was called from unidbg@0x7150ae6048
JNIEnv->GetStaticObjectField(class android/os/Build, MODEL Ljava/lang/String; => "unidbg-replay") was called from unidbg@0x7150ae60b8
JNIEnv->GetStringUtfChars("unidbg-replay") was called from unidbg@0x7150ae6994
  patch: 0x74795955c0 (__strncpy_chk -> strncpy) -> Unidbg 自带 libc 0x12052218
...
```

JNI 这条线彻底走通：`<unresolved>` JNI 调用全部正确执行，`vm.setVerbose(true)` 打出的调用轨迹和
目标源码里 `FindClass → GetStaticFieldID(MODEL) → GetStaticFieldID(FINGERPRINT) → GetStaticObjectField
→ GetStringUTFChars → strncpy → ...` 的真实调用顺序逐行对上；`strncpy`/`open`/`read` 三个 libc 符号
patch 依旧生效。

## 已知局限（对齐采样端 `trace_unidbg_dump` 的 v1 范围）

- 只验证了单线程主路径；多线程子路径未覆盖
- 路径覆盖：一旦回填后改变了输入（如 patch 外部符号），实际执行路径可能偏离原始采样时的路径，
  走到未被 dump 覆盖的地址——这是 dump 法固有边界，解法是同一目标函数多跑几次采样、合并覆盖范围，
  不在本模块 v1 范围
- **数据段误映射为可执行**：回填 `.bin` 段时统一用 `UC_PROT_ALL`（可读可写可执行），但有些段
  实际内容是「被当数据读的真机代码字节」（如 libc CRC 校验读到的 r-xp 段），本该保持只读/不可执行，
  后续可考虑按段的真实用途区分权限
- JNI：`X0` 整体换成 Unidbg 自己 env 已完整验证，但真机执行路径中如果引用了「中途才产生、不经过
  `env->functions->XXX` 标准调用路径」的其它 ART 运行时对象（比较少见），仍不在当前覆盖范围内

## 已排除的方案

- ❌ **先用 Unidbg 自己的 Loader 正常加载目标 SO（`memory.load(...)`），再拿 dump 数据去合并/覆盖**——
  Unidbg 的 Loader 没有公开 API 能指定固定加载基址，加载后的基址必然和真机 dump 时的基址不同，
  「合并」就要先做一轮地址重定位，相当于自己再手写一遍动态重定位；更根本的是这和 dump 法的初衷
  矛盾——dump 法本来就是为了**跳过**补环境/加载依赖，再绕回去用 Loader 加载等于把想省掉的工作量
  又加了回来。不做。
