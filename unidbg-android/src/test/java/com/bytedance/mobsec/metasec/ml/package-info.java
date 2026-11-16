/**
 * 抖音 39.4.0 的 {@code libmetasec_ml.so} 在 unidbg 里的本地补环境。文件按"往哪一层补"分组：
 *
 * <ol>
 *   <li><b>Java/JNI 层</b> — {@link ProfileJni}。metasec 向 Java 提出的一切（{@code MS.b} 回调、JNI 调用）都从
 *       {@code device/fp_values_full.json} 的录制回答；录制里没有的少数几条，在那里逐条注明来源。</li>
 *   <li><b>内核层</b> — {@link MetasecSyscalls}。unidbg 没有实现、或实现得不真实的 syscall 在测试侧补：
 *       {@code process_vm_readv}、{@code sysinfo}、{@code SIOCGIFCONF} 返回真机网卡、binder 拿不到的系统服务。</li>
 *   <li><b>启动装配</b> — {@link MetasecStartup}。属性区 {@code dev/__properties__}、两个 IOResolver
 *       （录制的 stat、{@code /proc/self}）、库解析器、shell 命令回放。只在启动时用一次。</li>
 *   <li><b>数据与状态</b> — {@link DeviceProfile}（{@code fp_values_full.json}）、{@link Build}
 *       （{@code metasec.json}，这个 so 版本的常量）、{@link MetasecState}（内存里的状态 + Keva 持久化）。</li>
 * </ol>
 *
 * <b>入口</b>：{@link MetasecEmulator} 构造即把环境补完，对外只有 {@code sign} / {@code ttEncrypt} /
 * {@code key} / {@code iv}。录制的初始化流程与断言在 {@link MetasecSign}。实验入口各自一个 {@code main}：
 * {@link CapturedApiTest}（回放一条抓包请求）、{@link RegisterFlowTest}（首装注册链路）、{@link ApplogUpload}
 * （ttEncrypt 外壳）、{@link MetasecSignRequest}（签一条真实请求）、{@link MssdkUpload}（mssdk 通道按时序回放）。
 * <p>
 * <b>单库验收（不是补环境）</b>：{@link EncryptorTest} 单独验 {@code libEncryptor} 的 ttEncrypt 往返。
 * <p>
 * 设备数据一律来自 {@code device/*.json}，代码里没有设备值。
 */
package com.bytedance.mobsec.metasec.ml;
