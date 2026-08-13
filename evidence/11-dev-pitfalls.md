# memshell-auditor 开发踩坑记录（二期取证功能）

> 目的：记录开发过程中的关键问题、根因分析与解法，作为后续技术文章的素材。
> 原则：**截图/输出/命令原文全部保留**，可追溯、可复现。

## 坑 1：lsof 抓错进程的连接（回连分析噪声）

**问题现象**：NetworkAnalyzer 用 `lsof -p <pid> -iTCP` 分析回连，结果抓到了 141 条连接，其中大量是无关进程的（rapportd/cloudd/Surge/AweSun 等系统与代理进程的连接），还有 localhost 内部连接、私有网段、系统端口。回连分析完全不可用。

**命令原文（复现）**：
```bash
lsof -p 44559 -iTCP -sTCP:ESTABLISHED
# 输出里出现 rapportd/cloudd/Surge/AweSun 等无关进程的连接
```

**根因分析**：macOS 的 lsof 在 `-p <pid>` 与 `-iTCP` 组合时存在已知行为——`-iTCP` 会匹配**所有** TCP socket 文件描述符，而不仅限于该进程，导致输出混入系统其他进程的连接。（实际上更准确：lsof 的 `-p` 应该只显示该进程的 fd，但输出显示的是别的问题——需要进一步确认是 lsof 版本行为还是 -iTCP 的扩展匹配）

**解法**：NetworkAnalyzer 增加**外部 IP 过滤**：
- 过滤 localhost / 127.0.0.1 / ::1 / *.local
- 过滤私有网段（10.x / 192.168.x / 172.x / 169.254.x）
- 过滤系统服务端口（1024/5228/5353 等）
- 过滤 IPv6 本地链路（fe80/fc/fd 前缀）
- 保留 443/80（C2 常用）

**验证**：过滤后从 141 条降到 62 条，但仍有 `117.28.246.44:10427`（腾讯云）等外连——需进一步结合进程实际网络行为判断（本机代理 Surge 的出口 IP 可能被误报）。

## 坑 2：ClassDumper 对 JMG 混淆载荷 retransform 失败

**问题现象**：dump 功能对磁盘类（BizFilter）和简单 defineClass 类（z9x8）都能成功提取字节码，但对 JMG 生成的 Suo5 内存马类（`org.springframework.SessionKqvcFilter`）抛 `InternalError: class redefinition failed: invalid class`。

**测试证据（DumpTest3 输出）**：
```
TEST: org.springframework.SessionKqvcFilter
  retransform FAIL: java.lang.InternalError: class redefinition failed: invalid class
TEST: BizFilter
  retransform OK, bytes=709
```

**根因分析**：
1. 简单 defineClass 类（自定义 EvilCl 加载的 z9x8）→ retransform **成功**，415B 字节码完整提取
2. 磁盘类（BizFilter）→ retransform 成功，709B
3. JMG 混淆载荷（SessionKqvcFilter）→ retransform 失败

**深入排查（DumpTest5）**：
```
TARGET: org.springframework.SessionKqvcFilter
  CodeSource: (null <no signer certificates>)   ← defineClass 注入类无 CodeSource（A1 补充证据）
  CodeSourceLoc: null
  classes field err: classes                      ← JDK 26 模块限制无法反射 ClassLoader.classes
```

**结论**：JMG 生成的载荷经过 ASM 字节码处理/常量池特殊处理，JVM 判定其不可重定义（invalid class）。这是**单点已知局限**，不是通用缺陷。对这类载荷：
- CodeSource=null 本身就是 A1 强信号的补充证据
- 兜底方案：`jmap -dump` 堆 dump 后从堆中恢复字节码（实测堆 dump 30MB 成功，但 hprof 中字节码被 JVM 优化存储，直接搜索 cafebabe 魔数未命中——需 MAT 分析或反序列化恢复）

## 坑 3：同一 JVM 重复 attach 缓存 agent 类

**问题现象**：反复修改 agent 代码后重新构建，attach 到同一目标 JVM 测试，发现**改动不生效**——执行的是旧版 agent 逻辑。

**复现**：
```bash
# 第一次 attach 加载了旧版 DumpTest2（无 $1 匿名类）
# 修复后重新打包 DumpTest2.jar（含 $1）
# 再次 attach 同一 JVM → 报 NoClassDefFoundError: DumpTest2$1
# 因为 DumpTest2 类已在 JVM 中加载（旧版），新 jar 的类不会重新加载
```

**根因**：attach 加载 agent 时，agent 类被目标 JVM 的系统 ClassLoader 加载；**同一 JVM 第二次 attach 同一 agent jar，类不会重新加载**（JVM 类加载缓存）。

**解法**：**每次修改 agent 代码后必须重启目标进程再测试**。这也是为什么后面测试都用新端口+新进程。

**文章素材价值**：这是 Java Agent 开发的经典坑，值得单独写。

## 坑 4：addTransformer 的 canRetransform 参数必须为 true

**问题现象**：`inst.addTransformer(tf, false)` 注册 transformer 后 `retransformClasses(cls)` 不触发 transform 回调，字节码提取失败返回 null。

**根因**：`addTransformer(transformer, canRetransform)` 第二个参数为 `false` 时，该 transformer **不会**在 retransformClasses 时被调用（只会在新类加载时调用）。要配合 retransform 提取字节码，**必须传 true**。

**解法**：
```java
inst.addTransformer(tf, true);  // canRetransform=true 关键
```

**验证**：改为 true 后 BizFilter 与 z9x8 都能成功 dump。

## 坑 5：JDK 21+ 动态 attach 警告与模块限制

**问题现象**：每次 attach 目标 JVM 都打印 WARNING：
```
WARNING: A Java agent has been loaded dynamically
WARNING: Dynamic loading of agents will be disallowed by default in a future release
```

**解法**：生产环境建议 `-XX:+EnableDynamicAgentLoading` 隐藏警告；JDK 9+ attach 需要 `--add-modules jdk.attach`。

## 坑 6：ClassLoader.defineClass 反射在 JDK 26 模块系统受限

**问题现象**：测试靶场注入内存马时，`ClassLoader.class.getDeclaredMethod("defineClass").setAccessible(true)` 抛 `InaccessibleObjectException: module java.base does not opens java.lang`。

**解法**：启动参数加 `--add-opens java.base/java.lang=ALL-UNNAMED`。这也解释了为什么真实攻击者在 JDK 17+ 环境下注入内存马需要特殊手法（MethodHandles.Lookup.defineClass 等）。

## 待解决 / 后续方向

1. **JMG 混淆载荷的字节码恢复**：jmap 堆 dump + MAT 分析（搜索 byte[] 内容）；或研究 Unsafe/内部 API
2. **回连分析精确化**：lsof 输出去噪后仍混入代理出口 IP，需结合连接时间/方向/进程 fd 归属更精确判定
3. **CFR 集成**：javap 反汇编展示有限，v2 计划集成 CFR 做完整 Java 反编译（核心代码可读性大幅提升）

## 坑 7：behinder 可 dump，suo5 不可 dump（JMG 载荷差异）

**问题现象**：二期最终验证发现，同为 JMG 生成的载荷，**behinder-filter 可以 retransform dump（4160B 成功），suo5-filter 不可以（invalid class）**。

**对比测试**：
| 载荷 | 类 | dump 结果 |
|---|---|---|
| behinder-filter | org.springframework.ServletRequestAujFilter | ✅ 4160B 完整提取 |
| suo5-filter | org.springframework.SessionKqvcFilter | ❌ invalid class |

**根因**：JMG 对不同工具的内存马采用了不同的字节码生成策略——Behinder 载荷字节码规整（可直接重定义），Suo5 载荷经过更激进的 ASM 处理（常量池/字节码结构导致 JVM 拒绝重定义）。这是生成端差异，不是检测端问题。

**解法**：
1. 能 dump 的类：自动 dump + javap 反编译（核心代码完整展示）✅
2. 不能 dump 的类：CodeSource=null 作为 A1 补充证据 + 建议 jmap 堆 dump 兜底

**验证（behinder-filter 反编译核心代码）**：
```
public class org.springframework.ServletRequestAujFilter extends java.lang.ClassLoader implements jakarta.servlet.Filter {
  public java.lang.String pass;         ← 冰蝎连接密码
  public java.lang.String headerName;   ← 认证头
  public java.lang.String headerValue;
  public byte[] doBase64Decode(String)  ← Base64 解码命令载荷
}
```

**文章素材价值**：展示了"真实生成器载荷的差异性"——检测工具必须对每种载荷做适配验证，不能假设生成器输出统一。

## 坑 8：回连分析混入代理出口 IP

**问题现象**：NetworkAnalyzer 过滤 localhost/私有网段后仍混入大量"正常外连"（8.136.124.250 是 AweSun/阿里云、117.28.246.44:10427 是代理出口等），导致 Callback 列表噪声大。

**根因**：目标进程（Tomcat 靶场）本身没有恶意外连，抓到的都是**本机其他服务**（AweSun 远程控制、Surge 代理、系统更新）的 ESTABLISHED 连接——lsof -p 在某些 macOS 版本下会匹配到系统共享的 socket 或代理重定向的连接。

**解法（待完善）**：
- 更精确的进程 fd 归属判断（lsof -p -a -i 组合）
- 增加"已知正常服务 IP"白名单（阿里云/AWS/GCP/腾讯云公网段）
- 结合 dump 出的代码字符串中的硬编码 IP（更可靠的 C2 指标）
- 结合威胁情报 API 查询（后续）

**文章素材价值**：这是所有网络取证工具的共性挑战——如何区分"进程真实外连"与"系统噪声"，值得展开写。

## 坑 9：混淆 agent 自身被审计误报

**问题现象**：混淆取证程序 attach 到目标 JVM 后，agent 自身的类（net.jvm.check.*）也被 ClassFeature/AgentAuditor 扫描到，因类名含 "inject"（AgentAuditor 的 SUSPICIOUS_KEYWORDS）等原因报 MEDIUM；且混淆后 "javacore" 成为新可疑词又触发。

**根因**：审计逻辑对"自身类"的排除写死了 `com.memshellauditor` 前缀；混淆后包名变成随机的 `net.jvm.check` 等，不再被排除。

**解法**：改为**动态识别自身**——通过 `ObfuscateAgentGenerator.class` / `AgentMain.class` 的包名动态获取当前 jar 的包前缀，审计时排除该前缀。这样主程序和混淆程序都能正确排除自身。

## 坑 10：jar 重写时 MANIFEST.MF 重复

**问题现象**：`JarOutputStream(Manifest)` 自动写入 MANIFEST.MF，遍历原 jar 又遇到 META-INF/MANIFEST.MF → `ZipException: duplicate entry`。

**解法**：遍历时跳过 META-INF/MANIFEST.MF 条目。

## 坑 11：替换规则顺序导致包名被二次替换

**问题现象**：HashMap 遍历顺序不定，`memshell→javacore` 规则先执行，把 `com.memshellauditor` 里的 `memshell` 替换成 `javacore`，变成 `com.javacoreauditor`，包名替换规则失配 → `wrong name: com/javacoreauditor/AuditorMain`。

**解法**：改用 LinkedHashMap 保证顺序（先包名后敏感词）；且敏感词替换只针对独立标记，不替换会出现在类名中的词（auditor/checker 等）。

## 坑 12：类名不能参与敏感词替换

**问题现象**：`auditor→checker` 规则把类名 `AuditorMain` 也替换成 `CheckerMain`，但 class 文件路径还是 AuditorMain.class，this_class 与文件路径不一致 → `NoClassDefFoundError: wrong name`。

**解法**：只替换包名前缀 + 独立敏感词（memshell/webshell 等），不替换类名中的词。

## 坑 13：取证人员不知道审计哪个 PID

**问题**：工具需要指定 `<pid>`，但现场取证人员面对几十个 Java 进程，不知道哪个是目标 Web 应用，逐个试不现实。

**解法**：新增 `--scan` 全自动扫描模式：
- 枚举所有 Java 进程（VirtualMachine.list()）
- 可疑度评分排序（Tomcat/Spring Boot/WebLogic 等 Web 容器 +100 优先，可疑关键字 +60，工具/守护 -30，自身 -1000）
- 自动跳过自身与工具进程，逐个 attach 审计
- 汇总按 HIGH 数排行输出（取证人员一眼锁定可疑进程）

**实测**：9 进程环境扫描，Web 容器 3 个排前，自身进程正确识别跳过，5 个目标逐个审计，汇总 HIGH=2/1/1/1/0。

**后续优化方向**：
- 并发扫描（当前串行，多进程场景可提速）
- 超时控制（个别进程 attach 卡住会影响整体）
- 报表文件聚合（当前每进程一个 JSON，可加总览 XML/HTML）
