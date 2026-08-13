# memshell-auditor v2.0 开发过程记录（文章素材：发现问题→方案→解决）

> 用途：完整记录 v2.0 架构演进中的每个问题、方案与解决过程，配截图/命令原文，作为后续技术文章的一手素材。
> 原则：每个问题 = 背景（为什么）→ 方案（设计决策）→ 实现（代码/命令）→ 验证（真实输出）

## 问题 1：取证工具自身可被识别（对抗问题）

**背景**：内存马攻击者/红队会监控目标机器上的进程列表、jar 文件名、类名特征。如果取证工具叫 `memshell-auditor.jar`、类名 `com.memshellauditor.*`，攻击者一看进程就知道"被取证了"，会立即隐藏内存马、销毁证据、甚至反制（如检测到取证工具后停止回连）。

**方案**：双程序架构——
- 主程序（分析者机器）：生成取证程序 + 分析报告
- 取证程序（目标系统）：每次由主程序 `--gen-agent` 生成，文件名/包名/类名/字符串全部随机混淆
- 关键点：**每次生成的特征不同**，攻击者无法预判

**实现**：`obf/ClassRewriter.java`（class 常量池重写器）+ `obf/ObfuscateAgentGenerator.java`

**验证（截图见 evidence/screenshots/06-dual-program.png）**：
```bash
$ java -jar memshell-auditor.jar --gen-agent /tmp/obf-test4 --name-prefix system-diag
[*] 混淆取证程序已生成: /tmp/obf-test4/system-diag-2c4488.jar
# 包名 com.memshellauditor → net.jvm.check（随机）
# 输出前缀 [memshell-auditor] → [jre-check]
# 全程无 memshell 特征
```

## 问题 2：取证人员不知道审计哪个 PID

**背景**：工具要求 `<pid>`，但现场取证人员面对几十个 Java 进程，不知道哪个是目标 Web 应用。

**方案**：`--scan` 全自动扫描——枚举所有 Java 进程 → 可疑度评分排序 → 逐个审计 → 汇总 HIGH 排行。

**验证（9 进程实测）**：
```
[01] ⚠️ 高优先 PID 92279  TomcatTarget2      ← Web容器自动识别
[04]   中优先 PID 67554  MemshellInjectTarget2 ← 可疑关键字:memshell
[09]   低优先 PID 72176  memshell-auditor.jar --scan  ← 自身已识别跳过
扫描汇总: 4 个高危目标 (HIGH=2/1/1/1) + 1 正常
```

## 问题 3：扫描/审计不该由主程序执行（v2.0 架构重划）

**背景（老大指出）**：如果主程序自己先"生成取证程序再执行扫描"，主程序的进程树（PID 分析）会暴露在目标机器上——主程序 tree 被识别出来，容易被对抗。**扫描功能应该只由生成的取证程序执行**，主程序只做纯分析端的事。

**方案（职责彻底分离）**：

| 能力 | 主程序（分析端） | 取证程序（现场端） |
|---|---|---|
| `--scan` 全自动扫描 | ❌ 移除 | ✅ 主战场 |
| `<pid>` 指定审计 | ❌ 移除 | ✅ |
| `--gen-agent` 生成取证程序 | ✅ | ❌ |
| `--analyze` 分析取证报告 | ✅ | ❌ |
| AI 增强分析 | ✅ | ❌ |
| 特征库管理 `--rules` | ✅ | ✅（内置已选规则） |
| 特征提交 `--submit` | ✅ | ❌ |

**实现**：AuditorMain 移除 attach 分支，仅保留 gen-agent/analyze/rules/submit。

## 问题 4：特征库需要在线更新（类 Metasploit）

**背景（老大要求）**：设计一套 GitHub 上的内存马检测特征库仓库，取证人员本地命令连接获取，手动更新；命令行可看提交人+标题；可全选/逐个勾选规则；可下载别人的特征库。

**方案**：
```
x7peeps/memshell-rules（GitHub 特征库仓库）
├── rules/               # 每个规则一个 JSON 文件
│   ├── MS-001-tomcat-filter-no-class.json
│   └── ...
├── index.json           # 规则索引（id/name/author/title/version）
├── template.json        # 规则模板
└── CONTRIBUTING.md      # 提交规范

CLI（主程序）:
  --rules update           # 拉取/更新特征库
  --rules list             # 列出（提交人/标题/勾选状态）
  --rules select [--all|--id X --id Y]  # 勾选
  --rules download <repo>  # 下载他人特征库
  --rules status           # 本地状态
```

## 问题 5：特征检出/未检出要自动形成提交包（众包反哺）

**背景（老大要求）**：针对特征检出和未检出，自动形成提交包；用户同意的情况下通过本地 git 自动提交，反哺特征库。

**方案**：`--submit --report <report.json>`：
1. 解析报告，提取检出/未检出的可疑类特征
2. 生成规则候选（含 author=user、title=自动生成、match=行为模式）
3. 形成提交包（rules/ 新文件 + 更新 index.json）
4. 用户确认后本地 git commit + push（走用户自己的 fork）

## 问题 6：--analyze 结尾引导配置 AI

**背景（老大要求）**：主程序分析功能默认运行时，结尾引导配置 AI；重新执行分析可自动带 AI 增强展示。

**方案**：`--analyze` 输出报告后，若未配置 AI → 打印引导（如何配置 ai-config/环境变量）；配置后重跑 → 自动带上 AI 分析结果展示。

---

> 持续更新中（每完成一个模块补一节）

## 问题 7：规则库随取证 agent 自动打包 + 文件名/id 不匹配

**背景（老大要求）**：如果可以同步的规则库应随生成取证 agent 自动包进去，现场离线也能用规则检测。

**方案**：ObfuscateAgentGenerator 生成时，把 ~/.memshell-rules/rules/ 下已勾选的规则打包进 jar 的 rules/ 目录（含 index.json），RuleEngine 从 classpath 加载。

**踩坑**：规则文件原名 `MS-001-filter-no-class.json` 但 index 里 id 是 `MS-001`，RuleEngine 按 `rules/MS-001.json` 加载找不到 → 规则引擎空转。
**修复**：打包时按规则真实 id 重命名文件（MS-001.json）。

**验证（反射测试 + 端到端）**：
```
classpath rules: 3  ← 混淆 jar 正确加载
✓ 证据带规则: 命中规则: MS-001:FilterDef 动态注册且磁盘无对应 class → 内存马强信号
[INFO] 规则引擎加载 3 条特征规则，高危命中 1 项
```

## 问题 8：主程序运行展示策略版本 + 作者署名

**背景（老大要求）**：主程序运行时要展示策略版本/补充策略情况，作者署名 x7peeps。

**方案**：VersionInfo.banner() —— 工具版本 v2.0 + 作者 x7peeps + 规则库 x7peeps/memshell-rules + 策略版本（~/.memshell-rules/version）+ 补充策略（规则数/启用数/更新时间）。主程序所有命令前展示。

**验证**：
```
==========================================
 memshell-auditor v2.0  Java 内存马审计平台
 作者: x7peeps  |  规则库: x7peeps/memshell-rules
------------------------------------------
 策略版本: 内置默认（未同步规则库，执行 --rules update 获取最新）
 补充策略: 本地规则 3 条 / 启用 3 条 / 最近更新: 2026-08-13 18:00
==========================================
```

## 问题 9：取证程序 CLI 暴露分析端能力

**背景（架构重划）**：生成的取证程序 Main-Class 指向 AuditorMain（分析端 CLI），暴露 --gen-agent/--analyze 等分析端命令——违反"取证程序只做现场"原则。

**方案**：新增 ForensicMain（现场端 CLI：--scan/pid/--list），生成时 Main-Class 指向 ForensicMain，并排除分析端类（AuditorMain/ReportAnalyzer/obf/ai）。

**验证**：
```
Manifest: Main-Class: io.core.check.ForensicMain
取证程序 CLI: jre-check 取证程序（现场端，混淆版）
  java -jar <取证程序>.jar --scan [--dump dir] [--heap dir]
  java -jar <取证程序>.jar <pid> [--report] [--dump] [--heap]
分析端类排除检查: 0（AuditorMain/ReportAnalyzer/obf/ai 全无）
```

## 问题 10：未检出特征 → 用户同意 → 自动提交 → 失败降级 Issue

**背景（老大要求）**：主程序每次跑完如果存在未检出的就提示用户是否提交，用户同意自动推送；提交不成功就打开项目创建 Issue，让用户粘贴本地内容。

**方案**：
1. `--analyze` 结束检测未命中规则的高危项 → 提示提交命令
2. `--submit --author --auto-commit` → 生成提交包 → git commit + push
3. push 成功 → 直接推送规则仓库
4. push 失败 → 生成 issue-body.md（五大段：场景/详情/规则/复现/说明）+ 自动打开 GitHub 新建 Issue 页面

**验证（无权限模拟）**：
```
[*] push 失败（权限/网络问题）
[*] Issue 内容已生成（含场景描述/检出详情/规则/复现步骤）: .../issue-body.md
[*] 打开新建 Issue 页面...
    URL: https://github.com/x7peeps/memshell-rules/issues/new?title=...
[*] 请将 issue-body.md 内容粘贴到 Issue 正文后提交
```

**经验**：作为仓库 owner push 会直接成功；普通用户 push 失败自动走 Issue 兜底——这是设计意图（众包贡献保护官方仓库 main）。

## 问题 11：规则库扩充至 18 条

**背景（老大要求）**：需要扩充规则。

**方案**：新增 12 条（MS-007~018），覆盖：
- 容器组件型：Servlet 动态注册/WebSocket Endpoint/Upgrade 处理器
- 类名特征型：无包名/短随机类名/大小写混淆
- 行为模式型：Base64+命令执行/AES 解密/MethodHandles defineClass/硬编码 IP 回连
- Agent 型：可疑 Transformer/反射获取 Instrumentation
版本升至 1.1.0，规则文件统一按 id 命名。

**验证**：`--rules update` 代理拉取 18 条成功；`--rules list` 展示提交人/标题/勾选；banner 显示策略版本 1.1.0。

## 问题 12：工具版本与策略版本分离自动更新 + 自定义规则保护

**背景（老大要求）**：
1. 产品版本、策略升级分开设计自动更新
2. 策略更新出问题建议版本也更新一下（便于识别）
3. 检测用户本地自定义策略要保留，不要误删
4. 策略库只同步更新内容不整体替换

**方案**：
- **版本分离**：工具版本（TOOL_VERSION v2.0，--update 检查 GitHub releases）+ 策略版本（~/.memshell-rules/version，--rules update 同步）
- **版本联动**：更新成功写 version + update-status.log（ok/failed/partial）；远端版本不可达时本地 bump（1.0.0→1.0.1），banner 显示 failed/partial 状态并提示重试
- **自定义规则保护**：官方规则存 rules/，自定义规则存 rules-custom/（origin 字段区分）；--rules update 增量同步只覆盖官方，自定义永不误删
- **增量同步**：只更新 index 中的官方规则，删除官方目录中已从 index 移除的规则，自定义目录完全不动

**验证**：
```
更新前: rules-custom/CUSTOM-001.json 存在
--rules update: 官方移除 18（旧目录清空重建）, 自定义规则保留 1 条
更新后: rules-custom/CUSTOM-001.json 仍在 ✓
banner: 补充策略: 规则 2 条（官方 1 / 自定义 1）启用 2 条
```

**事故教训**：--submit --auto-commit 测试时，SubmitCollector 用提交包的 index.json **整体覆盖**官方 index（127 行被删只剩 1 条）→ 官方仓库被污染。
**修复**：改为 mergeIndex（新规则追加到现有索引，绝不覆盖），恢复官方 index 18 条 + 删除测试规则 MS-118。
**教训**：自动提交功能必须合并而非替换，防止污染官方索引——这是众包系统的关键安全设计。

## 问题 13：matplotlib 中文字体方框（文章配图事故）

**症状**：文章配图所有中文显示为方框（□），vision 第一轮误判"正常"，老大肉眼抓出。

**根因**：`plt.rcParams['font.family'] = 'Arial Unicode MS'` 仅设置字体名，matplotlib 的 fontManager 未正确解析/注册该字体文件 → 中文缺字形渲染成方框。加 addfont() 后仍失败（rcParams 方法不稳定）。

**最终修复**：**每个 text 调用显式传 `fontproperties=FontProperties(fname='/Library/Fonts/Arial Unicode.ttf')`**——直接指定字体文件路径，绕过 fontManager 名称解析，100% 可靠。

**验证**：vision 三轮确认（03 信号体系图 + 08 终端图均"正常"）；网站 CI success + 公众号草稿 img_count 5 回读通过。

**教训**：matplotlib 中文渲染，**永远用 FontProperties(fname=绝对路径) 显式指定**，不要依赖 rcParams family 名称；vision 判断字体方框可能误判，重要图让老大最终确认。

## 问题 14：规则编号 MS- 前缀与微软漏洞编号混淆

**背景（老大指出）**：规则编号 MS-001 等与微软漏洞编号（MS17-010）过于相像，易混淆。

**方案**：前缀改为 JMSH-（Java MemShell），明确指向内存马检测。
- 规则仓库 18 文件重命名 + id 字段更新 + index.json/template/CONTRIBUTING 同步
- SubmitCollector 候选规则 id 生成改 JMSH-100+
- 代码注释/示例、网站文章、公众号 HTML 全部同步

**验证**：本地 --rules update 拉取 JMSH-001~018 成功；公众号草稿回读 has_JMSH=True has_MS_old=False；网站已推送。

## 问题 15：局限研究2 —— 实时监控 --live（LiveTransformer）

**目标**：解决局限4（attach 只能看到已加载类）+ 部分缓解局限1（retransform 失败的载荷）。

**方案**：attach 时 addTransformer(canRetransform=true) 安装监控 transformer，后续任何新 defineClass 的类都会经过 transform() 回调——在类定义时捕获字节码，实时检查（容器特征 + 行为评分）并 dump。

**实现**：LiveTransformer.java + AgentMain 集成（--live <seconds>）+ ForensicMain 参数传递。

**验证**（LiveTestTarget2 延迟 15 秒注入真实冰蝎载荷）：
```
[HIGH] Live: 实时监控捕获可疑动态加载类: org.springframework.ServletRequestAujFilter
       （字节码含命令执行/解密/回连特征）
✓ dump: org_springframework_ServletRequestAujFilter.class (4160B)
```
在注入瞬间捕获完整字节码，与 retransform dump 一致——**无需事后 retransform**。

**踩坑**：
1. 靶场进程用 `| head -5` 管道启动会被 SIGPIPE 杀掉（attach 时进程已死）
2. attach 必须用真实 Java PID（jps 确认），shell 管道 PID 会差几号
3. JMG jakarta 载荷注入需要 jakarta.servlet 在 classpath（NoClassDefFoundError）
4. live 模式的 stdout 被 attach 机制吞掉，验证要看报告/dump 目录

## 问题 16：研究3 —— native JVMTI 类级字节码读取不可行（研究结论）

**目标**：解决 JMG 混淆载荷 retransform 失败（InternalError: invalid class）的 dump 问题。

**方案尝试**：写 native JVMTI 模块（nativejvmti.c），试图用 GetClassFileBytes 直接读取 JVM 内部字节码。

**结论（查证 jvmti.h）**：
- JVMTI 标准接口**没有 GetClassFileBytes**（这是 JDK 内部 sun.misc 私有 API）
- JVMTI 只有 **GetBytecodes**（方法级字节码，非类级，且需 can_get_bytecodes 能力）
- 类级字节码读取在标准 JVMTI 中不存在 → native 方案不可行

**务实路线（已确认）**：
1. **定义时捕获（主路径）**：LiveTransformer --live 模式（v2.3 已实现）——attach 后新加载类在定义瞬间拿字节码，不经过 retransform 校验
2. **存量载荷兜底**：jmap 堆 dump（研究5 待做自动化解析）
3. **报告标记**：retransform 失败的类标记"已定义时捕获/JMAP 兜底"提示

**教训**：写 native 前先查 API 存在性——GetClassFileBytes 是 JDK 内部私有方法，非 JVMTI 标准；浪费一轮编译排错。

## 问题 17：研究4 —— 威胁情报集成（解决回连分析噪声）

**目标**：回连分析混入本机其他服务连接（代理/远程控制），需自动判定回连 IP 恶意性。

**实现**：
1. ThreatIntelClient（微步在线 API + 启发式降级）——零依赖
   - API: api.threatbook.cn/v3/scene/ip_reputation（--ai-config 加 threatbook_key）
   - 启发式: 非标准低端口/C2 隧道端口（10427/4444/5555/6666/8888/9000/10000）自动判 HIGH
2. ReportAnalyzer 集成：从已解析 report.findings 提取 Callback/Network 类别回连地址 → 自动查询

**验证**：
```
[threat] 威胁情报查询 34 个回连 IP（启发式降级）
  🔴 HIGH 117.28.246.44:10427  [heuristic] high | 常见恶意软件/隧道端口(10427)
```
10427 = 冰蝎/隧道常用端口，正确命中 HIGH。

**踩坑（JSON 中文转义）**：JSON 序列化后中文变成 \uXXXX，用 indexOf("提取到疑似回连地址") 匹配不到 → 改从已解析的 Report 对象提取（report.findings 遍历 Callback/Network），不再读原始 JSON 字符串。**教训：能解析对象就用对象，别在转义 JSON 字符串上做字符串匹配。**
