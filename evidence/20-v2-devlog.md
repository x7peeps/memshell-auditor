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
