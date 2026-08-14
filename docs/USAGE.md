# memshell-auditor 详细参数说明（USAGE）

> 完整命令行参数参考。快速上手见 [README](../README.md)，AI Agent 引入见 [AGENT-SKILL.md](AGENT-SKILL.md)。

## 主程序（分析端）

主程序**不 attach 目标 JVM**（双程序防识别架构），职责：生成取证程序 / 分析报告 / 管理特征库 / 提交特征。

### --gen-agent

生成混淆取证程序（每次随机文件名/包名/类名/字符串特征，防识别）。

```bash
java -jar memshell-auditor.jar --gen-agent <输出目录> [--name-prefix <前缀>]
```

| 参数 | 说明 |
|---|---|
| 输出目录 | 必填。生成的 jar 写入此目录 |
| --name-prefix | 可选。jar 名前缀（默认 system-diag），如 `--name-prefix system-diag` 生成 `system-diag-2c4488.jar` |

生成时自动：打包已勾选特征规则（rules/ 到 jar 内置）、排除 ai/ 模块（取证端无 AI）、Manifest 指向 ForensicMain。

### --analyze

分析取证报告，AI 增强（OpenAI 兼容，可配可跳过）。

```bash
java -jar memshell-auditor.jar --analyze <report.json> [--ai-config ai.json]
```

| 参数 | 说明 |
|---|---|
| report.json | 必填。取证程序产出（memshell-auditor-scan-<pid>.json 或自定义） |
| --ai-config | 可选。AI 配置 JSON（base_url/api_key/model/threatbook_key） |

行为：
- 无 AI 配置 → 本地规则分析 + 结尾引导三种配置方式（文件/环境变量/Ollama）
- 已配置 → 调用 LLM 增强分析（恶意行为解读/回连判断/处置建议），写入报告 aiAnalysis 字段
- 自动威胁情报查询：提取 Callback/Network 回连地址（微步 API 或启发式降级）
- 自动检测未命中规则的高危项 → 提示 --submit 贡献新特征

### --rules

特征库管理（GitHub 在线更新，类 Metasploit）。

```bash
java -jar memshell-auditor.jar --rules <update|list|select|download|status>
```

| 子命令 | 说明 |
|---|---|
| update | 拉取/更新特征库（增量同步，只覆盖官方规则；远端版本一致时跳过下载） |
| list | 列出规则（ID/状态/等级/提交人/标题） |
| select --all | 全选规则 |
| select --id JMSH-001 --id JMSH-002 | 逐个勾选 |
| download <repo> | 下载他人特征库（如 user/repo） |
| status | 本地规则状态（官方/自定义/版本/更新状态） |

代理支持：HTTPS_PROXY / HTTP_PROXY 环境变量。

### --submit

众包特征提交（检出项自动生成规则候选）。

```bash
java -jar memshell-auditor.jar --submit --report <report.json> --author <名字> [--auto-commit]
```

| 参数 | 说明 |
|---|---|
| --report | 必填。取证报告 |
| --author | 必填。GitHub 用户名（规则署名） |
| --auto-commit | 可选。自动 git 提交；push 失败自动打开 GitHub Issue（issue-body.md 含五大段描述） |

### --update

检查工具新版本（GitHub releases）。

```bash
java -jar memshell-auditor.jar --update
```

### --version

显示版本 + 策略版本 + 作者署名（x7peeps）。

## 取证程序（现场端）

由 --gen-agent 生成（如 system-diag-2c4488.jar），**不含 AI 能力**。

### --scan

全自动扫描所有 Java 进程（无需知道 PID）。

```bash
java -jar system-diag-xxxx.jar --scan [--dump dir] [--heap dir] [--report dir] [--max-jvms N] [--parallel N]
```

| 参数 | 说明 | 默认 |
|---|---|---|
| --dump | dump 目录（可疑类字节码 + 反编译） | 无 |
| --heap | jmap 堆 dump 目录 | 无 |
| --report | 报告输出目录（每进程一个 JSON） | 当前目录 |
| --max-jvms | 最多审计进程数 | 10 |
| --parallel | 并发审计线程数 | CPU/2 |

行为：枚举 JVM → 可疑度排序（Web 容器 +100 / 可疑关键字 +60 / 工具 -30 / 自身跳过）→ 并发审计 → 汇总 HIGH 排行。

### <PID>

指定进程审计。

```bash
java -jar system-diag-xxxx.jar <PID> [--report out.json] [--dump dir] [--heap dir] [--live sec] [--monitor cfg.json]
```

| 参数 | 说明 |
|---|---|
| --report | 报告文件路径 |
| --dump | dump 目录 |
| --heap | 堆取证目录 |
| --live | 实时监控秒数（attach 后捕获新注入类，定义时 dump） |
| --monitor | 值守监控配置（webhook 实时推送，见 monitor.example.json） |

### --list

列出本机 Java 进程（按可疑度排序）。

### --version

显示取证程序版本。

## 环境变量

| 变量 | 用途 |
|---|---|
| AI_BASE_URL | AI 服务 base_url（如 https://api.deepseek.com/v1） |
| AI_API_KEY | AI API key |
| AI_MODEL | AI 模型名（如 deepseek-chat） |
| HTTPS_PROXY / HTTP_PROXY | 规则拉取/webhook/AI 请求代理 |

## JDK 兼容性

| 目标 JVM | 要求 |
|---|---|
| JDK 8-20 | 直接 attach |
| JDK 21+ | `--add-modules jdk.attach`；动态 attach 可能需要 `-XX:+EnableDynamicAgentLoading` |
| 本机 JDK | 26（Temurin）已验证，--release 8 编译兼容 8-26 |

## 输出格式

报告 JSON 结构：

```json
{
  "tool": "memshell-auditor",
  "version": "2.8",
  "pid": 12345,
  "target": "java -jar app.jar",
  "javaVersion": "17.0.10",
  "summary": "HIGH=1 MEDIUM=0 ...",
  "findings": [
    {
      "level": "HIGH", "signal": "A1", "category": "Filter",
      "className": "org.springframework.ServletRequestAujFilter",
      "classLoader": "...", "reason": "...", "evidence": "...",
      "dumpPath": "/dump/xxx.class", "callbackIps": "..."
    }
  ],
  "aiAnalysis": "AI 增强分析结果（可选）"
}
```

## 退出码

| 码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 通用错误 |
| 2 | 参数错误 / 报告解析失败 |
