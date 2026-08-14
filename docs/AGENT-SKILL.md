---
name: memshell-auditor
description: "Use when needing to detect/forensics Java memory shells (内存马): attach to a JVM, scan all Java processes, live-monitor injections, or analyze reports with AI. Encapsulates the memshell-auditor CLI workflow for AI agents."
---

# memshell-auditor（Java 内存马检测取证工具）

本技能引导 AI Agent 正确使用 memshell-auditor：Java 内存马运行时审计 Agent，
attach 检测 Filter/Servlet/Listener/Valve/Agent 型内存马，支持 dump/反编译/回连/堆取证/AI 分析。

## 触发场景

- 用户要求检测 Java 内存马 / 排查可疑 JVM 进程
- 用户要求对某个 PID 做内存马审计
- 用户要求持续监控某个 JVM（值守场景）或实时告警
- 用户要求分析取证报告 / 更新检测规则 / 贡献新特征

## 架构速览（务必先理解）

**双程序架构**（防识别设计）：
- **主程序** `memshell-auditor.jar`：分析端，只做 `--gen-agent` / `--analyze` / `--rules` / `--submit`——**绝不 attach 目标**（避免暴露）
- **取证程序**（--gen-agent 生成，如 `system-diag-2c4488.jar`）：现场端，做 `--scan` / `<pid>` / `--live` / `--monitor`——**不含 AI**（防暴露）

> ⚠️ 关键设计约束：主程序不能直接 attach 目标 JVM。需要 attach 时必须先生成混淆取证程序，再在目标上执行。

## 快速使用流程

### 1. 生成取证程序（分析者机器）

```bash
java -jar memshell-auditor.jar --gen-agent ./agents --name-prefix system-diag
# 输出: agents/system-diag-<随机>.jar（文件名/包名/类名每次随机）
```

### 2. 目标系统取证（现场）

```bash
# 全自动扫描（无需知道 PID）
java -jar system-diag-xxxx.jar --scan --dump ./dump --heap ./heap

# 指定进程审计
java -jar system-diag-xxxx.jar <PID> --dump ./dump --heap ./heap

# 实时监控（attach 后新注入类定义时捕获，60 秒）
java -jar system-diag-xxxx.jar <PID> --dump ./dump --live 60

# 值守监控（webhook 实时推送到企业微信/钉钉/飞书群）
java -jar system-diag-xxxx.jar <PID> --monitor monitor.json --dump ./dump
```

### 3. 分析报告（分析者机器）

```bash
# 本地规则分析（自动降级）
java -jar memshell-auditor.jar --analyze report.json

# AI 增强分析（OpenAI 兼容）
java -jar memshell-auditor.jar --analyze report.json --ai-config ai.json
```

### 4. 特征库管理 / 贡献

```bash
java -jar memshell-auditor.jar --rules update|list|select|status
java -jar memshell-auditor.jar --submit --report report.json --author <name> --auto-commit
```

## 检测信号解读（分析报告时用）

| 信号 | 含义 | 处置 |
|---|---|---|
| 🔴 HIGH (A1) | 容器组件类磁盘无 class 文件——内存马核心特征 | 立即隔离→取证→清除→溯源 |
| 🔴 HIGH (A4) | -javaagent/Transformer 注入 | 同上 |
| 🟠 MEDIUM (A3/B1/B2) | 非系统 ClassLoader / 类名特征 | 深度审计后升级 |
| 🟡 LOW | 无法解析组件 | 人工复核 |

## AI 分析报告解读要点

当 --analyze 输出 `aiAnalysis` 字段时，向用户解释：
1. **检出项**：哪个类/组件被命中，命中哪个信号
2. **恶意行为**：dump 反编译展示的核心逻辑（Base64 解密/AES/命令执行/回连）
3. **回连判断**：callbackIps 中的地址 + 威胁情报查询结果（隧道端口如 10427 高可疑）
4. **处置建议**：断网隔离 → 保全证据 → 排查注入入口（反序列化/表达式注入/文件上传）→ 修复 → 重启

## 配置说明

### monitor.json（值守监控）
```json
{
  "webhook": {
    "url": "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx",
    "type": "wecom",            // wecom / dingtalk / feishu / generic
    "min_level": "MEDIUM"
  },
  "live_seconds": 3600,
  "interval_seconds": 60
}
```

### ai.json（AI 增强）
```json
{"base_url": "https://api.deepseek.com/v1", "api_key": "sk-xxx", "model": "deepseek-chat"}
```
环境变量：AI_BASE_URL / AI_API_KEY / AI_MODEL；威胁情报：ai.json 加 threatbook_key

## 常见问题

- **JDK 21+ attach 失败**：需要 `--add-modules jdk.attach`，必要时 `-XX:+EnableDynamicAgentLoading`
- **离线现场**：规则已打包进取证程序，检测/取证全本地；AI 自动降级本地规则分析
- **attach 不生效**：同一 JVM 重复 attach 会缓存旧 agent 类，改代码后必须重启目标进程
- **Windows 现场**：NetworkAnalyzer 自动用 netstat -ano（无需 lsof）
- **大堆 dump**：hprof 解析流式分块，1GB+ 无压力

## 陷阱

- 不要把主程序当取证程序用（双程序架构是防识别设计，不要违反）
- 不要给取证程序配置 AI（它不含 ai/ 模块，会降级）
- --monitor 的 webhook 有重试（指数退避），推送失败会自动重试 3 次
- 规则更新有缓存：版本一致时跳过下载（弱网友好）
