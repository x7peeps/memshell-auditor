<p align="center">
  <img src="assets/banner.svg" alt="memshell-auditor" width="100%">
</p>

# memshell-auditor 🔍
<p align="center">
  <a href="https://github.com/x7peeps/memshell-auditor"><img src="https://img.shields.io/badge/GitHub-x7peeps%2Fmemshell--auditor-2d6cdf?style=for-the-badge&logo=github" alt="GitHub"></a>
  <a href="https://github.com/x7peeps/memshell-auditor/releases"><img src="https://img.shields.io/badge/Release-v2.8-blue?style=for-the-badge" alt="Release v2.8"></a>
  <a href="https://github.com/x7peeps/memshell-auditor/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License: MIT"></a>
  <a href="https://img.shields.io/badge/JDK-8--26-orange?style=for-the-badge"><img src="https://img.shields.io/badge/JDK-8--26-orange?style=for-the-badge" alt="JDK 8-26"></a>
  <a href="https://img.shields.io/badge/Detection-7%2F7%20JMG%20payloads-red?style=for-the-badge"><img src="https://img.shields.io/badge/Detection-7%2F7%20JMG%20payloads-red?style=for-the-badge" alt="Detection 7/7"></a>
</p>

**Java 内存马运行时审计 Agent** —— attach 到目标 JVM，检测容器层（Filter/Servlet/Listener/Valve）与 JVM 层（Agent 型/defineClass 注入）内存马，并在检出后完成 dump / 反编译 / 回连 / 堆取证 / AI 分析的全链路闭环。

**零依赖**（JDK 8 编译，目标 JVM 兼容 JDK 8-26），**纯反射**实现（不依赖具体中间件类），**JSON/控制台双输出**。特征库随版本内置（rules/ 目录），在线更新 + 增量同步 + 自定义规则保护。

> ⚠️ 本工具仅用于授权环境下的安全应急响应、攻防演练与防御建设。请确保你的行为符合当地法律法规。

<table>
<tr><td><b>🔴 A1 强信号检测</b></td><td>容器组件注册的类在磁盘无对应 class 文件——主流生成器全部伪装 Spring 类名，但 A1 不受影响，实测 7/7 检出。</td></tr>
<tr><td><b>🕵️ 双程序防识别</b></td><td>--gen-agent 每次生成随机文件名/包名/类名的混淆取证程序，攻击者无法预判；取证程序不含 AI 防暴露。</td></tr>
<tr><td><b>⚡ 全自动扫描 --scan</b></td><td>无需知道 PID，自动枚举所有 Java 进程按可疑度排序审计，并发加速（--parallel）。</td></tr>
<tr><td><b>📡 实时监控 --live</b></td><td>attach 后新 defineClass 的类在定义瞬间捕获字节码，无需 retransform。</td></tr>
<tr><td><b>🔔 值守监控 --monitor</b></td><td>检测到可疑动态加载类实时推送群机器人（企业微信/钉钉/飞书 webhook），配置驱动，适合值守客户现场。</td></tr>
<tr><td><b>🛡️ 威胁情报集成</b></td><td>--analyze 自动查询回连 IP（微步 API + 启发式降级），C2/隧道端口自动判 HIGH。</td></tr>
<tr><td><b>🧠 hprof 堆解析</b></td><td>jmap 堆 dump 自动深度解析（流式分块，1GB+ 兼容），retransform 失败载荷从堆中恢复。</td></tr>
<tr><td><b>🤖 AI 增强分析</b></td><td>OpenAI 通用兼容接口（DeepSeek/通义/Ollama/vLLM），可配可跳过，离线自动降级本地规则。</td></tr>
<tr><td><b>📚 特征库生态</b></td><td>18 条内置规则（JMSH-001~018），在线更新 + 增量同步 + 自定义规则保护 + 众包特征提交。</td></tr>
</table>

---

## Quick Install

```bash
# 一键部署（下载 jar + 同步特征库 + 生成取证程序）
bash -c "$(curl -sL https://raw.githubusercontent.com/x7peeps/memshell-auditor/main/deploy.sh)"

# 或直接下载 Release
curl -L -o memshell-auditor.jar https://github.com/x7peeps/memshell-auditor/releases/latest/download/memshell-auditor.jar
```

环境要求：**JDK 8+**（JDK 21+ 附加 `--add-modules jdk.attach`）。

---

## Quick Start

### 1. 生成取证程序（分析者机器）

```bash
java -jar memshell-auditor.jar --gen-agent ./agents --name-prefix system-diag
# 输出: agents/system-diag-2c4488.jar（每次随机，防识别）
```

### 2. 目标系统取证（现场）

```bash
# 全自动扫描（无需知道 PID，自动识别可疑进程）
java -jar system-diag-2c4488.jar --scan --dump ./dump --heap ./heap

# 指定进程审计
java -jar system-diag-2c4488.jar <PID> --dump ./dump --heap ./heap

# 值守监控（webhook 实时推送群机器人，配置见 monitor.example.json）
java -jar system-diag-2c4488.jar <PID> --monitor monitor.json --dump ./dump
```

### 3. 分析报告（分析者机器）

```bash
# 本地规则分析（自动降级）；配置 AI 后自动增强（--ai-config ai.json）
java -jar memshell-auditor.jar --analyze report.json [--ai-config ai.json]
```

### 4. 特征库管理 / 贡献

```bash
java -jar memshell-auditor.jar --rules update|list|select|status
java -jar memshell-auditor.jar --submit --report report.json --author <name> --auto-commit
```

---

## 实测验证（开源生成器真实载荷）

使用 **java-memshell-generator (JMG) v1.0.9** 生成真实内存马载荷，注入 Tomcat 9/10 靶场，**7/7 全部检出（100%）**：

| 载荷 | 工具 | 真实类名（伪装） | 容器 | 结果 |
|---|---|---|---|---|
| behinder-filter | 冰蝎 | `org.springframework.ServletRequestAujFilter` | Tomcat 10.1 | ✅ HIGH |
| godzilla-filter | 哥斯拉 | `org.springframework.WhiteBlackListGbyfbdFilter` | Tomcat 10.1 | ✅ HIGH |
| antsword-filter | 蚁剑 | `org.springframework.AbstractMatcherVyjFilter` | Tomcat 10.1 | ✅ HIGH |
| suo5-filter | Suo5 | `org.springframework.SessionKqvcFilter` | Tomcat 9.0 | ✅ HIGH |
| behinder-listener | 冰蝎 | `org.apache.logging.Log4jConfigEaeListener` | Tomcat 10.1 | ✅ HIGH |
| godzilla-valve | 哥斯拉 | `org.apache.AbstractMatcherGbValve` | Tomcat 10.1 | ✅ HIGH |
| behinder-listener2 | 冰蝎 | `org.springframework.ContextLoaderDmasjListener` | Tomcat 9.0 | ✅ HIGH |

**关键结论**：主流生成器全部伪装类名，类名特征检测可被绕过；但 **A1 强信号（磁盘无 class 文件）不受影响**。误报控制：正常业务 Filter → INFO，JDK 类/自身类 → 白名单豁免。

---

## 文档

| 文档 | 内容 |
|---|---|
| [docs/USAGE.md](docs/USAGE.md) | 详细参数说明（全部 CLI 参数/环境变量/输出格式/退出码） |
| [docs/RULES.md](docs/RULES.md) | 检测规则库参数详情（规则格式/信号体系/内置规则清单/编写规范） |
| [docs/AGENT-SKILL.md](docs/AGENT-SKILL.md) | AI Agent 技能引导（如何让 AI 用好本产品） |
| [QUICKSTART.md](QUICKSTART.md) | 快速使用手册（九大章节） |
| [CONTRIBUTING-RULES.md](CONTRIBUTING-RULES.md) | 特征规则提交规范 |
| [evidence/20-v2-devlog.md](evidence/20-v2-devlog.md) | 开发过程与踩坑记录 |

**技术研究**：检测方法论、信号分级体系、工具演进历程、实战验证细节 → 见个人主页文章
[《Java 内存马应急检测实战：从手册到开源工具的全栈演进》](https://x7peeps.github.io/安全/应急响应/Java内存马应急检测实战/)

---

## 支持的中间件

- **Tomcat** 5-11（javax 与 jakarta 双命名空间，纯反射实现）
- **Spring Boot** 内嵌容器（StandardContext 同源）
- **国产中间件**：TongWeb / BES / InforSuite / Apusic / Primeton（StandardContext 类名兼容 + Loader 特征识别）
- 定位逻辑：`WebappClassLoader` 反查 + MBeanServer 辅助

## 项目结构

```
src/main/java/com/memshellauditor/
├── AgentMain.java           # agent 入口（premain/agentmain，含取证端规则分析）
├── AuditorMain.java         # 主程序 CLI（--gen-agent/--analyze/--rules/--submit）
├── ForensicMain.java        # 取证程序 CLI（--scan/pid/--live/--monitor）
├── ScanRunner.java          # 全自动扫描编排（并发审计）
├── JvmScanner.java          # JVM 进程枚举 + 可疑度评分
├── detect/                  # 检测器（容器/Agent/Transformer/ClassLoader/启发式/Live）
├── dump/                    # 取证（ClassDumper/Decompiler/NetworkAnalyzer/MemoryForensics/HprofParser）
├── ai/                      # AI 增强（AiClient/AiAnalyzer）
├── threat/                  # 威胁情报（ThreatIntelClient）
├── monitor/                 # 值守监控（WebhookClient/MonitorEngine）
├── obf/                     # 混淆生成（ClassRewriter/ObfuscateAgentGenerator）
├── rules/                   # 特征库（Rule/RuleEngine/RuleStore/RuleUpdater/SubmitCollector）
├── report/                  # 报告（Finding/Report）
└── util/                    # 反射工具（ReflectUtil）
```

## 局限性

1. **JMG 混淆载荷的 dump 限制**：Suo5 等激进 ASM 处理载荷 JVM 拒绝 retransform——由 **--live 定义时捕获** + **hprof 堆解析**双兜底
2. **Agent 型内存马（transformer 注入）**：JDK 标准 API 无法枚举已注册 transformer，通过 `getAllLoadedClasses` 类特征 + 内部字段探测间接检测
3. **回连分析噪声**：lsof 混入本机其他服务连接，已集成威胁情报自动判定，特殊场景人工复核
4. **容器定位依赖 WebappClassLoader**：极度精简 classpath 模式（非 WAR 部署）可能定位不到 StandardContext
5. **运行时窗口**：attach 只能看到当前已加载类；`--live` 覆盖后续注入

## Contributing

- **提 Issue/PR**：https://github.com/x7peeps/memshell-auditor/issues
- **贡献特征规则**：见 [CONTRIBUTING-RULES.md](CONTRIBUTING-RULES.md)，模板 `rules/template.json`
- **开发记录/踩坑**：见 [evidence/20-v2-devlog.md](evidence/20-v2-devlog.md)

## License

MIT
