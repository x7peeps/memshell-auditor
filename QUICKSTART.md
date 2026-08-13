# memshell-auditor 快速使用手册

> 配套文章：《Java 内存马应急检测实战：从手册到开源工具的全栈演进》
> 本文是关键词回复「内存马」的完整版落点文档。

## 一、快速安装

```bash
# 一键部署（下载 jar + 同步规则 + 生成取证程序）
bash -c "$(curl -sL https://raw.githubusercontent.com/x7peeps/memshell-auditor/main/deploy.sh)"

# 或手动下载
curl -L -o memshell-auditor.jar https://github.com/x7peeps/memshell-auditor/releases/latest/download/memshell-auditor.jar
```

环境要求：JDK 8+（JDK 21+ 附加 `--add-modules jdk.attach`）

## 二、现场取证（取证人员）

### 第一步：生成混淆取证程序（分析者机器）

```bash
java -jar memshell-auditor.jar --gen-agent ./agents --name-prefix system-diag
# 输出: agents/system-diag-2c4488.jar（每次随机名，防识别）
```

### 第二步：目标系统全自动扫描

```bash
java -jar system-diag-2c4488.jar --scan --dump ./dump --heap ./heap
```

- `--scan`：自动枚举所有 Java 进程，按可疑度排序审计（**无需知道 PID**）
- `--dump`：可疑类字节码落盘 + 反编译核心代码
- `--heap`：jmap 堆内存取证（跨平台）

### 第三步：指定进程审计（可选）

```bash
java -jar system-diag-2c4488.jar <PID> --dump ./dump --heap ./heap
```

## 三、报告分析（分析者机器）

```bash
# 无 AI 配置时自动降级本地规则分析，结尾引导配置
java -jar memshell-auditor.jar --analyze <report.json>

# 配置 AI 增强（OpenAI 兼容：DeepSeek/通义/Ollama/vLLM 均可用）
java -jar memshell-auditor.jar --analyze <report.json> --ai-config ai.json
```

ai.json 格式：
```json
{"base_url": "https://api.deepseek.com/v1", "api_key": "sk-xxx", "model": "deepseek-chat"}
```

也可用环境变量：`AI_BASE_URL` / `AI_API_KEY` / `AI_MODEL`

## 四、特征库管理

```bash
java -jar memshell-auditor.jar --rules update              # 拉取/更新特征库
java -jar memshell-auditor.jar --rules list                # 列出规则（提交人/标题）
java -jar memshell-auditor.jar --rules select --all        # 全选
java -jar memshell-auditor.jar --rules select --id MS-001  # 逐个勾选
java -jar memshell-auditor.jar --rules status              # 本地状态
```

- 增量同步：只更新官方规则，**自定义规则（rules-custom/）永不误删**
- 代理支持：`HTTPS_PROXY` 环境变量
- 版本联动：更新失败本地版本自动推进并提示

## 五、贡献新特征（众包反哺）

```bash
# 分析时发现未命中规则的高危项会自动提示
java -jar memshell-auditor.jar --submit --report <report.json> --author 你的名字 --auto-commit
# push 失败自动打开 GitHub Issue 供粘贴内容
```

## 六、判断标准速查（A/B 信号体系）

| 信号 | 含义 | 判定 |
|---|---|---|
| **A1** | 容器组件类磁盘无 class 文件 | 🔴 高度疑似（核心） |
| **A2** | 组件注册数量异常 | 🔴 需复核 |
| **A3** | 非系统 ClassLoader 加载恶意类 | 🟠 需复核 |
| **A4** | -javaagent/Transformer 注入 | 🔴 高度疑似 |
| **B1** | 类名特征（无包名/短随机/大小写混淆） | 🟡 辅助 |
| **B2** | 类名含恶意关键字 | 🟡 辅助 |

## 七、处置建议（检出后）

1. **隔离**：断网/隔离主机，防止回连与横向移动
2. **保全证据**：dump 类 + jmap 堆 + 反编译（工具已自动完成）
3. **排查入口**：反序列化/表达式注入/文件上传日志
4. **封禁 C2**：报告中的回连 IP 加防火墙封禁 + 威胁情报查询
5. **修复重启**：修复漏洞后重启（内存马随重启消失，但会再次植入）

## 八、常见问题

**Q：离线环境能用吗？**
能。规则已打包进取证程序，检测/取证全本地完成；AI 降级本地规则分析。

**Q：支持哪些中间件？**
Tomcat 5-11 / Spring Boot 内嵌 / Jetty / 国产中间件（TongWeb/BES/Apusic 等类 Tomcat 结构）。

**Q：会不会误报？**
A1 强信号误报极低（磁盘无 class 是硬证据）；B 系辅助信号需人工复核，报告会标注信号级别。

**Q：怎么防止攻击者识别取证工具？**
每次 --gen-agent 生成的取证程序文件名/包名/类名/字符串全随机，攻击者无法预判。

## 九、链接

- 主程序仓库：https://github.com/x7peeps/memshell-auditor
- 特征库仓库：https://github.com/x7peeps/memshell-rules
- 部署脚本：https://raw.githubusercontent.com/x7peeps/memshell-auditor/main/deploy.sh
- 规则模板：https://github.com/x7peeps/memshell-rules/blob/main/rules/template.json

---

*文档版本 v2.2 ｜ 作者 x7peeps ｜ 欢迎 Issue/PR 贡献*
