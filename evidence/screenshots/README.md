# 文章素材截图索引

> 位置：`evidence/screenshots/`，均为 matplotlib 生成的专业图表，dpi=150

| 文件 | 内容 | 用途 |
|---|---|---|
| `01-detection-matrix.png` | JMG 真实载荷 7/7 检测结果矩阵 | 文章核心数据展示 |
| `02-architecture.png` | 检测架构图（attach→StandardContext→A1 强信号） | 原理讲解 |
| `03-signal-levels.png` | 判断标准分级（A 系强信号 vs B 系辅助） | 方法论展示 |
| `04-cli-terminal.png` | CLI 终端效果图（审计输出含 HIGH/Dump/回连） | 工具使用演示 |
| `05-forensics-flow.png` | 取证闭环流程（检出→Dump→反编译→回连分析） | 二期功能展示 |

## 实测截图（终端真实输出，可复现）

- JMG 载荷生成：`java -cp ... GenPayload` 输出（7 种载荷清单）
- 注入靶场：`MemshellInjectTarget9` 输出（real memshell class: org.springframework.SessionKqvcFilter）
- 检测结果：`java -jar memshell-auditor.jar <pid> report.json dump/` 输出
- 完整检测 JSON：evidence/04~10-*.json（7 份，每份含 HIGH 命中）
