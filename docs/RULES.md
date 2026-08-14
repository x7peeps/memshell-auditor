# 检测规则库说明（RULES）

> 特征规则格式、信号体系、编写与提交规范。规则文件在仓库 `rules/` 目录，随版本发版。

## 规则文件结构

```
rules/
├── JMSH-001~018.json   # 检测规则（每个规则一个文件）
├── index.json          # 规则索引（提交人/标题/版本）
├── template.json       # 新建规则模板
├── version             # 策略版本号
└── CONTRIBUTING-RULES.md  # 提交规范（仓库根目录）
```

本地运行时规则存储在 `~/.memshell-rules/`：
- `rules/` 官方规则（--rules update 覆盖）
- `rules-custom/` 自定义规则（永不覆盖）
- `selected.json` 勾选状态
- `version` 策略版本

## 规则 JSON 格式（template.json）

```json
{
  "id": "JMSH-000",
  "name": "规则名称（一句话）",
  "signal": "A1",
  "category": "Filter",
  "level": "HIGH",
  "author": "your-github-username",
  "title": "规则标题（显示在 list）",
  "version": "1.0",
  "description": "详细描述（检出逻辑/适用场景）",
  "match": {
    "type": "filterdef_no_class_on_disk",
    "classname_pattern": null,
    "behavior_patterns": ["getParameter", "Cipher"]
  },
  "origin": "official"
}
```

### 字段说明

| 字段 | 类型 | 说明 |
|---|---|---|
| id | string | 规则编号（JMSH-xxx，避免与微软漏洞编号混淆） |
| name | string | 规则名 |
| signal | string | 关联信号（A1-A5 / B1-B5 / N/A） |
| category | string | 组件类别：Filter/Servlet/Listener/Valve/Agent/ClassLoader/ClassFeature/Heuristic |
| level | string | 等级：HIGH/MEDIUM/LOW |
| author | string | 提交人 GitHub 用户名 |
| title | string | 列表显示标题 |
| version | string | 规则版本 |
| description | string | 详细描述 |
| match.type | string | 匹配类型（当前主程序检测器类型） |
| match.classname_pattern | string|null | 类名正则（null=不匹配类名） |
| match.behavior_patterns | string[] | 行为模式关键字 |
| origin | string | official/custom（提交时忽略） |

## 信号体系（检测等级判定）

| 信号 | 检测项 | 等级 | 处置 |
|---|---|---|---|
| A1 | 容器组件注册类磁盘无 class 文件 | 🔴 HIGH | 高度疑似，立即处置 |
| A2 | 容器组件注册数量异常 | 🔴 HIGH | 需人工复核 |
| A3 | 非系统 ClassLoader 加载恶意类 | 🟠 MEDIUM | 深度审计 |
| A4 | -javaagent/agentlib/Transformer 注入 | 🔴 HIGH | 高度疑似 |
| A5 | 启动命令/环境变量异常 | 🔴 HIGH | 需复核 |
| B1 | 类名特征（无包名/短随机/大小写混淆） | 🟡 LOW | 辅助 |
| B2 | 类名含恶意关键字 | 🟡 LOW | 辅助 |

## 内置规则清单（JMSH-001~018）

| ID | 名称 | 信号 | 类别 |
|---|---|---|---|
| JMSH-001 | Filter 注册类磁盘无 class 文件 | A1 | Filter |
| JMSH-002 | Spring 伪装类名 Filter（冰蝎/哥斯拉） | A1 | Filter |
| JMSH-003 | 继承 ClassLoader 的容器组件 | A1 | Filter |
| JMSH-004 | Listener 伪装 Spring/Log4j 类名 | A1 | Listener |
| JMSH-005 | Valve 伪装 Spring 类名 | A1 | Valve |
| JMSH-006 | 可疑 Agent 参数注入 | A4 | Agent |
| JMSH-007 | Servlet 动态注册且磁盘无 class | A1 | Servlet |
| JMSH-008 | WebSocket Endpoint 动态注册 | A1 | WebSocket |
| JMSH-009 | Tomcat Upgrade/Protocol 处理器注入 | A1 | Upgrade |
| JMSH-010 | 容器组件实现类无包名（顶级类） | B1 | ClassFeature |
| JMSH-011 | 短随机类名 + 容器组件 | B1 | ClassFeature |
| JMSH-012 | 大小写混淆类名 | B1 | ClassFeature |
| JMSH-013 | Base64 载荷解密 + 命令执行组合 | B3 | Heuristic |
| JMSH-014 | AES/Cipher 载荷解密 | B3 | Heuristic |
| JMSH-015 | MethodHandles.Lookup.defineClass（JDK17+） | A1 | Heuristic |
| JMSH-016 | 硬编码 IP + Socket 回连 | B4 | Heuristic |
| JMSH-017 | 可疑 ClassFileTransformer 实现 | A4 | Agent |
| JMSH-018 | 反射获取 Instrumentation | A4 | Agent |

## 规则匹配逻辑（取证端 RuleEngine）

1. 取证程序内置规则（jar 的 rules/ 目录，--gen-agent 打包已勾选规则）
2. 检测时按规则 match 条件匹配：容器组件特征（category）+ 行为模式（behavior_patterns）+ 类名模式（classname_pattern）
3. 命中规则 → finding 的 evidence 标注 `命中规则: <id>:<title>`

## 编写新规则

1. 复制 `rules/template.json` 为 `rules/JMSH-<编号>-<英文名>.json`
2. 填写字段（参考内置规则）
3. 更新 `rules/index.json` 加入索引
4. 提交 PR 到仓库（或本地 --submit 自动生成候选）

## 规则维护命令

```bash
# 查看规则列表
java -jar memshell-auditor.jar --rules list

# 勾选启用/停用
java -jar memshell-auditor.jar --rules select --all
java -jar memshell-auditor.jar --rules select --id JMSH-001

# 更新规则
java -jar memshell-auditor.jar --rules update

# 本地状态
java -jar memshell-auditor.jar --rules status
```

## 版本联动

- 策略版本号在 `rules/version`
- --rules update 时：远端版本与本地一致 → 跳过下载（缓存优化）
- 更新失败/部分成功 → 本地版本自动 bump，banner 显示 partial/failed 状态
- 自定义规则（rules-custom/）永不因更新被删

## 众包提交

```bash
# 分析报告时未命中规则的高危项会提示
java -jar memshell-auditor.jar --submit --report report.json --author <name> --auto-commit
```

- 自动生成规则候选（JMSH-100+ 编号）到提交包
- git push 成功 → 直接推送；失败 → 打开 GitHub Issue（issue-body.md 五大段描述）
- 提交包结构：rules/*.json + index + COMMIT_MSG + issue-body.md
