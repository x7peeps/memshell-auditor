# CONTRIBUTING - 特征库提交规范

感谢贡献！本仓库是 memshell-auditor 的检测特征库，规则质量直接影响一线应急的检出能力。

## 规则提交流程

1. **复制模板**：从 `rules/template.json` 复制为新文件 `rules/MS-<编号>-<简短英文名>.json`
2. **填写字段**（必填）：
   - `id`：MS-xxx（与文件名一致）
   - `name`：规则名（中文描述）
   - `signal`：A1-A5 强信号 / B1-B5 辅助信号
   - `category`：检测类别
   - `level`：HIGH/MEDIUM/LOW
   - `author`：你的 GitHub 用户名
   - `title`：一句话特征描述（list 命令展示用）
   - `match`：匹配条件（至少一种）
3. **更新索引**：把新规则加入 `rules/index.json`
4. **本地验证**：
   ```bash
   java -jar memshell-auditor.jar --rules update --repo <你的fork>
   java -jar memshell-auditor.jar --rules list
   ```
5. **提交**：
   ```
   feat(rules): 新增 <特征名> 检测特征
   ```
   并 PR 到本仓库。

## 规则质量要求

- **可验证**：每条规则应附测试样本（内存马类名/字节码特征），PR 描述中说明来源
- **低误报**：classname_pattern 规则必须有明确的恶意特征（如随机后缀+伪装包名），避免命中正常类
- **行为优先**：优先用行为模式（behavior_keywords 组合）而非单一类名，对抗类名伪装
- **版本管理**：规则迭代更新 version 字段，不删除历史规则（标记 deprecated）

## 自动提交（memshell-auditor --submit）

取证人员用 `--submit --report <report.json>` 自动生成规则候选，会按本规范产出提交包：

```
~/.memshell-rules/submit-<timestamp>/
├── rules/MS-xxx.json    # 自动生成的规则（需人工复核后合并）
├── index.json
└── COMMIT_MSG
```

**自动生成 ≠ 直接合并**：人工复核规则质量后再 PR/推送。
