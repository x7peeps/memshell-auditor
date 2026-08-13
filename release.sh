#!/bin/bash
# ============================================================
# memshell-auditor 发版脚本（README 自动更新 + Release 发布）
# 用法: bash release.sh <版本号> <版本说明标题>
#   例: bash release.sh v2.6 "memshell-auditor v2.6 - 内存马检测与取证一体化"
# ============================================================
set -e
VERSION="${1:?用法: bash release.sh <版本号>}"
TITLE="${2:-memshell-auditor $VERSION}"

echo "=========================================="
echo " 发版: $VERSION - $TITLE"
echo "=========================================="

# 0. 构建
echo "[1/6] Maven 构建..."
mvn -q clean package -DskipTests
echo "  jar: $(ls -la target/memshell-auditor.jar | awk '{print $5}') bytes"

# 1. 自动更新 README 版本号（README.md 中出现的 vX.Y 标记全部更新）
echo "[2/6] 更新 README 版本号..."
CUR=$(grep -oE 'v[0-9]+\.[0-9]+' README.md | head -1 || echo "v2.6")
sed -i '' "s|${CUR}|${VERSION}|g" README.md
echo "  README: ${CUR} → ${VERSION}"

# 2. 生成 release notes（从 README 提取能力清单 + git log）
echo "[3/6] 生成 release notes..."
{
    echo "## ${TITLE}"
    echo ""
    echo "### 核心能力"
    echo "- **检测**：A1-A5 强信号 + B1-B5 辅助信号 + 启发式行为评分"
    echo "- **取证闭环**：dump 字节码 + javap 反编译 + 回连分析 + jmap 堆取证"
    echo "- **--scan** 全自动扫描 + 并发审计（--parallel）"
    echo "- **--live** 实时监控：新注入类定义时捕获，无需 retransform"
    echo "- **威胁情报**：--analyze 自动查询回连 IP（微步 API + 启发式）"
    echo "- **hprof 解析**：堆 dump 深度解析，retransform 失败类从堆中恢复"
    echo "- **双程序防识别**：--gen-agent 每次随机特征"
    echo "- **特征库生态**：rules/ 内置 18 条规则，在线更新 + 自定义保护 + 众包提交"
    echo "- **AI 增强**：OpenAI 兼容接口，可配可跳过，离线降级"
    echo ""
    echo "### 本版本更新"
    git log --oneline -15 --no-merges | head -10 | sed 's/^/- /'
    echo ""
    echo "### 安装"
    echo '```bash'
    echo 'bash -c "$(curl -sL https://raw.githubusercontent.com/x7peeps/memshell-auditor/main/deploy.sh)"'
    echo '```'
} > /tmp/release-notes.md
echo "  notes: /tmp/release-notes.md"

# 3. 提交 README 更新
echo "[4/6] 提交推送..."
git add -A
git -c user.email='xtpeeps@qq.com' -c user.name='x7peeps' commit -m "docs: 版本号更新至 ${VERSION}（README 自动更新）" || true
git push origin main

# 4. 打包规则
echo "[5/6] 打包规则..."
zip -j /tmp/memshell-rules.zip rules/*.json rules/version

# 5. 创建/更新 Release
echo "[6/6] 发布 Release ${VERSION}..."
if gh release view "$VERSION" >/dev/null 2>&1; then
    gh release upload "$VERSION" target/memshell-auditor.jar /tmp/memshell-rules.zip --clobber
else
    gh release create "$VERSION" target/memshell-auditor.jar /tmp/memshell-rules.zip \
        --title "$TITLE" --notes-file /tmp/release-notes.md
fi

echo ""
echo "=========================================="
echo " ✅ ${VERSION} 发版完成"
echo "    https://github.com/x7peeps/memshell-auditor/releases/tag/${VERSION}"
echo "=========================================="
