#!/bin/bash
# ============================================================
# memshell-auditor 一键部署脚本
# 用途：下载主程序 jar + 同步特征库 + 验证安装
# 用法：bash deploy.sh [安装目录]
# 默认安装到 ~/memshell-auditor
# ============================================================
set -e

INSTALL_DIR="${1:-$HOME/memshell-auditor}"
VERSION="v2.2"
REPO="x7peeps/memshell-auditor"
RULES_REPO="x7peeps/memshell-rules"

echo "=========================================="
echo " memshell-auditor 一键部署 ($VERSION)"
echo " 作者: x7peeps  |  规则库: $RULES_REPO"
echo "=========================================="

# 0. 检查 Java
if ! command -v java >/dev/null 2>&1; then
    echo "[!] 未检测到 Java，请先安装 JDK 8+"
    exit 1
fi
JAVA_VER=$(java -version 2>&1 | head -1)
echo "[✓] Java: $JAVA_VER"

# 1. 创建安装目录
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"
echo "[*] 安装目录: $INSTALL_DIR"

# 2. 下载主程序 jar
JAR_URL="https://github.com/$REPO/releases/latest/download/memshell-auditor.jar"
echo "[*] 下载主程序: $JAR_URL"
if curl -sL --max-time 120 -o memshell-auditor.jar "$JAR_URL" && [ -s memshell-auditor.jar ]; then
    echo "[✓] 主程序下载完成: $(ls -la memshell-auditor.jar | awk '{print $5}') bytes"
else
    echo "[!] GitHub 下载失败，尝试代理下载..."
    curl -sL --max-time 120 -x "${HTTPS_PROXY:-http://127.0.0.1:6152}" \
        -o memshell-auditor.jar "$JAR_URL" || {
        echo "[!] 下载失败，请手动下载: $JAR_URL"
        exit 1
    }
    echo "[✓] 主程序下载完成（代理）"
fi

# 3. 验证 jar 可运行
echo "[*] 验证安装..."
if java -jar memshell-auditor.jar --version >/dev/null 2>&1; then
    echo "[✓] 主程序可运行"
else
    echo "[!] 主程序启动异常（可能需要 JDK 9+ 模块参数）"
    echo "    提示: JDK 21+ 需要 --add-modules jdk.attach"
fi

# 4. 同步特征库
echo "[*] 同步特征库..."
java -jar memshell-auditor.jar --rules update 2>/dev/null || {
    echo "[!] 规则同步失败（网络受限时离线可用，规则已内置在取证程序）"
}

# 5. 生成混淆取证程序
echo "[*] 生成混淆取证程序..."
java -jar memshell-auditor.jar --gen-agent ./agents --name-prefix system-diag 2>/dev/null || echo "[!] 取证程序生成失败"

echo ""
echo "=========================================="
echo " 部署完成！"
echo " 主程序:   $INSTALL_DIR/memshell-auditor.jar"
echo " 取证程序: $INSTALL_DIR/agents/system-diag-*.jar"
echo ""
echo " 快速使用:"
echo "   现场扫描:   java -jar agents/system-diag-*.jar --scan --dump ./dump --heap ./heap"
echo "   分析报告:   java -jar memshell-auditor.jar --analyze <report.json> --ai-config ai.json"
echo "   更新规则:   java -jar memshell-auditor.jar --rules update"
echo "=========================================="
