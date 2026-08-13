package com.memshellauditor.ai;

import com.memshellauditor.report.Finding;
import com.memshellauditor.report.Report;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * AI 增强分析器：
 *  - 引导式：有配置用配置；无配置引导输入或跳过；离线降级本地规则
 *  - 输入：检测报告摘要 + dump 出的类 + 反编译核心代码
 *  - 输出：恶意行为解读 / 回连判断 / 处置建议（合并进报告 aiAnalysis 字段）
 */
public class AiAnalyzer {

    private final AiClient client;

    public AiAnalyzer() {
        this(new AiClient());
    }

    public AiAnalyzer(AiClient client) {
        this.client = client;
    }

    /**
     * 执行 AI 分析。
     * @param report    检测报告（含 findings）
     * @param dumpDir   dump 目录（可选）
     * @param interactive 是否允许交互式引导（CLI 模式 true；agent 模式 false）
     * @return 分析文本，未执行返回 null
     */
    public String analyze(Report report, File dumpDir, boolean interactive) {
        // 1. 检查配置
        if (client == null || !client.isConfigured()) {
            if (interactive) {
                System.out.println("[memshell-auditor] 未配置 AI 分析接口。");
                System.out.println("  可选：设置环境变量 AI_BASE_URL / AI_API_KEY / AI_MODEL");
                System.out.println("  或：--ai-config <file.json> ({\"base_url\":\"...\",\"api_key\":\"...\",\"model\":\"...\"})");
                System.out.println("  跳过 AI 分析，继续本地分析...");
            }
            return localAnalysis(report, dumpDir);
        }
        System.out.println("[memshell-auditor] AI 分析: " + client.baseUrl + " model=" + client.model);

        // 2. 构造分析上下文
        String context = buildContext(report, dumpDir);
        if (context == null || context.isEmpty()) return null;

        // 3. 调用 LLM（失败返回 null，由调用方决定降级）
        return client.chat(SYSTEM_PROMPT, context);
    }

    private static final String SYSTEM_PROMPT =
            "你是资深 Java Web 安全分析专家。根据给定的内存马检测报告、dump 出的恶意类字节码特征与反编译代码片段，输出结构化分析：\n" +
            "1. 恶意行为解读（这个类做了什么，命令执行/回连/解密等）\n" +
            "2. 回连地址判断（哪些 IP/域名可疑，为什么）\n" +
            "3. 攻击链还原（可能的注入方式与利用入口）\n" +
            "4. 处置建议（隔离/取证/清除/加固要点）\n" +
            "要求：基于证据分析，不臆测；如证据不足明确说明。中文输出。";

    /** 构造分析上下文（报告摘要 + dump 类信息） */
    private String buildContext(Report report, File dumpDir) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== 内存马检测报告摘要 ===\n");
        sb.append("目标: ").append(report.getTargetDesc() == null ? "?" : report.getTargetDesc()).append("\n");
        sb.append("PID: ").append(report.getPid()).append(" JVM: ").append(report.getJavaVersion()).append("\n\n");
        sb.append("检测发现（HIGH/MEDIUM）:\n");
        for (Finding f : report.getFindings()) {
            if (f.level == Finding.Level.HIGH || f.level == Finding.Level.MEDIUM) {
                sb.append("- [").append(f.level).append("] ").append(f.category)
                  .append(": ").append(f.className == null ? "" : f.className)
                  .append(" | ").append(f.reason == null ? "" : f.reason).append("\n");
                if (f.callbackIps != null && !f.callbackIps.isEmpty()) {
                    sb.append("  回连: ").append(f.callbackIps).append("\n");
                }
            }
        }
        // dump 目录中的类清单
        if (dumpDir != null && dumpDir.exists()) {
            sb.append("\n=== Dump 类清单 ===\n");
            File[] files = dumpDir.listFiles();
            if (files != null) {
                for (File f : files) {
                    if (f.getName().endsWith(".class")) {
                        sb.append("- ").append(f.getName()).append(" (").append(f.length()).append("B)\n");
                    }
                }
            }
        }
        return sb.toString();
    }

    /** 本地降级分析（离线/无 AI 时用规则） */
    private String localAnalysis(Report report, File dumpDir) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== 本地规则分析（未启用 AI） ===\n");
        boolean any = false;
        for (Finding f : report.getFindings()) {
            if (f.level == Finding.Level.HIGH) {
                any = true;
                sb.append("⚠️ 高危发现: ").append(f.category).append(" ")
                  .append(f.className == null ? "" : f.className).append("\n");
                sb.append("   判定: ").append(f.reason == null ? "" : f.reason).append("\n");
                if (f.callbackIps != null && !f.callbackIps.isEmpty()) {
                    sb.append("   疑似回连: ").append(f.callbackIps).append("\n");
                }
                if (f.dumpPath != null && !f.dumpPath.isEmpty()) {
                    sb.append("   已 dump: ").append(f.dumpPath).append(" → 用 javap -c 查看反汇编\n");
                }
                sb.append("   建议: 隔离主机 → 结合威胁情报查询回连地址 → 排查注入入口(反序列化/表达式/上传) → 修复后重启\n");
            }
        }
        if (!any) {
            sb.append("未发现高危内存马迹象。\n");
        }
        return sb.toString();
    }
}
