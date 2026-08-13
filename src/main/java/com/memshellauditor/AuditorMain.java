package com.memshellauditor;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * 主程序 CLI（分析端，v2.0 架构重划）：
 *
 * 职责边界（彻底分离，主程序绝不接触目标机器，防进程树暴露）：
 *  - --gen-agent  生成混淆取证程序（唯一产出"现场端"能力的入口）
 *  - --analyze    分析取证报告 + AI 增强（引导配置，可重跑自动带 AI）
 *  - --rules      特征库管理（update/list/select/download/status）
 *  - --submit     特征提交包生成（检出/未检出 → 本地 git 提交）
 *
 * 主程序不再提供 attach/PID 分析——扫描由生成的取证程序执行。
 *
 * 用法:
 *   java -jar memshell-auditor.jar --gen-agent <输出目录> [--name-prefix <前缀>]
 *   java -jar memshell-auditor.jar --analyze <report.json> [--ai-config ai.json]
 *   java -jar memshell-auditor.jar --rules <update|list|select|download|status> [args]
 *   java -jar memshell-auditor.jar --submit --report <report.json> [--author <name>]
 */
public class AuditorMain {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.out.print(VersionInfo.banner());
            usage();
            return;
        }
        String cmd = args[0];

        // ===== 生成混淆取证程序 =====
        if (cmd.equals("--gen-agent") || cmd.equals("-g")) {
            Map<String, String> opts = parseOptions(args, 1);
            String dir = (args.length > 1 && !args[1].startsWith("--")) ? args[1]
                    : opts.get("--output");
            if (dir == null) dir = ".";
            String prefix = opts.get("--name-prefix");
            File outDir = new File(dir);
            File gen = com.memshellauditor.obf.ObfuscateAgentGenerator.generate(outDir, prefix);
            if (gen != null) {
                System.out.println("[*] 混淆取证程序已生成: " + gen.getAbsolutePath());
                System.out.println("[*] 现场使用: java -jar " + gen.getName() + " --scan [--dump dir] [--heap dir]");
                System.out.println("[*] 取证报告带回分析端: java -jar memshell-auditor.jar --analyze <report.json> --ai-config ai.json");
            } else {
                System.err.println("[!] 生成失败（需从完整 jar 运行）");
                System.exit(2);
            }
            return;
        }

        // ===== 分析取证报告（AI 增强） =====
        if (cmd.equals("--analyze") || cmd.equals("-a")) {
            Map<String, String> opts = parseOptions(args, 1);
            String reportPath = (args.length > 1 && !args[1].startsWith("--")) ? args[1]
                    : opts.get("--report");
            if (reportPath == null) {
                System.err.println("[!] 用法: --analyze <report.json> [--ai-config file]");
                System.exit(2);
            }
            ReportAnalyzer.analyze(new File(reportPath), opts.get("--ai-config"));
            return;
        }

        // ===== 特征库管理 =====
        if (cmd.equals("--rules") || cmd.equals("-r")) {
            Map<String, String> opts = parseOptions(args, 2);
            String action = (args.length > 1 && !args[1].startsWith("--")) ? args[1] : "list";
            com.memshellauditor.rules.RuleUpdater.dispatch(action, args, opts);
            return;
        }

        // ===== 特征提交包 =====
        if (cmd.equals("--submit") || cmd.equals("-u")) {
            Map<String, String> opts = parseOptions(args, 1);
            String reportPath = opts.get("--report");
            if (reportPath == null) {
                System.err.println("[!] 用法: --submit --report <report.json> [--author <name>] [--auto-commit]");
                System.exit(2);
            }
            com.memshellauditor.rules.SubmitCollector.submit(new File(reportPath),
                    opts.get("--author"), opts.containsKey("--auto-commit"));
            return;
        }

        // ===== 版本 =====
        if (cmd.equals("--version") || cmd.equals("-v")) {
            System.out.print(VersionInfo.banner());
            return;
        }

        // 其他命令前展示策略版本横幅（主程序运行时都要看到策略情况与署名）
        if (!cmd.equals("--gen-agent") && !cmd.equals("-g")) {
            System.out.print(VersionInfo.banner());
        }

        usage();
    }

    private static Map<String, String> parseOptions(String[] args, int start) {
        Map<String, String> opts = new HashMap<String, String>();
        for (int i = start; i < args.length; i++) {
            String a = args[i];
            if (a.startsWith("--")) {
                if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
                    opts.put(a, args[i + 1]);
                    i++;
                } else {
                    opts.put(a, "");
                }
            }
        }
        return opts;
    }

    private static void usage() {
        System.out.println("memshell-auditor v2.0 - Java 内存马审计（分析端）");
        System.out.println();
        System.out.println("用法:");
        System.out.println("  java -jar memshell-auditor.jar --gen-agent <输出目录> [--name-prefix <前缀>]");
        System.out.println("      生成混淆取证程序（防识别，每次随机特征），丢到目标系统执行 --scan");
        System.out.println();
        System.out.println("  java -jar memshell-auditor.jar --analyze <report.json> [--ai-config ai.json]");
        System.out.println("      分析取证报告；未配置 AI 时结尾引导配置，配置后重跑自动带 AI 增强");
        System.out.println();
        System.out.println("  java -jar memshell-auditor.jar --rules <update|list|select|download|status> [args]");
        System.out.println("      特征库管理（GitHub 在线更新，类 Metasploit）");
        System.out.println("        --rules update            拉取/更新特征库");
        System.out.println("        --rules list              列出规则（提交人/标题/勾选状态）");
        System.out.println("        --rules select --all      全选规则");
        System.out.println("        --rules select --id MS-001 --id MS-002  逐个勾选");
        System.out.println("        --rules download <repo>   下载他人特征库");
        System.out.println("        --rules status            本地规则状态");
        System.out.println();
        System.out.println("  java -jar memshell-auditor.jar --submit --report <report.json> [--author <name>] [--auto-commit]");
        System.out.println("      特征提交包（检出/未检出 → 规则候选 → 本地 git 提交）");
        System.out.println();
        System.out.println("AI 配置（OpenAI 兼容）:");
        System.out.println("  --ai-config ai.json   ({\"base_url\":\"...\",\"api_key\":\"...\",\"model\":\"...\"})");
        System.out.println("  或环境变量 AI_BASE_URL / AI_API_KEY / AI_MODEL");
        System.out.println("  兼容 OpenAI/DeepSeek/通义/Ollama/vLLM");
    }
}
