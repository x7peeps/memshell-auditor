package com.memshellauditor;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

/**
 * CLI 启动器：attach 到目标 JVM 执行完整审计（检测 + 取证 + AI 分析）。
 *
 * 用法（单命令完成所有能力）:
 *   java -jar memshell-auditor.jar --list
 *   java -jar memshell-auditor.jar <pid>
 *   java -jar memshell-auditor.jar <pid> --report out.json --dump ./dump --heap ./heap
 *   java -jar memshell-auditor.jar <pid> --ai-config ai.json --dump ./dump
 *
 * 兼容 JDK 8+：反射调用 com.sun.tools.attach 避免编译期硬依赖。
 * JDK 9+ 模块系统下需要 --add-modules jdk.attach（脚本已封装）。
 */
public class AuditorMain {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            usage();
            return;
        }
        // --list / -l
        if (args[0].equals("--list") || args[0].equals("-l")) {
            listJvms();
            return;
        }

        // --gen-agent <输出目录> [--name-prefix <前缀>] 生成混淆取证程序
        if (args[0].equals("--gen-agent") || args[0].equals("-g")) {
            Map<String, String> opts = parseOptions(args, 1);
            String dir = (args.length > 1 && !args[1].startsWith("--")) ? args[1]
                    : opts.get("--output");
            if (dir == null) dir = ".";
            String prefix = opts.get("--name-prefix");
            File outDir = new File(dir);
            File gen = com.memshellauditor.obf.ObfuscateAgentGenerator.generate(outDir, prefix);
            if (gen != null) {
                System.out.println("[*] 混淆取证程序已生成: " + gen.getAbsolutePath());
                System.out.println("[*] 使用: java -jar " + gen.getName() + " <pid> [--dump dir] [--heap dir]");
                System.out.println("[*] 取证报告带回分析端: java -jar memshell-auditor.jar --analyze <report.json> --ai-config ai.json");
            } else {
                System.err.println("[!] 生成失败（需从完整 jar 运行）");
                System.exit(2);
            }
            return;
        }

        // --analyze <report.json> [--ai-config file] 分析取证报告（主程序 AI 增强）
        if (args[0].equals("--analyze") || args[0].equals("-a")) {
            Map<String, String> opts = parseOptions(args, 1);
            String reportPath = (args.length > 1 && !args[1].startsWith("--")) ? args[1]
                    : opts.get("--report");
            if (reportPath == null) {
                System.err.println("[!] 用法: --analyze <report.json> [--ai-config file]");
                System.exit(2);
            }
            analyzeReport(new File(reportPath), opts.get("--ai-config"));
            return;
        }

        String pid = args[0];
        Map<String, String> opts = parseOptions(args, 1);

        String report = opts.get("--report");
        if (report == null) {
            // 兼容旧式位置参数: [report.json] [dump_dir]
            for (int i = 1; i < args.length; i++) {
                if (!args[i].startsWith("--") && report == null) {
                    report = args[i];
                    if (i + 1 < args.length && !args[i + 1].startsWith("--") && opts.get("--dump") == null) {
                        opts.put("--dump", args[i + 1]);
                    }
                    break;
                }
            }
        }
        if (report == null) {
            report = "memshell-auditor-report-" + pid + "-" + System.currentTimeMillis() + ".json";
        }

        File agentJar = locateAgentJar();
        if (agentJar == null) {
            System.err.println("[!] 无法定位 memshell-auditor agent jar（应与本 CLI 同目录或同 classpath）");
            System.exit(2);
        }
        run(pid, agentJar, report, opts);
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
        System.out.println("memshell-auditor - Java 内存马运行时审计 Agent CLI");
        System.out.println();
        System.out.println("用法:");
        System.out.println("  java -jar memshell-auditor.jar --list");
        System.out.println("  java -jar memshell-auditor.jar <pid> [选项]");
        System.out.println("  java -jar memshell-auditor.jar --gen-agent <输出目录> [--name-prefix <前缀>]");
        System.out.println();
        System.out.println("选项:");
        System.out.println("  --report <path>    报告输出路径 (默认 memshell-auditor-report-<pid>.json)");
        System.out.println("  --dump <dir>       Dump 目录：可疑类字节码落盘 + 反编译 + 回连分析");
        System.out.println("  --heap <dir>       Heap 目录：jmap 堆内存取证 (跨平台, 证据链完整性)");
        System.out.println("  --ai-config <file> AI 分析配置 (JSON: {\"base_url\":\"...\",\"api_key\":\"...\",\"model\":\"...\"})");
        System.out.println("                     OpenAI 兼容: DeepSeek/通义/Ollama/vLLM 等均可用");
        System.out.println("  --gen-agent        生成混淆取证程序（随机名+特征混淆，防被识别）");
        System.out.println("  --name-prefix      生成程序文件名前缀 (默认 jre-check)");
        System.out.println();
        System.out.println("示例:");
        System.out.println("  java -jar memshell-auditor.jar 12345");
        System.out.println("  java -jar memshell-auditor.jar 12345 --dump ./dump");
        System.out.println("  java -jar memshell-auditor.jar 12345 --dump ./dump --heap ./heap --ai-config ai.json");
        System.out.println();
        System.out.println("AI 环境变量: AI_BASE_URL / AI_API_KEY / AI_MODEL (未配置自动跳过, 离线可用)");
    }

    private static void listJvms() throws Exception {
        Class<?> vmClass = Class.forName("com.sun.tools.attach.VirtualMachine");
        Method list = vmClass.getMethod("list");
        Object vms = list.invoke(null);
        java.util.List<?> lst = (java.util.List<?>) vms;
        System.out.println("本机 Java 进程:");
        for (Object vm : lst) {
            Method id = vm.getClass().getMethod("id");
            Method display = vm.getClass().getMethod("displayName");
            System.out.println("  " + id.invoke(vm) + "  " + display.invoke(vm));
        }
    }

    private static void run(String pid, File agentJar, String outPath, Map<String, String> opts) throws Exception {
        System.out.println("[*] attach 目标 PID=" + pid);
        Class<?> vmClass = Class.forName("com.sun.tools.attach.VirtualMachine");
        Method attach = vmClass.getMethod("attach", String.class);
        Object vm = attach.invoke(null, pid);
        try {
            // 组装 agent 参数
            StringBuilder agentArgs = new StringBuilder();
            agentArgs.append("output=").append(new File(outPath).getAbsolutePath());
            agentArgs.append(",pid=").append(pid);
            String dumpDir = opts.get("--dump");
            if (dumpDir != null && !dumpDir.isEmpty()) {
                agentArgs.append(",dump=").append(new File(dumpDir).getAbsolutePath());
            }
            String heapDir = opts.get("--heap");
            if (heapDir != null && !heapDir.isEmpty()) {
                agentArgs.append(",heap=").append(new File(heapDir).getAbsolutePath());
            }
            String aiConfig = opts.get("--ai-config");
            if (aiConfig != null && !aiConfig.isEmpty()) {
                agentArgs.append(",ai=").append(new File(aiConfig).getAbsolutePath());
            }
            Method loadAgent = vmClass.getMethod("loadAgent", String.class, String.class);
            System.out.println("[*] 加载 agent: " + agentJar.getAbsolutePath());
            loadAgent.invoke(vm, agentJar.getAbsolutePath(), agentArgs.toString());
            System.out.println("[*] agent 执行完成，报告: " + new File(outPath).getAbsolutePath());
            // 输出报告内容
            File f = new File(outPath);
            if (f.exists()) {
                System.out.println("========== JSON 报告 ==========");
                InputStream in = new FileInputStream(f);
                byte[] buf = new byte[(int) Math.min(f.length(), 512 * 1024)];
                int n = in.read(buf);
                in.close();
                if (n > 0) System.out.println(new String(buf, 0, n, "UTF-8"));
            }
        } finally {
            Method detach = vmClass.getMethod("detach");
            detach.invoke(vm);
        }
    }

    private static File locateAgentJar() {
        // 1) 同目录
        try {
            File self = new File(AuditorMain.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            if (self.isFile() && self.getName().endsWith(".jar")) {
                return self;
            }
        } catch (Throwable t) {
            // ignore
        }
        // 2) 环境变量
        String env = System.getenv("MEMSHELL_AUDITOR_JAR");
        if (env != null && new File(env).exists()) return new File(env);
        return null;
    }

    /**
     * 分析取证报告（主程序 AI 增强模式）：
     *  读取取证端生成的 report.json → 重建 Report → 输出 AI/本地分析结论。
     *  用于分析者机器上对离线采集的报告做 AI 增强（OpenAI 兼容接口）。
     */
    private static void analyzeReport(File reportFile, String aiConfig) {
        try {
            if (!reportFile.exists()) {
                System.err.println("[!] 报告不存在: " + reportFile);
                System.exit(2);
            }
            String content = new String(java.nio.file.Files.readAllBytes(reportFile.toPath()), "UTF-8");
            com.memshellauditor.report.Report report = com.memshellauditor.report.Report.fromJson(content);
            System.out.println("[*] 读取取证报告: " + reportFile.getAbsolutePath());
            System.out.println("[*] 目标: " + report.getTargetDesc() + " PID: " + report.getPid());
            System.out.println("------------------------------------------");
            // 控制台输出 findings
            System.out.println(report.toConsole());

            // AI 增强分析（OpenAI 兼容，可跳过）
            try {
                Class<?> aiAnalyzerCls = Class.forName("com.memshellauditor.ai.AiAnalyzer");
                Class<?> aiClientCls = Class.forName("com.memshellauditor.ai.AiClient");
                Object client = aiClientCls.getConstructor().newInstance();
                if (aiConfig != null && !aiConfig.isEmpty()) {
                    java.lang.reflect.Method fromCfg = aiClientCls.getMethod("fromConfigFile", String.class);
                    client = fromCfg.invoke(null, aiConfig);
                }
                java.lang.reflect.Method analyze = aiAnalyzerCls.getMethod("analyze",
                        com.memshellauditor.report.Report.class, File.class, boolean.class);
                String result = (String) analyze.invoke(aiAnalyzerCls.getConstructor().newInstance(),
                        report, null, false);
                if (result != null && !result.isEmpty()) {
                    System.out.println("===== AI 增强分析结果 =====");
                    System.out.println(result);
                }
            } catch (Throwable t) {
                System.out.println("[memshell-auditor] AI 分析未执行: " + t.getMessage());
            }
        } catch (Throwable t) {
            System.err.println("[!] 报告解析失败: " + t);
            System.exit(2);
        }
    }
}
