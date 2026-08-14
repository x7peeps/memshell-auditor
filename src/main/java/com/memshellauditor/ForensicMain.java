package com.memshellauditor;

import java.io.File;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

/**
 * 取证程序 CLI（现场端，v2.0 架构重划）：
 *  由主程序 --gen-agent 生成（混淆），部署到目标系统执行。
 *  只包含现场能力：扫描/指定审计/dump/堆取证/规则匹配；不含分析端能力（AI/gen-agent/analyze）。
 *
 * 用法:
 *   java -jar <取证程序>.jar --scan [--dump dir] [--heap dir] [--max-jvms N]
 *   java -jar <取证程序>.jar <pid> [--report out.json] [--dump dir] [--heap dir]
 *   java -jar <取证程序>.jar --list
 */
public class ForensicMain {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            usage();
            return;
        }
        String cmd = args[0];

        // ===== 全自动扫描 =====
        if (cmd.equals("--scan") || cmd.equals("-s")) {
            Map<String, String> opts = parseOptions(args, 1);
            File agentJar = locateAgentJar();
            if (agentJar == null) {
                System.err.println("[!] 无法定位取证 agent jar");
                System.exit(2);
            }
            ScanRunner.scan(agentJar, opts);
            return;
        }

        // ===== 指定 PID 审计 =====
        if (cmd.matches("\\d+")) {
            Map<String, String> opts = parseOptions(args, 1);
            String pid = cmd;
            File agentJar = locateAgentJar();
            if (agentJar == null) {
                System.err.println("[!] 无法定位取证 agent jar");
                System.exit(2);
            }
            auditOne(pid, agentJar, opts);
            return;
        }

        // ===== 列出进程 =====
        if (cmd.equals("--list") || cmd.equals("-l")) {
            java.util.List<JvmScanner.JvmInfo> jvms = JvmScanner.listJvms();
            for (JvmScanner.JvmInfo j : jvms) JvmScanner.score(j);
            JvmScanner.sortByScore(jvms);
            System.out.println("本机 Java 进程（按可疑度排序）:");
            for (JvmScanner.JvmInfo j : jvms) {
                String tag = j.score >= 80 ? "⚠️ " : "   ";
                System.out.println("  " + tag + j.id + "  " + truncate(j.displayName, 90));
            }
            return;
        }

        // ===== 版本 =====
        if (cmd.equals("--version") || cmd.equals("-v")) {
            System.out.println("memshell-auditor 取证程序 (现场端, 混淆版)");
            return;
        }

        usage();
    }

    /** attach 单个 PID 审计 */
    private static void auditOne(String pid, File agentJar, Map<String, String> opts) throws Exception {
        String reportPath = opts.get("--report");
        if (reportPath == null) reportPath = "memshell-auditor-report-" + pid + ".json";
        String dumpDir = opts.get("--dump");
        String heapDir = opts.get("--heap");
        String out = reportPath;
        System.out.println("[*] attach 目标 PID=" + pid);
        Class<?> vmClass = Class.forName("com.sun.tools.attach.VirtualMachine");
        Method attach = vmClass.getMethod("attach", String.class);
        Object vm = attach.invoke(null, pid);
        try {
            StringBuilder agentArgs = new StringBuilder();
            agentArgs.append("output=").append(new File(out).getAbsolutePath());
            agentArgs.append(",pid=").append(pid);
            if (dumpDir != null && !dumpDir.isEmpty()) {
                agentArgs.append(",dump=").append(new File(dumpDir).getAbsolutePath());
            }
            if (heapDir != null && !heapDir.isEmpty()) {
                agentArgs.append(",heap=").append(new File(heapDir).getAbsolutePath());
            }
            // 实时监控模式：--live [seconds] 保持监听捕获后续新注入类
            String live = opts.get("--live");
            if (live != null) {
                agentArgs.append(",live=").append(live.isEmpty() ? "60" : live);
            }
            // 值守监控模式：--monitor <config.json> webhook 实时推送
            String monitor = opts.get("--monitor");
            if (monitor != null && !monitor.isEmpty()) {
                agentArgs.append(",monitor=").append(new File(monitor).getAbsolutePath());
            }
            Method loadAgent = vmClass.getMethod("loadAgent", String.class, String.class);
            loadAgent.invoke(vm, agentJar.getAbsolutePath(), agentArgs.toString());
            System.out.println("[*] 取证完成，报告: " + new File(out).getAbsolutePath());
        } finally {
            Method detach = vmClass.getMethod("detach");
            detach.invoke(vm);
        }
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

    private static File locateAgentJar() {
        try {
            File self = new File(ForensicMain.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            if (self.isFile() && self.getName().endsWith(".jar")) return self;
        } catch (Throwable t) {
            // ignore
        }
        String env = System.getenv("MEMSHELL_AUDITOR_JAR");
        if (env != null && new File(env).exists()) return new File(env);
        return null;
    }

    private static void usage() {
        System.out.println("memshell-auditor 取证程序（现场端，混淆版）");
        System.out.println();
        System.out.println("用法:");
        System.out.println("  java -jar <取证程序>.jar --scan [--dump dir] [--heap dir] [--max-jvms N]");
        System.out.println("      全自动扫描所有 Java 进程（无需指定 PID）");
        System.out.println("  java -jar <取证程序>.jar <pid> [--report out.json] [--dump dir] [--heap dir]");
        System.out.println("      指定进程审计");
        System.out.println("  java -jar <取证程序>.jar --list");
        System.out.println("      列出 Java 进程（按可疑度排序）");
        System.out.println();
        System.out.println("取证报告可带回分析端: java -jar memshell-auditor.jar --analyze <report.json> --ai-config ai.json");
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
