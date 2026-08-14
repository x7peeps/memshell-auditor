package com.memshellauditor;

import com.memshellauditor.ai.AiAnalyzer;
import com.memshellauditor.ai.AiClient;
import com.memshellauditor.detect.AgentAuditor;
import com.memshellauditor.detect.ClassFeatureAuditor;
import com.memshellauditor.detect.ClassLoaderAuditor;
import com.memshellauditor.detect.ContainerAuditor;
import com.memshellauditor.detect.HeuristicAuditor;
import com.memshellauditor.detect.TransformerAuditor;
import com.memshellauditor.report.Report;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.HashMap;
import java.util.Map;

/**
 * Java Agent 入口（premain / agentmain 双支持）。
 *
 * agentmain: attach 时被 JVM 调用，执行内存马审计 + 取证 + AI 分析。
 *   args 格式: output=<path>,pid=<pid>[,dump=<dir>][,heap=<dir>][,ai=<config>]
 * premain : 启动时 -javaagent 挂载，用于事前巡检（配合基线）。
 *
 * 无第三方依赖，JDK 8 编译，可在 JDK 8-21+ 目标 JVM 上运行。
 */
public class AgentMain {

    public static void premain(String args, Instrumentation inst) {
        run(args, inst, true);
    }

    public static void agentmain(String args, Instrumentation inst) {
        run(args, inst, false);
    }

    private static void run(String args, Instrumentation inst, boolean premain) {
        Map<String, String> opts = parseArgs(args);
        String outPath = opts.get("output");
        String dumpDir = opts.get("dump");
        String heapDir = opts.get("heap");
        String aiConfig = opts.get("ai");

        Report report = new Report();
        report.begin();
        report.setTargetDesc(System.getProperty("user.dir", "?") + " / " + System.getProperty("sun.java.command", "?"));
        try {
            report.setPid(Long.parseLong(opts.containsKey("pid") ? opts.get("pid") : "-1"));
        } catch (Throwable t) {
            report.setPid(-1);
        }
        report.setJavaVersion(System.getProperty("java.version", "?"));

        // ===== 核心审计 =====
        try { new ContainerAuditor().audit(inst, report); } catch (Throwable t) {
            report.add(com.memshellauditor.report.Finding.low("N/A", "Container", null, null, "容器审计异常: " + t, null));
        }
        try { new AgentAuditor().audit(inst, report); } catch (Throwable t) {
            report.add(com.memshellauditor.report.Finding.low("N/A", "Agent", null, null, "Agent 审计异常: " + t, null));
        }
        try { new ClassLoaderAuditor().audit(inst, report); } catch (Throwable t) {
            report.add(com.memshellauditor.report.Finding.low("N/A", "ClassLoader", null, null, "ClassLoader 审计异常: " + t, null));
        }
        try { new ClassFeatureAuditor().audit(inst, report); } catch (Throwable t) {
            report.add(com.memshellauditor.report.Finding.low("N/A", "ClassFeature", null, null, "类特征审计异常: " + t, null));
        }
        try { new TransformerAuditor().audit(inst, report); } catch (Throwable t) {
            report.add(com.memshellauditor.report.Finding.low("N/A", "Transformer", null, null, "Transformer 审计异常: " + t, null));
        }
        // 未知内存马启发式检测
        try { new HeuristicAuditor().audit(inst, report); } catch (Throwable t) {
            report.add(com.memshellauditor.report.Finding.low("N/A", "Heuristic", null, null, "启发式审计异常: " + t, null));
        }

        // ===== 规则引擎匹配（取证端内置规则，离线可用） =====
        try {
            java.util.List<com.memshellauditor.rules.Rule> rules = com.memshellauditor.rules.RuleEngine.loadClasspathRules();
            if (rules.isEmpty()) {
                rules = com.memshellauditor.rules.RuleEngine.loadUserRules();
            }
            int ruleHits = 0;
            if (!rules.isEmpty()) {
                for (com.memshellauditor.report.Finding f : report.getFindings()) {
                    if (f.level != com.memshellauditor.report.Finding.Level.HIGH) continue;
                    java.util.List<String> hits = com.memshellauditor.rules.RuleEngine.matchRules(
                            rules, f.category, f.signal, f.className);
                    if (!hits.isEmpty()) {
                        ruleHits++;
                        if (f.evidence == null || f.evidence.isEmpty()) {
                            f.evidence = "命中规则: " + String.join(", ", hits);
                        } else {
                            f.evidence = f.evidence + " | 命中规则: " + String.join(", ", hits);
                        }
                    }
                }
                report.add(com.memshellauditor.report.Finding.info("RuleEngine",
                        "规则引擎加载 " + rules.size() + " 条特征规则，高危命中 " + ruleHits + " 项"));
            }
        } catch (Throwable t) {
            report.add(com.memshellauditor.report.Finding.low("N/A", "RuleEngine", null, null,
                    "规则引擎异常: " + t, null));
        }

        // ===== 实时监控模式（--live / --monitor）：attach 后保持监听，捕获后续新注入类 =====
        String liveSeconds = opts.get("live");
        String monitorConfigPath = opts.get("monitor");
        com.memshellauditor.monitor.MonitorEngine.MonitorSession monitorSession = null;
        if (monitorConfigPath != null) {
            try {
                com.memshellauditor.monitor.MonitorEngine.MonitorConfig mcfg =
                        com.memshellauditor.monitor.MonitorEngine.parseConfig(new File(monitorConfigPath));
                monitorSession = new com.memshellauditor.monitor.MonitorEngine.MonitorSession(
                        mcfg, System.getProperty("sun.java.command", "?"));
                if (liveSeconds == null) liveSeconds = String.valueOf(mcfg.liveSeconds);
                System.out.println("[monitor] 值守监控已配置 webhook: " + mcfg.webhookType
                        + " (min_level=" + mcfg.minLevel + ", interval=" + mcfg.intervalSeconds + "s)");
            } catch (Throwable t) {
                System.out.println("[monitor] 监控配置解析失败: " + t);
            }
        }
        if (liveSeconds != null) {
            try {
                final Report liveReport = report;
                final java.io.File liveDumpDir = dumpDir != null ? new File(dumpDir) : null;
                final com.memshellauditor.monitor.MonitorEngine.MonitorSession mSession = monitorSession;
                com.memshellauditor.detect.LiveTransformer.enable(inst, new com.memshellauditor.detect.LiveTransformer.LiveListener() {
                    @Override
                    public void onNewClass(ClassLoader loader, String className,
                                           byte[] classfileBuffer, ProtectionDomain protectionDomain) {
                        try {
                            String name = className.replace('/', '.');
                            // 跳过自身/JDK/框架类
                            if (name.startsWith("java.") || name.startsWith("javax.")
                                    || name.startsWith("jdk.") || name.startsWith("sun.")
                                    || com.memshellauditor.util.ReflectUtil.isSelfClass(name)) return;
                            // 实时规则检查：容器组件 + 可疑行为
                            boolean suspicious = checkLiveClass(name, classfileBuffer, loader);
                            if (suspicious) {
                                String reason = "实时监控捕获可疑动态加载类: " + name
                                        + "（字节码含命令执行/解密/回连特征）";
                                liveReport.add(com.memshellauditor.report.Finding.high("A1", "Live", name, null, reason,
                                        "dump 目录: " + liveDumpDir));
                                // 立即 dump
                                if (liveDumpDir != null) {
                                    try {
                                        java.io.File f = new java.io.File(liveDumpDir,
                                                name.replaceAll("[^A-Za-z0-9_.]", "_") + ".class");
                                        java.io.FileOutputStream fos = new java.io.FileOutputStream(f);
                                        fos.write(classfileBuffer);
                                        fos.close();
                                        System.out.println("[live] dump: " + f.getAbsolutePath());
                                    } catch (Throwable ignored) {}
                                }
                                // webhook 实时推送（值守监控模式）
                                if (mSession != null) {
                                    mSession.reportFinding("HIGH", "捕获可疑动态加载类: " + name,
                                            "类名: " + name + " | 字节码: " + classfileBuffer.length + "B | dump: "
                                                    + (liveDumpDir != null ? liveDumpDir.getAbsolutePath() : "未启用"));
                                }
                            }
                        } catch (Throwable ignored) {}
                    }
                });
                System.out.println("[live] 实时监控已启用，持续捕获新加载类...");
                // 保持进程存活指定秒数（默认 60）
                long secs = 60;
                try {
                    secs = Long.parseLong(liveSeconds);
                } catch (Throwable ignored) {}
                try {
                    Thread.sleep(1000 * secs);
                } catch (InterruptedException ignored) {}
                System.out.println("[live] 实时监控结束（共 " + secs + " 秒）");
                if (monitorSession != null) {
                    monitorSession.close();
                    System.out.println("[monitor] 值守监控结束，剩余发现已推送");
                }
            } catch (Throwable t) {
                System.err.println("[live] 实时监控启用失败: " + t);
            }
        }

        File dumpFile = null;
        if (dumpDir != null) {
            dumpFile = new File(dumpDir);
            try {
                new com.memshellauditor.dump.ForensicsService(inst, dumpFile).enrich(report);
            } catch (Throwable t) {
                report.add(com.memshellauditor.report.Finding.low("N/A", "Forensics", null, null, "取证分析异常: " + t, null));
            }
        } else {
            System.out.println("[memshell-auditor] 未指定 dump 目录，跳过类级取证（使用 --dump <dir> 启用）");
        }

        // ===== 跨平台内存取证（jmap heap dump） =====
        String hprofPath = null;
        if (heapDir != null) {
            try {
                hprofPath = com.memshellauditor.dump.MemoryForensics.heapDump((int) report.getPid(), new File(heapDir));
                if (hprofPath != null) {
                    String scan = com.memshellauditor.dump.MemoryForensics.quickScan(hprofPath);
                    report.add(com.memshellauditor.report.Finding.info("Memory", "堆内存取证完成: " + hprofPath
                            + (scan != null ? " | " + scan.replace("\n", " ") : "")));
                }
            } catch (Throwable t) {
                report.add(com.memshellauditor.report.Finding.low("N/A", "Memory", null, null, "内存取证异常: " + t, null));
            }
        }

        // ===== AI 增强分析（仅在主程序，取证端不含 AI 能力） =====
        // 反射调用 ai 模块：混淆取证端打包时排除 ai/ 类，此处优雅降级为本地规则分析
        String aiAnalysis = null;
        try {
            Class<?> aiAnalyzerCls = Class.forName("com.memshellauditor.ai.AiAnalyzer");
            Class<?> aiClientCls = Class.forName("com.memshellauditor.ai.AiClient");
            Object client = aiClientCls.getConstructor().newInstance();
            if (aiConfig != null && !aiConfig.isEmpty()) {
                java.lang.reflect.Method fromCfg = aiClientCls.getMethod("fromConfigFile", String.class);
                client = fromCfg.invoke(null, aiConfig);
            }
            java.lang.reflect.Method analyze = aiAnalyzerCls.getMethod("analyze",
                    Report.class, File.class, boolean.class);
            aiAnalysis = (String) analyze.invoke(aiAnalyzerCls.getConstructor().newInstance(),
                    report, dumpFile, false);
            if (aiAnalysis == null || aiAnalysis.isEmpty()) {
                // AI 调用失败/未配置 → 取证端本地规则分析
                aiAnalysis = localRuleAnalysis(report, dumpFile);
            }
        } catch (ClassNotFoundException e) {
            // 取证端（混淆程序）：无 AI 模块，用本地规则分析
            aiAnalysis = localRuleAnalysis(report, dumpFile);
            System.out.println("[memshell-auditor] 取证端模式：本地规则分析（AI 能力仅在主程序）");
        } catch (Throwable t) {
            System.out.println("[memshell-auditor] AI 分析异常: " + t);
        }

        // ===== 输出报告 =====
        String console = report.toConsole();
        String json = report.toJson();
        if (aiAnalysis != null && !aiAnalysis.isEmpty()) {
            json = json.replace("\n}", "\n  ,\"aiAnalysis\": \"" + jsonEscape(aiAnalysis) + "\"\n}");
        }
        System.out.println(console);
        if (aiAnalysis != null && !aiAnalysis.isEmpty()) {
            System.out.println("===== AI/本地分析结果 =====");
            System.out.println(aiAnalysis);
        }

        if (outPath != null) {
            try {
                File f = new File(outPath);
                File parent = f.getParentFile();
                if (parent != null) parent.mkdirs();
                PrintWriter pw = new PrintWriter(new OutputStreamWriter(new FileOutputStream(f), "UTF-8"));
                pw.print(json);
                pw.flush();
                pw.close();
                System.out.println("[memshell-auditor] report written to " + f.getAbsolutePath());
            } catch (Throwable t) {
                System.out.println("[memshell-auditor] failed to write report: " + t);
            }
        }
    }


    /** 实时类检查：字节码字符串特征（命令执行/解密/回连/容器） */
    private static boolean checkLiveClass(String name, byte[] bytes, ClassLoader loader) {
        if (bytes == null || bytes.length < 100) return false;
        // 字节码 → 可读字符串（常量池 utf8 近似提取）
        String s = new String(bytes, java.nio.charset.StandardCharsets.ISO_8859_1);
        // 恶意行为特征
        int score = 0;
        if (s.contains("Runtime") && s.contains("exec")) score++;
        if (s.contains("ProcessBuilder")) score++;
        if (s.contains("defineClass") || s.contains("ClassLoader")) score++;
        if (s.contains("Base64") || s.contains("Cipher") || s.contains("AES")) score++;
        if (s.contains("Socket") || s.contains("URLConnection")) score++;
        if (s.contains("getParameter") || s.contains("getHeader")) score++;
        // 容器组件特征
        boolean container = s.contains("Filter") || s.contains("Servlet")
                || s.contains("Listener") || s.contains("Valve");
        return container && score >= 2;
    }
        File dumpFile = null;
    private static Map<String, String> parseArgs(String args) {
        Map<String, String> map = new HashMap<String, String>();
        if (args == null || args.isEmpty()) return map;
        for (String kv : args.trim().split(",")) {
            int eq = kv.indexOf('=');
            if (eq > 0) {
                map.put(kv.substring(0, eq).trim(), kv.substring(eq + 1).trim());
            }
        }
        return map;
    }

    /**
     * 取证端本地规则匹配分析（内置在取证程序，离线可用，不依赖 AI）：
     * 基于检测报告 findings 的规则引擎：高危命中 → 处置建议；辅助信号 → 复核提示。
     * 与主程序 AI 分析互补：取证现场先出规则结论，分析者机器上再 AI 增强。
     */
    private static String localRuleAnalysis(Report report, File dumpDir) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== 取证端规则匹配分析 ===\n");
        int high = 0, medium = 0;
        for (com.memshellauditor.report.Finding f : report.getFindings()) {
            if (f.level == com.memshellauditor.report.Finding.Level.HIGH) high++;
            if (f.level == com.memshellauditor.report.Finding.Level.MEDIUM) medium++;
        }
        sb.append("规则统计: HIGH=").append(high).append(" MEDIUM=").append(medium).append("\n\n");
        for (com.memshellauditor.report.Finding f : report.getFindings()) {
            if (f.level == com.memshellauditor.report.Finding.Level.HIGH) {
                sb.append("⚠️ 高危: [").append(f.category).append("] ")
                  .append(f.className == null ? "" : f.className).append("\n");
                sb.append("   判定: ").append(f.reason == null ? "" : f.reason).append("\n");
                if (f.signal != null && !f.signal.equals("N/A")) {
                    sb.append("   信号: ").append(f.signal).append(" → 强信号，按内存马处置\n");
                }
                if (f.callbackIps != null && !f.callbackIps.isEmpty()) {
                    sb.append("   回连: ").append(f.callbackIps).append("\n");
                }
                if (f.dumpPath != null && !f.dumpPath.isEmpty()) {
                    sb.append("   已dump: ").append(f.dumpPath).append("（带回分析端反编译）\n");
                }
                sb.append("   处置: 隔离主机 → 断网 → 保全证据 → 排查注入入口 → 修复重启\n");
            } else if (f.level == com.memshellauditor.report.Finding.Level.MEDIUM) {
                sb.append("⚠️ 中危: [").append(f.category).append("] ")
                  .append(f.className == null ? "" : f.className).append("\n");
                sb.append("   判定: ").append(f.reason == null ? "" : f.reason).append("\n");
                sb.append("   建议: 人工复核确认，配合基线比对\n");
            }
        }
        if (high == 0 && medium == 0) {
            sb.append("未命中高危/中危规则，疑似干净。\n");
        }
        sb.append("\n提示: 本报告可带回分析端执行 java -jar memshell-auditor.jar --analyze <report.json> --ai-config ai.json 进行 AI 增强分析。\n");
        return sb.toString();
    }

    private static String jsonEscape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }
}
