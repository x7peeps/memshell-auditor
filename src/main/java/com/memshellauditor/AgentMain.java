package com.memshellauditor;

import com.memshellauditor.detect.AgentAuditor;
import com.memshellauditor.detect.ClassFeatureAuditor;
import com.memshellauditor.detect.ClassLoaderAuditor;
import com.memshellauditor.detect.ContainerAuditor;
import com.memshellauditor.report.Report;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.lang.instrument.Instrumentation;

/**
 * Java Agent 入口（premain / agentmain 双支持）。
 *
 * agentmain: attach 时被 JVM 调用，执行内存马审计，输出报告。
 *   args 格式: [output=</path/to/report.json>] 或直接传输出路径
 * premain : 启动时 -javaagent 挂载，用于事前巡检（配合基线）。
 *
 * 无第三方依赖，JDK 8 编译，可在 JDK 8-21 目标 JVM 上运行。
 */
public class AgentMain {

    public static void premain(String args, Instrumentation inst) {
        run(args, inst, true);
    }

    public static void agentmain(String args, Instrumentation inst) {
        run(args, inst, false);
    }

    private static void run(String args, Instrumentation inst, boolean premain) {
        String outPath = parseOutPath(args);
        Report report = new Report();
        report.begin();
        report.setTargetDesc(System.getProperty("user.dir", "?") + " / " + System.getProperty("sun.java.command", "?"));
        try {
            report.setPid(Long.parseLong(System.getProperty("memshell.pid", "-1")));
        } catch (Throwable t) {
            report.setPid(-1);
        }
        report.setJavaVersion(System.getProperty("java.version", "?"));

        // 核心审计
        try {
            new ContainerAuditor().audit(inst, report);
        } catch (Throwable t) {
            report.add(com.memshellauditor.report.Finding.low("N/A", "Container", null, null,
                    "容器审计异常: " + t, null));
        }
        try {
            new AgentAuditor().audit(inst, report);
        } catch (Throwable t) {
            report.add(com.memshellauditor.report.Finding.low("N/A", "Agent", null, null,
                    "Agent 审计异常: " + t, null));
        }
        try {
            new ClassLoaderAuditor().audit(inst, report);
        } catch (Throwable t) {
            report.add(com.memshellauditor.report.Finding.low("N/A", "ClassLoader", null, null,
                    "ClassLoader 审计异常: " + t, null));
        }
        try {
            new ClassFeatureAuditor().audit(inst, report);
        } catch (Throwable t) {
            report.add(com.memshellauditor.report.Finding.low("N/A", "ClassFeature", null, null,
                    "类特征审计异常: " + t, null));
        }

        String console = report.toConsole();
        String json = report.toJson();
        System.out.println(console);

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

    private static String parseOutPath(String args) {
        if (args == null || args.isEmpty()) return null;
        String a = args.trim();
        if (a.startsWith("output=")) {
            // 同时解析 pid= 参数（agent 内无法读宿主 pid，需 CLI 传入）
            String out = null;
            for (String kv : a.split(",")) {
                if (kv.startsWith("pid=")) {
                    try {
                        long p = Long.parseLong(kv.substring(4).trim());
                        System.setProperty("memshell.pid", String.valueOf(p));
                    } catch (Throwable ignored) {
                    }
                } else if (kv.startsWith("output=")) {
                    out = kv.substring("output=".length()).trim();
                }
            }
            return out;
        }
        // 直接传路径（兼容）
        if (a.endsWith(".json") || a.endsWith(".log")) return a;
        return null;
    }
}
