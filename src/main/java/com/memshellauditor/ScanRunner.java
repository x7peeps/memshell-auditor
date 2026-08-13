package com.memshellauditor;

import java.io.File;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/**
 * 全自动扫描编排（--scan 模式）：
 *  枚举所有 Java 进程 → 可疑度排序 → 逐个 attach 审计 → 汇总可疑进程排行。
 *
 * 现场取证人员无需知道 PID，一条命令扫描全部：
 *   java -jar memshell-auditor.jar --scan [--dump dir] [--heap dir] [--ai-config file] [--max-jvms N]
 */
public class ScanRunner {

    /**
     * 执行全量扫描。
     * @param agentJar 当前 agent jar
     * @param opts CLI 选项
     */
    public static void scan(File agentJar, java.util.Map<String, String> opts) throws Exception {
        List<JvmScanner.JvmInfo> jvms = JvmScanner.listJvms();
        // 打分排序
        for (JvmScanner.JvmInfo j : jvms) JvmScanner.score(j);
        JvmScanner.sortByScore(jvms);

        System.out.println("[*] 发现 " + jvms.size() + " 个 Java 进程，按可疑度排序：");
        System.out.println("------------------------------------------");
        for (int i = 0; i < jvms.size(); i++) {
            JvmScanner.JvmInfo j = jvms.get(i);
            String scoreTag = j.score >= 80 ? "⚠️ 高优先" : (j.score >= 40 ? "  中优先" : "  低优先");
            System.out.printf("  [%02d] %s PID %-8s %s%n", i + 1, scoreTag, j.id,
                    truncate(j.displayName, 90));
            if (j.reasons != null && j.reasons.length > 0) {
                System.out.println("        特征: " + String.join(", ", j.reasons));
            }
        }
        System.out.println("------------------------------------------");

        // 过滤：跳过自身与低优先工具进程
        List<JvmScanner.JvmInfo> targets = new ArrayList<JvmScanner.JvmInfo>();
        for (JvmScanner.JvmInfo j : jvms) {
            if (j.score <= -100) continue;          // 自身
            if (j.score < 0) continue;              // 工具/守护
            targets.add(j);
        }

        int max = 10;
        String maxOpt = opts.get("--max-jvms");
        if (maxOpt != null) {
            try { max = Integer.parseInt(maxOpt); } catch (Throwable t) { max = 10; }
        }
        if (targets.size() > max) {
            System.out.println("[*] 目标过多，仅审计前 " + max + " 个（--max-jvms 调整）");
            targets = targets.subList(0, max);
        }

        if (targets.isEmpty()) {
            System.out.println("[*] 无可审计的 Java 业务进程（或仅剩工具/守护进程）");
            return;
        }

        // 汇总统计
        List<String[]> summary = new ArrayList<String[]>();
        for (JvmScanner.JvmInfo j : targets) {
            String pid = j.id;
            String reportPath = opts.get("--report");
            String dumpDir = opts.get("--dump");
            String heapDir = opts.get("--heap");
            String aiConfig = opts.get("--ai-config");
            System.out.println();
            System.out.println("========== 审计 PID " + pid + " ==========");
            System.out.println("目标: " + truncate(j.displayName, 100));
            try {
                String out = "memshell-auditor-scan-" + pid + ".json";
                if (reportPath != null && !reportPath.isEmpty()) {
                    File rf = new File(reportPath);
                    if (rf.isDirectory()) out = new File(rf, out).getAbsolutePath();
                }
                int high = attachAndAudit(pid, agentJar, out, dumpDir, heapDir, aiConfig);
                summary.add(new String[]{pid, j.displayName, String.valueOf(high)});
            } catch (Throwable t) {
                System.out.println("[!] 审计 PID " + pid + " 失败: " + t.getMessage());
            }
        }

        // 汇总排行
        System.out.println();
        System.out.println("==========================================");
        System.out.println(" 扫描汇总（按检出 HIGH 数排序）");
        System.out.println("==========================================");
        summary.sort((a, b) -> Integer.compare(Integer.parseInt(b[2]), Integer.parseInt(a[2])));
        boolean anyHigh = false;
        for (String[] row : summary) {
            int high = Integer.parseInt(row[2]);
            String tag = high > 0 ? "⚠️ 检出高危" : "  正常";
            System.out.printf("  %s PID %-8s HIGH=%d  %s%n", tag, row[0], high, truncate(row[1], 80));
            if (high > 0) anyHigh = true;
        }
        if (!anyHigh) {
            System.out.println("  未发现高危内存马迹象（建议人工复核 MEDIUM 项）");
        }
    }

    /**
     * attach 到单个 JVM 执行审计，返回 HIGH 数。
     */
    private static int attachAndAudit(String pid, File agentJar, String outPath,
                                      String dumpDir, String heapDir, String aiConfig) throws Exception {
        Class<?> vmClass = Class.forName("com.sun.tools.attach.VirtualMachine");
        Method attach = vmClass.getMethod("attach", String.class);
        Object vm = null;
        try {
            vm = attach.invoke(null, pid);
            StringBuilder agentArgs = new StringBuilder();
            agentArgs.append("output=").append(new File(outPath).getAbsolutePath());
            agentArgs.append(",pid=").append(pid);
            if (dumpDir != null && !dumpDir.isEmpty()) {
                agentArgs.append(",dump=").append(new File(dumpDir).getAbsolutePath());
            }
            if (heapDir != null && !heapDir.isEmpty()) {
                agentArgs.append(",heap=").append(new File(heapDir).getAbsolutePath());
            }
            if (aiConfig != null && !aiConfig.isEmpty()) {
                agentArgs.append(",ai=").append(new File(aiConfig).getAbsolutePath());
            }
            Method loadAgent = vmClass.getMethod("loadAgent", String.class, String.class);
            loadAgent.invoke(vm, agentJar.getAbsolutePath(), agentArgs.toString());
        } finally {
            if (vm != null) {
                try {
                    Method detach = vmClass.getMethod("detach");
                    detach.invoke(vm);
                } catch (Throwable ignored) {}
            }
        }
        // 读取报告统计 HIGH
        int high = 0;
        try {
            File f = new File(outPath);
            if (f.exists()) {
                String content = new String(java.nio.file.Files.readAllBytes(f.toPath()), "UTF-8");
                int idx = content.indexOf("\"HIGH\":");
                if (idx >= 0) {
                    int start = idx + 7;
                    int end = content.indexOf(',', start);
                    if (end < 0) end = content.indexOf('}', start);
                    if (end > start) {
                        high = Integer.parseInt(content.substring(start, end).trim());
                    }
                }
                System.out.println("  → 报告: " + f.getAbsolutePath() + " (HIGH=" + high + ")");
            }
        } catch (Throwable t) {
            // ignore
        }
        return high;
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
