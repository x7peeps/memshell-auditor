package com.memshellauditor.report;

import java.util.ArrayList;
import java.util.List;

/**
 * 审计报告：收集全部 Finding，提供统计与输出。
 */
public class Report {
    private final List<Finding> findings = new ArrayList<Finding>();
    private long pid = -1;
    private String targetDesc = "";
    private String javaVersion = "";
    private long startNanos;

    public void begin() {
        startNanos = System.nanoTime();
    }

    public void setPid(long pid) {
        this.pid = pid;
    }

    public void setTargetDesc(String d) {
        this.targetDesc = d;
    }

    public void setJavaVersion(String v) {
        this.javaVersion = v;
    }

    public void add(Finding f) {
        if (f != null) findings.add(f);
    }

    public void addAll(List<Finding> fs) {
        if (fs != null) findings.addAll(fs);
    }

    public List<Finding> getFindings() {
        return findings;
    }

    public int count(Finding.Level l) {
        int n = 0;
        for (Finding f : findings) if (f.level == l) n++;
        return n;
    }

    /** 控制台人类可读输出 */
    public String toConsole() {
        StringBuilder sb = new StringBuilder();
        sb.append("==========================================\n");
        sb.append(" memshell-auditor 审计报告\n");
        sb.append("==========================================\n");
        sb.append("目标: ").append(targetDesc).append('\n');
        sb.append("PID : ").append(pid).append('\n');
        sb.append("JVM : ").append(javaVersion).append('\n');
        sb.append("------------------------------------------\n");
        int i = 1;
        for (Finding f : findings) {
            sb.append(String.format("[%02d] [%-6s] %s\n", i++, f.level, f.category));
            if (f.signal != null && !f.signal.equals("N/A")) {
                sb.append("     信号: ").append(f.signal).append('\n');
            }
            if (f.className != null) sb.append("     类  : ").append(f.className).append('\n');
            if (f.classLoader != null) sb.append("     Loader: ").append(f.classLoader).append('\n');
            sb.append("     原因: ").append(f.reason).append('\n');
            if (f.evidence != null && !f.evidence.isEmpty()) {
                sb.append("     证据: ").append(f.evidence).append('\n');
            }
            sb.append('\n');
        }
        sb.append("------------------------------------------\n");
        sb.append("汇总: HIGH=").append(count(Finding.Level.HIGH))
          .append(" MEDIUM=").append(count(Finding.Level.MEDIUM))
          .append(" LOW=").append(count(Finding.Level.LOW))
          .append(" INFO=").append(count(Finding.Level.INFO))
          .append(" 总计=").append(findings.size()).append('\n');
        long ms = (System.nanoTime() - startNanos) / 1000000L;
        sb.append("耗时: ").append(ms).append(" ms\n");
        return sb.toString();
    }

    /** 全量 JSON 输出（零依赖） */
    public String toJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"tool\": \"memshell-auditor\",\n");
        sb.append("  \"version\": \"1.0.0\",\n");
        sb.append("  \"pid\": ").append(pid).append(",\n");
        sb.append("  \"target\": \"").append(jsonEsc(targetDesc)).append("\",\n");
        sb.append("  \"javaVersion\": \"").append(jsonEsc(javaVersion)).append("\",\n");
        sb.append("  \"summary\": {");
        sb.append("\"HIGH\": ").append(count(Finding.Level.HIGH));
        sb.append(", \"MEDIUM\": ").append(count(Finding.Level.MEDIUM));
        sb.append(", \"LOW\": ").append(count(Finding.Level.LOW));
        sb.append(", \"INFO\": ").append(count(Finding.Level.INFO));
        sb.append(", \"total\": ").append(findings.size());
        sb.append("},\n");
        sb.append("  \"findings\": [\n");
        for (int i = 0; i < findings.size(); i++) {
            sb.append("    ").append(findings.get(i).toJson());
            sb.append(i < findings.size() - 1 ? ",\n" : "\n");
        }
        sb.append("  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    private static String jsonEsc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
