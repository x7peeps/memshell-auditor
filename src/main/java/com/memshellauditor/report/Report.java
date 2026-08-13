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

    public long getPid() {
        return pid;
    }

    public String getTargetDesc() {
        return targetDesc;
    }

    public String getJavaVersion() {
        return javaVersion;
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
            if (f.dumpPath != null && !f.dumpPath.isEmpty()) {
                sb.append("     Dump : ").append(f.dumpPath).append('\n');
            }
            if (f.callbackIps != null && !f.callbackIps.isEmpty()) {
                sb.append("     回连 : ").append(f.callbackIps).append('\n');
            }
            if (f.coreCode != null && !f.coreCode.isEmpty()) {
                sb.append("     核心代码片段:\n");
                for (String line : f.coreCode.split("\n")) {
                    sb.append("       ").append(line).append('\n');
                }
            }
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

    /** 从 JSON 报告重建 Report 对象（用于 --analyze 分析取证报告） */
    public static Report fromJson(String json) {
        Report report = new Report();
        report.begin();
        try {
            // 极简解析：提取顶层字段
            report.pid = parseLongField(json, "\"pid\"");
            report.targetDesc = parseStringField(json, "\"target\"");
            report.javaVersion = parseStringField(json, "\"javaVersion\"");
            // 解析 findings 数组
            String findingsSection = extractArray(json, "\"findings\"");
            if (findingsSection != null) {
                // 按对象切分（简易：寻找 {"level" 开头）
                int idx = 0;
                while (true) {
                    int start = findingsSection.indexOf("{\"level\"", idx);
                    if (start < 0) break;
                    // 找到对象结束（配对大括号）
                    int end = findJsonObjectEnd(findingsSection, start);
                    if (end < 0) break;
                    String obj = findingsSection.substring(start, end + 1);
                    Finding f = parseFinding(obj);
                    if (f != null) report.add(f);
                    idx = end + 1;
                }
            }
        } catch (Throwable t) {
            // ignore, 返回部分解析结果
        }
        return report;
    }

    private static Finding parseFinding(String obj) {
        try {
            String level = parseStringField(obj, "\"level\"");
            String signal = parseStringField(obj, "\"signal\"");
            String category = parseStringField(obj, "\"category\"");
            String className = parseStringField(obj, "\"className\"");
            String classLoader = parseStringField(obj, "\"classLoader\"");
            String reason = parseStringField(obj, "\"reason\"");
            String evidence = parseStringField(obj, "\"evidence\"");
            String dumpPath = parseStringField(obj, "\"dumpPath\"");
            String callbackIps = parseStringField(obj, "\"callbackIps\"");
            Finding.Level lv;
            try {
                lv = Finding.Level.valueOf(level);
            } catch (Throwable t) {
                lv = Finding.Level.INFO;
            }
            Finding f = new Finding(lv, signal, category, className, classLoader, reason, evidence);
            f.dumpPath = dumpPath;
            f.callbackIps = callbackIps;
            return f;
        } catch (Throwable t) {
            return null;
        }
    }

    private static String parseStringField(String json, String key) {
        try {
            String pattern = key + "\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"";
            java.util.regex.Matcher m = java.util.regex.Pattern.compile(pattern).matcher(json);
            if (m.find()) {
                return m.group(1).replace("\\\"", "\"").replace("\\\\", "\\");
            }
        } catch (Throwable ignored) {}
        return null;
    }

    private static long parseLongField(String json, String key) {
        try {
            String pattern = key + "\\s*:\\s*(\\d+)";
            java.util.regex.Matcher m = java.util.regex.Pattern.compile(pattern).matcher(json);
            if (m.find()) return Long.parseLong(m.group(1));
        } catch (Throwable ignored) {}
        return -1;
    }

    private static String extractArray(String json, String key) {
        try {
            int idx = json.indexOf(key);
            if (idx < 0) return null;
            int bracket = json.indexOf('[', idx);
            if (bracket < 0) return null;
            int end = findJsonArrayEnd(json, bracket);
            if (end < 0) return null;
            return json.substring(bracket + 1, end);
        } catch (Throwable t) {
            return null;
        }
    }

    private static int findJsonObjectEnd(String s, int start) {
        int depth = 0;
        boolean inStr = false;
        for (int i = start; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inStr) {
                if (c == '\\') { i++; continue; }
                if (c == '"') inStr = false;
            } else {
                if (c == '"') inStr = true;
                else if (c == '{') depth++;
                else if (c == '}') {
                    depth--;
                    if (depth == 0) return i;
                }
            }
        }
        return -1;
    }

    private static int findJsonArrayEnd(String s, int start) {
        int depth = 0;
        boolean inStr = false;
        for (int i = start; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inStr) {
                if (c == '\\') { i++; continue; }
                if (c == '"') inStr = false;
            } else {
                if (c == '"') inStr = true;
                else if (c == '[') depth++;
                else if (c == ']') {
                    depth--;
                    if (depth == 0) return i;
                }
            }
        }
        return -1;
    }

    private static String jsonEsc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
