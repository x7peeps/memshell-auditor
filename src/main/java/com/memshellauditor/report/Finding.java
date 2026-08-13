package com.memshellauditor.report;

/**
 * 单个发现项（Finding）
 *
 * level:  HIGH / MEDIUM / LOW / INFO
 * signal: 对应判断标准编号（A1-A5 强信号 / B1-B5 辅助信号），无则 N/A
 * category: 组件类别（Filter/Servlet/Listener/Valve/Agent/ClassLoader/ClassFeature...）
 */
public class Finding {
    public enum Level { HIGH, MEDIUM, LOW, INFO }

    public Level level;
    public String signal;       // A1..B5 / N/A
    public String category;
    public String className;    // 涉及的类名（可为空）
    public String classLoader;  // 所属 ClassLoader 描述（可为空）
    public String reason;       // 判定原因（人类可读）
    public String evidence;     // 证据/命令参考（可为空）

    public Finding(Level level, String signal, String category, String className,
                   String classLoader, String reason, String evidence) {
        this.level = level;
        this.signal = signal;
        this.category = category;
        this.className = className;
        this.classLoader = classLoader;
        this.reason = reason;
        this.evidence = evidence;
    }

    public static Finding high(String signal, String category, String className,
                               String classLoader, String reason, String evidence) {
        return new Finding(Level.HIGH, signal, category, className, classLoader, reason, evidence);
    }

    public static Finding medium(String signal, String category, String className,
                                 String classLoader, String reason, String evidence) {
        return new Finding(Level.MEDIUM, signal, category, className, classLoader, reason, evidence);
    }

    public static Finding low(String signal, String category, String className,
                              String classLoader, String reason, String evidence) {
        return new Finding(Level.LOW, signal, category, className, classLoader, reason, evidence);
    }

    public static Finding info(String category, String reason) {
        return new Finding(Level.INFO, "N/A", category, null, null, reason, null);
    }

    /** 简易 JSON 序列化（零依赖） */
    public String toJson() {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        sb.append("\"level\":\"").append(level).append('"');
        sb.append(",\"signal\":\"").append(signal == null ? "N/A" : signal).append('"');
        sb.append(",\"category\":\"").append(jsonEsc(category)).append('"');
        sb.append(",\"className\":\"").append(jsonEsc(className)).append('"');
        sb.append(",\"classLoader\":\"").append(jsonEsc(classLoader)).append('"');
        sb.append(",\"reason\":\"").append(jsonEsc(reason)).append('"');
        sb.append(",\"evidence\":\"").append(jsonEsc(evidence)).append('"');
        sb.append('}');
        return sb.toString();
    }

    private static String jsonEsc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")
                .replace("\r", "\\r").replace("\t", "\\t");
    }
}
