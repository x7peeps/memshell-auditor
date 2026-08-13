package com.memshellauditor.detect;

import com.memshellauditor.report.Finding;
import com.memshellauditor.report.Report;
import com.memshellauditor.util.ReflectUtil;

import java.lang.instrument.Instrumentation;
import java.util.Map;

/**
 * Agent 型内存马审计器（市场空白点）：
 *  1. 启动参数审计：-javaagent / -agentlib / JAVA_TOOL_OPTIONS / JDK_JAVA_OPTIONS
 *  2. Instrumentation 已加载类审计：寻找可疑的 Agent 特征类
 *  3. Transformer 间接审计：Agent 型内存马必然携带可观察的类特征
 *
 * 说明：JDK 标准 API 无法直接枚举已注册的 ClassFileTransformer（JVMTI 层不开放），
 * 因此通过"启动链 + 已加载类特征 + 动态代理/字节码生成器特征"组合间接检测。
 */
public class AgentAuditor {

    private static final String[] AGENT_FLAG_PREFIXES = {
            "-javaagent:", "-agentlib:", "-agentpath:"
    };

    private static final String[] SUSPICIOUS_AGENT_KEYWORDS = {
            "memshell", "webshell", "shell", "behinder", "godzilla",
            "inject", "payload", "backdoor", "trojan"
    };

    public void audit(Instrumentation inst, Report report) {
        auditStartupParams(report);
        auditSystemProps(report);
        auditLoadedAgentClasses(inst, report);
    }

    /** 审计启动参数链（运行时参数 + 环境变量注入） */
    private void auditStartupParams(Report report) {
        // 1. JVM 运行时参数（含 -javaagent）
        String vmArgs = System.getProperty("sun.java.command");
        if (vmArgs == null) vmArgs = "";
        boolean foundAgent = false;
        for (String flag : AGENT_FLAG_PREFIXES) {
            if (vmArgs.contains(flag)) {
                report.add(Finding.high("A4", "Agent", null, null,
                        "JVM 启动参数包含 Agent 加载项: " + extractFlag(vmArgs, flag),
                        "核对启动脚本/容器配置是否业务需要"));
                foundAgent = true;
            }
        }
        if (!foundAgent && !vmArgs.isEmpty()) {
            report.add(Finding.info("Agent", "启动参数未发现 -javaagent/-agentlib，sun.java.command=" + truncate(vmArgs, 160)));
        }

        // 2. 环境变量注入（攻击者常用 JAVA_TOOL_OPTIONS 无感注入）
        String[] envVars = {"JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"};
        for (String ev : envVars) {
            String val = getEnv(ev);
            if (val != null && !val.isEmpty()) {
                boolean suspicious = false;
                for (String flag : AGENT_FLAG_PREFIXES) {
                    if (val.contains(flag)) suspicious = true;
                }
                if (suspicious) {
                    report.add(Finding.high("A4", "Agent", null, null,
                            "环境变量 " + ev + " 被注入 Agent 加载项: " + truncate(val, 200),
                            "echo $" + ev + " ; 检查是否被篡改（持久化排查: /etc/profile, systemd, crontab）"));
                } else {
                    report.add(Finding.low("N/A", "Agent", null, null,
                            "环境变量 " + ev + " 存在（未含 agent 标志）: " + truncate(val, 120),
                            null));
                }
            }
        }

        // 3. java.class.path 审计（污染 jar 特征）
        String cp = System.getProperty("java.class.path");
        if (cp != null && !cp.isEmpty()) {
            String[] parts = cp.split(System.getProperty("path.separator"));
            for (String p : parts) {
                if (p == null || p.isEmpty()) continue;
                String lower = p.toLowerCase();
                if (lower.contains("shell") || lower.contains("behinder") || lower.contains("godzilla")
                        || lower.contains("backdoor") || lower.contains("payload")) {
                    report.add(Finding.high("A4", "Agent", null, null,
                            "classpath 包含可疑条目: " + p,
                            "核对 " + p + " 是否业务依赖"));
                }
            }
        }
    }

    /** 审计系统属性（-D 注入 / agent 修改） */
    private void auditSystemProps(Report report) {
        String agent = System.getProperty("javaagent");
        if (agent != null && !agent.isEmpty()) {
            report.add(Finding.medium("A4", "Agent", null, null,
                    "系统属性 javaagent=" + agent + "（非标准属性名，可疑）", null));
        }
        // 常见内存马会在系统属性中留下标记
        String vendor = System.getProperty("java.vm.info");
        if (vendor != null && vendor.toLowerCase().contains("inject")) {
            report.add(Finding.medium("B2", "Agent", null, null,
                    "java.vm.info 含可疑关键字: " + vendor, null));
        }
    }

    /** 审计已加载类中的 Agent 特征类 */
    private void auditLoadedAgentClasses(Instrumentation inst, Report report) {
        Class<?>[] loaded = inst.getAllLoadedClasses();
        if (loaded == null || loaded.length == 0) {
            report.add(Finding.info("Agent", "getAllLoadedClasses 返回空（可能被安全策略限制）"));
            return;
        }
        int agentLike = 0;
        for (Class<?> cls : loaded) {
            if (cls == null) continue;
            String fullName = cls.getName();
            // 排除自身与数组类
            if (ReflectUtil.isSelfClass(fullName)) continue;
            if (fullName.startsWith("[")) continue;
            String name = fullName.toLowerCase();
            boolean suspicious = false;
            for (String kw : SUSPICIOUS_AGENT_KEYWORDS) {
                if (name.contains(kw)) { suspicious = true; break; }
            }
            if (!suspicious) continue;
            // 排除常见开源组件误报
            if (name.contains("org.apache.catalina") || name.contains("org.springframework")
                    || name.contains("org.apache.tomcat") || name.contains("org.eclipse.jetty")
                    || name.contains("io.undertow") || name.contains("com.thoughtworks.xstream")
                    || name.contains("org.apache.commons") || name.contains("jdk.internal")
                    || name.contains("java.lang") || name.contains("sun.nio") || name.contains("com.sun")) {
                continue;
            }
            agentLike++;
            if (agentLike <= 20) {
                report.add(Finding.medium("B2", "Agent", cls.getName(), loaderOf(cls),
                        "已加载类名含可疑关键字（memshell/webshell/inject 等）",
                        "jad " + cls.getName() + " ; 核对来源 jar"));
            }
        }
        if (agentLike > 20) {
            report.add(Finding.medium("B2", "Agent", null, null,
                    "另有 " + (agentLike - 20) + " 个可疑命名类未逐一列出（建议导出全量类清单比对基线）", null));
        }
        if (agentLike == 0) {
            report.add(Finding.info("Agent", "已加载类中未发现可疑 Agent 特征类"));
        }
    }

    private String extractFlag(String args, String prefix) {
        int i = args.indexOf(prefix);
        if (i < 0) return "";
        int end = args.indexOf(' ', i);
        if (end < 0) end = args.length();
        return args.substring(i, end);
    }

    private String getEnv(String name) {
        try {
            return System.getenv(name);
        } catch (Throwable t) {
            return null;
        }
    }

    private String loaderOf(Class<?> cls) {
        ClassLoader cl = cls.getClassLoader();
        if (cl == null) return "bootstrap";
        String s = cl.toString();
        return s.length() > 160 ? s.substring(0, 160) + "..." : s;
    }

    private String truncate(String s, int n) {
        if (s == null) return "";
        return s.length() > n ? s.substring(0, n) + "..." : s;
    }
}
