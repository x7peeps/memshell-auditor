package com.memshellauditor.detect;

import com.memshellauditor.report.Finding;
import com.memshellauditor.report.Report;
import com.memshellauditor.util.ReflectUtil;

import java.lang.instrument.Instrumentation;
import java.lang.reflect.Field;
import java.util.Map;

/**
 * Agent 型内存马审计器（Transformer 审计）：
 *  检测目标 JVM 中已注册的 ClassFileTransformer 与 Instrumentation 状态。
 *
 * 原理：Agent 型内存马通过 Instrumentation.addTransformer() 注册字节码转换器，
 * 对任意类改写字节码实现后门。JDK 标准 API 不暴露已注册 transformer 列表，
 * 但可通过 sun.instrument.InstrumentationImpl 的 native 字段/内部状态间接审计：
 *  1. transformer 数量异常（正常 JVM 通常 0-3 个：debugger/APM/RASP 等）
 *  2. transformer 类名可疑（恶意 agent 的特征类）
 *  3. Instrumentation 对象被非法获取（通过反射拿 inst 实例）
 */
public class TransformerAuditor {

    private static final String[] SUSPICIOUS_TRANSFORMER_KEYWORDS = {
            "memshell", "webshell", "shell", "behinder", "godzilla",
            "inject", "payload", "backdoor", "trojan", "exploit", "hook"
    };

    public void audit(Instrumentation inst, Report report) {
        auditInstrumentationState(inst, report);
        auditLoadedAgentClasses(inst, report);
        auditInstrumentationRetrieval(report);
    }

    /** 审计 Instrumentation 内部状态（transformer 列表等） */
    private void auditInstrumentationState(Instrumentation inst, Report report) {
        try {
            // 尝试反射读取 sun.instrument.InstrumentationImpl 的 mTransformerList
            Field tfList = findField(inst.getClass(), "mTransformerList");
            if (tfList != null) {
                tfList.setAccessible(true);
                Object list = tfList.get(inst);
                if (list instanceof Iterable) {
                    int count = 0;
                    java.util.List<String> names = new java.util.ArrayList<String>();
                    for (Object o : (Iterable<?>) list) {
                        count++;
                        if (o != null) {
                            names.add(o.getClass().getName());
                        }
                    }
                    if (count == 0) {
                        report.add(Finding.info("Transformer", "未注册任何 ClassFileTransformer（正常）"));
                    } else {
                        // 多于 3 个 transformer 且类名可疑 → 高可疑
                        boolean suspicious = false;
                        StringBuilder sb = new StringBuilder();
                        for (String n : names) {
                            String lower = n.toLowerCase();
                            for (String kw : SUSPICIOUS_TRANSFORMER_KEYWORDS) {
                                if (lower.contains(kw)) {
                                    suspicious = true;
                                    break;
                                }
                            }
                            if (sb.length() > 0) sb.append(", ");
                            sb.append(n);
                        }
                        if (suspicious || count > 8) {
                            report.add(Finding.high("A4", "Transformer", null, null,
                                    "注册了 " + count + " 个 ClassFileTransformer，其中含可疑类名: " + sb,
                                    "核对是否为业务需要的字节码增强（APM/RASP/调试器）"));
                        } else {
                            report.add(Finding.low("A4", "Transformer", null, null,
                                    "注册了 " + count + " 个 ClassFileTransformer: " + sb,
                                    "核对是否为业务需要的字节码增强"));
                        }
                    }
                }
            }
        } catch (Throwable t) {
            // 高版本 JDK 无法访问内部字段，静默降级
            report.add(Finding.info("Transformer", "无法枚举 transformer（JDK 模块限制），改用类特征间接审计"));
        }
    }

    /** 审计已加载类中的可疑 transformer/agent 特征类 */
    private void auditLoadedAgentClasses(Instrumentation inst, Report report) {
        try {
            Class<?>[] loaded = inst.getAllLoadedClasses();
            int suspicious = 0;
            for (Class<?> cls : loaded) {
                if (cls == null) continue;
                String n = cls.getName();
                // 跳过自身与 JDK 类
                if (ReflectUtil.isSelfClass(n)) continue;
                if (n.startsWith("java.") || n.startsWith("javax.") || n.startsWith("jdk.")
                        || n.startsWith("sun.") || n.startsWith("com.sun.")) continue;
                // 实现 ClassFileTransformer 接口的类
                if (!ReflectUtil.implementsInterface(cls, "java.lang.instrument.ClassFileTransformer")) continue;
                String lower = n.toLowerCase();
                boolean bad = false;
                for (String kw : SUSPICIOUS_TRANSFORMER_KEYWORDS) {
                    if (lower.contains(kw)) { bad = true; break; }
                }
                if (bad) {
                    suspicious++;
                    if (suspicious <= 10) {
                        report.add(Finding.high("A4", "Transformer", n, loaderDesc(cls),
                                "已加载类实现 ClassFileTransformer 且类名含可疑关键字，疑似 Agent 型内存马",
                                "jad " + n + " ; 核对来源"));
                    }
                }
            }
            if (suspicious == 0) {
                report.add(Finding.info("Transformer", "已加载类中未发现可疑 ClassFileTransformer 实现"));
            }
        } catch (Throwable t) {
            // ignore
        }
    }

    /** 审计 Instrumentation 实例是否被非法获取（通过反射/静态字段） */
    private void auditInstrumentationRetrieval(Report report) {
        try {
            // 检查系统属性是否有 javaagent 痕迹
            String javaagent = System.getProperty("javaagent");
            if (javaagent != null && !javaagent.isEmpty()) {
                report.add(Finding.high("A4", "Transformer", null, null,
                        "系统属性 javaagent=" + javaagent + "（非标准属性，Agent 注入痕迹）",
                        "核对启动脚本"));
            }
            // 检查 -javaagent 启动参数
            String cmd = System.getProperty("sun.java.command", "");
            if (cmd != null && cmd.contains("-javaagent")) {
                report.add(Finding.high("A4", "Transformer", null, null,
                        "启动命令包含 -javaagent（Agent 预挂载）: " + cmd,
                        "核对是否为业务 agent"));
            }
        } catch (Throwable t) {
            // ignore
        }
    }

    private static Field findField(Class<?> cls, String name) {
        Class<?> c = cls;
        while (c != null && c != Object.class) {
            try {
                Field f = c.getDeclaredField(name);
                return f;
            } catch (NoSuchFieldException ignored) {
            }
            c = c.getSuperclass();
        }
        return null;
    }

    private String loaderDesc(Class<?> cls) {
        ClassLoader cl = cls.getClassLoader();
        if (cl == null) return "bootstrap";
        String s = cl.toString();
        return s.length() > 160 ? s.substring(0, 160) + "..." : s;
    }
}
