package com.memshellauditor.detect;

import com.memshellauditor.report.Finding;
import com.memshellauditor.report.Report;
import com.memshellauditor.util.ReflectUtil;

import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.util.regex.Pattern;

/**
 * 类特征审计器（B1 信号）：
 *  遍历已加载类，检测可疑类名特征（无包名 / 短随机名 / 混淆名 / 恶意关键字），
 *  并对实现容器接口（Filter/Servlet/Listener）的可疑类重点标记。
 */
public class ClassFeatureAuditor {

    private static final Pattern SHORT_RANDOM = Pattern.compile("^[a-z0-9]{1,6}$");
    private static final Pattern MIXED_RANDOM = Pattern.compile("^[A-Za-z0-9]{8,32}$");

    private static final String[] MALICIOUS_KEYWORDS = {
            "memshell", "webshell", "behinder", "godzilla", "suo5", "yso",
            "payload", "inject", "backdoor", "trojan", "exploit"
    };

    private static final int MAX_LISTED = 20;

    public void audit(Instrumentation inst, Report report) {
        Class<?>[] loaded = inst.getAllLoadedClasses();
        if (loaded == null) return;

        int total = 0;
        int suspicious = 0;
        for (Class<?> cls : loaded) {
            if (cls == null) continue;
            String name = cls.getName();
            // 跳过数组类、JDK/框架正常类、自身
            if (name.startsWith("[")) continue;
            if (isBenignPackage(name)) continue;
            if (name.startsWith("com.memshellauditor.")) continue; // 自身
            total++;
            // A1 强信号：非系统 Loader 加载 + 磁盘无对应 class 文件 = defineClass 动态注入
            ClassLoader cl = cls.getClassLoader();
            if (cl != null && !ReflectUtil.isSystemClassLoader(cl) && !classExistsOnDisk(name, cl)) {
                suspicious++;
                if (suspicious <= MAX_LISTED) {
                    report.add(Finding.high("A1", "ClassFeature", name, loaderOf(cls),
                            "类由非系统 ClassLoader 动态加载且磁盘无对应 class 文件（defineClass 注入特征），高度疑似内存马",
                            "jad " + name + " ; arthas: classloader -c <hash> -r"));
                }
                continue;
            }
            int score = scoreClass(name);
            if (score <= 0) continue;
            suspicious++;
            if (suspicious <= MAX_LISTED) {
                String reason = describe(score, name);
                report.add(Finding.medium("B1", "ClassFeature", name, loaderOf(cls),
                        reason,
                        "jad " + name + " ; 核对来源（arthas: classloader -c <hash> -r）"));
            }
        }
        if (suspicious == 0) {
            report.add(Finding.info("ClassFeature", "已加载类中未发现可疑类名特征（扫描 " + total + " 个业务类）"));
        } else if (suspicious > MAX_LISTED) {
            report.add(Finding.medium("B1", "ClassFeature", null, null,
                    "另有 " + (suspicious - MAX_LISTED) + " 个可疑类未逐一列出，建议导出全量类清单比对基线", null));
        }
    }

    private boolean isBenignPackage(String name) {
        if (name.startsWith("java.") || name.startsWith("javax.") || name.startsWith("jdk.")
                || name.startsWith("sun.") || name.startsWith("com.sun.")) return true;
        if (name.startsWith("org.apache.") || name.startsWith("org.springframework")
                || name.startsWith("org.eclipse.") || name.startsWith("io.undertow")
                || name.startsWith("org.mybatis") || name.startsWith("com.fasterxml")
                || name.startsWith("com.alibaba") || name.startsWith("org.slf4j")
                || name.startsWith("ch.qos.") || name.startsWith("org.jboss")
                || name.startsWith("com.zaxxer") || name.startsWith("org.yaml")
                || name.startsWith("com.mysql") || name.startsWith("org.postgresql")) return true;
        return false;
    }

    /** 打分：>0 可疑 */
    private int scoreClass(String name) {
        int idx = name.lastIndexOf('.');
        String pkg = (idx >= 0) ? name.substring(0, idx) : "";
        String simple = (idx >= 0) ? name.substring(idx + 1) : name;
        String lower = name.toLowerCase();

        // 恶意关键字直接高分
        for (String kw : MALICIOUS_KEYWORDS) {
            if (lower.contains(kw)) return 5;
        }
        // 无包名（顶级类）
        if (pkg.isEmpty() && !name.equals("T")) return 4;
        // 短随机名
        if (SHORT_RANDOM.matcher(simple).matches() && simple.length() >= 2) return 3;
        // 纯数字/混淆长名（8-32 位字母数字，无业务语义）
        if (MIXED_RANDOM.matcher(simple).matches() && simple.length() >= 10) {
            // 需排除正常长类名（含大写驼峰）。纯小写+数字混合且无驼峰分隔 → 可疑
            if (!simple.matches(".*[A-Z].*") && simple.matches(".*[0-9].*")) return 2;
        }
        return 0;
    }

    private String describe(int score, String name) {
        int idx = name.lastIndexOf('.');
        String simple = (idx >= 0) ? name.substring(idx + 1) : name;
        switch (score) {
            case 5: return "类名包含恶意关键字（memshell/webshell/behinder/godzilla 等）";
            case 4: return "类名无包名（顶级类），动态生成类常见特征";
            case 3: return "短随机类名（" + simple + "），疑似动态生成";
            default: return "混淆类名特征（" + simple + "）";
        }
    }

    private String loaderOf(Class<?> cls) {
        ClassLoader cl = cls.getClassLoader();
        if (cl == null) return "bootstrap";
        String s = cl.toString();
        return s.length() > 160 ? s.substring(0, 160) + "..." : s;
    }

    /** 判断类是否在磁盘存在（通过 ClassLoader 资源定位） */
    private boolean classExistsOnDisk(String className, ClassLoader loader) {
        if (className == null) return false;
        String path = className.replace('.', '/') + ".class";
        InputStream in = null;
        try {
            in = loader.getResourceAsStream(path);
            if (in != null) return true;
        } catch (Throwable t) {
            // ignore
        } finally {
            if (in != null) try { in.close(); } catch (Exception ignored) {}
        }
        // 再试系统 loader
        try {
            in = ClassLoader.getSystemResourceAsStream(path);
            if (in != null) { try { in.close(); } catch (Exception ignored) {} return true; }
        } catch (Throwable t) {
            // ignore
        }
        return false;
    }
}
