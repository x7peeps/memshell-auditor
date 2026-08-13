package com.memshellauditor.detect;

import com.memshellauditor.report.Finding;
import com.memshellauditor.report.Report;
import com.memshellauditor.util.ReflectUtil;

import java.lang.instrument.Instrumentation;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * ClassLoader 血缘审计器（A3 信号）：
 *  - 枚举所有已加载类 → 统计每个 ClassLoader 加载的类数
 *  - 定位"非系统 ClassLoader"（自定义 Loader），内存马常使用独立 Loader 加载恶意字节码
 *  - 对可疑 Loader 展开其加载的类清单供复核
 */
public class ClassLoaderAuditor {

    private static final int MAX_LISTED = 15;

    public void audit(Instrumentation inst, Report report) {
        Class<?>[] loaded = inst.getAllLoadedClasses();
        if (loaded == null) return;

        Map<ClassLoader, Integer> counts = new LinkedHashMap<ClassLoader, Integer>();
        for (Class<?> cls : loaded) {
            if (cls == null) continue;
            ClassLoader cl = cls.getClassLoader();
            if (cl == null) continue; // bootstrap 不算
            Integer c = counts.get(cl);
            counts.put(cl, c == null ? 1 : c + 1);
        }

        int suspiciousLoaders = 0;
        for (Map.Entry<ClassLoader, Integer> e : counts.entrySet()) {
            ClassLoader cl = e.getKey();
            int n = e.getValue();
            if (ReflectUtil.isSystemClassLoader(cl)) continue;
            if (isBenignFrameworkLoader(cl)) continue;
            suspiciousLoaders++;
            if (suspiciousLoaders <= 10) {
                report.add(Finding.medium("A3", "ClassLoader", null, loaderName(cl),
                        "发现非系统 ClassLoader（加载 " + n + " 个类），需确认来源",
                        "arthas: classloader -c <hash> -r 查看其加载的类"));
            }
        }
        if (suspiciousLoaders == 0) {
            report.add(Finding.info("ClassLoader", "未发现非系统 ClassLoader，血缘结构正常"));
        } else if (suspiciousLoaders > 10) {
            report.add(Finding.medium("A3", "ClassLoader", null, null,
                    "另有 " + (suspiciousLoaders - 10) + " 个非系统 Loader 未逐一列出", null));
        }
    }

    /** 常见业务框架 Loader（非恶意） */
    private boolean isBenignFrameworkLoader(ClassLoader cl) {
        String s = cl.toString();
        // Spring Boot / Tomcat 类加载器是常态
        if (s.contains("org.springframework.boot") || s.contains("org.springframework.boot.loader")) return true;
        if (s.contains("org.apache.catalina") || s.contains("WebappClassLoader")) return true;
        if (s.contains("org.eclipse.jetty") || s.contains("io.undertow")) return true;
        if (s.contains("groovy") || s.contains("bsh") || s.contains("jruby")) return true;
        if (s.contains("net.bytebuddy") || s.contains("cglib") || s.contains("javassist")) return true;
        if (s.contains("sun.reflect") || s.contains("jdk.internal") || s.contains("java.lang")) return true;
        return false;
    }

    private String loaderName(ClassLoader cl) {
        String s = cl.toString();
        if (s == null || s.isEmpty()) s = cl.getClass().getName();
        return s.length() > 160 ? s.substring(0, 160) + "..." : s;
    }
}
