package com.memshellauditor.detect;

import com.memshellauditor.report.Finding;
import com.memshellauditor.report.Report;
import com.memshellauditor.util.ReflectUtil;

import java.lang.instrument.Instrumentation;
import java.util.ArrayList;
import java.util.List;

/**
 * 未知内存马启发式检测器（不依赖已知特征）：
 *
 * 核心思路：不假设"我知道内存马长什么样"，而是检测"这个类做了什么不该做的事"。
 * 通过类的结构特征 + 字节码可读字符串中的行为模式进行组合评分：
 *
 *  行为模式（从字节码常量池/方法引用提取）：
 *   - 命令执行: Runtime.exec / ProcessBuilder
 *   - 动态加载: defineClass / 继承 ClassLoader
 *   - 载荷解密: Base64 / AES / DES / Cipher
 *   - 网络回连: Socket / URLConnection / 硬编码 IP
 *   - WebShell 回显: getParameter + 响应流
 *
 * 判定：容器组件特征 + ≥2 个恶意行为模式 → 可疑（未知变种同样命中）
 */
public class HeuristicAuditor {

    // 恶意行为模式 → 权重
    private static final String[][] PATTERNS = {
            // 命令执行
            {"EXEC", "runtime.exec", "processbuilder"},
            {"EXEC", "getruntime", "exec("},
            // 动态加载
            {"DEFINE", "defineclass", "classextractor"},
            {"DEFINE", "classloader", "loadclass"},
            // 载荷解密
            {"DECRYPT", "base64", "getdecoder", "getencoder"},
            {"DECRYPT", "cipher", "des", "aes", "rsa"},
            // 网络回连
            {"NET", "socket", "connect", "inetaddress"},
            {"NET", "urlconnection", "openconnection", "httpurlconnection"},
            // WebShell 回显
            {"SHELL", "getparameter", "servletrequest"},
            {"SHELL", "getoutputstream", "getwriter", "getresponse"},
            // 进程操作
            {"PROC", "process", "waitfor", "getinputstream"},
            {"PROC", "cmd", "shell", "bash", "powershell"},
    };

    /** 结构特征：类实现了容器组件接口（Filter/Servlet/Listener/Valve） */
    private static final String[] CONTAINER_INTERFACES = {
            "javax.servlet.Filter", "jakarta.servlet.Filter",
            "javax.servlet.Servlet", "jakarta.servlet.Servlet",
            "javax.servlet.ServletRequestListener", "jakarta.servlet.ServletRequestListener",
            "javax.servlet.http.HttpServlet", "jakarta.servlet.http.HttpServlet",
            "org.apache.catalina.Valve",
    };

    public void audit(Instrumentation inst, Report report) {
        try {
            Class<?>[] loaded = inst.getAllLoadedClasses();
            if (loaded == null) return;

            List<String> suspiciousClasses = new ArrayList<String>();
            int checked = 0;
            for (Class<?> cls : loaded) {
                if (cls == null) continue;
                String name = cls.getName();
                // 跳过自身/JDK/框架类
                if (ReflectUtil.isSelfClass(name)) continue;
                if (name.startsWith("java.") || name.startsWith("javax.")
                        || name.startsWith("jdk.") || name.startsWith("sun.")
                        || name.startsWith("com.sun.") || name.startsWith("org.apache.")
                        || name.startsWith("org.springframework") || name.startsWith("org.eclipse.")
                        || name.startsWith("io.undertow") || name.startsWith("com.fasterxml")
                        || name.startsWith("ch.qos.") || name.startsWith("org.slf4j")
                        || name.startsWith("org.mybatis") || name.startsWith("com.alibaba")) continue;
                // 只检测"可能成为内存马"的类：实现容器接口 / 继承 ClassLoader / 无包名动态类
                boolean isContainerLike = isContainerLike(cls);
                boolean isClassLoaderLike = ClassLoader.class.isAssignableFrom(cls);
                if (!isContainerLike && !isClassLoaderLike) continue;

                checked++;
                // 从字节码可读字符串提取行为模式（通过类资源或反汇编）
                String readable = readClassStrings(cls);
                if (readable == null || readable.isEmpty()) continue;

                List<String> matched = matchPatterns(readable.toLowerCase());
                if (matched.size() >= 2 || (matched.size() >= 1 && isClassLoaderLike)) {
                    suspiciousClasses.add(cls.getName());
                    if (suspiciousClasses.size() <= 15) {
                        report.add(Finding.high("A1", "Heuristic", cls.getName(), loaderDesc(cls),
                                "未知内存马启发式命中：容器组件特征 + 行为模式[" + String.join(",", matched) + "]",
                                "jad " + cls.getName() + " ; dump 分析核心代码"));
                    }
                }
            }
            if (suspiciousClasses.isEmpty()) {
                report.add(Finding.info("Heuristic", "未发现未知内存马行为特征（启发式扫描 " + checked + " 个可疑类）"));
            } else if (suspiciousClasses.size() > 15) {
                report.add(Finding.high("A1", "Heuristic", null, null,
                        "另有 " + (suspiciousClasses.size() - 15) + " 个启发式可疑类未逐一列出", null));
            }
        } catch (Throwable t) {
            report.add(Finding.low("N/A", "Heuristic", null, null,
                    "启发式审计异常: " + t, null));
        }
    }

    private boolean isContainerLike(Class<?> cls) {
        for (String iface : CONTAINER_INTERFACES) {
            if (ReflectUtil.implementsInterface(cls, iface)) return true;
        }
        return false;
    }

    /** 读取类字节码可读字符串（用于行为模式匹配） */
    private String readClassStrings(Class<?> cls) {
        try {
            ClassLoader cl = cls.getClassLoader();
            String path = cls.getName().replace('.', '/') + ".class";
            java.io.InputStream in = null;
            if (cl != null) in = cl.getResourceAsStream(path);
            if (in == null) in = ClassLoader.getSystemResourceAsStream(path);
            if (in == null) return null;
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
            in.close();
            return com.memshellauditor.dump.ClassDumper.extractReadableStrings(bos.toByteArray(), 65536);
        } catch (Throwable t) {
            return null;
        }
    }

    /** 匹配行为模式，返回命中的模式标签列表 */
    private List<String> matchPatterns(String lower) {
        List<String> matched = new ArrayList<String>();
        for (String[] p : PATTERNS) {
            for (int i = 1; i < p.length; i++) {
                if (lower.contains(p[i])) {
                    matched.add(p[0]);
                    break;
                }
            }
        }
        // 去重
        List<String> uniq = new ArrayList<String>();
        for (String m : matched) if (!uniq.contains(m)) uniq.add(m);
        return uniq;
    }

    private String loaderDesc(Class<?> cls) {
        ClassLoader cl = cls.getClassLoader();
        if (cl == null) return "bootstrap";
        String s = cl.toString();
        return s.length() > 160 ? s.substring(0, 160) + "..." : s;
    }
}
