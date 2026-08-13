package com.memshellauditor.dump;

import com.memshellauditor.util.ReflectUtil;

import com.memshellauditor.report.Finding;
import com.memshellauditor.report.Report;

import java.io.File;
import java.lang.instrument.Instrumentation;
import java.util.ArrayList;
import java.util.List;

/**
 * 取证服务（v1.1 增强）：对可疑类执行 检出 → dump → 反编译 → 回连分析 闭环。
 *
 * 流程：
 *  1. 对 HIGH/MEDIUM 级别且带 className 的 Finding 执行类字节码提取（ClassDumper）
 *  2. 字节码落盘到 dump 目录（取证留证）
 *  3. javap 反汇编 + 提取恶意核心代码片段
 *  4. 从字节码可读字符串 / 反汇编文本中提取疑似回连 IP/域名
 *  5. 独立分析进程网络外连（NetworkAnalyzer）
 */
public final class ForensicsService {

    private final Instrumentation inst;
    private final File dumpDir;
    private final List<String> callbackIps = new ArrayList<String>();

    public ForensicsService(Instrumentation inst, File dumpDir) {
        this.inst = inst;
        this.dumpDir = dumpDir;
        if (!dumpDir.exists()) dumpDir.mkdirs();
    }

    /** 对报告中的可疑 Finding 执行取证，直接回填 dumpPath/callbackIps/coreCode */
    public void enrich(Report report) {
        // 1. 网络外连分析（进程级，独立于类）
        List<NetworkAnalyzer.Conn> conns = NetworkAnalyzer.analyze(report.getPid() > 0 ? (int) report.getPid() : currentPid());
        if (!conns.isEmpty()) {
            StringBuilder sb = new StringBuilder();
            for (NetworkAnalyzer.Conn c : conns) {
                if (sb.length() > 0) sb.append("; ");
                sb.append(c.local).append("->").append(c.remote);
            }
            report.add(Finding.medium("N/A", "Network", null, null,
                    "检测到 ESTABLISHED 外连（" + conns.size() + " 条）: " + sb,
                    "lsof -p " + report.getPid() + " -iTCP -sTCP:ESTABLISHED"));
            for (NetworkAnalyzer.Conn c : conns) {
                callbackIps.add(c.remote);
            }
        } else {
            report.add(Finding.info("Network", "未发现 ESTABLISHED 外连（或无法读取 /proc/lsof）"));
        }

        // 2. 对每个可疑 Finding 执行类级取证
        for (Finding f : new ArrayList<Finding>(report.getFindings())) {
            if (f.className == null || f.className.isEmpty()) continue;
            if (f.level != Finding.Level.HIGH && f.level != Finding.Level.MEDIUM) continue;
            // 跳过自身与 JDK 类
            if (ReflectUtil.isSelfClass(f.className)) continue;
            if (f.className.startsWith("java.") || f.className.startsWith("javax.")
                    || f.className.startsWith("jdk.") || f.className.startsWith("sun.")) continue;

            Class<?> cls = findClass(f.className);
            if (cls == null) continue;

            // 2.1 dump（磁盘存在的类用资源流；defineClass 注入类用 retransform）
            String path = ClassDumper.dumpClass(inst, cls, dumpDir);
            if (path != null) {
                f.dumpPath = path;
                System.out.println("[memshell-auditor] dumped " + f.className + " -> " + path);
            }

            // 2.2 反编译核心代码
            byte[] code = ClassDumper.getClassBytes(inst, cls);
            if (code != null) {
                // 从字节码可读字符串提取回连
                String strs = ClassDumper.extractReadableStrings(code, 8192);
                String cb = Decompiler.extractCallbacks(strs);
                if (!cb.isEmpty()) {
                    f.callbackIps = cb;
                    addCallback(cb);
                }
                // javap 反汇编
                String path2 = path != null ? path : null;
                if (path2 != null) {
                    String javapOut = Decompiler.javap(new File(path2), false);
                    if (javapOut != null) {
                        String core = Decompiler.extractMaliciousCore(javapOut, 30);
                        if (!core.isEmpty()) {
                            f.coreCode = core.length() > 4000 ? core.substring(0, 4000) : core;
                        }
                        String cb2 = Decompiler.extractCallbacks(javapOut);
                        if (!cb2.isEmpty()) {
                            f.callbackIps = (f.callbackIps == null ? "" : f.callbackIps) + (f.callbackIps != null && !f.callbackIps.isEmpty() ? ", " : "") + cb2;
                            addCallback(cb2);
                        }
                    }
                }
            }
        }

        // 3. 汇总回连地址（若存在则追加一条高价值 INFO）
        if (!callbackIps.isEmpty()) {
            StringBuilder uniq = new StringBuilder();
            java.util.LinkedHashSet<String> set = new java.util.LinkedHashSet<String>(callbackIps);
            for (String s : set) {
                if (uniq.length() > 0) uniq.append(", ");
                uniq.append(s);
            }
            report.add(Finding.high("N/A", "Callback", null, null,
                    "提取到疑似回连地址: " + uniq,
                    "对目标 IP 进行威胁情报查询 / 防火墙封禁"));
        }
    }

    private void addCallback(String cb) {
        if (cb == null) return;
        for (String s : cb.split(",")) {
            String t = s.trim();
            if (!t.isEmpty()) callbackIps.add(t);
        }
    }

    private Class<?> findClass(String name) {
        try {
            if (inst != null) {
                Class<?>[] loaded = inst.getAllLoadedClasses();
                for (Class<?> c : loaded) {
                    if (c != null && c.getName().equals(name)) return c;
                }
            }
            return Class.forName(name, false, ClassLoader.getSystemClassLoader());
        } catch (Throwable t) {
            return null;
        }
    }

    private static int currentPid() {
        try {
            return Integer.parseInt(new java.io.File("/proc/self").getCanonicalFile().getName());
        } catch (Throwable t) {
            try {
                // JDK9+: RuntimeMXBean.getPid()；JDK8 用 ManagementFactory 无此方法，走反射
                Object bean = java.lang.management.ManagementFactory.getRuntimeMXBean();
                java.lang.reflect.Method m = bean.getClass().getMethod("getPid");
                return ((Number) m.invoke(bean)).intValue();
            } catch (Throwable t2) {
                return -1;
            }
        }
    }
}
