package com.memshellauditor;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * JVM 进程扫描器（--scan 模式）：
 *  自动枚举本机所有 Java 进程，按可疑度评分排序，供取证人员快速定位审计目标。
 *
 * 可疑度评分（优先级从高到低）：
 *  - Web 容器（Tomcat/Spring Boot/Jetty/WebLogic/Resin/Undertow 等）→ 内存马最常驻留
 *  - 业务应用（java -jar / Main 类）→ 次之
 *  - 含可疑关键字（memshell/behinder/inject 等）→ 加分
 *  - 工具/守护进程（jps/attach 自身/IDE）→ 降权
 */
public class JvmScanner {

    /** 扫描到的 JVM 进程 */
    public static class JvmInfo {
        public String id;
        public String displayName;
        public int score;
        public String[] reasons;
    }

    /** 枚举本机所有 Java 进程 */
    public static List<JvmInfo> listJvms() {
        List<JvmInfo> result = new ArrayList<JvmInfo>();
        try {
            Class<?> vmClass = Class.forName("com.sun.tools.attach.VirtualMachine");
            Method list = vmClass.getMethod("list");
            Object vms = list.invoke(null);
            for (Object vm : (List<?>) vms) {
                Method id = vm.getClass().getMethod("id");
                Method display = vm.getClass().getMethod("displayName");
                JvmInfo info = new JvmInfo();
                info.id = String.valueOf(id.invoke(vm));
                Object dn = display.invoke(vm);
                info.displayName = dn == null ? "" : String.valueOf(dn);
                result.add(info);
            }
        } catch (Throwable t) {
            // ignore
        }
        return result;
    }

    /** 计算可疑度评分（用于排序） */
    public static int score(JvmInfo info) {
        String name = info.displayName == null ? "" : info.displayName.toLowerCase();
        List<String> reasons = new ArrayList<String>();
        int score = 0;

        // 高优先级：Web 容器（内存马最常驻留）
        if (name.contains("tomcat") || name.contains("catalina")) {
            score += 100;
            reasons.add("Tomcat/Catalina");
        }
        if (name.contains("spring") && (name.contains("boot") || name.contains("app"))) {
            score += 90;
            reasons.add("Spring Boot");
        }
        if (name.contains("jetty")) { score += 90; reasons.add("Jetty"); }
        if (name.contains("weblogic")) { score += 100; reasons.add("WebLogic"); }
        if (name.contains("resin")) { score += 90; reasons.add("Resin"); }
        if (name.contains("undertow")) { score += 80; reasons.add("Undertow"); }
        if (name.contains("wildfly") || name.contains("jboss")) { score += 90; reasons.add("WildFly/JBoss"); }
        if (name.contains("websphere")) { score += 100; reasons.add("WebSphere"); }
        if (name.contains("tongweb") || name.contains("bes") || name.contains("apusic")
                || name.contains("infor") || name.contains("primeton")) {
            score += 100;
            reasons.add("国产中间件");
        }
        // 业务应用
        if (name.contains("java -jar") || name.contains("-jar") || name.contains(".war")) {
            score += 40;
            reasons.add("应用进程");
        }
        // 可疑关键字
        String[] sus = {"memshell", "behinder", "godzilla", "inject", "exploit", "payload", "shell"};
        for (String s : sus) {
            if (name.contains(s)) {
                score += 60;
                reasons.add("可疑关键字:" + s);
                break;
            }
        }
        // 降权：工具/守护/自身
        if (name.isEmpty() || name.contains("jps") || name.contains("jconsole")
                || name.contains("jvisualvm") || name.contains("attach")) {
            score -= 30;
            reasons.add("工具/守护进程");
        }
        if (name.contains("memshell-auditor") || name.contains("memshellauditor")) {
            score = -1000;
            reasons.add("自身");
        }
        // 无显示名（system JVM）降权
        if (name.isEmpty()) score -= 10;

        info.score = score;
        info.reasons = reasons.toArray(new String[0]);
        return score;
    }

    /** 按可疑度降序排序 */
    public static void sortByScore(List<JvmInfo> list) {
        Collections.sort(list, new Comparator<JvmInfo>() {
            public int compare(JvmInfo a, JvmInfo b) {
                return Integer.compare(b.score, a.score);
            }
        });
    }
}
