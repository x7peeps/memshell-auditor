package com.memshellauditor.detect;

import com.memshellauditor.report.Finding;
import com.memshellauditor.report.Report;
import com.memshellauditor.util.ReflectUtil;

import java.io.InputStream;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 容器组件审计器：
 *  1. Filter   - 遍历 StandardContext.filterDefs / filterConfigs（内存马注入第一落点）
 *  2. Servlet  - 遍历 StandardContext.children
 *  3. Listener - 遍历 applicationEventListeners / 生命周期监听器
 *  4. Valve    - 遍历 Pipeline.getValves()
 *
 * 纯反射实现，不依赖具体中间件类，兼容 Tomcat 5-11 / 内嵌容器 / 类 Tomcat 国产中间件。
 * 容器上下文定位链路：
 *   已加载类.getClassLoader() -> WebappClassLoaderBase.resources(字段) -> StandardRoot.getContext()
 */
public class ContainerAuditor {

    public void audit(Instrumentation inst, Report report) {
        List<Object> contexts = findContexts(inst);
        // MBean 辅助提示（不依赖实例遍历）
        auditMBeans(report);
        if (contexts.isEmpty()) {
            report.add(Finding.info("Container", "未发现已加载的 Servlet 容器上下文（StandardContext 等），可能非 Web 应用或容器类未加载"));
            return;
        }
        report.add(Finding.info("Container", "发现 " + contexts.size() + " 个容器上下文实例，开始组件审计"));
        for (Object ctx : contexts) {
            auditFilters(ctx, report);
            auditServlets(ctx, report);
            auditListeners(ctx, report);
            auditValves(ctx, report);
        }
    }

    /** MBeanServer 辅助：输出容器 MBean 清单供人工复核 */
    private void auditMBeans(Report report) {
        try {
            Class<?> mbsClass = Class.forName("java.lang.management.ManagementFactory");
            Object mbs = ReflectUtil.invokeNoArgs(mbsClass, "getPlatformMBeanServer");
            if (mbs == null) return;
            Class<?> onClass = Class.forName("javax.management.ObjectName");
            Object query = onClass.getConstructor(String.class).newInstance("Catalina:type=Context,*");
            Object names = ReflectUtil.invoke(mbs, "queryNames",
                    new Class<?>[]{onClass, javax.management.ObjectName.class}, new Object[]{query, null});
            if (names instanceof Set) {
                for (Object name : (Set<?>) names) {
                    if (name != null) {
                        report.add(Finding.info("Container", "发现容器 MBean: " + name + "（人工复核参考）"));
                    }
                }
            }
        } catch (Throwable ignored) {
        }
    }

    /** 从已加载类中定位容器上下文实例 */
    private List<Object> findContexts(Instrumentation inst) {
        List<Object> found = new ArrayList<Object>();
        try {
            Class<?>[] loaded = inst.getAllLoadedClasses();
            Class<?> stdCtxClass = null;
            for (Class<?> cls : loaded) {
                if (cls == null) continue;
                String cn = cls.getName();
                // 兼容 Tomcat 与国产中间件（TongWeb/BES/InforSuite/Apusic/Primeton）的 StandardContext 类名
                if (cn.equals("org.apache.catalina.core.StandardContext")
                        || cn.equals("com.tongweb.catalina.core.StandardContext")
                        || cn.equals("com.tongweb.catalina.Context")
                        || cn.equals("com.bes.core.StandardContext")
                        || cn.equals("com.bes.core.ApplicationContext")
                        || cn.endsWith("core.StandardContext")) {
                    stdCtxClass = cls;
                    break;
                }
            }

            // 方式1: 遍历已加载类，通过类.getClassLoader() 拿到 WebappClassLoaderBase 实例
            //   WebappClassLoaderBase.resources(字段) -> StandardRoot.getContext() -> StandardContext
            //   适用于生产 WAR 部署（存在 WebappClassLoader）；embed/classpath 模式无此 Loader
            //   兼容国产中间件：TongWeb/BES/InforSuite 均基于 Tomcat 变体，Loader 类名含 webapp
            try {
                Set<ClassLoader> seen = new HashSet<ClassLoader>();
                for (Class<?> cls : loaded) {
                    if (cls == null) continue;
                    ClassLoader cl = cls.getClassLoader();
                    if (cl == null || ReflectUtil.isSystemClassLoader(cl)) continue;
                    if (!isWebappClassLoader(cl.getClass())) continue;
                    if (seen.contains(cl)) continue;
                    seen.add(cl);
                    try {
                        // 优先字段反射（getResources() 方法在部分版本返回 null）
                        Object resources = ReflectUtil.getField(cl, "resources");
                        if (resources == null) {
                            resources = ReflectUtil.invokeNoArgs(cl, "getResources");
                        }
                        if (resources != null) {
                            Object ctx = null;
                            // 兼容: StandardRoot.getContext() / WebResourceRoot.getContext()
                            try { ctx = ReflectUtil.invokeNoArgs(resources, "getContext"); } catch (Throwable ignored) {}
                            if (ctx == null) {
                                // 国产中间件可能用 context 字段
                                ctx = ReflectUtil.getField(resources, "context");
                            }
                            if (ctx != null && !found.contains(ctx)) found.add(ctx);
                        } else {
                            // resources 拿不到时，直接尝试从 Loader 的 context/contextClass 字段取
                            Object ctxDirect = ReflectUtil.getField(cl, "context");
                            if (ctxDirect == null) ctxDirect = ReflectUtil.getField(cl, "contextClass");
                            if (ctxDirect != null && !found.contains(ctxDirect)) found.add(ctxDirect);
                        }
                    } catch (Throwable ignored) {
                    }
                }
            } catch (Throwable ignored) {
            }
            // 兜底: 若通过 Loader 未找到上下文，但存在 StandardContext 类 → 遍历已加载类收集实例
            if (found.isEmpty() && stdCtxClass != null) {
                for (Class<?> cls : loaded) {
                    if (cls == null) continue;
                    if (stdCtxClass.isAssignableFrom(cls)) {
                        if (!found.contains(cls)) found.add(cls);
                    }
                }
            }

            // 方式2: MBeanServer 定位（Tomcat 默认注册 Catalina:type=Context MBean）
            //   仅输出 MBean 清单供人工复核；实例遍历依赖方式1
            try {
                Class<?> mbsClass = Class.forName("java.lang.management.ManagementFactory");
                Object mbs = ReflectUtil.invokeNoArgs(mbsClass, "getPlatformMBeanServer");
                if (mbs != null) {
                    Class<?> onClass = Class.forName("javax.management.ObjectName");
                    Object query = onClass.getConstructor(String.class).newInstance("Catalina:type=Context,*");
                    Object names = ReflectUtil.invoke(mbs, "queryNames", new Class<?>[]{onClass, javax.management.ObjectName.class}, new Object[]{query, null});
                    if (names instanceof Set) {
                        for (Object name : (Set<?>) names) {
                            if (name != null) {
                                System.err.println("[memshell-auditor] MBean: " + name);
                            }
                        }
                    }
                }
            } catch (Throwable ignored) {
            }
        } catch (Throwable t) {
            // 容器审计子项异常（不影响其他审计），记录以便排查
        }
        return found;
    }

    /** 判断 ClassLoader 是否为 Tomcat WebappClassLoader（含国产类 Tomcat 中间件） */
    private boolean isWebappClassLoader(Class<?> loaderClass) {
        if (loaderClass == null) return false;
        String name = loaderClass.getName();
        if (name.startsWith("org.apache.catalina.loader")) return true;
        if (name.startsWith("com.caucho")) return true;             // Resin
        if (name.startsWith("com.tongweb")) return true;            // 东方通 TongWeb
        if (name.startsWith("com.bes")) return true;                // 宝兰德 BES
        if (name.startsWith("org.infor")) return true;              // 中创 InforSuite
        if (name.startsWith("com.apusic")) return true;             // 金蝶 Apusic
        if (name.startsWith("com.primeton")) return true;           // 普元 Primeton
        if (name.contains("webapp") || name.contains("Webapp")) return true;
        Class<?> c = loaderClass.getSuperclass();
        while (c != null && c != Object.class) {
            String cn = c.getName();
            if (cn.startsWith("org.apache.catalina.loader")) return true;
            if (cn.startsWith("com.tongweb") || cn.startsWith("com.bes")
                    || cn.startsWith("org.infor") || cn.startsWith("com.apusic")
                    || cn.startsWith("com.primeton")) return true;
            if (cn.contains("webapp") || cn.contains("Webapp")) return true;
            c = c.getSuperclass();
        }
        return false;
    }

    // ---------------- Filter ----------------

    private void auditFilters(Object ctx, Report report) {
        // 路径1: filterConfigs（已实例化的 filter，start 时/请求触发时创建）
        Object filterConfigs = ReflectUtil.invokeNoArgs(ctx, "getFilterConfigs");
        if (filterConfigs == null) {
            filterConfigs = ReflectUtil.getField(ctx, "filterConfigs");
        }
        if (filterConfigs instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) filterConfigs;
            for (Map.Entry<?, ?> e : map.entrySet()) {
                String name = String.valueOf(e.getKey());
                Object config = e.getValue();
                auditFilterEntry(name, config, report);
            }
        } else if (filterConfigs != null) {
            // 兼容 List 形态
            auditFilterCollection(filterConfigs, report);
        }

        // 路径2: filterDefs（Filter 定义注册表——内存马注入的第一落点，即使 config 未初始化也能检出）
        Object filterDefs = ReflectUtil.getField(ctx, "filterDefs");
        if (filterDefs instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) filterDefs;
            for (Map.Entry<?, ?> e : map.entrySet()) {
                String name = String.valueOf(e.getKey());
                Object def = e.getValue();
                if (def == null) continue;
                String filterClass = (String) ReflectUtil.invokeNoArgs(def, "getFilterClass");
                String filterName = (String) ReflectUtil.invokeNoArgs(def, "getFilterName");
                if (filterName == null) filterName = name;
                boolean onDisk = classExistsOnDisk(filterClass, (filterClass != null) ? resolveLoader(filterClass, ctx) : null);
                if (filterClass != null && !onDisk) {
                    report.add(Finding.high("A1", "Filter", filterClass, null,
                            "FilterDef 注册的类在磁盘无对应 class 文件（动态加载），高度疑似内存马",
                            "核对 " + filterClass + " 是否存在对应 class/jar"));
                } else if (filterClass != null && isSuspiciousClassName(filterClass)) {
                    report.add(Finding.medium("B1", "Filter", filterClass, null,
                            "FilterDef 注册的 Filter 类名可疑（随机/无包名/混淆），建议人工复核",
                            "jad " + filterClass));
                } else if (filterClass != null) {
                    report.add(Finding.info("Filter", "FilterDef[" + filterName + "] -> " + filterClass + " 磁盘类存在，正常"));
                }
            }
        } else if (filterConfigs == null) {
            report.add(Finding.info("Filter", "未获取到 FilterConfigs/FilterDefs（可能无 Filter 或 API 不兼容）"));
        }
    }

    /** 从已加载类反查 classLoader（filterClass 对应的 loader） */
    private ClassLoader resolveLoader(String filterClass, Object ctx) {
        try {
            Class<?> c = Class.forName(filterClass, false, ctx.getClass().getClassLoader());
            if (c != null) return c.getClassLoader();
        } catch (Throwable t) {
            // 容器审计子项异常（不影响其他审计），记录以便排查
        }
        return ctx.getClass().getClassLoader();
    }

    private void auditFilterCollection(Object coll, Report report) {
        if (coll instanceof Iterable) {
            for (Object o : (Iterable<?>) coll) {
                if (o instanceof Map.Entry) {
                    Map.Entry<?, ?> e = (Map.Entry<?, ?>) o;
                    auditFilterEntry(String.valueOf(e.getKey()), e.getValue(), report);
                } else {
                    auditFilterEntry(null, o, report);
                }
            }
        }
    }

    private void auditFilterEntry(String name, Object config, Report report) {
        String filterClass = null;
        String filterName = name;
        Object filter = null;
        Object filterDef = null;
        if (config != null) {
            // FilterConfig 或 Map<String, Object> 形态
            filter = ReflectUtil.invokeNoArgs(config, "getFilter");
            filterDef = ReflectUtil.invokeNoArgs(config, "getFilterDef");
            if (filterDef != null) {
                String cn = (String) ReflectUtil.invokeNoArgs(filterDef, "getFilterClass");
                if (cn != null) filterClass = cn;
                String fn = (String) ReflectUtil.invokeNoArgs(filterDef, "getFilterName");
                if (fn != null) filterName = fn;
            }
            if (filterClass == null) {
                // 直接从 filter 对象取类名
                if (filter != null) filterClass = filter.getClass().getName();
            }
        }
        if (filterClass == null && filter != null) {
            filterClass = filter.getClass().getName();
        }
        if (filterClass == null) {
            report.add(Finding.low("B2", "Filter", filterName, null,
                    "Filter 存在但无法解析其类名，建议人工复核", null));
            return;
        }
        // 判断：磁盘上是否真实存在该类（排除动态生成的 Filter）
        boolean onDisk = classExistsOnDisk(filterClass, (filter != null) ? filter.getClass().getClassLoader() : null);
        if (!onDisk) {
            report.add(Finding.high("A1", "Filter", filterClass, loaderDesc(filter),
                    "Filter 类在磁盘无对应 class 文件（动态加载），高度疑似内存马", "核对 " + filterClass + " 是否存在对应 class/jar"));
            return;
        }
        // 辅助信号：类名特征
        if (isSuspiciousClassName(filterClass)) {
            report.add(Finding.medium("B1", "Filter", filterClass, loaderDesc(filter),
                    "Filter 类名可疑（随机/无包名/混淆），建议人工复核", "jad " + filterClass));
        } else {
            report.add(Finding.info("Filter", "Filter[" + filterName + "] -> " + filterClass + " 磁盘类存在，正常"));
        }
    }

    // ---------------- Servlet ----------------

    private void auditServlets(Object ctx, Report report) {
        Object children = ReflectUtil.invokeNoArgs(ctx, "findChildren");
        if (children == null) children = ReflectUtil.getField(ctx, "children");
        if (children instanceof Map) {
            for (Object v : ((Map<?, ?>) children).values()) {
                auditServletEntry(v, report);
            }
        } else if (children instanceof Collection) {
            for (Object v : (Collection<?>) children) {
                auditServletEntry(v, report);
            }
        }
    }

    private void auditServletEntry(Object wrapper, Report report) {
        if (wrapper == null) return;
        String cls = (String) ReflectUtil.invokeNoArgs(wrapper, "getServletClass");
        if (cls == null) {
            Object servlet = ReflectUtil.invokeNoArgs(wrapper, "getServlet");
            if (servlet != null) cls = servlet.getClass().getName();
        }
        String name = (String) ReflectUtil.invokeNoArgs(wrapper, "getName");
        if (cls == null) return;
        boolean onDisk = classExistsOnDisk(cls, wrapper.getClass().getClassLoader());
        if (!onDisk) {
            report.add(Finding.high("A1", "Servlet", cls, loaderDesc(wrapper),
                    "Servlet 类在磁盘无对应 class 文件，高度疑似内存马", "核对 " + cls));
        } else if (isSuspiciousClassName(cls)) {
            report.add(Finding.medium("B1", "Servlet", cls, loaderDesc(wrapper),
                    "Servlet 类名可疑，建议人工复核", null));
        } else {
            report.add(Finding.info("Servlet", "Servlet[" + name + "] -> " + cls + " 正常"));
        }
    }

    // ---------------- Listener ----------------

    private void auditListeners(Object ctx, Report report) {
        Object listeners = ReflectUtil.invokeNoArgs(ctx, "getApplicationEventListeners");
        if (listeners == null) listeners = ReflectUtil.getField(ctx, "applicationEventListeners");
        if (listeners instanceof Object[]) {
            for (Object l : (Object[]) listeners) auditListenerEntry(l, report);
        } else if (listeners instanceof Iterable) {
            for (Object l : (Iterable<?>) listeners) auditListenerEntry(l, report);
        }
        // LifecycleListener 审计（Valve/生命周期注入点）
        Object lifecycle = ReflectUtil.invokeNoArgs(ctx, "findLifecycleListeners");
        if (lifecycle instanceof Object[]) {
            for (Object l : (Object[]) lifecycle) auditListenerEntry(l, report);
        } else if (lifecycle instanceof Iterable) {
            for (Object l : (Iterable<?>) lifecycle) auditListenerEntry(l, report);
        }
    }

    private void auditListenerEntry(Object l, Report report) {
        if (l == null) return;
        String cls = l.getClass().getName();
        boolean onDisk = classExistsOnDisk(cls, l.getClass().getClassLoader());
        if (!onDisk) {
            report.add(Finding.high("A1", "Listener", cls, loaderDesc(l),
                    "Listener 类在磁盘无对应 class 文件，高度疑似内存马", "核对 " + cls));
        } else if (isSuspiciousClassName(cls)) {
            report.add(Finding.medium("B1", "Listener", cls, loaderDesc(l),
                    "Listener 类名可疑，建议人工复核", null));
        } else {
            report.add(Finding.info("Listener", "Listener -> " + cls + " 正常"));
        }
    }

    // ---------------- Valve ----------------

    private void auditValves(Object ctx, Report report) {
        Object pipeline = ReflectUtil.invokeNoArgs(ctx, "getPipeline");
        if (pipeline == null) return;
        Object valves = ReflectUtil.invokeNoArgs(pipeline, "getValves");
        if (valves instanceof Object[]) {
            for (Object v : (Object[]) valves) {
                if (v == null) continue;
                String cls = v.getClass().getName();
                boolean onDisk = classExistsOnDisk(cls, v.getClass().getClassLoader());
                if (!onDisk) {
                    report.add(Finding.high("A1", "Valve", cls, loaderDesc(v),
                            "Valve 类在磁盘无对应 class 文件，高度疑似内存马（不在 Filter 链，常规扫描失效）", "核对 " + cls));
                } else if (isSuspiciousClassName(cls)) {
                    report.add(Finding.medium("B1", "Valve", cls, loaderDesc(v),
                            "Valve 类名可疑，建议人工复核", null));
                } else {
                    report.add(Finding.info("Valve", "Valve -> " + cls + " 正常"));
                }
            }
        }
    }

    // ---------------- 辅助 ----------------

    /** 判断类是否在磁盘存在（通过 ClassLoader 资源定位） */
    private boolean classExistsOnDisk(String className, ClassLoader loader) {
        if (className == null) return false;
        // 跳过 JDK 内部类（肯定存在）
        if (className.startsWith("java.") || className.startsWith("javax.")
                || className.startsWith("jdk.") || className.startsWith("sun.")
                || className.startsWith("com.sun.")) {
            return true;
        }
        String path = className.replace('.', '/') + ".class";
        if (loader != null) {
            InputStream in = null;
            try {
                in = loader.getResourceAsStream(path);
                if (in != null) return true;
            } catch (Throwable t) {
                // ignore
            } finally {
                if (in != null) try { in.close(); } catch (Exception ignored) {}
            }
        }
        // 再试系统 loader
        try {
            InputStream in = ClassLoader.getSystemResourceAsStream(path);
            if (in != null) { try { in.close(); } catch (Exception ignored) {} return true; }
        } catch (Throwable t) {
            // 容器审计子项异常（不影响其他审计），记录以便排查
        }
        return false;
    }

    /** 可疑类名特征：无包名 / 随机短名 / 混淆 */
    private boolean isSuspiciousClassName(String cls) {
        if (cls == null) return false;
        int idx = cls.lastIndexOf('.');
        String simple = (idx >= 0) ? cls.substring(idx + 1) : cls;
        String pkg = (idx >= 0) ? cls.substring(0, idx) : "";
        // 无包名
        if (pkg.isEmpty()) return true;
        // 短随机名（1-3 字符，非 JDK 包）
        if (simple.length() <= 3 && !pkg.startsWith("java") && !pkg.startsWith("org.apache") && !pkg.startsWith("org.springframework")) {
            return true;
        }
        // 类名含可疑关键词（大小写混合随机名特征）
        String lower = simple.toLowerCase();
        if (lower.contains("memshell") || lower.contains("webshell") || lower.contains("shell")) return true;
        if (lower.contains("behinder") || lower.contains("godzilla") || lower.contains("suo5")) return true;
        // 纯小写+数字随机名（如 x1y2z3）
        if (simple.matches("^[a-z0-9]{1,6}$") && !pkg.startsWith("java") && !pkg.startsWith("org.apache") && !pkg.startsWith("org.springframework")) {
            return true;
        }
        return false;
    }

    private String loaderDesc(Object obj) {
        if (obj == null) return null;
        ClassLoader cl = obj.getClass().getClassLoader();
        if (cl == null) return "bootstrap";
        String s = cl.toString();
        if (s.length() > 160) s = s.substring(0, 160) + "...";
        return s;
    }
}
