package com.memshellauditor.util;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

/**
 * 零依赖反射工具：绕过编译期对中间件类的依赖，运行时反射遍历容器内部结构。
 * 兼容 Tomcat 5-11 / Spring Boot 内嵌容器 / 类 Tomcat 国产中间件。
 */
public final class ReflectUtil {

    private ReflectUtil() {}

    /** 反射调用静态/实例方法，失败返回 null */
    public static Object invoke(Object target, String methodName, Class<?>[] paramTypes, Object[] args) {
        try {
            Class<?> cls = (target instanceof Class) ? (Class<?>) target : target.getClass();
            Method m = cls.getDeclaredMethod(methodName, paramTypes);
            m.setAccessible(true);
            return m.invoke(target, args);
        } catch (Throwable t) {
            // 尝试父类
            try {
                Class<?> cls = (target instanceof Class) ? (Class<?>) target : target.getClass();
                Method m = findMethod(cls, methodName, paramTypes);
                if (m == null) return null;
                m.setAccessible(true);
                return m.invoke(target, args);
            } catch (Throwable t2) {
                return null;
            }
        }
    }

    private static Method findMethod(Class<?> cls, String name, Class<?>[] paramTypes) {
        Class<?> c = cls;
        while (c != null && c != Object.class) {
            try {
                Method m = c.getDeclaredMethod(name, paramTypes);
                if (m != null) return m;
            } catch (NoSuchMethodException ignored) {
            }
            c = c.getSuperclass();
        }
        return null;
    }

    /** 无参方法便捷调用 */
    public static Object invokeNoArgs(Object target, String methodName) {
        return invoke(target, methodName, new Class<?>[0], new Object[0]);
    }

    /** 读取字段（含私有/父类），失败返回 null */
    public static Object getField(Object target, String fieldName) {
        try {
            Class<?> cls = target.getClass();
            while (cls != null && cls != Object.class) {
                try {
                    Field f = cls.getDeclaredField(fieldName);
                    f.setAccessible(true);
                    return f.get(target);
                } catch (NoSuchFieldException ignored) {
                }
                cls = cls.getSuperclass();
            }
        } catch (Throwable t) {
            // fallthrough
        }
        return null;
    }

    /** 读取静态字段，失败返回 null */
    public static Object getStaticField(Class<?> cls, String fieldName) {
        try {
            Field f = cls.getDeclaredField(fieldName);
            f.setAccessible(true);
            return f.get(null);
        } catch (Throwable t) {
            return null;
        }
    }

    /** 判断类是否实现了某个接口名（按名称匹配，避免类加载） */
    public static boolean implementsInterface(Class<?> cls, String interfaceName) {
        if (cls == null) return false;
        Class<?>[] ifaces = cls.getInterfaces();
        for (Class<?> i : ifaces) {
            if (i.getName().equals(interfaceName)) return true;
        }
        // 父类
        Class<?> sup = cls.getSuperclass();
        if (sup != null && sup != Object.class) {
            if (implementsInterface(sup, interfaceName)) return true;
        }
        return false;
    }

    /** 判断类名是否实现（含父类链上）某个接口 */
    public static boolean hasInterfaceInHierarchy(Class<?> cls, String interfaceName) {
        return implementsInterface(cls, interfaceName);
    }

    /** 判断 ClassLoader 是否为系统类加载器（Bootstrap/Platform/App） */
    public static boolean isSystemClassLoader(ClassLoader cl) {
        if (cl == null) return true; // bootstrap
        ClassLoader sys = ClassLoader.getSystemClassLoader();
        ClassLoader platform = null;
        try {
            Method m = ClassLoader.class.getDeclaredMethod("getPlatformClassLoader");
            m.setAccessible(true);
            platform = (ClassLoader) m.invoke(null);
        } catch (Throwable t) {
            // JDK8 无 platform loader
        }
        if (cl == sys || cl == platform) return true;
        // 判断是否系统链上的祖先
        ClassLoader cur = sys;
        while (cur != null) {
            if (cur == cl) return true;
            cur = cur.getParent();
        }
        return false;
    }

    /**
     * 获取当前 agent 自身的包前缀（动态识别，兼容混淆版）。
     * 主程序：com.memshellauditor；混淆版：net.jvm.check 等随机包。
     * 用于审计时排除自身类，避免自误报。
     */
    public static String selfPackagePrefix() {
        try {
            String name = ReflectUtil.class.getName();
            int idx = name.lastIndexOf('.');
            if (idx > 0) return name.substring(0, idx); // 不含最后一个点
        } catch (Throwable t) {
            // ignore
        }
        return "com.memshellauditor";
    }

    /** 判断类名是否属于当前 agent 自身 */
    public static boolean isSelfClass(String className) {
        if (className == null) return false;
        String prefix = selfPackagePrefix();
        return prefix != null && !prefix.isEmpty() && className.startsWith(prefix + ".");
    }
}
