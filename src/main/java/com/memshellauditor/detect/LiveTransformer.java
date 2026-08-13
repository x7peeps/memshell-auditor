package com.memshellauditor.detect;

import java.lang.instrument.Instrumentation;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import java.lang.reflect.Field;

/**
 * 研究2：实时监控 ClassFileTransformer（LiveWatch）
 *
 * 目标：attach 后安装监控 transformer，后续任何新 defineClass 的类都会经过
 *      transform() 回调——在类定义时即捕获字节码，实时检查/dump。
 *
 * 同时解决：
 *  - 局限4（运行时窗口）：attach 后新加载的类全部可见
 *  - 局限1 的一部分：新注入的内存马在定义时就能 dump（不需要事后 retransform）
 */
public class LiveTransformer {

    private static volatile boolean liveEnabled = false;

    /** 在 agentmain 中调用：注册实时监控 transformer */
    public static void enable(Instrumentation inst, final LiveListener listener) {
        if (liveEnabled) return;
        liveEnabled = true;
        inst.addTransformer(new ClassFileTransformer() {
            @Override
            public byte[] transform(ClassLoader loader, String className,
                                    Class<?> classBeingRedefined,
                                    ProtectionDomain protectionDomain,
                                    byte[] classfileBuffer) {
                // 只监控新定义（非重定义）
                if (classBeingRedefined == null && className != null) {
                    try {
                        listener.onNewClass(loader, className, classfileBuffer, protectionDomain);
                    } catch (Throwable ignored) {
                    }
                }
                return null; // 不修改字节码
            }
        }, true);
    }

    /** 监听接口 */
    public interface LiveListener {
        void onNewClass(ClassLoader loader, String className,
                        byte[] classfileBuffer, ProtectionDomain protectionDomain);
    }
}
