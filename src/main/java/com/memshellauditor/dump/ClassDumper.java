package com.memshellauditor.dump;

import java.io.File;
import java.io.FileOutputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;

/**
 * 可疑类字节码提取器（Dump Module）：
 *  - 对磁盘存在的类：ClassLoader.getResourceAsStream 直接读
 *  - 对 defineClass 注入的内存马（磁盘无文件）：用 ClassFileTransformer + retransformClasses
 *    技巧——注册一个只读 transformer，对目标类 retransform，在回调里截获 classfileBuffer。
 *
 * 这是取证的关键：检测到可疑类后，把恶意字节码 dump 到磁盘供反编译与留证。
 */
public final class ClassDumper {

    private ClassDumper() {}

    /**
     * 提取单个类的字节码。返回 null 表示提取失败。
     */
    public static byte[] getClassBytes(Instrumentation inst, Class<?> cls) {
        if (cls == null) return null;
        // 方式1: ClassLoader 资源（磁盘存在的类）
        try {
            ClassLoader cl = cls.getClassLoader();
            String path = cls.getName().replace('.', '/') + ".class";
            java.io.InputStream in = null;
            if (cl != null) {
                in = cl.getResourceAsStream(path);
            }
            if (in == null) {
                in = ClassLoader.getSystemResourceAsStream(path);
            }
            if (in != null) {
                byte[] b = readAll(in);
                in.close();
                if (b != null && b.length > 0) return b;
            }
        } catch (Throwable ignored) {
        }

        // 方式2: transformer + retransform（defineClass 注入类专用，Arthas 同款技巧）
        // 注意: addTransformer 第二个参数 canRetransform 必须为 true，
        // 否则 retransformClasses 不会触发该 transformer（关键坑）
        if (inst == null) return null;
        final byte[][] holder = new byte[1][];
        final String targetName = cls.getName().replace('.', '/');
        ClassFileTransformer tf = new ClassFileTransformer() {
            public byte[] transform(ClassLoader loader, String className,
                                    Class<?> classBeingRedefined, ProtectionDomain pd,
                                    byte[] classfileBuffer) {
                // 匹配正在 retransform 的目标类
                if (classBeingRedefined == cls
                        || (className != null && className.equals(targetName))) {
                    holder[0] = classfileBuffer.clone();
                }
                return null; // 只读，不修改
            }
        };
        inst.addTransformer(tf, true);
        try {
            inst.retransformClasses(cls);
        } catch (Throwable t) {
            // 某些类不支持 retransform（JDK 内部类等），忽略
        } finally {
            try {
                inst.removeTransformer(tf);
            } catch (Throwable ignored) {
            }
        }
        return holder[0];
    }

    /**
     * 提取并写入磁盘。
     * @return 落盘文件路径，失败返回 null
     */
    public static String dumpClass(Instrumentation inst, Class<?> cls, File outDir) {
        try {
            byte[] bytes = getClassBytes(inst, cls);
            if (bytes == null || bytes.length == 0) return null;
            if (!outDir.exists()) outDir.mkdirs();
            String safeName = cls.getName().replace('.', '_').replace('$', '_');
            File f = new File(outDir, safeName + ".class");
            FileOutputStream fos = new FileOutputStream(f);
            fos.write(bytes);
            fos.flush();
            fos.close();
            return f.getAbsolutePath();
        } catch (Throwable t) {
            return null;
        }
    }

    /** 从字节码中提取可读字符串（用于快速判断恶意行为与回连地址） */
    public static String extractReadableStrings(byte[] code, int maxLen) {
        if (code == null) return "";
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i < code.length - 1) {
            int len = ((code[i] & 0xFF) << 8) | (code[i + 1] & 0xFF);
            if (len > 0 && len < 512 && i + 2 + len <= code.length) {
                boolean printable = true;
                for (int j = i + 2; j < i + 2 + len; j++) {
                    byte b = code[j];
                    if (b < 0x20 && b != 0x09 && b != 0x0A && b != 0x0D) { printable = false; break; }
                }
                if (printable) {
                    String s = new String(code, i + 2, len, java.nio.charset.StandardCharsets.UTF_8);
                    // 只保留有信息量的字符串（URL/IP/命令/关键字）
                    if (s.length() >= 4 && looksInteresting(s)) {
                        sb.append(s).append('\n');
                        if (sb.length() > maxLen) break;
                    }
                }
            }
            i += 2 + (len > 0 && len < 512 ? len : 0);
        }
        return sb.toString();
    }

    private static boolean looksInteresting(String s) {
        String lower = s.toLowerCase();
        if (lower.contains("http") || lower.contains("://")) return true;
        if (lower.contains("exec") || lower.contains("processbuilder") || lower.contains("runtime")) return true;
        if (lower.contains("socket") || lower.contains("connect") || lower.contains("inet")) return true;
        if (lower.contains(".com") || lower.contains(".cn") || lower.contains(".net") || lower.contains(".io")) return true;
        if (lower.contains("cmd") || lower.contains("shell") || lower.contains("bash") || lower.contains("powershell")) return true;
        if (lower.contains("pass") || lower.contains("key") || lower.contains("token")) return true;
        if (lower.contains("response") || lower.contains("request") || lower.contains("servlet")) return true;
        if (lower.contains("filter") || lower.contains("listener") || lower.contains("valve")) return true;
        if (s.matches(".*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*")) return true;
        return false;
    }

    private static byte[] readAll(java.io.InputStream in) throws Exception {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        return bos.toByteArray();
    }
}
