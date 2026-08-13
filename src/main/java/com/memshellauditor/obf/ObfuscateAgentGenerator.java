package com.memshellauditor.obf;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

/**
 * 混淆取证程序生成器（取证工具自防识别）：
 *  读取自身 jar 中的全部 class，做常量池级混淆重写（类名/包名/敏感字符串），
 *  重新打包为"随机文件名 + 混淆特征"的取证程序。
 *
 * 用法（主程序）:
 *   java -jar memshell-auditor.jar --gen-agent <输出目录> [--name-prefix <前缀>]
 *
 * 生成后：
 *   java -jar <随机名>.jar <pid> --dump ... --heap ... --ai-config ...
 *   功能与主程序完全一致，但进程名/类名/字符串特征不可识别。
 */
public final class ObfuscateAgentGenerator {

    private static final Random RAND = new Random();

    private ObfuscateAgentGenerator() {}

    /**
     * 生成混淆取证程序。
     * @return 生成的 jar 文件；失败返回 null
     */
    public static File generate(File outDir, String namePrefix) {
        try {
            if (!outDir.exists()) outDir.mkdirs();

            // 1. 定位自身 jar
            File self = null;
            try {
                self = new File(ObfuscateAgentGenerator.class.getProtectionDomain()
                        .getCodeSource().getLocation().toURI());
            } catch (Throwable t) {
                return null;
            }
            if (self == null || !self.isFile() || !self.getName().endsWith(".jar")) return null;

            // 2. 随机生成混淆参数
            String newPkg = randomPackage();          // 随机包名（斜杠）
            String prefix = (namePrefix != null && !namePrefix.isEmpty())
                    ? sanitize(namePrefix) : "jre-check";
            String randSuffix = randomHex(6);
            String outName = prefix + "-" + randSuffix + ".jar";

            // 3. 读取原 jar 的 Manifest（用于 Agent-Class 重写）
            JarFile jf = new JarFile(self);
            Manifest man = jf.getManifest();

            // 5. 重写规则
            Map<String, String> rules = ClassRewriter.buildRules(
                    "com/memshellauditor", newPkg);

            // 5.1 构建新 Manifest（重写 Agent-Class/Main-Class/Premain-Class 指向新包名）
            Manifest newMan = new Manifest();
            java.util.jar.Attributes attrs = newMan.getMainAttributes();
            attrs.put(java.util.jar.Attributes.Name.MANIFEST_VERSION, "1.0");
            if (man != null) {
                java.util.jar.Attributes old = man.getMainAttributes();
                for (Object key : old.keySet()) {
                    String k = String.valueOf(key);
                    String v = String.valueOf(old.get(key));
                    // 类名引用重写：com.memshellauditor.AgentMain → 新包名.AgentMain
                    if (v.contains("com.memshellauditor")) {
                        v = v.replace("com.memshellauditor", newPkg.replace('/', '.'));
                    }
                    attrs.putValue(k, v);
                }
            }
            // 兜底确保关键属性存在
            attrs.putValue("Premain-Class", newPkg.replace('/', '.') + ".AgentMain");
            attrs.putValue("Agent-Class", newPkg.replace('/', '.') + ".AgentMain");
            attrs.putValue("Main-Class", newPkg.replace('/', '.') + ".AuditorMain");
            attrs.putValue("Can-Redefine-Classes", "true");
            attrs.putValue("Can-Retransform-Classes", "true");
            attrs.putValue("Can-Set-Native-Method-Prefix", "true");

            // 6. 遍历 class 重写，其他资源原样复制
            File outJar = new File(outDir, outName);
            JarOutputStream jos = new JarOutputStream(new FileOutputStream(outJar), newMan);
            try {
                Enumeration<JarEntry> entries = jf.entries();
                while (entries.hasMoreElements()) {
                    JarEntry e = entries.nextElement();
                    String name = e.getName();
                    // 取证端不含 AI 模块（AI 能力仅在主程序）
                    if (name.startsWith("com/memshellauditor/ai/")) continue;
                    // JarOutputStream(Manifest) 已自动写入 MANIFEST.MF，跳过原条目避免 duplicate
                    if (name.equals("META-INF/MANIFEST.MF")) continue;
                    if (e.isDirectory()) {
                        jos.putNextEntry(new JarEntry(name));
                        jos.closeEntry();
                        continue;
                    }
                    byte[] data = readAll(jf.getInputStream(e));
                    if (name.endsWith(".class")) {
                        // 重写 class
                        byte[] rewritten = ClassRewriter.rewrite(data, rules);
                        if (rewritten != null) {
                            // 更新 class 路径（包名变化）
                            String newName = rewriteEntryName(name, "com/memshellauditor", newPkg);
                            jos.putNextEntry(new JarEntry(newName));
                            jos.write(rewritten);
                            jos.closeEntry();
                            continue;
                        }
                    }
                    // 原样复制
                    jos.putNextEntry(new JarEntry(name));
                    jos.write(data);
                    jos.closeEntry();
                }
            } finally {
                jos.close();
                jf.close();
            }
            return outJar;
        } catch (Throwable t) {
            t.printStackTrace(System.err);
            return null;
        }
    }

    /** 重写 class 条目路径（包名替换） */
    private static String rewriteEntryName(String entryName, String oldPkg, String newPkg) {
        if (entryName == null) return entryName;
        return entryName.replace(oldPkg, newPkg);
    }

    private static String randomPackage() {
        // 生成类似 com/java/core/check 的随机包名（模仿常见 JDK/系统包）
        String[] top = {"com", "org", "net", "io"};
        String[] middle = {"java", "jre", "jvm", "core", "system", "util", "runtime"};
        String[] leaf = {"check", "scan", "diag", "monitor", "probe", "view", "meta"};
        return top[RAND.nextInt(top.length)] + "/" + middle[RAND.nextInt(middle.length)]
                + "/" + leaf[RAND.nextInt(leaf.length)];
    }

    private static String randomHex(int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n; i++) {
            sb.append("0123456789abcdef".charAt(RAND.nextInt(16)));
        }
        return sb.toString();
    }

    private static String sanitize(String s) {
        return s.replaceAll("[^a-zA-Z0-9_-]", "-");
    }

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        return bos.toByteArray();
    }
}
