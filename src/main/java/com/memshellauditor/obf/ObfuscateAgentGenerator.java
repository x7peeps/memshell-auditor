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
            // 兜底确保关键属性存在（取证程序 Main-Class 指向现场端 ForensicMain）
            attrs.putValue("Premain-Class", newPkg.replace('/', '.') + ".AgentMain");
            attrs.putValue("Agent-Class", newPkg.replace('/', '.') + ".AgentMain");
            attrs.putValue("Main-Class", newPkg.replace('/', '.') + ".ForensicMain");
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
                    // 取证端不含分析端类（gen-agent/analyze/obf 混淆器只在主程序）
                    if (name.startsWith("com/memshellauditor/obf/")) continue;
                    if (name.startsWith("com/memshellauditor/AuditorMain")) continue;
                    if (name.startsWith("com/memshellauditor/ReportAnalyzer")) continue;
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
                // 6.1 打包已勾选的特征规则（现场离线可用）
                packRules(jos, rules);
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

    /** 打包已勾选的特征规则到 jar 的 rules/ 目录（现场离线检测用） */
    private static void packRules(JarOutputStream jos, Map<String, String> rules) throws Exception {
        try {
            java.io.File rulesDir = com.memshellauditor.rules.RuleStore.rulesDir();
            java.io.File[] files = rulesDir.listFiles();
            if (files == null || files.length == 0) {
                System.out.println("[*] 无本地规则，取证程序使用内置默认规则");
                return;
            }
            int packed = 0;
            StringBuilder index = new StringBuilder();
            index.append("[\n");
            java.util.List<String> packedIds = new java.util.ArrayList<String>();
            for (java.io.File f : files) {
                if (!f.getName().endsWith(".json")) continue;
                String id = f.getName().replace(".json", "");
                // 只打包已勾选规则
                if (!com.memshellauditor.rules.RuleStore.isSelected(id)) continue;
                byte[] data = java.nio.file.Files.readAllBytes(f.toPath());
                // 用规则文件的真实 id 重命名（兼容 id 与文件名不一致：JMSH-001 vs 长文件名）
                String entryName = f.getName();
                try {
                    com.memshellauditor.rules.Rule r = com.memshellauditor.rules.Rule.fromMap(
                            new com.memshellauditor.rules.TinyJson().parseObject(new String(data, "UTF-8")));
                    if (r.id != null && !r.id.isEmpty()) {
                        entryName = com.memshellauditor.rules.RuleStore.sanitize(r.id) + ".json";
                    }
                } catch (Throwable t) {
                    // 保持原文件名
                }
                jos.putNextEntry(new JarEntry("rules/" + entryName));
                jos.write(data);
                jos.closeEntry();
                // 解析规则取 author/title 供 index
                try {
                    com.memshellauditor.rules.Rule r = com.memshellauditor.rules.Rule.fromMap(
                            new com.memshellauditor.rules.TinyJson().parseObject(new String(data, "UTF-8")));
                    if (index.length() > 2) index.append(",\n");
                    index.append("  {\"id\": \"").append(r.id).append("\", \"name\": \"")
                         .append(jsonEscape(r.name)).append("\", \"author\": \"")
                         .append(jsonEscape(r.author)).append("\", \"title\": \"")
                         .append(jsonEscape(r.title)).append("\", \"version\": \"")
                         .append(jsonEscape(r.version)).append("\"}");
                } catch (Throwable t) {
                    if (index.length() > 2) index.append(",\n");
                    index.append("  {\"id\": \"").append(id).append("\", \"name\": \"")
                         .append(id).append("\", \"author\": \"x7peeps\", \"title\": \"")
                         .append(id).append("\", \"version\": \"1.0\"}");
                }
                packedIds.add(id);
                packed++;
            }
            index.append("\n]\n");
            // 打包 index.json（RuleEngine 加载列表依赖它）
            jos.putNextEntry(new JarEntry("rules/index.json"));
            jos.write(index.toString().getBytes("UTF-8"));
            jos.closeEntry();
            System.out.println("[*] 已打包 " + packed + " 条检测规则到取证程序（现场离线可用）");
        } catch (Throwable t) {
            System.err.println("[!] 规则打包失败（取证程序使用内置默认规则）: " + t.getMessage());
        }
    }

    private static String jsonEscape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
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
