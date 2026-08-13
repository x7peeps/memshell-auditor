package com.memshellauditor.obf;

import java.io.ByteArrayOutputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * Class 文件常量池重写器（纯字节码级，不依赖 JDK 编译）：
 *  解析 class 文件常量池，对 Utf8 条目做字符串替换（长度可变化），重新序列化。
 *
 * 用途：取证工具自混淆——把 com.memshellauditor 包名、主类名、
 * 敏感字符串（memshell/auditor/webshell 等）替换为随机中性内容，
 * 使生成的取证程序无法被攻击者从进程名/类名/字符串特征识别。
 *
 * 实现要点：
 *  - 按常量池顺序解析，Utf8 条目替换后长度变化，但后续条目从新偏移继续读
 *  - long/double 条目占 2 个槽位（索引跳 2）
 *  - 常量池之后的部分（access_flags/methods/attributes）原样复制
 */
public final class ClassRewriter {

    private ClassRewriter() {}

    /**
     * 重写 class 字节码。
     * @param code 原始 class 字节
     * @param replacements 替换规则（key → value），作用于所有 Utf8 条目内容
     * @return 重写后的 class 字节；解析失败返回 null
     */
    public static byte[] rewrite(byte[] code, Map<String, String> replacements) {
        if (code == null || code.length < 10) return null;
        if (code[0] != (byte) 0xCA || code[1] != (byte) 0xFE || code[2] != (byte) 0xBA || code[3] != (byte) 0xBE) {
            return null;
        }
        try {
            int cpCount = ((code[8] & 0xFF) << 8) | (code[9] & 0xFF);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(code, 0, 10); // magic + minor + major + cp_count
            int idx = 10;
            for (int i = 1; i < cpCount; i++) {
                int tag = code[idx] & 0xFF;
                out.write(tag);
                idx++;
                switch (tag) {
                    case 1: { // Utf8 — 可替换
                        int len = ((code[idx] & 0xFF) << 8) | (code[idx + 1] & 0xFF);
                        idx += 2;
                        String s = new String(code, idx, len, java.nio.charset.StandardCharsets.UTF_8);
                        idx += len;
                        String ns = applyReplacements(s, replacements);
                        byte[] nb = ns.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                        out.write((nb.length >> 8) & 0xFF);
                        out.write(nb.length & 0xFF);
                        out.write(nb);
                        break;
                    }
                    case 7: case 8: case 16: case 19: case 20: { // Class/String/MethodType/Module/Package
                        out.write(code, idx, 2);
                        idx += 2;
                        break;
                    }
                    case 15: { // MethodHandle
                        out.write(code, idx, 3);
                        idx += 3;
                        break;
                    }
                    case 3: case 4: case 9: case 10: case 11: case 12:
                    case 17: case 18: { // int/float/Fieldref/Methodref/InterfaceMethodref/NameAndType/Dynamic/InvokeDynamic
                        out.write(code, idx, 4);
                        idx += 4;
                        break;
                    }
                    case 5: case 6: { // long/double 占 2 槽
                        out.write(code, idx, 8);
                        idx += 8;
                        i++;
                        break;
                    }
                    default: {
                        return null; // 未知 tag，放弃
                    }
                }
            }
            // 常量池之后原样复制
            if (idx < code.length) {
                out.write(code, idx, code.length - idx);
            }
            return out.toByteArray();
        } catch (Throwable t) {
            return null;
        }
    }

    private static String applyReplacements(String s, Map<String, String> reps) {
        if (s == null || reps == null || reps.isEmpty()) return s;
        String r = s;
        for (Map.Entry<String, String> e : reps.entrySet()) {
            if (e.getKey() != null && !e.getKey().isEmpty()) {
                r = r.replace(e.getKey(), e.getValue());
            }
        }
        return r;
    }

    /**
     * 构建替换规则：把原包名替换为新包名。
     * 注意：只替换包名前缀（com.memshellauditor → 新包名），
     * 不替换类名本身（AuditorMain/AgentMain 等保持原名，避免 this_class 不一致）。
     * 敏感字符串（memshell/webshell 等）只出现在常量池文本中，可安全替换；
     * 但 auditor/checker 这类出现在类名中的词不能全局替换，只替换明确的全名标记。
     */
    public static Map<String, String> buildRules(String oldPkg, String newPkg) {
        // LinkedHashMap 保证替换顺序：先包名，后敏感词
        Map<String, String> rules = new java.util.LinkedHashMap<String, String>();
        if (oldPkg != null && newPkg != null) {
            rules.put(oldPkg, newPkg);                       // 斜杠格式
            rules.put(oldPkg.replace('/', '.'), newPkg.replace('/', '.')); // 点分格式
        }
        // 敏感词替换放在包名替换之后；且必须精确匹配独立标记，避免误伤包名
        // 注意：包名已先替换完成，这里只处理剩余文本中的独立词
        rules.put("memshell-auditor", "jre-check");
        rules.put("memshell_auditor", "jre_check");
        rules.put("memshell", "javacore");
        rules.put("Memshell", "Javacore");
        rules.put("Memory Shell", "Java Core");
        rules.put("webshell", "classcore");
        rules.put("WebShell", "ClassCore");
        return rules;
    }
}
