package com.memshellauditor.rules;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/**
 * 本地特征库存储：
 *  - rules/<ruleId>.json     规则文件
 *  - index.json              规则索引（id/name/author/title/version/enabled）
 *  - selected.json           勾选状态（全选/逐个）
 *
 * 目录结构（用户主目录下 .memshell-rules/）：
 *   ~/.memshell-rules/
 *   ├── rules/
 *   ├── index.json
 *   └── selected.json
 */
public class RuleStore {

    private static File baseDir() {
        String home = System.getProperty("user.home", ".");
        return new File(home, ".memshell-rules");
    }

    public static File rulesDir() {
        File d = new File(baseDir(), "rules");
        if (!d.exists()) d.mkdirs();
        return d;
    }

    public static File indexFile() {
        return new File(baseDir(), "index.json");
    }

    public static File selectedFile() {
        return new File(baseDir(), "selected.json");
    }

    /** 保存规则到本地 */
    public static void saveRule(Rule rule) {
        try {
            File f = new File(rulesDir(), sanitize(rule.id) + ".json");
            PrintWriter pw = new PrintWriter(new OutputStreamWriter(
                    new FileOutputStream(f), StandardCharsets.UTF_8));
            pw.print(rule.toJson());
            pw.flush();
            pw.close();
        } catch (Throwable t) {
            System.err.println("[!] 保存规则失败: " + t.getMessage());
        }
    }

    /** 列出本地全部规则（从 index 或规则文件读取） */
    public static List<Rule> listRules() {
        List<Rule> rules = new ArrayList<Rule>();
        File[] files = rulesDir().listFiles();
        if (files == null) return rules;
        for (File f : files) {
            if (!f.getName().endsWith(".json")) continue;
            try {
                String content = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
                Rule r = Rule.fromMap(new TinyJson().parseObject(content));
                if (r.id != null && !r.id.isEmpty()) rules.add(r);
            } catch (Throwable ignored) {
            }
        }
        return rules;
    }

    /** 获取规则勾选状态 */
    public static boolean isSelected(String ruleId) {
        try {
            File f = selectedFile();
            if (!f.exists()) return true; // 默认全选
            String content = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
            return content.contains("\"" + ruleId + "\"");
        } catch (Throwable t) {
            return true;
        }
    }

    /** 保存勾选状态 */
    public static void saveSelection(List<String> selectedIds) {
        try {
            PrintWriter pw = new PrintWriter(new OutputStreamWriter(
                    new FileOutputStream(selectedFile()), StandardCharsets.UTF_8));
            pw.println("[");
            for (int i = 0; i < selectedIds.size(); i++) {
                pw.print("  \"" + selectedIds.get(i) + "\"");
                pw.println(i < selectedIds.size() - 1 ? "," : "");
            }
            pw.println("]");
            pw.flush();
            pw.close();
        } catch (Throwable t) {
            System.err.println("[!] 保存勾选失败: " + t.getMessage());
        }
    }

    public static String sanitize(String s) {
        if (s == null) return "rule";
        return s.replaceAll("[^a-zA-Z0-9_-]", "_");
    }
}
