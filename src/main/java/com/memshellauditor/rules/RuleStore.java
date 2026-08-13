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

    /** 用户自定义规则目录（--rules update 时保留，不覆盖不删除） */
    public static File customRulesDir() {
        File d = new File(baseDir(), "rules-custom");
        if (!d.exists()) d.mkdirs();
        return d;
    }

    /** 判断规则是否官方（来自官方索引，更新时可覆盖） */
    public static boolean isOfficial(String ruleId) {
        try {
            File f = indexFile();
            if (!f.exists()) return true; // 无索引时默认官方
            String content = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
            return content.contains("\"" + ruleId + "\"");
        } catch (Throwable t) {
            return true;
        }
    }

    /** 保存规则：官方规则存 rules/，自定义规则存 rules-custom/ */
    public static void saveRule(Rule rule) {
        try {
            File targetDir = "custom".equals(rule.origin) ? customRulesDir() : rulesDir();
            File f = new File(targetDir, sanitize(rule.id) + ".json");
            PrintWriter pw = new PrintWriter(new OutputStreamWriter(
                    new FileOutputStream(f), StandardCharsets.UTF_8));
            pw.print(rule.toJson());
            pw.flush();
            pw.close();
        } catch (Throwable t) {
            System.err.println("[!] 保存规则失败: " + t.getMessage());
        }
    }

    /** 列出本地全部规则（官方 + 自定义） */
    public static List<Rule> listRules() {
        List<Rule> rules = new ArrayList<Rule>();
        rules.addAll(listRulesIn(rulesDir()));
        rules.addAll(listRulesIn(customRulesDir()));
        return rules;
    }

    /** 仅列出官方规则 */
    public static List<Rule> listOfficialRules() {
        return listRulesIn(rulesDir());
    }

    /** 仅列出用户自定义规则 */
    public static List<Rule> listCustomRules() {
        return listRulesIn(customRulesDir());
    }

    private static List<Rule> listRulesIn(File dir) {
        List<Rule> rules = new ArrayList<Rule>();
        File[] files = dir.listFiles();
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

    public static File indexFile() {
        return new File(baseDir(), "index.json");
    }

    public static File selectedFile() {
        return new File(baseDir(), "selected.json");
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
