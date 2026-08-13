package com.memshellauditor.rules;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 特征库管理器（类 Metasploit 在线更新）：
 *  从 GitHub 拉取/更新/列出/勾选/下载检测特征规则。
 *
 * 命令:
 *   --rules update            # 拉取/更新特征库（默认 x7peeps/memshell-rules）
 *   --rules list              # 列出规则（提交人/标题/勾选状态）
 *   --rules select --all      # 全选
 *   --rules select --id X --id Y  # 逐个勾选
 *   --rules download <repo>   # 下载他人特征库（如 user/repo）
 *   --rules status            # 本地规则状态
 *
 * 默认规则仓库：https://github.com/x7peeps/memshell-rules
 * 规则文件路径：rules/<id>.json（每个规则一个文件，便于 diff/PR）
 */
public class RuleUpdater {

    private static final String DEFAULT_REPO = "x7peeps/memshell-rules";
    private static final String RAW_PREFIX = "https://raw.githubusercontent.com/";

    public static void dispatch(String action, String[] args, Map<String, String> opts) {
        if (action.equals("update") || action.equals("pull") || action.equals("u")) {
            update(opts.get("--repo") != null ? opts.get("--repo") : DEFAULT_REPO);
        } else if (action.equals("list") || action.equals("l")) {
            list();
        } else if (action.equals("select") || action.equals("s")) {
            select(args, opts);
        } else if (action.equals("download") || action.equals("d")) {
            String repo = (args.length > 2 && !args[2].startsWith("--")) ? args[2]
                    : opts.get("--repo");
            if (repo == null) {
                System.err.println("[!] 用法: --rules download <user/repo>");
                return;
            }
            update(repo);
        } else if (action.equals("status") || action.equals("st")) {
            status();
        } else if (action.equals("help") || action.equals("h")) {
            System.out.println("--rules <update|list|select|download|status>");
            System.out.println("  update             拉取/更新特征库 (默认 " + DEFAULT_REPO + ")");
            System.out.println("  list               列出规则（提交人/标题/勾选状态）");
            System.out.println("  select --all       全选规则");
            System.out.println("  select --id X      逐个勾选规则（可多个 --id）");
            System.out.println("  download <repo>    下载他人特征库 (如 other/memshell-rules)");
            System.out.println("  status             本地规则状态");
        } else {
            System.out.println("[!] 未知动作: " + action + " （--rules help 查看用法）");
        }
    }

    /** 从 GitHub 拉取特征库（增量同步：只覆盖官方规则，保留本地自定义） */
    public static void update(String repo) {
        System.out.println("[*] 从 " + repo + " 拉取特征库...");
        // 拉取策略版本
        String ver = fetch(RAW_PREFIX + repo + "/main/version");
        if (ver == null) ver = fetch(RAW_PREFIX + repo + "/master/version");
        if (ver != null && !ver.trim().isEmpty()) {
            com.memshellauditor.VersionInfo.writeRuleVersion(ver.trim());
            System.out.println("[*] 策略版本: " + ver.trim());
        }
        String indexUrl = RAW_PREFIX + repo + "/main/rules/index.json";
        String indexContent = fetch(indexUrl);
        if (indexContent == null) {
            indexContent = fetch(RAW_PREFIX + repo + "/master/rules/index.json");
        }
        if (indexContent == null) {
            System.err.println("[!] 拉取失败（网络不可达或仓库不存在）");
            System.err.println("  离线场景可手动放置规则文件到 ~/.memshell-rules/rules/");
            com.memshellauditor.VersionInfo.writeUpdateStatus("failed", "拉取 index 失败");
            return;
        }
        // 解析 index（数组或对象）
        TinyJson tj = new TinyJson();
        Object parsed = tj.parseObject("{\"x\":" + indexContent + "}");
        Map<String, Object> root = (Map<String, Object>) parsed;
        Object x = root.get("x");
        List<Object> list = new ArrayList<Object>();
        if (x instanceof List) {
            list = (List<Object>) x;
        } else if (x instanceof Map) {
            Map<String, Object> m = (Map<String, Object>) x;
            list.add(m);
        }
        System.out.println("[*] index 发现 " + list.size() + " 条官方规则");
        int ok = 0, fail = 0, custom = RuleStore.listCustomRules().size();
        java.util.Set<String> officialIds = new java.util.HashSet<String>();
        for (Object o : list) {
            if (!(o instanceof Map)) continue;
            Map<String, Object> entry = (Map<String, Object>) o;
            String id = str(entry.get("id"));
            if (id == null || id.isEmpty()) continue;
            officialIds.add(id);
            String ruleUrl = RAW_PREFIX + repo + "/main/rules/" + RuleStore.sanitize(id) + ".json";
            String ruleJson = fetch(ruleUrl);
            if (ruleJson == null) {
                ruleUrl = RAW_PREFIX + repo + "/master/rules/" + RuleStore.sanitize(id) + ".json";
                ruleJson = fetch(ruleUrl);
            }
            if (ruleJson != null) {
                Rule rule = Rule.fromMap(new TinyJson().parseObject(ruleJson));
                rule.origin = "official";
                RuleStore.saveRule(rule);
                ok++;
                System.out.println("  ✓ " + id + "  " + truncate(rule.name, 50)
                        + "  (by " + rule.author + ")");
            } else {
                fail++;
                System.out.println("  ✗ " + id + " 规则文件拉取失败");
            }
        }
        // 增量同步：删除"官方目录中但官方索引已移除"的规则（保持官方目录与索引一致）
        // 注意：自定义目录 rules-custom/ 完全不动，用户规则永不误删
        int removed = 0;
        try {
            java.io.File[] localOfficial = RuleStore.rulesDir().listFiles();
            if (localOfficial != null) {
                for (java.io.File f : localOfficial) {
                    if (!f.getName().endsWith(".json")) continue;
                    String id = f.getName().replace(".json", "");
                    if (!officialIds.contains(id)) {
                        f.delete();
                        removed++;
                        System.out.println("  - " + id + " 已从官方目录移除（不在官方索引中）");
                    }
                }
            }
        } catch (Throwable t) {
            // ignore
        }
        System.out.println("[*] 更新完成: 成功 " + ok + ", 失败 " + fail
                + ", 官方移除 " + removed + ", 自定义规则保留 " + custom + " 条");
        // 版本联动：更新成功则推进策略版本（若已有旧版本则 bump minor）
        String oldVer = com.memshellauditor.VersionInfo.readRuleVersion();
        if (ver != null && !ver.trim().isEmpty()) {
            if (oldVer != null && !oldVer.equals(ver.trim())) {
                System.out.println("[*] 策略版本: " + oldVer + " → " + ver.trim());
            }
            com.memshellauditor.VersionInfo.writeRuleVersion(ver.trim());
            com.memshellauditor.VersionInfo.writeUpdateStatus("ok", ver.trim() + ", " + ok + " 条规则");
        } else {
            // 拉不到远端版本但有本地版本 → 本地推进（策略更新出问题时版本也更新，便于识别）
            if (oldVer != null) {
                String bumped = bumpVersion(oldVer);
                com.memshellauditor.VersionInfo.writeRuleVersion(bumped);
                com.memshellauditor.VersionInfo.writeUpdateStatus("partial", "远端版本不可达，本地版本推进至 " + bumped);
                System.out.println("[*] 远端版本不可达，本地策略版本推进至 " + bumped + "（更新状态: partial）");
            }
        }
        System.out.println("  本地规则目录: " + RuleStore.rulesDir().getAbsolutePath());
    }

    /** 版本号推进（1.0.0 → 1.0.1 → 1.1.0） */
    private static String bumpVersion(String ver) {
        try {
            String[] parts = ver.trim().split("\\.");
            if (parts.length == 3) {
                int patch = Integer.parseInt(parts[2]) + 1;
                return parts[0] + "." + parts[1] + "." + patch;
            }
        } catch (Throwable t) {
            // ignore
        }
        return ver + ".1";
    }

    /** 列出规则（提交人/标题/勾选状态） */
    public static void list() {
        List<Rule> rules = RuleStore.listRules();
        if (rules.isEmpty()) {
            System.out.println("[*] 本地无规则（执行 --rules update 拉取）");
            return;
        }
        System.out.println("[*] 本地规则 " + rules.size() + " 条：");
        System.out.println("  ID        状态  等级   提交人      标题");
        System.out.println("  --------------------------------------------------------------------");
        for (Rule r : rules) {
            String sel = RuleStore.isSelected(r.id) ? "✓" : " ";
            System.out.printf("  %-10s [%s]  %-6s %-12s %s%n",
                    r.id, sel, r.level, r.author, truncate(r.title != null ? r.title : r.name, 60));
        }
    }

    /** 勾选规则 */
    public static void select(String[] args, Map<String, String> opts) {
        List<Rule> rules = RuleStore.listRules();
        if (rules.isEmpty()) {
            System.out.println("[!] 本地无规则，先执行 --rules update");
            return;
        }
        if (opts.containsKey("--all") || contains(args, "--all")) {
            List<String> ids = new ArrayList<String>();
            for (Rule r : rules) ids.add(r.id);
            RuleStore.saveSelection(ids);
            System.out.println("[*] 已全选 " + ids.size() + " 条规则");
            return;
        }
        // 逐个勾选
        List<String> ids = new ArrayList<String>();
        boolean hasId = false;
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("--id") && i + 1 < args.length) {
                ids.add(args[i + 1]);
                hasId = true;
                i++;
            }
        }
        if (!hasId) {
            System.out.println("[!] 用法: --rules select --all  或  --rules select --id JMSH-001 --id JMSH-002");
            return;
        }
        // 合并已选
        List<String> finalIds = new ArrayList<String>();
        for (Rule r : rules) {
            if (RuleStore.isSelected(r.id) || ids.contains(r.id)) {
                finalIds.add(r.id);
            }
        }
        RuleStore.saveSelection(finalIds);
        System.out.println("[*] 勾选 " + ids.size() + " 条，当前启用 " + finalIds.size() + " 条");
    }

    /** 本地状态 */
    public static void status() {
        List<Rule> rules = RuleStore.listRules();
        int enabled = 0;
        for (Rule r : rules) if (RuleStore.isSelected(r.id)) enabled++;
        System.out.println("本地特征库状态:");
        System.out.println("  规则目录: " + RuleStore.rulesDir().getAbsolutePath());
        System.out.println("  规则总数: " + rules.size());
        System.out.println("  启用规则: " + enabled);
        System.out.println("  默认仓库: " + DEFAULT_REPO);
        System.out.println("  上次更新: " + (rules.isEmpty() ? "从未" : "见各规则文件 mtime"));
    }

    /** HTTP GET 拉取（零依赖，支持 HTTP_PROXY/HTTPS_PROXY 环境变量代理） */
    private static String fetch(String urlStr) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(30000);
            conn.setRequestProperty("User-Agent", "memshell-auditor-rules");
            // 代理支持：HTTPS_PROXY / HTTP_PROXY 环境变量（取证人员内网环境常用）
            String proxy = System.getenv("HTTPS_PROXY");
            if (proxy == null || proxy.isEmpty()) proxy = System.getenv("https_proxy");
            if (proxy == null || proxy.isEmpty()) proxy = System.getenv("HTTP_PROXY");
            if (proxy == null || proxy.isEmpty()) proxy = System.getenv("http_proxy");
            if (proxy != null && !proxy.isEmpty()) {
                try {
                    java.net.URI proxyUri = new java.net.URI(proxy.startsWith("http") ? proxy : "http://" + proxy);
                    java.net.InetSocketAddress addr = new java.net.InetSocketAddress(
                            proxyUri.getHost(), proxyUri.getPort() > 0 ? proxyUri.getPort() : 80);
                    conn.setConnectTimeout(20000);
                    java.net.Proxy p = new java.net.Proxy(java.net.Proxy.Type.HTTP, addr);
                    conn = (HttpURLConnection) url.openConnection(p);
                    conn.setConnectTimeout(20000);
                    conn.setReadTimeout(30000);
                    conn.setRequestProperty("User-Agent", "memshell-auditor-rules");
                } catch (Throwable t) {
                    // 代理解析失败则直连
                }
            }
            int code = conn.getResponseCode();
            if (code != 200) return null;
            InputStream in = conn.getInputStream();
            BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) sb.append(line).append('\n');
            br.close();
            return sb.toString();
        } catch (Throwable t) {
            return null;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    private static boolean contains(String[] args, String v) {
        if (args == null) return false;
        for (String a : args) if (v.equals(a)) return true;
        return false;
    }

    private static String str(Object o) {
        return o == null ? "" : String.valueOf(o);
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
