package com.memshellauditor;

import com.memshellauditor.rules.Rule;
import com.memshellauditor.rules.RuleStore;

import java.io.File;
import java.util.List;

/**
 * 工具版本与策略版本展示（主程序运行时输出）：
 *  - 工具版本：memshell-auditor v2.0
 *  - 策略版本：本地特征库版本（rules/version 文件），无则提示"内置默认"
 *  - 补充策略情况：规则总数/启用数/最近更新时间/来源仓库
 *  - 作者署名：x7peeps
 */
public class VersionInfo {

    public static final String TOOL_VERSION = "v2.0";
    public static final String AUTHOR = "x7peeps";
    public static final String RULES_REPO = "x7peeps/memshell-rules";

    /** 主程序启动横幅（含策略版本与署名） */
    public static String banner() {
        StringBuilder sb = new StringBuilder();
        sb.append("==========================================\n");
        sb.append(" memshell-auditor ").append(TOOL_VERSION).append("  Java 内存马审计平台\n");
        sb.append(" 作者: ").append(AUTHOR).append("  |  规则库: ").append(RULES_REPO).append("\n");
        sb.append("------------------------------------------\n");
        // 策略版本与补充策略情况
        sb.append(policyInfo());
        sb.append("==========================================\n");
        return sb.toString();
    }

    /** 策略（规则库）版本与补充情况 */
    public static String policyInfo() {
        StringBuilder sb = new StringBuilder();
        // 策略版本
        String version = readRuleVersion();
        if (version != null && !version.isEmpty()) {
            sb.append(" 策略版本: ").append(version).append("\n");
        } else {
            sb.append(" 策略版本: 内置默认（未同步规则库，执行 --rules update 获取最新）\n");
        }
        // 补充策略情况（官方 + 自定义分开统计）
        List<Rule> rules = RuleStore.listRules();
        int enabled = 0;
        for (Rule r : rules) if (RuleStore.isSelected(r.id)) enabled++;
        int custom = RuleStore.listCustomRules().size();
        sb.append(" 补充策略: 规则 ").append(rules.size()).append(" 条（官方 ").append(rules.size() - custom)
          .append(" / 自定义 ").append(custom).append("）启用 ").append(enabled).append(" 条");
        if (!rules.isEmpty()) {
            File[] files = RuleStore.rulesDir().listFiles();
            long maxMtime = 0;
            if (files != null) {
                for (File f : files) if (f.lastModified() > maxMtime) maxMtime = f.lastModified();
            }
            if (maxMtime > 0) {
                sb.append(" / 最近更新: ").append(new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm").format(new java.util.Date(maxMtime)));
            }
        }
        sb.append("\n");
        // 更新状态（failed/partial 时提示）
        String status = lastUpdateStatus();
        if (status != null) {
            if (status.contains("| failed") || status.contains("| partial")) {
                sb.append(" ⚠️ 上次策略更新状态: ").append(status).append("\n");
                sb.append("   建议重新执行 --rules update 同步（自定义规则已保留）\n");
            }
        }
        return sb.toString();
    }

    /** 读取规则版本（~/.memshell-rules/version） */
    public static String readRuleVersion() {
        try {
            File vf = new File(System.getProperty("user.home"), ".memshell-rules/version");
            if (vf.exists()) {
                String v = new String(java.nio.file.Files.readAllBytes(vf.toPath()), "UTF-8").trim();
                return v.isEmpty() ? null : v;
            }
        } catch (Throwable t) {
            // ignore
        }
        return null;
    }

    /** 记录规则版本（--rules update 成功后写） */
    public static void writeRuleVersion(String version) {
        try {
            File dir = new File(System.getProperty("user.home"), ".memshell-rules");
            dir.mkdirs();
            java.nio.file.Files.write(new File(dir, "version").toPath(),
                    version.getBytes("UTF-8"));
        } catch (Throwable t) {
            // ignore
        }
    }

    /** 记录最近一次策略更新状态（ok/failed/partial） */
    public static void writeUpdateStatus(String status, String detail) {
        try {
            File dir = new File(System.getProperty("user.home"), ".memshell-rules");
            dir.mkdirs();
            String line = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new java.util.Date())
                    + " | " + status + " | " + detail + "\n";
            File f = new File(dir, "update-status.log");
            // 只保留最近 20 条
            java.util.List<String> lines = new java.util.ArrayList<String>();
            if (f.exists()) {
                lines.addAll(java.nio.file.Files.readAllLines(f.toPath(), java.nio.charset.StandardCharsets.UTF_8));
            }
            lines.add(line.trim());
            if (lines.size() > 20) lines = lines.subList(lines.size() - 20, lines.size());
            StringBuilder sb = new StringBuilder();
            for (String l : lines) sb.append(l).append('\n');
            java.nio.file.Files.write(f.toPath(), sb.toString().getBytes("UTF-8"));
        } catch (Throwable t) {
            // ignore
        }
    }

    /** 读取最近一次更新状态（供 banner 展示） */
    public static String lastUpdateStatus() {
        try {
            File f = new File(System.getProperty("user.home"), ".memshell-rules/update-status.log");
            if (f.exists()) {
                java.util.List<String> lines = java.nio.file.Files.readAllLines(f.toPath(),
                        java.nio.charset.StandardCharsets.UTF_8);
                if (!lines.isEmpty()) return lines.get(lines.size() - 1);
            }
        } catch (Throwable t) {
            // ignore
        }
        return null;
    }

    /** 检查工具最新版本（GitHub releases API，失败返回 null 不阻塞） */
    public static String checkLatestToolVersion() {
        try {
            String url = "https://api.github.com/repos/x7peeps/memshell-auditor/releases/latest";
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) new java.net.URL(url).openConnection();
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(15000);
            conn.setRequestProperty("User-Agent", "memshell-auditor");
            int code = conn.getResponseCode();
            if (code != 200) return null;
            java.io.BufferedReader br = new java.io.BufferedReader(new java.io.InputStreamReader(
                    conn.getInputStream(), java.nio.charset.StandardCharsets.UTF_8));
            String line;
            String tag = null;
            while ((line = br.readLine()) != null) {
                int idx = line.indexOf("\"tag_name\"");
                if (idx >= 0) {
                    int s = line.indexOf('"', idx + 12);
                    int e = line.indexOf('"', s + 1);
                    if (s >= 0 && e > s) {
                        tag = line.substring(s + 1, e);
                        break;
                    }
                }
            }
            br.close();
            return tag;
        } catch (Throwable t) {
            return null;
        }
    }
}
