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
        // 补充策略情况
        List<Rule> rules = RuleStore.listRules();
        int enabled = 0;
        for (Rule r : rules) if (RuleStore.isSelected(r.id)) enabled++;
        sb.append(" 补充策略: 本地规则 ").append(rules.size()).append(" 条 / 启用 ").append(enabled).append(" 条");
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
        return sb.toString();
    }

    /** 读取规则版本（~/.memshell-rules/version） */
    private static String readRuleVersion() {
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
}
