package com.memshellauditor.rules;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 规则引擎（取证端内置，离线可用）：
 *  从 classpath 的 rules/ 目录加载特征规则（生成取证程序时已打包），
 *  对检测发现项做规则匹配，输出"命中规则"辅助判定。
 *
 * 规则来源优先级：
 *  1. classpath rules/ 目录（取证程序内置，--gen-agent 时打包）
 *  2. 用户主目录 ~/.memshell-rules/rules/（主程序本地）
 *  3. 内置默认规则（兜底）
 */
public class RuleEngine {

    /** 从 classpath 加载规则 */
    public static List<Rule> loadClasspathRules() {
        List<Rule> rules = new ArrayList<Rule>();
        try {
            // 读取 rules/index.json 列表
            InputStream idxIn = RuleEngine.class.getClassLoader()
                    .getResourceAsStream("rules/index.json");
            if (idxIn != null) {
                String idx = readAll(idxIn);
                TinyJson tj = new TinyJson();
                Object parsed = tj.parseObject("{\"x\":" + idx + "}");
                Object x = ((java.util.Map<String, Object>) parsed).get("x");
                if (x instanceof List) {
                    for (Object o : (List<Object>) x) {
                        if (!(o instanceof java.util.Map)) continue;
                        java.util.Map<String, Object> entry = (java.util.Map<String, Object>) o;
                        String id = String.valueOf(entry.get("id"));
                        if (id == null || id.equals("null")) continue;
                        InputStream ruleIn = RuleEngine.class.getClassLoader()
                                .getResourceAsStream("rules/" + id + ".json");
                        if (ruleIn != null) {
                            Rule r = Rule.fromMap(new TinyJson().parseObject(readAll(ruleIn)));
                            if (r.id != null && !r.id.isEmpty()) rules.add(r);
                        }
                    }
                }
            }
        } catch (Throwable t) {
            // ignore
        }
        return rules;
    }

    /** 加载本地用户规则目录 */
    public static List<Rule> loadUserRules() {
        return RuleStore.listRules();
    }

    /** 匹配规则：返回命中的规则 id 列表 */
    public static List<String> matchRules(List<Rule> rules, String category, String signal, String className) {
        List<String> hits = new ArrayList<String>();
        if (rules == null) return hits;
        for (Rule r : rules) {
            if (r.matches(category, signal, className)) {
                hits.add(r.id + ":" + (r.title != null ? r.title : r.name));
            }
        }
        return hits;
    }

    /** 规则状态摘要（用于报告/日志） */
    public static String summarize(List<Rule> rules) {
        if (rules == null || rules.isEmpty()) return "无规则";
        return rules.size() + " 条规则";
    }

    private static String readAll(InputStream in) throws Exception {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        in.close();
        return new String(bos.toByteArray(), StandardCharsets.UTF_8);
    }
}
