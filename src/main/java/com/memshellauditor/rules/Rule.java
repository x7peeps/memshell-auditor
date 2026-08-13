package com.memshellauditor.rules;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * 内存马检测特征规则模型（可扩展，JSON 加载）。
 *
 * 规则结构（对应 memshell-rules 仓库 template.json）：
 * {
 *   "id": "JMSH-001",
 *   "name": "Tomcat Filter 磁盘无 class 文件",
 *   "signal": "A1",
 *   "category": "Filter",
 *   "level": "HIGH",
 *   "author": "x7peeps",
 *   "title": "冰蝎 Filter 内存马特征",
 *   "version": "1.0",
 *   "description": "...",
 *   "match": {
 *     "type": "filterdef_no_class_on_disk | classname_pattern | behavior_pattern | loader_suspect | agent_transformer",
 *     "classname_regex": "可选正则",
 *     "behavior_keywords": ["Runtime.getRuntime", "ProcessBuilder", "Cipher", "Socket"],
 *     "min_behaviors": 2
 *   }
 * }
 */
public class Rule {

    public String id;
    public String name;
    public String signal;      // A1..B5 / N/A
    public String category;    // Filter/Servlet/Listener/Valve/Agent/ClassLoader/ClassFeature/Heuristic
    public String level;       // HIGH/MEDIUM/LOW/INFO
    public String author;
    public String title;
    public String version;
    public String description;
    public String origin = "official"; // official=官方规则库 / custom=用户本地自定义（更新时保留）
    public Match match = new Match();

    /** 匹配条件 */
    public static class Match {
        public String type;                 // filterdef_no_class_on_disk / classname_pattern / behavior_pattern / loader_suspect / agent_transformer
        public String classnameRegex;       // 类名正则
        public List<String> behaviorKeywords = new ArrayList<String>(); // 行为关键字
        public int minBehaviors = 2;        // 最少命中行为数
        public String loaderPrefix;         // ClassLoader 前缀特征
        public boolean diskCheck = false;   // 是否要求磁盘无 class
    }

    /** 是否匹配某条发现项（简化匹配：按 category+signal 与类名/行为特征粗筛，具体匹配在审计器内做） */
    public boolean matches(String findingCategory, String findingSignal, String className) {
        if (category != null && !category.isEmpty() && !category.equalsIgnoreCase(findingCategory)) {
            return false;
        }
        if (signal != null && !signal.isEmpty() && !signal.equals("N/A") && !signal.equalsIgnoreCase(findingSignal)) {
            return false;
        }
        if (className != null && match != null && match.classnameRegex != null
                && !match.classnameRegex.isEmpty()) {
            try {
                if (!className.matches(match.classnameRegex)) return false;
            } catch (Throwable t) {
                return false;
            }
        }
        return true;
    }

    /** 从 Map（JSON 解析结果）构建 Rule */
    @SuppressWarnings("unchecked")
    public static Rule fromMap(Map<String, Object> map) {
        Rule r = new Rule();
        r.id = str(map.get("id"));
        r.name = str(map.get("name"));
        r.signal = str(map.get("signal"));
        r.category = str(map.get("category"));
        r.level = str(map.get("level"));
        r.author = str(map.get("author"));
        r.title = str(map.get("title"));
        r.version = str(map.get("version"));
        r.description = str(map.get("description"));
        Object originObj = map.get("origin");
        r.origin = originObj == null ? "official" : String.valueOf(originObj);
        Object m = map.get("match");
        if (m instanceof Map) {
            Map<String, Object> mm = (Map<String, Object>) m;
            r.match.type = str(mm.get("type"));
            r.match.classnameRegex = str(mm.get("classname_regex"));
            r.match.minBehaviors = intVal(mm.get("min_behaviors"), 2);
            r.match.loaderPrefix = str(mm.get("loader_prefix"));
            r.match.diskCheck = Boolean.TRUE.equals(mm.get("disk_check"));
            Object bk = mm.get("behavior_keywords");
            if (bk instanceof List) {
                for (Object o : (List<Object>) bk) {
                    if (o != null) r.match.behaviorKeywords.add(String.valueOf(o));
                }
            }
        }
        return r;
    }

    /** 规则转 JSON 字符串（提交包/模板用） */
    public String toJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"id\": \"").append(jsonEsc(id)).append("\",\n");
        sb.append("  \"name\": \"").append(jsonEsc(name)).append("\",\n");
        sb.append("  \"signal\": \"").append(jsonEsc(signal)).append("\",\n");
        sb.append("  \"category\": \"").append(jsonEsc(category)).append("\",\n");
        sb.append("  \"level\": \"").append(jsonEsc(level)).append("\",\n");
        sb.append("  \"author\": \"").append(jsonEsc(author)).append("\",\n");
        sb.append("  \"title\": \"").append(jsonEsc(title)).append("\",\n");
        sb.append("  \"version\": \"").append(jsonEsc(version)).append("\",\n");
        sb.append("  \"origin\": \"").append(jsonEsc(origin)).append("\",\n");
        sb.append("  \"description\": \"").append(jsonEsc(description)).append("\",\n");
        sb.append("  \"match\": {\n");
        sb.append("    \"type\": \"").append(jsonEsc(match.type)).append("\",\n");
        sb.append("    \"classname_regex\": \"").append(jsonEsc(match.classnameRegex)).append("\",\n");
        sb.append("    \"behavior_keywords\": [");
        for (int i = 0; i < match.behaviorKeywords.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append("\"").append(jsonEsc(match.behaviorKeywords.get(i))).append("\"");
        }
        sb.append("],\n");
        sb.append("    \"min_behaviors\": ").append(match.minBehaviors).append(",\n");
        sb.append("    \"loader_prefix\": \"").append(jsonEsc(match.loaderPrefix)).append("\",\n");
        sb.append("    \"disk_check\": ").append(match.diskCheck).append("\n");
        sb.append("  }\n");
        sb.append("}");
        return sb.toString();
    }

    private static String str(Object o) {
        return o == null ? "" : String.valueOf(o);
    }

    private static int intVal(Object o, int def) {
        if (o == null) return def;
        try { return Integer.parseInt(String.valueOf(o)); } catch (Throwable t) { return def; }
    }

    private static String jsonEsc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
