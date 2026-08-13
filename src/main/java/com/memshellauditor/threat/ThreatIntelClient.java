package com.memshellauditor.threat;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;

/**
 * 威胁情报客户端（解决回连分析噪声）：
 *  对疑似回连 IP 自动查询威胁情报，判定恶意性（微步在线 API，零依赖）。
 *
 * 微步在线：https://api.threatbook.cn/v3/scene/ip_reputation
 *  请求: ?apikey=<key>&resource=<ip>
 *  返回: {response_code:0, data:{severity:high/middle/low/info, judgments:[...], ...}}
 *
 * 无需 API key 时可降级使用 IP 地理位置 + 端口特征启发式。
 */
public class ThreatIntelClient {

    public static class IntelResult {
        public String ip;
        public String severity;      // high / middle / low / info / unknown
        public String judgments;     // 威胁判定描述
        public String location;      // 地理位置（启发式）
        public boolean verdict;      // 是否判定恶意
        public String source;        // api / heuristic / none
    }

    private final String apiKey;

    public ThreatIntelClient(String apiKey) {
        this.apiKey = apiKey;
    }

    /** 查询单个 IP */
    public IntelResult lookup(String ip) {
        IntelResult r = new IntelResult();
        r.ip = ip;
        r.severity = "unknown";
        r.judgments = "";
        r.source = "none";
        if (apiKey != null && !apiKey.isEmpty()) {
            try {
                String json = queryThreatBook(ip);
                parseThreatBook(json, r);
                r.source = "api";
            } catch (Throwable t) {
                // API 失败降级启发式
            }
        }
        if (r.source.equals("none") || r.severity.equals("unknown")) {
            heuristic(ip, r);
            if (r.source.equals("none")) r.source = "heuristic";
        }
        r.verdict = "high".equals(r.severity) || "middle".equals(r.severity);
        return r;
    }

    /** 批量查询（带并发限制） */
    public List<IntelResult> lookupAll(List<String> ips) {
        List<IntelResult> results = new ArrayList<IntelResult>();
        for (String ip : ips) {
            results.add(lookup(ip));
        }
        return results;
    }

    /** 微步在线 IP 信誉查询 */
    private String queryThreatBook(String ip) throws Exception {
        String url = "https://api.threatbook.cn/v3/scene/ip_reputation"
                + "?apikey=" + URLEncoder.encode(apiKey, "UTF-8")
                + "&resource=" + URLEncoder.encode(ip, "UTF-8");
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);
        conn.setRequestMethod("GET");
        conn.setRequestProperty("User-Agent", "memshell-auditor/2.3");
        BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream(), "UTF-8"));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) sb.append(line);
        br.close();
        conn.disconnect();
        return sb.toString();
    }

    /** 解析微步响应（极简 JSON 提取，避免引入依赖） */
    private void parseThreatBook(String json, IntelResult r) {
        // {"response_code":0,"data":{"severity":"high","judgments":["木马"]}}
        if (json.contains("\"response_code\":0") || json.contains("\"response_code\": 0")) {
            String sev = extract(json, "\"severity\"");
            if (sev != null) r.severity = sev;
            String judges = extractArray(json, "\"judgments\"");
            if (judges != null) r.judgments = judges;
        } else if (json.contains("\"error_code\"")) {
            // API key 无效/限流
            String msg = extract(json, "\"verbose_msg\"");
            if (msg != null && !msg.isEmpty()) r.judgments = "API: " + msg;
        }
    }

    /** 启发式判定：非标准端口 + 常见 C2 端口特征 */
    private void heuristic(String ip, IntelResult r) {
        int port = extractPort(ip);
        // 常见 C2/代理端口特征（非标准端口多数可疑）
        if (port > 0 && port < 1024 && port != 80 && port != 443 && port != 22
                && port != 21 && port != 25 && port != 53 && port != 110 && port != 143
                && port != 3306 && port != 6379 && port != 8080 && port != 8443) {
            r.severity = "middle";
            r.judgments = "非标准低端口(" + port + ")，疑似 C2 回连";
        } else if (port == 10427 || port == 4444 || port == 5555 || port == 6666
                || port == 8888 || port == 9000 || port == 10000) {
            r.severity = "high";
            r.judgments = "常见恶意软件/隧道端口(" + port + ")";
        } else if (port == 443 || port == 80) {
            r.severity = "low";
            r.judgments = "HTTPS/HTTP 端口，需结合域名判断";
        } else {
            r.severity = "info";
            r.judgments = "端口未见明显异常";
        }
    }

    private int extractPort(String ipPort) {
        int idx = ipPort.lastIndexOf(':');
        if (idx < 0) return -1;
        try {
            return Integer.parseInt(ipPort.substring(idx + 1).trim());
        } catch (Throwable t) {
            return -1;
        }
    }

    private String extract(String json, String key) {
        int i = json.indexOf(key);
        if (i < 0) return null;
        i = json.indexOf(':', i + key.length());
        if (i < 0) return null;
        i++;
        while (i < json.length() && Character.isWhitespace(json.charAt(i))) i++;
        if (i >= json.length()) return null;
        if (json.charAt(i) == '"') {
            int end = json.indexOf('"', i + 1);
            return end > i ? json.substring(i + 1, end) : null;
        }
        int end = i;
        while (end < json.length() && (Character.isLetterOrDigit(json.charAt(end)) || json.charAt(end) == '_')) end++;
        return json.substring(i, end);
    }

    private String extractArray(String json, String key) {
        int i = json.indexOf(key);
        if (i < 0) return null;
        i = json.indexOf('[', i);
        if (i < 0) return null;
        int end = json.indexOf(']', i);
        if (end < 0) return null;
        String raw = json.substring(i + 1, end);
        raw = raw.replace("\"", "").trim();
        return raw.isEmpty() ? null : raw;
    }
}
