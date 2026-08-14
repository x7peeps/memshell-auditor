package com.memshellauditor.monitor;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Webhook 推送客户端（值守监控模式）：
 *  支持企业微信 / 钉钉 / 飞书 群机器人 webhook，markdown 消息格式，零依赖。
 *
 * 配置示例（monitor.json）：
 * {
 *   "webhook": {
 *     "url": "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx",
 *     "type": "wecom",            // wecom / dingtalk / feishu / generic
 *     "min_level": "MEDIUM"       // 最低推送级别 HIGH/MEDIUM/LOW/INFO
 *   },
 *   "live_seconds": 3600,         // 监控时长（秒）
 *   "interval_seconds": 60        // 汇总推送间隔（秒）
 * }
 */
public class WebhookClient {

    public static final int LEVEL_HIGH = 3;
    public static final int LEVEL_MEDIUM = 2;
    public static final int LEVEL_LOW = 1;
    public static final int LEVEL_INFO = 0;

    private final String url;
    private final String type;      // wecom / dingtalk / feishu / generic
    private final int minLevel;

    public WebhookClient(String url, String type, String minLevel) {
        this.url = url;
        this.type = type == null ? "wecom" : type.toLowerCase();
        this.minLevel = parseLevel(minLevel);
    }

    public static int parseLevel(String s) {
        if (s == null) return LEVEL_INFO;
        String up = s.toUpperCase();
        if (up.contains("HIGH")) return LEVEL_HIGH;
        if (up.contains("MEDIUM")) return LEVEL_MEDIUM;
        if (up.contains("LOW")) return LEVEL_LOW;
        return LEVEL_INFO;
    }

    public boolean shouldPush(int level) {
        return level >= minLevel;
    }

    /** 推送 markdown 消息。返回是否成功（HTTP 2xx）。 */
    public boolean pushMarkdown(String title, String body) {
        if (url == null || url.isEmpty()) return false;
        try {
            String payload = buildPayload(title, body);
            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            conn.setDoOutput(true);
            OutputStream os = conn.getOutputStream();
            os.write(payload.getBytes("UTF-8"));
            os.flush();
            os.close();
            int code = conn.getResponseCode();
            // 读取响应（错误信息诊断用）
            java.io.InputStream is = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
            StringBuilder sb = new StringBuilder();
            if (is != null) {
                java.io.BufferedReader br = new java.io.BufferedReader(
                        new java.io.InputStreamReader(is, "UTF-8"));
                String line;
                while ((line = br.readLine()) != null) sb.append(line);
                br.close();
            }
            conn.disconnect();
            if (code >= 200 && code < 300) {
                System.out.println("[monitor] webhook 推送成功 (" + code + "): " + title);
                return true;
            } else {
                System.out.println("[monitor] webhook 推送失败 (" + code + "): " + sb);
                return false;
            }
        } catch (Throwable t) {
            System.out.println("[monitor] webhook 推送异常: " + t);
            return false;
        }
    }

    /** 按平台类型构造 markdown 消息 payload */
    private String buildPayload(String title, String body) {
        String md = "### 🚨 " + title + "\n" + body;
        if ("dingtalk".equals(type)) {
            // 钉钉 markdown
            return "{\"msgtype\":\"markdown\",\"markdown\":{\"title\":\"" + jsonEsc(title)
                    + "\",\"text\":\"" + jsonEsc(md) + "\"}}";
        } else if ("feishu".equals(type)) {
            // 飞书 post 文本（markdown 需 interactive 卡片，这里用 text 简单版）
            String text = "🚨 " + title + "\n" + body.replace("**", "").replace("`", "")
                    .replace("#", "").replace("|", " ");
            return "{\"msg_type\":\"text\",\"content\":{\"text\":\"" + jsonEsc(text) + "\"}}";
        } else if ("generic".equals(type)) {
            return "{\"title\":\"" + jsonEsc(title) + "\",\"text\":\"" + jsonEsc(body) + "\"}";
        } else {
            // 企业微信 markdown
            return "{\"msgtype\":\"markdown\",\"markdown\":{\"content\":\"" + jsonEsc(md) + "\"}}";
        }
    }

    private static String jsonEsc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }
}
