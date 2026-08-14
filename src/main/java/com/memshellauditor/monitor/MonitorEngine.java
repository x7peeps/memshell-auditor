package com.memshellauditor.monitor;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * 值守监控引擎（--monitor 模式）：
 *  针对值守客户现场场景——attach 目标 JVM 后持续监控，检测到可疑动态加载类
 *  立即（或按间隔汇总）通过 webhook 实时推送到企业微信/钉钉/飞书群。
 *
 * 配置文件 monitor.json（模板见 monitor.example.json）：
 * {
 *   "webhook": { "url": "...", "type": "wecom", "min_level": "MEDIUM" },
 *   "live_seconds": 3600,
 *   "interval_seconds": 60
 * }
 *
 * 用法：
 *   java -jar memshell-auditor.jar --monitor <monitor.json> <PID>
 *   取证程序: java -jar system-diag-xxx.jar --monitor <monitor.json> <PID>
 */
public class MonitorEngine {

    public static class MonitorConfig {
        public String webhookUrl;
        public String webhookType = "wecom";
        public String minLevel = "MEDIUM";
        public long liveSeconds = 3600;
        public long intervalSeconds = 60;
        public int targetPid = -1;
    }

    /** 解析 monitor.json（极简，兼容无引号/宽松 JSON） */
    public static MonitorConfig parseConfig(File f) throws Exception {
        MonitorConfig c = new MonitorConfig();
        if (f == null || !f.exists()) return c;
        String json = new String(java.nio.file.Files.readAllBytes(f.toPath()), "UTF-8");
        c.webhookUrl = extract(json, "\"url\"");
        c.webhookType = extract(json, "\"type\"");
        if (c.webhookType == null) c.webhookType = "wecom";
        c.minLevel = extract(json, "\"min_level\"");
        if (c.minLevel == null) c.minLevel = "MEDIUM";
        String ls = extract(json, "\"live_seconds\"");
        if (ls != null) { try { c.liveSeconds = Long.parseLong(ls); } catch (Throwable t) {} }
        String iv = extract(json, "\"interval_seconds\"");
        if (iv != null) { try { c.intervalSeconds = Long.parseLong(iv); } catch (Throwable t) {} }
        return c;
    }

    private static String extract(String json, String key) {
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
        while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '.')) end++;
        return json.substring(i, end);
    }

    /** 监控会话：收集发现项并按间隔推送 */
    public static class MonitorSession {
        public final MonitorConfig config;
        public final WebhookClient client;
        public final String targetDesc;
        private final List<String[]> pending = new ArrayList<String[]>(); // {level, title, body}
        private long lastPush = 0;

        public MonitorSession(MonitorConfig cfg, String targetDesc) {
            this.config = cfg;
            this.client = new WebhookClient(cfg.webhookUrl, cfg.webhookType, cfg.minLevel);
            this.targetDesc = targetDesc;
        }

        /** 记录一条发现（level: HIGH/MEDIUM/LOW/INFO），达到推送条件则立即推送 */
        public synchronized void reportFinding(String level, String title, String body) {
            int lv = WebhookClient.parseLevel(level);
            if (!client.shouldPush(lv)) return;
            pending.add(new String[]{level, title, body});
            long now = System.currentTimeMillis();
            if (now - lastPush >= config.intervalSeconds * 1000) {
                flush();
            }
        }

        /** 启动心跳线程（每 intervalSeconds 推送一次心跳，确认监控存活） */
        public synchronized void startHeartbeat() {
            if (heartbeatStarted) return;
            heartbeatStarted = true;
            final String desc = targetDesc;
            Thread t = new Thread(new Runnable() {
                @Override
                public void run() {
                    while (!stopped) {
                        try {
                            Thread.sleep(Math.max(config.intervalSeconds, 30) * 1000);
                            if (!stopped) client.pushHeartbeat(desc);
                        } catch (InterruptedException e) {
                            break;
                        }
                    }
                }
            }, "monitor-heartbeat");
            t.setDaemon(true);
            t.start();
        }

        private volatile boolean stopped = false;
        private boolean heartbeatStarted = false;

        /** 汇总推送全部待发发现 */
        public synchronized void flush() {
            if (pending.isEmpty()) return;
            StringBuilder body = new StringBuilder();
            body.append("**目标**: ").append(targetDesc).append("\n");
            body.append("**时间**: ").append(new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
                    .format(new java.util.Date())).append("\n\n");
            int high = 0;
            for (String[] f : pending) {
                if ("HIGH".equals(f[0])) high++;
                body.append("- **[").append(f[0]).append("]** ").append(f[1]).append("\n");
                if (f[2] != null && !f[2].isEmpty()) body.append("  ").append(f[2]).append("\n");
            }
            client.pushMarkdown("内存马监控告警: " + high + " 条高危 / 共 " + pending.size() + " 条", body.toString());
            pending.clear();
            lastPush = System.currentTimeMillis();
        }

        /** 监控结束（超时/中断）时强制推送剩余 + 停止心跳 */
        public synchronized void close() {
            stopped = true;
            flush();
        }
    }
}
