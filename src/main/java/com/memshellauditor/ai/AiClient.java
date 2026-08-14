package com.memshellauditor.ai;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * OpenAI 通用兼容客户端（零依赖）：
 *  - base_url + api_key + model 三要素可配
 *  - 兼容 OpenAI / DeepSeek / 通义千问 / 本地 Ollama / vLLM 等一切 OpenAI 协议服务
 *  - 使用标准 java.net.HttpURLConnection，不引入第三方库
 *
 * 配置来源（优先级从高到低）：
 *  1. AI_CONFIG 环境变量指向的 JSON 配置文件
 *  2. 命令行参数 --ai-base-url --ai-key --ai-model
 *  3. 环境变量 AI_BASE_URL / AI_API_KEY / AI_MODEL
 */
public class AiClient {

    public String baseUrl;
    public String apiKey;
    public String model;
    public int timeoutMs = 60000;

    public AiClient() {
        // 从环境变量加载默认值
        baseUrl = System.getenv("AI_BASE_URL");
        apiKey = System.getenv("AI_API_KEY");
        model = System.getenv("AI_MODEL");
        if (baseUrl == null) baseUrl = "https://api.openai.com/v1";
        if (model == null) model = "gpt-4o-mini";
    }

    public boolean isConfigured() {
        return apiKey != null && !apiKey.isEmpty()
                && baseUrl != null && !baseUrl.isEmpty();
    }

    /** 从 JSON 配置文件加载（{base_url, api_key, model}） */
    public static AiClient fromConfigFile(String path) {
        AiClient client = new AiClient();
        try {
            String content = new String(java.nio.file.Files.readAllBytes(
                    new java.io.File(path).toPath()), "UTF-8");
            // 极简 JSON 解析（不引入依赖）
            client.baseUrl = extractJsonString(content, "base_url");
            client.apiKey = extractJsonString(content, "api_key");
            client.model = extractJsonString(content, "model");
            String timeout = extractJsonString(content, "timeout_ms");
            if (timeout != null) {
                try { client.timeoutMs = Integer.parseInt(timeout.trim()); } catch (Throwable ignored) {}
            }
            if (client.baseUrl == null) client.baseUrl = System.getenv("AI_BASE_URL");
            if (client.model == null) client.model = System.getenv("AI_MODEL");
        } catch (Throwable t) {
            return client;
        }
        return client;
    }

    private static String extractJsonString(String json, String key) {
        try {
            String pattern = "\"" + key + "\"\\s*:\\s*\"([^\"]*)\"";
            java.util.regex.Matcher m = java.util.regex.Pattern.compile(pattern).matcher(json);
            if (m.find()) return m.group(1);
        } catch (Throwable ignored) {}
        return null;
    }

    /**
     * 发送 chat completion 请求。
     * @param systemPrompt 系统提示词
     * @param userPrompt   用户内容
     * @return 模型回复文本；失败返回 null
     */
    public String chat(String systemPrompt, String userPrompt) {
        if (!isConfigured()) return null;
        int maxRetries = 2;
        long delay = 1000;
        for (int attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                String url = baseUrl;
                if (!url.endsWith("/chat/completions")) {
                    if (!url.endsWith("/")) url += "/";
                    url += "chat/completions";
                }
                HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
                conn.setRequestMethod("POST");
                conn.setConnectTimeout(timeoutMs);
                conn.setReadTimeout(timeoutMs);
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Authorization", "Bearer " + apiKey);
                conn.setDoOutput(true);

                String body = buildChatBody(systemPrompt, userPrompt);
                OutputStream os = conn.getOutputStream();
                os.write(body.getBytes("UTF-8"));
                os.flush();
                os.close();

                int code = conn.getResponseCode();
                if (code >= 200 && code < 300) {
                    return parseChatResponse(readAll(conn.getInputStream()));
                } else if (code >= 500 || code == 429) {
                    // 服务端错误/限流 → 可重试
                    System.out.println("[ai] 调用失败 (" + code + ")，重试 " + (attempt + 1) + "/" + maxRetries);
                    conn.disconnect();
                    if (attempt < maxRetries) {
                        try { Thread.sleep(delay); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); return null; }
                        delay *= 2;
                        continue;
                    }
                    return null;
                } else {
                    // 4xx 客户端错误 → 不重试
                    String err = readAll(conn.getErrorStream());
                    conn.disconnect();
                    return null;
                }
            } catch (Throwable t) {
                // 网络异常 → 可重试
                if (attempt < maxRetries) {
                    try { Thread.sleep(delay); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); return null; }
                    delay *= 2;
                    continue;
                }
                return null;
            }
        }
        return null;
    }

    private String buildChatBody(String system, String user) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"model\":\"").append(jsonEscape(model)).append("\",");
        sb.append("\"messages\":[");
        if (system != null && !system.isEmpty()) {
            sb.append("{\"role\":\"system\",\"content\":\"").append(jsonEscape(system)).append("\"},");
        }
        sb.append("{\"role\":\"user\",\"content\":\"").append(jsonEscape(user)).append("\"}],");
        sb.append("\"temperature\":0.2,\"max_tokens\":2048}");
        return sb.toString();
    }

    private String parseChatResponse(String json) {
        try {
            // 极简解析：取第一个 "content":"..." 
            String contentKey = "\"content\":\"";
            int idx = json.indexOf(contentKey);
            if (idx < 0) return null;
            int start = idx + contentKey.length();
            int end = json.indexOf('"', start);
            if (end < 0) return null;
            return json.substring(start, end)
                    .replace("\\n", "\n").replace("\\\"", "\"").replace("\\\\", "\\");
        } catch (Throwable t) {
            return null;
        }
    }

    private static String readAll(InputStream in) throws Exception {
        if (in == null) return "";
        BufferedReader br = new BufferedReader(new InputStreamReader(in, "UTF-8"));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) sb.append(line).append('\n');
        br.close();
        return sb.toString();
    }

    private static String jsonEscape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }
}
