package com.memshellauditor;

import java.io.File;
import java.lang.reflect.Method;

/**
 * 取证报告分析器（主程序 --analyze）：
 *  - 读取取证报告，重建 Report，输出 findings 摘要
 *  - AI 增强：已配置 → 直接调用；未配置 → 结尾引导配置，重跑自动带 AI
 *  - 引导信息含 OpenAI 兼容接口的三种配置方式
 */
public class ReportAnalyzer {

    public static void analyze(File reportFile, String aiConfig) {
        try {
            if (!reportFile.exists()) {
                System.err.println("[!] 文件不存在: " + reportFile);
                System.exit(2);
            }
            // 内存镜像（hprof）→ 堆分析路径
            if (reportFile.getName().toLowerCase().endsWith(".hprof")) {
                analyzeHeapDump(reportFile, aiConfig);
                return;
            }
            String content = new String(java.nio.file.Files.readAllBytes(reportFile.toPath()), "UTF-8");
            com.memshellauditor.report.Report report = com.memshellauditor.report.Report.fromJson(content);
            System.out.println("[*] 读取取证报告: " + reportFile.getAbsolutePath());
            System.out.println("[*] 目标: " + report.getTargetDesc() + " PID: " + report.getPid()
                    + " JVM: " + report.getJavaVersion());
            System.out.println("------------------------------------------");
            System.out.println(report.toConsole());

            // ===== AI 增强（可配可跳过） =====
            boolean aiConfigured = isAiConfigured(aiConfig);
            if (aiConfigured) {
                String aiResult = runAi(report, aiConfig);
                if (aiResult != null && !aiResult.isEmpty()) {
                    System.out.println("===== AI 增强分析结果 =====");
                    System.out.println(aiResult);
                    // 写回报告（附加 aiAnalysis 字段，避免重复叠加）
                    try {
                        String json = report.toJson();
                        // 移除旧的 aiAnalysis 字段后重新附加
                        json = json.replaceAll("\\s*,\\s*\"aiAnalysis\":\\s*\".*?\"\\s*\\n?\\}", "\n}");
                        json = json.replace("\n}", "\n  ,\"aiAnalysis\": \"" + jsonEscape(aiResult) + "\"\n}");
                        java.nio.file.Files.write(reportFile.toPath(), json.getBytes("UTF-8"));
                        System.out.println("[*] AI 分析结果已写回报告: " + reportFile.getAbsolutePath());
                    } catch (Throwable t) {
                        // ignore
                    }
                } else {
                    // AI 调用失败 → 本地降级 + 提示
                    System.out.println("[*] AI 调用失败，降级本地规则分析");
                    String local = runLocalAnalysis(report);
                    if (local != null) {
                        System.out.println("===== 本地规则分析 =====");
                        System.out.println(local);
                    }
                    showAiGuide(reportFile.getName());
                }
            } else {
                // 未配置 → 引导配置
                String local = runLocalAnalysis(report);
                if (local != null) {
                    System.out.println("===== 本地规则分析（未启用 AI） =====");
                    System.out.println(local);
                }
                showAiGuide(reportFile.getName());
            }

            // ===== 未命中规则的高危检出 → 提示提交新特征 =====
            checkUnmatchedFindings(report, reportFile);

            // ===== 威胁情报查询（回连 IP 自动判定） =====
            threatIntelScan(report, aiConfig);
        } catch (Throwable t) {
            System.err.println("[!] 报告解析失败: " + t);
            System.exit(2);
        }
    }

    /** 对报告中疑似回连 IP 做威胁情报查询（微步 API，无 key 时启发式降级） */
    private static void threatIntelScan(com.memshellauditor.report.Report report, String aiConfig) {
        try {
            String tbKey = null;
            if (aiConfig != null && !aiConfig.isEmpty()) {
                File cf = new File(aiConfig);
                if (cf.exists()) {
                    String cfg = new String(java.nio.file.Files.readAllBytes(cf.toPath()),
                            java.nio.charset.StandardCharsets.UTF_8);
                    int i = cfg.indexOf("threatbook_key");
                    if (i >= 0) {
                        int c = cfg.indexOf(':', i);
                        if (c >= 0) {
                            String v = cfg.substring(c + 1).replace("\"", "").trim();
                            if (!v.isEmpty() && !v.startsWith("{")) tbKey = v;
                        }
                    }
                }
            }
            // 从已解析的 report.findings 中提取 Callback 类别的回连地址（含完整 IP:端口）
            java.util.List<String> ips = new java.util.ArrayList<String>();
            java.util.regex.Pattern p = java.util.regex.Pattern.compile(
                    "(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})(?::(\\d+))?");
            for (com.memshellauditor.report.Finding f : report.getFindings()) {
                if (f.category == null) continue;
                if (f.category.equals("Callback") || f.category.equals("Network")) {
                    String src = (f.reason != null ? f.reason : "") + " " + (f.evidence != null ? f.evidence : "");
                    java.util.regex.Matcher m = p.matcher(src);
                    while (m.find()) {
                        String ipPort = m.group(1) + (m.group(2) != null ? ":" + m.group(2) : "");
                        if (!ips.contains(ipPort)) ips.add(ipPort);
                    }
                }
            }
            if (ips.isEmpty()) {
                System.out.println("[threat] 报告未发现回连 IP，跳过威胁情报查询");
                return;
            }
            com.memshellauditor.threat.ThreatIntelClient client =
                    new com.memshellauditor.threat.ThreatIntelClient(tbKey);
            System.out.println("[threat] 威胁情报查询 " + ips.size() + " 个回连 IP" + (tbKey != null ? "（微步 API）" : "（启发式降级）"));
            for (String ip : ips) {
                com.memshellauditor.threat.ThreatIntelClient.IntelResult r = client.lookup(ip);
                String tag = "INFO";
                if ("high".equals(r.severity)) tag = "🔴 HIGH";
                else if ("middle".equals(r.severity)) tag = "🟠 MEDIUM";
                else if ("low".equals(r.severity)) tag = "🟡 LOW";
                System.out.println("  " + tag + " " + ip + "  [" + r.source + "] "
                        + r.severity + " | " + r.judgments);
            }
        } catch (Throwable t) {
            System.out.println("[threat] 威胁情报查询跳过: " + t);
        }
    }

    /** 检测未命中规则的高危检出项，提示用户提交新特征 */
    private static void checkUnmatchedFindings(com.memshellauditor.report.Report report, File reportFile) {
        try {
            // 加载本地/内置规则
            java.util.List<com.memshellauditor.rules.Rule> rules = com.memshellauditor.rules.RuleEngine.loadClasspathRules();
            if (rules.isEmpty()) {
                rules = com.memshellauditor.rules.RuleEngine.loadUserRules();
            }
            if (rules.isEmpty()) return; // 无规则无法判断"未命中"
            int unmatched = 0;
            for (com.memshellauditor.report.Finding f : report.getFindings()) {
                if (f.level != com.memshellauditor.report.Finding.Level.HIGH) continue;
                java.util.List<String> hits = com.memshellauditor.rules.RuleEngine.matchRules(
                        rules, f.category, f.signal, f.className);
                if (hits.isEmpty()) unmatched++;
            }
            if (unmatched > 0) {
                System.out.println();
                System.out.println("==================================================================");
                System.out.println("⚠️ 发现 " + unmatched + " 条未命中现有特征库的高危检出项（新特征候选）");
                System.out.println("   欢迎贡献到社区特征库（作者署名将保留在规则中）:");
                System.out.println("   java -jar memshell-auditor.jar --submit --report " + reportFile.getName()
                        + " --author " + System.getProperty("user.name", "anonymous") + " --auto-commit");
                System.out.println("   提交成功自动推送；失败会打开 Issue 供粘贴内容");
                System.out.println("==================================================================");
            }
        } catch (Throwable t) {
            // 提示失败不影响主流程
        }
    }

    /** 分析内存镜像（hprof）：快速扫描特征 + AI 增强 */
    private static void analyzeHeapDump(File hprof, String aiConfig) {
        System.out.println("[*] 分析内存镜像: " + hprof.getAbsolutePath()
                + " (" + (hprof.length() / 1024 / 1024) + " MB)");
        String scan = com.memshellauditor.dump.MemoryForensics.quickScan(hprof.getAbsolutePath());
        System.out.println("------------------------------------------");
        System.out.println("[*] 快速扫描结果:");
        if (scan != null) {
            System.out.println(scan);
        } else {
            System.out.println("  镜像过大或无法解析（>200MB 建议用 MAT 分析）");
            System.out.println("  提示: jhat / MAT / 字符串搜索工具均可进一步分析");
        }
        System.out.println("------------------------------------------");
        System.out.println("[*] 提取可读字符串中的可疑特征...");
        // 提取可读字符串供 AI 分析
        String readable = extractReadableStrings(hprof);
        if (readable != null && !readable.isEmpty()) {
            System.out.println("  提取到 " + readable.length() + " 字符可读内容");
        }

        // AI 增强
        boolean aiConfigured = isAiConfigured(aiConfig);
        if (aiConfigured) {
            String aiResult = runAiOnHeap(hprof, scan, readable, aiConfig);
            if (aiResult != null && !aiResult.isEmpty()) {
                System.out.println("===== AI 内存镜像分析结果 =====");
                System.out.println(aiResult);
            } else {
                System.out.println("[*] AI 调用失败");
                showAiGuide(hprof.getName());
            }
        } else {
            showAiGuide(hprof.getName());
        }
    }

    /** 从 hprof 提取可读字符串（UTF-8 连续可打印字符） */
    private static String extractReadableStrings(File hprof) {
        try {
            if (hprof.length() > 300 * 1024 * 1024) return null;
            byte[] data = java.nio.file.Files.readAllBytes(hprof.toPath());
            StringBuilder sb = new StringBuilder();
            StringBuilder cur = new StringBuilder();
            for (byte b : data) {
                if (b >= 32 && b < 127) {
                    cur.append((char) b);
                } else {
                    if (cur.length() >= 6) {
                        if (sb.length() < 60000) {
                            sb.append(cur).append('\n');
                        }
                    }
                    cur.setLength(0);
                }
            }
            return sb.toString();
        } catch (Throwable t) {
            return null;
        }
    }

    /** AI 分析堆镜像（把扫描结果 + 可读字符串特征发给 LLM） */
    private static String runAiOnHeap(File hprof, String scan, String readable, String aiConfig) {
        try {
            Class<?> aiClientCls = Class.forName("com.memshellauditor.ai.AiClient");
            Object client = aiClientCls.getConstructor().newInstance();
            if (aiConfig != null && !aiConfig.isEmpty()) {
                java.lang.reflect.Method fromCfg = aiClientCls.getMethod("fromConfigFile", String.class);
                client = fromCfg.invoke(null, aiConfig);
            }
            java.lang.reflect.Method chat = aiClientCls.getMethod("chat", String.class, String.class);
            String system = "你是资深 Java 内存取证分析专家。根据堆内存镜像扫描结果，分析是否存在内存马/恶意代码迹象。中文输出，基于证据，不臆测。";
            String prompt = "=== 内存镜像扫描结果 ===\n" + (scan == null ? "无" : scan)
                    + "\n=== 可读字符串特征（节选） ===\n"
                    + (readable == null ? "无" : readable.substring(0, Math.min(readable.length(), 4000)))
                    + "\n\n请分析：1) 是否存在内存马/后门特征 2) 可疑类/字符串 3) 建议";
            return (String) chat.invoke(client, system, prompt);
        } catch (Throwable t) {
            return null;
        }
    }

    /** 判断 AI 是否已配置 */
    private static boolean isAiConfigured(String aiConfig) {
        try {
            if (aiConfig != null && !aiConfig.isEmpty()) {
                Class<?> aiClientCls = Class.forName("com.memshellauditor.ai.AiClient");
                Object client = aiClientCls.getConstructor().newInstance();
                java.lang.reflect.Method fromCfg = aiClientCls.getMethod("fromConfigFile", String.class);
                Object cfgClient = fromCfg.invoke(null, aiConfig);
                java.lang.reflect.Method isCfg = aiClientCls.getMethod("isConfigured");
                return Boolean.TRUE.equals(isCfg.invoke(cfgClient));
            }
            Class<?> aiClientCls = Class.forName("com.memshellauditor.ai.AiClient");
            Object client = aiClientCls.getConstructor().newInstance();
            java.lang.reflect.Method isCfg = aiClientCls.getMethod("isConfigured");
            return Boolean.TRUE.equals(isCfg.invoke(client));
        } catch (Throwable t) {
            return false;
        }
    }

    /** 本地规则降级分析（无 AI 时） */
    private static String runLocalAnalysis(com.memshellauditor.report.Report report) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== 本地规则分析 ===\n");
        boolean any = false;
        for (com.memshellauditor.report.Finding f : report.getFindings()) {
            if (f.level == com.memshellauditor.report.Finding.Level.HIGH) {
                any = true;
                sb.append("⚠️ 高危发现: ").append(f.category).append(" ")
                  .append(f.className == null ? "" : f.className).append("\n");
                sb.append("   判定: ").append(f.reason == null ? "" : f.reason).append("\n");
                if (f.callbackIps != null && !f.callbackIps.isEmpty()) {
                    sb.append("   疑似回连: ").append(f.callbackIps).append("\n");
                }
                if (f.dumpPath != null && !f.dumpPath.isEmpty()) {
                    sb.append("   已 dump: ").append(f.dumpPath).append(" → 用 javap -c 查看反汇编\n");
                }
                sb.append("   建议: 隔离主机 → 结合威胁情报查询回连地址 → 排查注入入口(反序列化/表达式/上传) → 修复后重启\n");
            }
        }
        if (!any) sb.append("未发现高危内存马迹象。\n");
        return sb.toString();
    }

    /** 展示 AI 配置引导 */
    private static void showAiGuide(String reportName) {
        System.out.println();
        System.out.println("===== AI 增强分析未启用 =====");
        System.out.println("配置 AI 后重新执行 --analyze 即可自动带 AI 增强展示（恶意行为解读/回连判断/处置建议）。");
        System.out.println();
        System.out.println("配置方式 1：JSON 配置文件（推荐）");
        System.out.println("  cat > ai.json <<'EOF'");
        System.out.println("  {\"base_url\": \"https://api.deepseek.com/v1\", \"api_key\": \"sk-xxx\", \"model\": \"deepseek-chat\"}");
        System.out.println("  EOF");
        System.out.println("  java -jar memshell-auditor.jar --analyze " + reportName + " --ai-config ai.json");
        System.out.println();
        System.out.println("配置方式 2：环境变量");
        System.out.println("  AI_BASE_URL=https://api.deepseek.com/v1 AI_API_KEY=sk-xxx AI_MODEL=deepseek-chat \\");
        System.out.println("    java -jar memshell-auditor.jar --analyze " + reportName);
        System.out.println();
        System.out.println("配置方式 3：本地 Ollama（完全离线）");
        System.out.println("  AI_BASE_URL=http://localhost:11434/v1 AI_API_KEY=ollama AI_MODEL=llama3.1 \\");
        System.out.println("    java -jar memshell-auditor.jar --analyze " + reportName);
        System.out.println();
        System.out.println("提示：支持一切 OpenAI 兼容服务（OpenAI/DeepSeek/通义/智谱/Ollama/vLLM）");
    }

    /** 调用 AI 分析（反射，ai 模块在主程序完整包含） */
    private static String runAi(com.memshellauditor.report.Report report, String aiConfig) {
        try {
            Class<?> aiAnalyzerCls = Class.forName("com.memshellauditor.ai.AiAnalyzer");
            Class<?> aiClientCls = Class.forName("com.memshellauditor.ai.AiClient");
            Object client = aiClientCls.getConstructor().newInstance();
            if (aiConfig != null && !aiConfig.isEmpty()) {
                Method fromCfg = aiClientCls.getMethod("fromConfigFile", String.class);
                client = fromCfg.invoke(null, aiConfig);
            }
            Method analyze = aiAnalyzerCls.getMethod("analyze",
                    com.memshellauditor.report.Report.class, File.class, boolean.class);
            return (String) analyze.invoke(aiAnalyzerCls.getConstructor().newInstance(),
                    report, null, false);
        } catch (Throwable t) {
            return null;
        }
    }

    private static String jsonEscape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }
}
