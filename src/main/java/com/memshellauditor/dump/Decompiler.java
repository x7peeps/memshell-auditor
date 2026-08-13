package com.memshellauditor.dump;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;

/**
 * 反编译/反汇编模块：
 *  1. javap -c -p 反汇编（JDK 自带，零依赖）——展示方法字节码与常量池
 *  2. javap -c -p -v 详细模式——包含常量池（可看到 URL/IP/命令字符串）
 *
 * 说明：完整 Java 反编译（CFR/Fernflower）会引入大体积依赖，v1.0 用 javap
 * 反汇编 + ClassDumper 可读字符串提取实现"核心代码可见"，v2 计划集成 CFR。
 */
public final class Decompiler {

    private Decompiler() {}

    /**
     * 对 class 文件反汇编。
     * @return 反汇编文本，失败返回 null
     */
    public static String javap(File classFile, boolean verbose) {
        if (classFile == null || !classFile.exists()) return null;
        String javaBin = System.getProperty("java.home") + File.separator + "bin" + File.separator + "javap";
        File javapBin = new File(javaBin);
        if (!javapBin.exists()) {
            // macOS JDK: bin/javap 通常存在；找不到则尝试 which
            return null;
        }
        try {
            ProcessBuilder pb = verbose
                    ? new ProcessBuilder(javapBin.getAbsolutePath(), "-c", "-p", "-v", classFile.getAbsolutePath())
                    : new ProcessBuilder(javapBin.getAbsolutePath(), "-c", "-p", classFile.getAbsolutePath());
            pb.redirectErrorStream(true);
            Process p = pb.start();
            StringBuilder sb = new StringBuilder();
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), "UTF-8"));
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line).append('\n');
                if (sb.length() > 512 * 1024) break; // 防止超大输出
            }
            p.waitFor();
            return sb.toString();
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * 提取恶意核心代码片段：从 javap 输出中筛选命令执行/网络/回连相关方法。
     */
    public static String extractMaliciousCore(String javapOutput, int maxLines) {
        if (javapOutput == null) return "";
        StringBuilder sb = new StringBuilder();
        String[] lines = javapOutput.split("\n");
        int shown = 0;
        boolean inInterestingMethod = false;
        for (String line : lines) {
            String lower = line.toLowerCase();
            boolean interesting = lower.contains("runtime.exec")
                    || lower.contains("processbuilder")
                    || lower.contains("getruntime")
                    || lower.contains("java/net/socket")
                    || lower.contains("java/net/inetsocketaddress")
                    || lower.contains("httpurlconnection")
                    || lower.contains("url.openconnection")
                    || lower.contains("datagramsocket")
                    || lower.contains("/bin/sh")
                    || lower.contains("powershell")
                    || lower.contains("cmd.exe")
                    || lower.contains("servletrequest")
                    || lower.contains("servletresponse")
                    || lower.contains("getparameter")
                    || lower.contains("getoutputstream")
                    || lower.contains("getinputstream")
                    || lower.contains("new string")
                    || lower.contains("base64")
                    || lower.contains("des")
                    || lower.contains("aes")
                    || lower.contains("cipher");
            if (interesting) {
                if (!inInterestingMethod) {
                    sb.append("--- malicious core ---\n");
                    inInterestingMethod = true;
                }
                sb.append(line).append('\n');
                shown++;
                if (shown >= maxLines) break;
            } else if (inInterestingMethod) {
                // 方法结束后继续显示几行上下文
                if (line.trim().isEmpty() || line.contains("public") || line.contains("private") || line.contains("protected")) {
                    inInterestingMethod = false;
                }
            }
        }
        return sb.toString();
    }

    /**
     * 从反汇编/字节码可读字符串中提取疑似回连地址（IP / 域名 / URL）。
     * @return 去重后的候选列表（逗号分隔），无则空串
     */
    public static String extractCallbacks(String text) {
        if (text == null || text.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("((?:https?://)?(?:\\d{1,3}\\.){3}\\d{1,3}(?::\\d{1,5})?|(?:https?://)?[a-zA-Z0-9-]+\\.(?:com|cn|net|org|io|top|xyz|vip)(?:/[^\\s\"]*)?)")
                .matcher(text);
        java.util.Set<String> seen = new java.util.LinkedHashSet<String>();
        while (m.find()) {
            String cand = m.group();
            if (cand == null) continue;
            // 过滤明显非回连的（jar 包路径、本地类名等）
            if (cand.contains("maven") || cand.contains("apache.org") || cand.contains("springframework")
                    || cand.contains("github.com") || cand.contains("oracle.com") || cand.contains("java.sun.com")) {
                continue;
            }
            if (seen.add(cand)) {
                if (sb.length() > 0) sb.append(", ");
                sb.append(cand);
            }
        }
        return sb.toString();
    }
}
