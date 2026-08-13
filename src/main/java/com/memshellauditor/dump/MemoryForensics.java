package com.memshellauditor.dump;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;

/**
 * 跨平台内存取证（heap dump 集成）：
 *  对目标 PID 执行 jmap -dump:format=b 生成堆转储文件（取证基线）。
 *  兼容 Linux / macOS / Windows（通过 JDK 自带 jmap，自动探测 java.home）。
 *
 * 堆 dump 用途：
 *  - 内存马字节码完整留证（即使 retransform 受限的类也可在堆中恢复）
 *  - 全量对象/字符串分析（回连地址、命令、配置）
 *  - 与检测报告的 dump 目录互为补充，构成完整证据链
 */
public final class MemoryForensics {

    private MemoryForensics() {}

    /**
     * 对 PID 执行 jmap heap dump。
     * @return 生成的 hprof 文件路径；失败返回 null
     */
    public static String heapDump(int pid, File outDir) {
        if (pid <= 0) return null;
        try {
            if (!outDir.exists()) outDir.mkdirs();
            String stamp = new java.text.SimpleDateFormat("yyyyMMdd_HHmmss").format(new java.util.Date());
            File hprof = new File(outDir, "heap-" + pid + "-" + stamp + ".hprof");

            // 探测 jmap 路径（JDK 自带，跨平台）
            String javaHome = System.getProperty("java.home", "");
            String jmap = javaHome + File.separator + "bin" + File.separator + "jmap";
            File jmapBin = new File(jmap);
            if (!jmapBin.exists()) {
                // 尝试 PATH 中的 jmap
                jmap = "jmap";
            }

            ProcessBuilder pb = new ProcessBuilder(jmap, "-dump:format=b,file=" + hprof.getAbsolutePath(),
                    String.valueOf(pid));
            pb.redirectErrorStream(true);
            Process p = pb.start();
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), "UTF-8"));
            StringBuilder log = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) log.append(line).append('\n');
            int code = p.waitFor();
            if (code == 0 && hprof.exists() && hprof.length() > 0) {
                System.out.println("[memshell-auditor] 内存取证完成: " + hprof.getAbsolutePath()
                        + " (" + (hprof.length() / 1024 / 1024) + " MB)");
                return hprof.getAbsolutePath();
            } else {
                System.out.println("[memshell-auditor] jmap heap dump 失败 (exit=" + code + "): " + log);
                return null;
            }
        } catch (Throwable t) {
            System.out.println("[memshell-auditor] 内存取证异常: " + t);
            return null;
        }
    }

    /**
     * 从 hprof 文件中做深度解析（HprofParser：字符串/类名/恶意特征/类字节码统计）。
     * 返回解析摘要，详细结果由 HprofParser.parse 获得。
     */
    public static String quickScan(String hprofPath) {
        if (hprofPath == null) return null;
        try {
            File f = new File(hprofPath);
            if (!f.exists()) return null;
            HprofParser.HprofResult r = HprofParser.parse(f);
            if (r.suspicious.isEmpty()) {
                return r.summary;
            }
            // 附上前几条恶意特征命中
            StringBuilder sb = new StringBuilder(r.summary);
            sb.append(" | 命中示例: ");
            int shown = 0;
            for (String s : r.suspicious) {
                if (shown >= 3) break;
                String t = s.replace("\n", " ").replace("\r", " ").trim();
                if (t.length() > 60) t = t.substring(0, 60) + "...";
                sb.append("[").append(t).append("] ");
                shown++;
            }
            return sb.toString();
        } catch (Throwable t) {
            return null;
        }
    }

    private static int countOccurrences(byte[] haystack, byte[] needle) {
        int count = 0;
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) continue outer;
            }
            count++;
        }
        return count;
    }
}
