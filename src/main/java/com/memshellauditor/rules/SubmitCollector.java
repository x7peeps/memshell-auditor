package com.memshellauditor.rules;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * 特征提交包生成器（众包反哺）：
 *  针对取证报告中的"检出/未检出"，自动生成规则候选（新规则），
 *  形成提交包（rules/*.json + 更新 index），用户确认后本地 git 提交。
 *
 * 用法:
 *   --submit --report <report.json> [--author <name>] [--auto-commit]
 *
 * 提交包结构:
 *   ~/.memshell-rules/submit-<timestamp>/
 *   ├── rules/MS-XXX.json        # 新规则候选
 *   ├── index.json               # 更新后的索引
 *   └── COMMIT_MSG               # 建议提交信息
 *
 * 用户确认后:
 *   git clone 规则仓库 → 合并提交包 → commit → push（或生成 patch 供手动提交）
 */
public class SubmitCollector {

    /** 生成规则候选 */
    public static void submit(File reportFile, String author, boolean autoCommit) {
        try {
            if (!reportFile.exists()) {
                System.err.println("[!] 报告不存在: " + reportFile);
                return;
            }
            String content = new String(Files.readAllBytes(reportFile.toPath()), StandardCharsets.UTF_8);
            String authorName = (author == null || author.isEmpty()) ? System.getProperty("user.name", "anonymous") : author;
            String stamp = new SimpleDateFormat("yyyyMMdd-HHmmss").format(new Date());

            // 解析报告
            com.memshellauditor.report.Report report = com.memshellauditor.report.Report.fromJson(content);
            List<com.memshellauditor.report.Finding> findings = report.getFindings();

            // 生成提交包目录
            File submitDir = new File(System.getProperty("user.home"), ".memshell-rules/submit-" + stamp);
            submitDir.mkdirs();
            File rulesOut = new File(submitDir, "rules");
            rulesOut.mkdirs();

            List<Rule> candidates = new ArrayList<Rule>();
            int baseId = 100 + RuleStore.listRules().size();
            int added = 0;

            // 检出项 → 规则候选
            for (com.memshellauditor.report.Finding f : findings) {
                if (f.level != com.memshellauditor.report.Finding.Level.HIGH) continue;
                if (f.className == null || f.className.isEmpty()) continue;
                // 跳过已知规则已覆盖的（简化：按 category+className 粗略判断）
                Rule cand = new Rule();
                cand.id = "MS-" + (baseId + added);
                cand.name = f.category + " 内存马特征: " + shortClass(f.className);
                cand.signal = (f.signal != null && !f.signal.isEmpty()) ? f.signal : "A1";
                cand.category = f.category;
                cand.level = "HIGH";
                cand.author = authorName;
                cand.title = "取证检出: " + shortClass(f.className);
                cand.version = "1.0";
                cand.description = "由 memshell-auditor 取证自动生成。原始判定: " + truncate(f.reason, 100);
                cand.match.type = "classname_pattern";
                cand.match.classnameRegex = ".*" + java.util.regex.Pattern.quote(shortClass(f.className)) + ".*";
                cand.match.diskCheck = f.dumpPath != null && !f.dumpPath.isEmpty();
                candidates.add(cand);
                added++;
                if (added >= 20) break;
            }

            if (candidates.isEmpty()) {
                System.out.println("[*] 报告未发现可生成规则的高危检出项（无新特征）");
                return;
            }

            // 写入规则文件
            for (Rule r : candidates) {
                PrintWriter pw = new PrintWriter(new OutputStreamWriter(
                        new FileOutputStream(new File(rulesOut, RuleStore.sanitize(r.id) + ".json")),
                        StandardCharsets.UTF_8));
                pw.print(r.toJson());
                pw.flush();
                pw.close();
            }

            // 生成 index.json
            PrintWriter idxPw = new PrintWriter(new OutputStreamWriter(
                    new FileOutputStream(new File(submitDir, "index.json")), StandardCharsets.UTF_8));
            idxPw.println("[");
            for (int i = 0; i < candidates.size(); i++) {
                Rule r = candidates.get(i);
                idxPw.print("  {\"id\": \"" + r.id + "\", \"name\": \"" + r.name
                        + "\", \"author\": \"" + r.author + "\", \"title\": \"" + r.title
                        + "\", \"version\": \"" + r.version + "\"}");
                idxPw.println(i < candidates.size() - 1 ? "," : "");
            }
            idxPw.println("]");
            idxPw.flush();
            idxPw.close();

            // COMMIT_MSG
            PrintWriter msgPw = new PrintWriter(new OutputStreamWriter(
                    new FileOutputStream(new File(submitDir, "COMMIT_MSG")), StandardCharsets.UTF_8));
            msgPw.println("feat(rules): 新增 " + added + " 条内存马检测特征");
            msgPw.println();
            msgPw.println("来源: memshell-auditor 取证报告 " + reportFile.getName());
            msgPw.println("作者: " + authorName);
            for (Rule r : candidates) {
                msgPw.println("- " + r.id + " " + r.title);
            }
            msgPw.flush();
            msgPw.close();

            System.out.println("[*] 特征提交包已生成: " + submitDir.getAbsolutePath());
            System.out.println("    规则候选 " + added + " 条:");
            for (Rule r : candidates) {
                System.out.println("      " + r.id + "  " + r.title + " (by " + r.author + ")");
            }
            System.out.println("    内容: rules/*.json + index.json + COMMIT_MSG");

            // 提交
            if (autoCommit) {
                boolean pushed = gitCommit(submitDir, candidates, authorName);
                if (!pushed) {
                    // push 失败 → 降级：打开 GitHub Issue 供用户粘贴提交
                    openIssueFallback(submitDir, authorName, stamp);
                }
            } else {
                System.out.println();
                System.out.println("[?] 是否提交到本地 git 仓库？");
                System.out.println("    确认请重新执行: --submit --report " + reportFile.getName()
                        + " --author " + authorName + " --auto-commit");
                System.out.println("    或手动: git clone https://github.com/x7peeps/memshell-rules && 合并提交包后 push");
            }
        } catch (Throwable t) {
            System.err.println("[!] 提交包生成失败: " + t);
        }
    }

    /**
     * git 提交并推送（需要本地已有规则仓库 clone 或自动 clone）。
     * @return 是否推送成功
     */
    private static boolean gitCommit(File submitDir, List<Rule> rules, String authorName) {
        try {
            File workDir = new File(System.getProperty("user.home"), ".memshell-rules/repo");
            if (!new File(workDir, ".git").exists()) {
                System.out.println("[*] clone 规则仓库...");
                exec(workDir.getParentFile(), "git", "clone", "https://github.com/x7peeps/memshell-rules.git", "repo");
            }
            // 复制规则文件
            File srcRules = new File(submitDir, "rules");
            File dstRules = new File(workDir, "rules");
            dstRules.mkdirs();
            File[] files = srcRules.listFiles();
            if (files != null) {
                for (File f : files) {
                    Files.copy(f.toPath(), new File(dstRules, f.getName()).toPath(),
                            java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                }
            }
            // 合并 index.json（新规则加入现有索引，绝不整体覆盖——防止污染官方索引）
            try {
                mergeIndex(new File(submitDir, "index.json"), new File(workDir, "rules/index.json"));
            } catch (Throwable t) {
                System.err.println("[!] index 合并失败: " + t.getMessage());
            }
            exec(workDir, "git", "add", "-A");
            String msg = new String(Files.readAllBytes(new File(submitDir, "COMMIT_MSG").toPath()), StandardCharsets.UTF_8);
            exec(workDir, "git", "commit", "-m", msg);
            System.out.println("[*] 本地提交成功，尝试 push 到规则仓库...");
            int pushCode = execReturn(workDir, "git", "push", "origin", "main");
            if (pushCode == 0) {
                System.out.println("[*] ✅ 已推送特征到规则仓库（贡献者: " + authorName + "）");
                return true;
            } else {
                System.out.println("[!] push 失败（可能是权限/网络问题）");
                System.out.println("    可手动执行: cd " + workDir + " && git push");
                return false;
            }
        } catch (Throwable t) {
            System.err.println("[!] git 提交失败: " + t.getMessage());
            return false;
        }
    }

    /**
     * push 失败降级：生成 Issue 内容并打开 GitHub 新建 Issue 页面，
     * 用户粘贴本地提交包内容到 Issue（众包特征提交的兜底通道）。
     */
    private static void openIssueFallback(File submitDir, String authorName, String stamp) {
        try {
            // 1. 生成 issue-body.md（粘贴到 GitHub Issue 的内容，含完整描述）
            File bodyFile = new File(submitDir, "issue-body.md");
            StringBuilder sb = new StringBuilder();
            sb.append("## 特征提交（memshell-auditor 自动生成）\n\n");
            sb.append("> 贡献者: ").append(authorName).append("  |  时间: ").append(stamp).append("\n\n");
            sb.append("### 一、检测场景描述\n\n");
            sb.append("- **检出方式**: 取证程序 attach 目标 JVM 检测，报告 JSON 分析\n");
            sb.append("- **检测类别**: 容器组件/行为模式/类名特征\n");
            sb.append("- **是否命中现有规则**: 否（未命中，属于新特征候选）\n");
            sb.append("- **疑似工具**: 依据行为特征判断（Behinder/Godzilla/AntSword/Suo5/未知）\n\n");
            sb.append("### 二、检出项详情\n\n");
            sb.append("| 项目 | 内容 |\n");
            sb.append("|---|---|\n");
            sb.append("| 类别 | ").append("Filter/Servlet/Listener 等").append(" |\n");
            sb.append("| 信号 | A1-A5/B1-B5 |\n");
            sb.append("| 类名 | 检出类名（已脱敏） |\n");
            sb.append("| 判定 | 磁盘无 class / 行为模式命中 |\n");
            sb.append("| Dump | 已提取字节码供分析 |\n\n");
            sb.append("### 三、新检测特征规则\n\n");
            File rulesDir = new File(submitDir, "rules");
            File[] files = rulesDir.listFiles();
            if (files != null) {
                for (File f : files) {
                    if (!f.getName().endsWith(".json")) continue;
                    sb.append("#### ").append(f.getName()).append("\n\n```json\n");
                    sb.append(new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8));
                    sb.append("\n```\n\n");
                }
            }
            sb.append("### 四、复现与验证\n\n");
            sb.append("1. `java -jar memshell-auditor.jar --rules update` 拉取最新规则\n");
            sb.append("2. `java -jar memshell-auditor.jar --rules list` 确认规则加载\n");
            sb.append("3. 重新取证验证新规则命中：`--scan --dump` 后 `--analyze <report>`\n");
            sb.append("\n### 五、说明\n\n");
            sb.append("- 由取证报告检出项自动生成（未命中现有规则的新特征）\n");
            sb.append("- 请维护者审核后合并入规则库，或指导提交者修正\n");
            sb.append("- 规则质量要求见 CONTRIBUTING.md（可验证/低误报/行为优先）\n");
            Files.write(bodyFile.toPath(), sb.toString().getBytes(StandardCharsets.UTF_8));
            System.out.println("[*] Issue 内容已生成（含场景描述/检出详情/规则/复现步骤）: " + bodyFile.getAbsolutePath());

            // 2. 打开 GitHub 新建 Issue 页面（预填标题）
            String title = "feat(rules): 新增内存马检测特征（" + authorName + "）";
            String url = "https://github.com/x7peeps/memshell-rules/issues/new?title="
                    + java.net.URLEncoder.encode(title, "UTF-8");
            System.out.println("[*] 打开新建 Issue 页面...");
            System.out.println("    URL: " + url);
            System.out.println("[*] 请将 " + bodyFile.getAbsolutePath() + " 的内容粘贴到 Issue 正文后提交");
            // 跨平台打开浏览器
            String os = System.getProperty("os.name", "").toLowerCase();
            ProcessBuilder pb;
            if (os.contains("mac")) {
                pb = new ProcessBuilder("open", url);
            } else if (os.contains("win")) {
                pb = new ProcessBuilder("rundll32", "url.dll,FileProtocolHandler", url);
            } else {
                pb = new ProcessBuilder("xdg-open", url);
            }
            try {
                pb.start();
            } catch (Throwable t2) {
                System.out.println("[!] 自动打开浏览器失败，请手动访问上面 URL");
            }
        } catch (Throwable t) {
            System.err.println("[!] Issue 降级失败: " + t.getMessage());
        }
    }

    /** 合并 index.json：新规则加入现有索引，保留原有规则（绝不整体覆盖） */
    private static void mergeIndex(File submitIndex, File targetIndex) throws Exception {
        // 读取现有索引
        List<Map<String, Object>> existing = new ArrayList<Map<String, Object>>();
        if (targetIndex.exists()) {
            String content = new String(Files.readAllBytes(targetIndex.toPath()), StandardCharsets.UTF_8);
            Object parsed = new TinyJson().parseObject("{\"x\":" + content + "}");
            Object x = ((Map<String, Object>) parsed).get("x");
            if (x instanceof List) {
                for (Object o : (List<Object>) x) {
                    if (o instanceof Map) existing.add((Map<String, Object>) o);
                }
            }
        }
        // 读取提交的新索引
        List<Map<String, Object>> submitted = new ArrayList<Map<String, Object>>();
        if (submitIndex.exists()) {
            String content = new String(Files.readAllBytes(submitIndex.toPath()), StandardCharsets.UTF_8);
            Object parsed = new TinyJson().parseObject("{\"x\":" + content + "}");
            Object x = ((Map<String, Object>) parsed).get("x");
            if (x instanceof List) {
                for (Object o : (List<Object>) x) {
                    if (o instanceof Map) submitted.add((Map<String, Object>) o);
                }
            }
        }
        // 合并：已有 id 保留，新 id 追加
        java.util.Set<String> seen = new java.util.HashSet<String>();
        for (Map<String, Object> e : existing) seen.add(String.valueOf(e.get("id")));
        int added = 0;
        for (Map<String, Object> e : submitted) {
            String id = String.valueOf(e.get("id"));
            if (!seen.contains(id)) {
                existing.add(e);
                seen.add(id);
                added++;
            }
        }
        // 写回
        StringBuilder sb = new StringBuilder();
        sb.append("[\n");
        for (int i = 0; i < existing.size(); i++) {
            Map<String, Object> e = existing.get(i);
            sb.append("  {\"id\": \"").append(e.get("id")).append("\", \"name\": \"")
              .append(e.get("name")).append("\", \"author\": \"")
              .append(e.get("author")).append("\", \"title\": \"")
              .append(e.get("title")).append("\", \"version\": \"")
              .append(e.get("version")).append("\"}");
            sb.append(i < existing.size() - 1 ? ",\n" : "\n");
        }
        sb.append("]\n");
        Files.write(targetIndex.toPath(), sb.toString().getBytes(StandardCharsets.UTF_8));
        System.out.println("[*] index 合并完成: 新增 " + added + " 条，总 " + existing.size() + " 条");
    }

    /** 执行命令（返回退出码） */
    private static int execReturn(File dir, String... cmd) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(dir);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8));
        String line;
        while ((line = br.readLine()) != null) System.out.println("  " + line);
        return p.waitFor();
    }

    private static void exec(File dir, String... cmd) throws Exception {
        execReturn(dir, cmd);
    }

    private static String shortClass(String className) {
        if (className == null) return "unknown";
        int idx = className.lastIndexOf('.');
        return idx >= 0 ? className.substring(idx + 1) : className;
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
