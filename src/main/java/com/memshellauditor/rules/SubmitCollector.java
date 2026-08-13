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
                gitCommit(submitDir, candidates);
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

    /** git 提交（需要本地已有规则仓库 clone 或自动 clone） */
    private static void gitCommit(File submitDir, List<Rule> rules) {
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
            // 更新 index.json（合并）
            try {
                Files.copy(new File(submitDir, "index.json").toPath(),
                        new File(workDir, "rules/index.json").toPath(),
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (Throwable ignored) {}
            exec(workDir, "git", "add", "-A");
            String msg = new String(Files.readAllBytes(new File(submitDir, "COMMIT_MSG").toPath()), StandardCharsets.UTF_8);
            exec(workDir, "git", "commit", "-m", msg);
            System.out.println("[*] 已提交（push 需用户确认: cd " + workDir + " && git push）");
        } catch (Throwable t) {
            System.err.println("[!] git 提交失败: " + t.getMessage());
        }
    }

    private static void exec(File dir, String... cmd) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(dir);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8));
        String line;
        while ((line = br.readLine()) != null) System.out.println("  " + line);
        p.waitFor();
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
