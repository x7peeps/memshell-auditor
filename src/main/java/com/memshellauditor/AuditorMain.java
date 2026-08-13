package com.memshellauditor;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.util.Properties;

/**
 * CLI 启动器：attach 到目标 JVM 并加载审计 Agent。
 *
 * 用法:
 *   java -jar memshell-auditor.jar <pid> [output.json]
 *   java -jar memshell-auditor.jar --list            # 列出本机 Java 进程
 *
 * 兼容 JDK 8+：使用反射调用 com.sun.tools.attach 避免编译期硬依赖。
 * JDK 9+ 模块系统下需要 --add-modules jdk.attach（脚本已封装）。
 */
public class AuditorMain {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            usage();
            return;
        }
        if (args[0].equals("--list") || args[0].equals("-l")) {
            listJvms();
            return;
        }
        String pid = args[0];
        String out = (args.length > 1) ? args[1] : null;
        if (out == null) {
            out = "memshell-auditor-report-" + pid + "-" + System.currentTimeMillis() + ".json";
        }
        File agentJar = locateAgentJar();
        if (agentJar == null) {
            System.err.println("[!] 无法定位 memshell-auditor agent jar（应与本 CLI 同目录或同 classpath）");
            System.exit(2);
        }
        run(pid, agentJar, out);
    }

    private static void usage() {
        System.out.println("memshell-auditor - Java 内存马运行时审计 Agent CLI");
        System.out.println("用法:");
        System.out.println("  java -jar memshell-auditor.jar <pid> [output.json]");
        System.out.println("  java -jar memshell-auditor.jar --list");
        System.out.println("示例:");
        System.out.println("  java -jar memshell-auditor.jar 12345");
        System.out.println("  java -jar memshell-auditor.jar 12345 /tmp/report.json");
    }

    private static void listJvms() throws Exception {
        Class<?> vmClass = Class.forName("com.sun.tools.attach.VirtualMachine");
        Method list = vmClass.getMethod("list");
        Object vms = list.invoke(null);
        java.util.List<?> lst = (java.util.List<?>) vms;
        System.out.println("本机 Java 进程:");
        for (Object vm : lst) {
            Method id = vm.getClass().getMethod("id");
            Method display = vm.getClass().getMethod("displayName");
            System.out.println("  " + id.invoke(vm) + "  " + display.invoke(vm));
        }
    }

    private static void run(String pid, File agentJar, String outPath) throws Exception {
        System.out.println("[*] attach 目标 PID=" + pid);
        Class<?> vmClass = Class.forName("com.sun.tools.attach.VirtualMachine");
        Method attach = vmClass.getMethod("attach", String.class);
        Object vm = attach.invoke(null, pid);
        try {
            Method loadAgent = vmClass.getMethod("loadAgent", String.class, String.class);
            String agentArgs = "output=" + new File(outPath).getAbsolutePath() + ",pid=" + pid;
            System.out.println("[*] 加载 agent: " + agentJar.getAbsolutePath());
            loadAgent.invoke(vm, agentJar.getAbsolutePath(), agentArgs);
            System.out.println("[*] agent 执行完成，报告: " + new File(outPath).getAbsolutePath());
            // 输出报告内容
            File f = new File(outPath);
            if (f.exists()) {
                System.out.println("========== JSON 报告 ==========");
                InputStream in = new java.io.FileInputStream(f);
                byte[] buf = new byte[(int) Math.min(f.length(), 512 * 1024)];
                int n = in.read(buf);
                in.close();
                if (n > 0) System.out.println(new String(buf, 0, n, "UTF-8"));
            }
        } finally {
            Method detach = vmClass.getMethod("detach");
            detach.invoke(vm);
        }
    }

    private static File locateAgentJar() {
        // 1) 同目录
        try {
            File self = new File(AuditorMain.class.getProtectionDomain().getCodeSource().getLocation().toURI());
            if (self.isFile() && self.getName().endsWith(".jar")) {
                return self;
            }
        } catch (Throwable t) {
            // ignore
        }
        // 2) 环境变量
        String env = System.getenv("MEMSHELL_AUDITOR_JAR");
        if (env != null && new File(env).exists()) return new File(env);
        return null;
    }
}
