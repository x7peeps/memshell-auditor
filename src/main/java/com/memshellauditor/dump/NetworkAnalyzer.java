package com.memshellauditor.dump;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 进程网络连接分析器（回连 IP 分析）：
 *  - Linux: 解析 /proc/&lt;pid&gt;/net/tcp + tcp6，结合 /proc/&lt;pid&gt;/fd 的 socket inode 匹配本进程连接
 *  - macOS: 执行 lsof -p &lt;pid&gt; -iTCP（可选，需要 lsof 权限）
 *
 * 输出：ESTABLISHED 外连（本地端口 -> 远端 IP:端口），用于判断内存马回连 C2。
 */
public final class NetworkAnalyzer {

    private NetworkAnalyzer() {}

    /** 分析指定 PID 的网络外连 */
    public static List<Conn> analyze(int pid) {
        List<Conn> result = new ArrayList<Conn>();
        String os = System.getProperty("os.name", "").toLowerCase();
        try {
            if (os.contains("linux")) {
                result = analyzeLinux(pid);
            } else if (os.contains("mac") || os.contains("darwin")) {
                result = analyzeMac(pid);
            } else if (os.contains("win")) {
                result = analyzeWindows(pid);
            } else {
                // 其他系统尝试 lsof
                result = analyzeMac(pid);
            }
        } catch (Throwable t) {
            // ignore
        }
        // 过滤：只保留"疑似外连"（非 localhost / 非私有网段 / 非常见系统端口）
        List<Conn> filtered = new ArrayList<Conn>();
        for (Conn c : result) {
            if (isSuspiciousRemote(c.remote)) filtered.add(c);
        }
        return filtered;
    }

    /** 判断远端是否为疑似外连（过滤 localhost / 私有网段 / mDNS / 系统服务） */
    private static boolean isSuspiciousRemote(String remote) {
        if (remote == null || remote.isEmpty()) return false;
        String host = remote.split(":")[0].replace("[", "").replace("]", "");
        // 本机回环与主机名
        if (host.equals("localhost") || host.equals("127.0.0.1") || host.equals("::1")) return false;
        if (host.contains(".local")) return false;
        // 私有网段
        if (host.startsWith("10.") || host.startsWith("192.168.") || host.startsWith("172.")
                || host.startsWith("169.254.")) return false;
        // 系统服务端口（代理、监控等常见非恶意端口）
        String portPart = remote.contains(":") ? remote.substring(remote.lastIndexOf(':') + 1) : "";
        if (portPart.equals("1024") || portPart.equals("5228") || portPart.equals("5353")
                || portPart.equals("443") || portPart.equals("80")) {
            // 443/80 保留（C2 常用），其他系统端口过滤
            if (!portPart.equals("443") && !portPart.equals("80")) return false;
        }
        // IPv6 本地链路
        if (host.startsWith("fe80") || host.startsWith("fc") || host.startsWith("fd")) return false;
        return true;
    }

    // ---------------- Linux ----------------

    private static List<Conn> analyzeLinux(int pid) {
        List<Conn> conns = new ArrayList<Conn>();
        Map<String, String> inodes = new LinkedHashMap<String, String>();
        // 1. 收集进程的 socket inode
        File fdDir = new File("/proc/" + pid + "/fd");
        File[] fds = fdDir.listFiles();
        if (fds != null) {
            for (File fd : fds) {
                try {
                    String target = new java.io.File("/proc/" + pid + "/fd/" + fd.getName())
                            .getCanonicalPath();
                    if (target.contains("socket:[")) {
                        String inode = target.substring(target.indexOf('[') + 1, target.indexOf(']'));
                        inodes.put(inode, fd.getName());
                    }
                } catch (Throwable ignored) {
                }
            }
        }
        // 2. 解析 /proc/net/tcp 与 tcp6
        for (String proto : new String[]{"tcp", "tcp6"}) {
            File netFile = new File("/proc/" + pid + "/net/" + proto);
            if (!netFile.exists()) {
                // 某些容器内 /proc/pid/net 不可见，尝试 /proc/net
                netFile = new File("/proc/net/" + proto);
            }
            if (!netFile.exists()) continue;
            BufferedReader br = null;
            try {
                br = new BufferedReader(new InputStreamReader(new java.io.FileInputStream(netFile), "UTF-8"));
                String line;
                br.readLine(); // header
                while ((line = br.readLine()) != null) {
                    String[] parts = line.trim().split("\\s+");
                    if (parts.length < 10) continue;
                    String local = parts[1];
                    String remote = parts[2];
                    String state = parts[3];
                    String inode = parts[9];
                    // 只关心 ESTABLISHED（01）且有远端地址
                    if (!state.equals("01")) continue;
                    if (remote.equals("00000000:0000") || remote.equals("00000000000000000000000000000000:0000")) continue;
                    if (!inodes.containsKey(inode)) continue; // 不是本进程的连接
                    String lIp = hexToIpv4(local.split(":")[0]);
                    int lPort = Integer.parseInt(local.split(":")[1], 16);
                    String rIp = hexToIpv4(remote.split(":")[0]);
                    int rPort = Integer.parseInt(remote.split(":")[1], 16);
                    conns.add(new Conn("ESTABLISHED", lIp + ":" + lPort, rIp + ":" + rPort, inode));
                }
            } catch (Throwable ignored) {
            } finally {
                if (br != null) try { br.close(); } catch (Exception ignored) {}
            }
        }
        return conns;
    }

    private static String hexToIpv4(String hex) {
        try {
            if (hex.length() == 8) {
                long v = Long.parseLong(hex, 16);
                return (v & 0xFF) + "." + ((v >> 8) & 0xFF) + "." + ((v >> 16) & 0xFF) + "." + ((v >> 24) & 0xFF);
            }
        } catch (Throwable ignored) {
        }
        return hex;
    }

    // ---------------- macOS ----------------

    private static List<Conn> analyzeMac(int pid) {
        List<Conn> conns = new ArrayList<Conn>();
        try {
            ProcessBuilder pb = new ProcessBuilder("lsof", "-p", String.valueOf(pid), "-iTCP", "-sTCP:ESTABLISHED");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), "UTF-8"));
            String line;
            br.readLine(); // header
            while ((line = br.readLine()) != null) {
                // lsof 输出: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
                String[] parts = line.trim().split("\\s+");
                if (parts.length < 9) continue;
                String name = parts[8];
                // NAME 形如 1.2.3.4:5678->5.6.7.8:9999
                if (name.contains("->")) {
                    String local = name.split("->")[0];
                    String remote = name.split("->")[1];
                    conns.add(new Conn("ESTABLISHED", local, remote, parts[7]));
                }
            }
            br.close();
        } catch (Throwable ignored) {
        }
        return conns;
    }

    /** 连接记录 */
    public static class Conn {
        public final String state;
        public final String local;
        public final String remote;
        public final String inode;

        public Conn(String state, String local, String remote, String inode) {
            this.state = state;
            this.local = local;
            this.remote = remote;
            this.inode = inode;
        }

        public String toJson() {
            return "{\"state\":\"" + state + "\",\"local\":\"" + local
                    + "\",\"remote\":\"" + remote + "\",\"inode\":\"" + inode + "\"}";
        }

        @Override
        public String toString() {
            return local + " -> " + remote + " (" + state + ")";
        }
    }

    // ---------------- Windows ----------------

    private static List<Conn> analyzeWindows(int pid) {
        List<Conn> conns = new ArrayList<Conn>();
        try {
            // netstat -ano 输出: TCP 1.2.3.4:80 5.6.7.8:443 ESTABLISHED 1234
            ProcessBuilder pb = new ProcessBuilder("netstat", "-ano");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream(), "UTF-8"));
            String line;
            String pidStr = String.valueOf(pid);
            while ((line = br.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty()) continue;
                if (!line.toLowerCase().startsWith("tcp")) continue;
                // 最后一段是 PID
                int lastSpace = line.lastIndexOf(' ');
                if (lastSpace < 0) continue;
                String linePid = line.substring(lastSpace + 1).trim();
                if (!linePid.equals(pidStr)) continue;
                String[] parts = line.split("\\s+");
                if (parts.length < 4) continue;
                String local = parts[1];
                String remote = parts[2];
                String state = parts[3];
                if ("0.0.0.0:0".equals(remote) || "[::]:0".equals(remote) || "127.0.0.1".equals(remote.split(":")[0])) continue;
                conns.add(new Conn(state, local, remote, "-"));
            }
            br.close();
            p.waitFor();
        } catch (Throwable t) {
            // ignore
        }
        return conns;
    }
}
