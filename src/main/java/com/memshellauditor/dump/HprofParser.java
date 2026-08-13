package com.memshellauditor.dump;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * hprof 堆转储解析器（轻量版，零依赖）：
 *  - 解析 hprof 二进制格式的 STRING 记录 → 提取所有字符串（类名/IP/URL/命令等）
 *  - 解析 LOAD CLASS 记录 → 类名列表（堆中加载过的类）
 *  - 在堆的字节数组中搜索类字节码（cafebabe 魔数 → 可恢复内存马字节码）
 *
 * hprof 格式（1.0.2）：
 *  文件头: "JAVA PROFILE 1.0.2" + idSize + heapDumpTimestamp
 *  记录:  1字节tag + 4字节time + 4字节length + body
 *  STRING (0x01): id + UTF8 bytes
 *  LOAD CLASS (0x02): classSerial(4) + classObjectId(id) + stackTraceSerial(4) + classNameStringId(id)
 */
public final class HprofParser {

    private HprofParser() {}

    public static class HprofResult {
        public List<String> strings = new ArrayList<String>();      // 提取的字符串
        public List<String> classNames = new ArrayList<String>();   // 类名
        public List<String> suspicious = new ArrayList<String>();   // 恶意特征命中
        public int classBytecodeHits = 0;                           // 堆中类字节码数量
        public String summary = "";
    }

    private static final String[] MALICIOUS_KEYWORDS = {
            "behinder", "godzilla", "memshell", "webshell", "ClassLoader",
            "Runtime.getRuntime", "ProcessBuilder", "getParameter", "Cipher",
            "AES", "Base64", "Socket", "InetSocketAddress"
    };

    /** 解析 hprof 文件（限制 1GB 防内存溢出） */
    public static HprofResult parse(File hprof) {
        HprofResult r = new HprofResult();
        if (hprof == null || !hprof.exists() || hprof.length() == 0) return r;
        try {
            RandomAccessFile raf = new RandomAccessFile(hprof, "r");
            // 文件头: "JAVA PROFILE 1.0.x" + \0 + idSize(1) + timestamp(8)
            byte[] header = new byte[24];
            int n = raf.read(header);
            if (n < 24) { raf.close(); return r; }
            String magic = new String(header, 0, 16, "US-ASCII");
            if (!magic.startsWith("JAVA PROFILE")) { raf.close(); return r; }
            // magic 字符串长度可变（1.0.1/1.0.2），找 \0 分隔符
            int zeroIdx = -1;
            for (int i = 0; i < 24; i++) {
                if (header[i] == 0) { zeroIdx = i; break; }
            }
            if (zeroIdx < 0) { raf.close(); return r; }
            // idSize 是 u4（4 字节大端）：offset zeroIdx+1 .. zeroIdx+4
            int idSize = ((header[zeroIdx + 1] & 0xFF) << 24)
                    | ((header[zeroIdx + 2] & 0xFF) << 16)
                    | ((header[zeroIdx + 3] & 0xFF) << 8)
                    | (header[zeroIdx + 4] & 0xFF);
            if (idSize != 4 && idSize != 8) idSize = 4; // 兜底
            // 文件头结束位置 = magic + \0 + idSize(u4=4) + timestamp(u8=8)
            raf.seek(zeroIdx + 1 + 4 + 8);

            // 遍历记录
            long fileLen = raf.length();
            int recordCount = 0;
            Map<Long, String> stringTable = new HashMap<Long, String>();
            while (raf.getFilePointer() + 9 <= fileLen && recordCount < 5_000_000) {
                int tag = raf.readUnsignedByte();
                raf.readInt(); // time
                int len = raf.readInt();
                if (len < 0 || raf.getFilePointer() + len > fileLen) break;
                long bodyStart = raf.getFilePointer();
                try {
                    if (tag == 0x01) { // STRING
                        long id = readId(raf, idSize);
                        int strLen = len - idSize;
                        if (strLen > 0 && strLen < 100_000) {
                            byte[] buf = new byte[strLen];
                            raf.readFully(buf);
                            String s = new String(buf, "UTF-8");
                            stringTable.put(id, s);
                            r.strings.add(s);
                        }
                    } else if (tag == 0x02) { // LOAD CLASS
                        raf.readInt(); // class serial
                        readId(raf, idSize); // class object id
                        raf.readInt(); // stack trace serial
                        long nameId = readId(raf, idSize);
                        String name = stringTable.get(nameId);
                        if (name != null) r.classNames.add(name);
                    }
                } finally {
                    raf.seek(bodyStart + len);
                }
                recordCount++;
            }
            raf.close();

            // 恶意特征扫描（字符串）
            for (String s : r.strings) {
                if (s == null || s.length() < 3) continue;
                String lower = s.toLowerCase();
                for (String kw : MALICIOUS_KEYWORDS) {
                    if (lower.contains(kw.toLowerCase())) {
                        if (s.length() <= 120) r.suspicious.add(s);
                        break;
                    }
                }
            }

            // 类字节码统计（cafebabe 魔数在堆中的出现，含内存马字节码）
            try {
                byte[] buf = new byte[(int) Math.min(hprof.length(), 256 * 1024 * 1024)];
                RandomAccessFile raf2 = new RandomAccessFile(hprof, "r");
                raf2.readFully(buf);
                raf2.close();
                r.classBytecodeHits = countMagic(buf);
            } catch (Throwable ignored) {}

            // 汇总
            StringBuilder sb = new StringBuilder();
            sb.append("hprof 解析: 字符串 ").append(r.strings.size())
              .append(" 条 / 类 ").append(r.classNames.size())
              .append(" 个 / 恶意特征命中 ").append(r.suspicious.size())
              .append(" / 类字节码 ").append(r.classBytecodeHits).append(" 段");
            r.summary = sb.toString();
        } catch (Throwable t) {
            r.summary = "hprof 解析异常: " + t;
        }
        return r;
    }

    private static long readId(RandomAccessFile raf, int idSize) throws Exception {
        long v = 0;
        for (int i = 0; i < idSize; i++) {
            v = (v << 8) | (raf.readUnsignedByte() & 0xFF);
        }
        return v;
    }

    private static int countMagic(byte[] data) {
        int count = 0;
        for (int i = 0; i <= data.length - 4; i++) {
            if ((data[i] & 0xFF) == 0xCA && (data[i+1] & 0xFF) == 0xFE
                    && (data[i+2] & 0xFF) == 0xBA && (data[i+3] & 0xFF) == 0xBE) count++;
        }
        return count;
    }
}
