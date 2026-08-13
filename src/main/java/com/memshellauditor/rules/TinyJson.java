package com.memshellauditor.rules;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 极简 JSON 解析器（零依赖，仅支持规则文件所需结构：对象/数组/字符串/数字/布尔/null）
 */
public class TinyJson {

    private String s;
    private int pos;

    public Map<String, Object> parseObject(String json) {
        this.s = json;
        this.pos = 0;
        Object o = parseValue();
        if (o instanceof Map) return (Map<String, Object>) o;
        return new LinkedHashMap<String, Object>();
    }

    private Object parseValue() {
        skipWs();
        if (pos >= s.length()) return null;
        char c = s.charAt(pos);
        if (c == '{') return parseMap();
        if (c == '[') return parseList();
        if (c == '"') return parseString();
        if (c == 't') { pos += 4; return Boolean.TRUE; }
        if (c == 'f') { pos += 5; return Boolean.FALSE; }
        if (c == 'n') { pos += 4; return null; }
        return parseNumber();
    }

    private Map<String, Object> parseMap() {
        Map<String, Object> map = new LinkedHashMap<String, Object>();
        pos++; // {
        skipWs();
        if (pos < s.length() && s.charAt(pos) == '}') { pos++; return map; }
        while (pos < s.length()) {
            skipWs();
            String key = parseString();
            skipWs();
            if (pos < s.length() && s.charAt(pos) == ':') pos++;
            Object val = parseValue();
            map.put(key, val);
            skipWs();
            if (pos < s.length() && s.charAt(pos) == ',') { pos++; continue; }
            if (pos < s.length() && s.charAt(pos) == '}') { pos++; break; }
        }
        return map;
    }

    private List<Object> parseList() {
        List<Object> list = new ArrayList<Object>();
        pos++; // [
        skipWs();
        if (pos < s.length() && s.charAt(pos) == ']') { pos++; return list; }
        while (pos < s.length()) {
            Object val = parseValue();
            list.add(val);
            skipWs();
            if (pos < s.length() && s.charAt(pos) == ',') { pos++; continue; }
            if (pos < s.length() && s.charAt(pos) == ']') { pos++; break; }
        }
        return list;
    }

    private String parseString() {
        if (pos >= s.length() || s.charAt(pos) != '"') return "";
        pos++;
        StringBuilder sb = new StringBuilder();
        while (pos < s.length()) {
            char c = s.charAt(pos);
            if (c == '"') { pos++; break; }
            if (c == '\\' && pos + 1 < s.length()) {
                char n = s.charAt(pos + 1);
                if (n == 'n') { sb.append('\n'); pos += 2; continue; }
                if (n == 't') { sb.append('\t'); pos += 2; continue; }
                if (n == 'r') { sb.append('\r'); pos += 2; continue; }
                if (n == 'u' && pos + 5 < s.length()) {
                    try {
                        sb.append((char) Integer.parseInt(s.substring(pos + 2, pos + 6), 16));
                        pos += 6;
                        continue;
                    } catch (Throwable ignored) {}
                }
                sb.append(n);
                pos += 2;
                continue;
            }
            sb.append(c);
            pos++;
        }
        return sb.toString();
    }

    private Object parseNumber() {
        int start = pos;
        while (pos < s.length() && (Character.isDigit(s.charAt(pos))
                || s.charAt(pos) == '-' || s.charAt(pos) == '.' || s.charAt(pos) == 'e' || s.charAt(pos) == 'E')) {
            pos++;
        }
        try {
            String num = s.substring(start, pos);
            if (num.contains(".")) return Double.parseDouble(num);
            return Long.parseLong(num);
        } catch (Throwable t) {
            return null;
        }
    }

    private void skipWs() {
        while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) pos++;
    }
}
