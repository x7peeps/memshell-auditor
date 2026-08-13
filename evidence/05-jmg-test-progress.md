# JMG 真实内存马检测验证（进行中）

## 已完成验证

### 1. 冰蝎 Behinder Filter（Tomcat 10 / jakarta）

**注入**：JMG v1.0.9 生成 → defineClass 注入 WebappClassLoader → FilterDef 注册
**真实类名**：`org.springframework.ServletRequestAujFilter`（Spring 伪装）

**检测结果**：
```
[HIGH  ] Filter org.springframework.ServletRequestAujFilter
        信号: A1
        原因: FilterDef 注册的类在磁盘无对应 class 文件（动态加载），高度疑似内存马
[HIGH=1 MEDIUM=2 INFO=9]  → 容器组件全正常（Listener/Valve 无误报）
```

**重要发现**：真实内存马载荷全部伪装类名（Spring 前缀 + 随机后缀）：
- 冰蝎 Filter: `org.springframework.ServletRequestAujFilter`
- 哥斯拉 Filter: `org.springframework.WhiteBlackListGbyfbdFilter`
- 蚁剑 Filter: `org.springframework.AbstractMatcherVyjFilter`
- Suo5 Filter: `org.springframework.SessionKqvcFilter`
- 冰蝎 Listener: `org.springframework.Log4jConfigEaeListener`
- 哥斯拉 Valve: `org.springframework.AbstractMatcherGbValve`

→ **类名特征检测（B1）会被伪装绕过，A1 磁盘无 class 强信号是核心检测能力**
