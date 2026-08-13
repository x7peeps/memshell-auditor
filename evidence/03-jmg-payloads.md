# JMG (java-memshell-generator v1.0.9) 真实载荷生成记录

> 日期：2026-08-13 ｜ 工具：pen4uin/java-memshell-generator v1.0.9_250101（源码构建）
> 生成方式：jmg-sdk API（Tomcat 9 + 各工具/内存马类型 + BASE64 格式 + bypass JDK Module）

## 生成的载荷清单（/tmp/jmg-payloads/）

| 载荷名 | 工具 | 内存马类型 | shell 大小 | injector 大小 |
|---|---|---|---|---|
| behinder-filter | 冰蝎 Behinder | JakartaFilter | 4195 B | 13439 B |
| behinder-listener | 冰蝎 Behinder | JakartaListener | 4700 B | 12027 B |
| behinder-listener2 | 冰蝎 Behinder | Listener | 4678 B | 12044 B |
| godzilla-filter | 哥斯拉 Godzilla | JakartaFilter | 6508 B | 14991 B |
| godzilla-valve | 哥斯拉 Godzilla | Valve | 6068 B | 12530 B |
| antsword-filter | 蚁剑 AntSword | JakartaFilter | 3593 B | 13138 B |
| suo5-filter | Suo5 隧道 | JakartaFilter | 16329 B | 21931 B |

## 生成命令（等价 SDK 配置）

```java
AbstractConfig config = new AbstractConfig() {{
    setToolType(Constants.TOOL_BEHINDER);          // 工具类型
    setServerType(Constants.SERVER_TOMCAT);        // 目标中间件
    setShellType(Constants.SHELL_JAKARTA_FILTER);  // 内存马类型
    setPass("pass"); setKey("key");                // 连接密码/密钥
    setOutputFormat(Constants.FORMAT_BASE64);
    setGadgetType(Constants.GADGET_NONE);
    build();
}};
config.setEnableBypassJDKModule(true);
```

## 验证要点

- 载荷为真实开源生成器产物（非手工模拟）
- 覆盖 Filter / Listener / Valve 三种注入形态
- 覆盖冰蝎/哥斯拉/蚁剑/Suo5 四种主流工具
- 注入靶场后由 memshell-auditor attach 检测
