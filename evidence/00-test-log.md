# memshell-auditor 检测能力验证记录（最终版）

> 日期：2026-08-13 ｜ 环境：macOS (Apple Silicon) ｜ JDK 26 编译（--release 8）
> 测试载荷：java-memshell-generator (JMG) v1.0.9_250101 源码构建生成

## 测试矩阵：开源生成器真实载荷检测

| # | 载荷 | 工具 | 内存马类型 | 真实类名（伪装） | 目标容器 | 检测结果 |
|---|---|---|---|---|---|---|
| 1 | behinder-filter | 冰蝎 Behinder | JakartaFilter | `org.springframework.ServletRequestAujFilter` | Tomcat 10.1 | ✅ **HIGH** |
| 2 | godzilla-filter | 哥斯拉 Godzilla | JakartaFilter | `org.springframework.WhiteBlackListGbyfbdFilter` | Tomcat 10.1 | ✅ **HIGH** |
| 3 | antsword-filter | 蚁剑 AntSword | JakartaFilter | `org.springframework.AbstractMatcherVyjFilter` | Tomcat 10.1 | ✅ **HIGH** |
| 4 | suo5-filter | Suo5 隧道 | Filter | `org.springframework.SessionKqvcFilter` | Tomcat 9.0 | ✅ **HIGH** |
| 5 | behinder-listener | 冰蝎 Behinder | JakartaListener | `org.apache.logging.Log4jConfigEaeListener` | Tomcat 10.1 | ✅ **HIGH** |
| 6 | godzilla-valve | 哥斯拉 Godzilla | Valve | `org.apache.AbstractMatcherGbValve` | Tomcat 10.1 | ✅ **HIGH** |
| 7 | behinder-listener2 | 冰蝎 Behinder | Listener | `org.springframework.ContextLoaderDmasjListener` | Tomcat 9.0 | ✅ **HIGH** |

**命中率：7/7 (100%)**，全部以 A1 强信号（FilterDef 注册类磁盘无 class 文件）判定为 HIGH

## 核心发现

### 1. 真实内存马全部伪装类名
JMG v1.0.9 生成的所有载荷均伪装为框架类名（Spring/Logging/Apache 前缀 + 随机后缀）：
- 这证明 **B1 类名特征检测可被绕过**（伪装类名规避关键字/包名规则）
- **A1 磁盘无 class 文件强信号不受影响**——因为不管类名伪装成什么，磁盘上都不存在对应 class 文件

### 2. 检测机制（为什么能命中）
```
FilterDef 注册表审计（内存马第一落点）
  └─ 读取 filterDefs 中的 filterClass
      └─ classExistsOnDisk() 用 ClassLoader.getResourceAsStream 探测磁盘
          └─ 磁盘无对应 class 文件 → A1 强信号 → HIGH
```

### 3. 误报控制
- 正常 Filter（BizFilter，磁盘 WEB-INF/classes 存在）→ INFO 正常
- 容器自带 Listener/Valve → 全部 INFO 正常
- JDK 类/数组类/自身类 → 白名单豁免

## 检测输出示例（behinder-filter）

```json
{
  "level": "HIGH",
  "signal": "A1",
  "category": "Filter",
  "className": "org.springframework.ServletRequestAujFilter",
  "reason": "FilterDef 注册的类在磁盘无对应 class 文件（动态加载），高度疑似内存马"
}
```

## 测试环境

- Tomcat 10.1.24 (jakarta) / Tomcat 9.0.89 (javax)
- 注入方式：defineClass 注入 WebappClassLoader + FilterDef 动态注册（与真实攻击链一致）
- JMG 生成配置：TOOL_BEHINDER/GODZILLA/ANTSWORD/SUO5 + SHELL_JAKARTA_FILTER/LISTENER/VALVE + BASE64 + bypass JDK Module
