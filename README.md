# memshell-auditor

Java 内存马（Memory Shell）运行时审计 Agent —— attach 到目标 JVM，检测容器层（Filter/Servlet/Listener/Valve）与 JVM 层（Agent 型/defineClass 注入）内存马。

**零依赖**（JDK 8 编译，目标 JVM 兼容 JDK 8-21+），**纯反射**实现（不依赖具体中间件类），**JSON/控制台双输出**。

> ⚠️ 本工具仅用于授权环境下的安全应急响应、攻防演练与防御建设。请确保你的行为符合当地法律法规。

## 为什么需要它

内存马是 Web 攻防中最难检测的一类后门：
- **无文件落盘**：磁盘扫描/WAF/EDR 文件检测全部失效
- **类名伪装**：主流生成器（JMG/MemShellParty）生成的载荷全部伪装成 `org.springframework.*` 等框架类名，规避关键词检测
- **容器层扫描盲区**：Filter 型内存马注册在容器内部，不产生磁盘文件，传统 WebShell 扫描器无能为力

memshell-auditor 通过 **attach 到运行中的 JVM**，直接审计容器内部组件注册表与 JVM 已加载类，从根源判断"这个组件磁盘上到底存不存在"。

## 检测能力

### 检测维度

| 信号 | 检测项 | 判定 |
|---|---|---|
| **A1** | FilterDef/FilterConfig/Servlet/Listener/Valve 注册的类在磁盘无对应 class 文件 | 🔴 高度疑似（内存马核心特征） |
| **A2** | 容器组件注册数量异常（对比基线） | 🔴 需人工复核 |
| **A3** | 非系统 ClassLoader（自定义 Loader）加载恶意类 | 🟠 需人工复核 |
| **A4** | `-javaagent`/`-agentlib`/`JAVA_TOOL_OPTIONS` 注入 Agent | 🔴 高度疑似 |
| **B1** | 类名特征（无包名/短随机名/恶意关键字） | 🟡 辅助信号 |
| **B2** | 已加载类名含可疑关键字 | 🟡 辅助信号 |

### 检测原理

```
attach 目标 JVM (VirtualMachine.attach)
  ├─ ContainerAuditor: 定位 StandardContext
  │    └─ WebappClassLoader.resources(字段) → StandardRoot.getContext()
  │         ├─ filterDefs/filterConfigs 审计 → Filter 类磁盘存在性
  │         ├─ findChildren() → Servlet 审计
  │         ├─ applicationEventListeners → Listener 审计
  │         └─ getPipeline().getValves() → Valve 审计
  ├─ AgentAuditor: 启动参数/环境变量/classpath 审计
  ├─ ClassLoaderAuditor: ClassLoader 血缘分析
  └─ ClassFeatureAuditor: 已加载类特征 + 磁盘存在性
        └─ 非系统 Loader + 磁盘无 class → A1 强信号
```

### 实测检测结果（开源生成器真实载荷）

使用 **java-memshell-generator (JMG) v1.0.9** 生成真实内存马载荷，注入 Tomcat 9/10 靶场（defineClass 注入 WebappClassLoader + FilterDef 动态注册，与真实攻击链一致），**7/7 全部检出（100%）**：

| 载荷 | 工具 | 内存马类型 | 真实类名（伪装） | 容器 | 结果 |
|---|---|---|---|---|---|
| behinder-filter | 冰蝎 Behinder | JakartaFilter | `org.springframework.ServletRequestAujFilter` | Tomcat 10.1 | ✅ HIGH |
| godzilla-filter | 哥斯拉 Godzilla | JakartaFilter | `org.springframework.WhiteBlackListGbyfbdFilter` | Tomcat 10.1 | ✅ HIGH |
| antsword-filter | 蚁剑 AntSword | JakartaFilter | `org.springframework.AbstractMatcherVyjFilter` | Tomcat 10.1 | ✅ HIGH |
| suo5-filter | Suo5 隧道 | Filter | `org.springframework.SessionKqvcFilter` | Tomcat 9.0 | ✅ HIGH |
| behinder-listener | 冰蝎 Behinder | JakartaListener | `org.apache.logging.Log4jConfigEaeListener` | Tomcat 10.1 | ✅ HIGH |
| godzilla-valve | 哥斯拉 Godzilla | Valve | `org.apache.AbstractMatcherGbValve` | Tomcat 10.1 | ✅ HIGH |
| behinder-listener2 | 冰蝎 Behinder | Listener | `org.springframework.ContextLoaderDmasjListener` | Tomcat 9.0 | ✅ HIGH |

**关键结论**：主流生成器全部伪装类名（Spring/Logging/Apache 前缀 + 随机后缀），类名特征检测可被绕过；但 **A1 强信号（磁盘无 class 文件）不受影响**，因为无论类名伪装成什么，磁盘上都不存在对应 class 文件。

**误报控制**：正常业务 Filter（磁盘 WEB-INF/classes 存在）→ INFO；容器自带 Listener/Valve → INFO；JDK 类/数组类/自身类 → 白名单豁免。

完整测试记录见 [evidence/00-test-log.md](evidence/00-test-log.md)。

## 快速开始

### 构建

```bash
mvn clean package -DskipTests
# 产物: target/memshell-auditor.jar
```

需要 JDK 8+ 编译环境（`--release 8` 保证目标 JVM 兼容 JDK 8-21+）。

### 使用

```bash
# 1. 列出本机 Java 进程
java -jar memshell-auditor.jar --list

# 2. attach 到目标 JVM 执行审计（JDK 9+ 需要 --add-modules jdk.attach）
java -jar memshell-auditor.jar <PID> [report.json]

# 3. 审计器输出 JSON 报告（控制台同时打印人类可读摘要）
```

示例：

```bash
$ java -jar memshell-auditor.jar 12345 /tmp/report.json

目标: /opt/app / java -jar app.jar
PID : 12345
JVM : 17.0.10
------------------------------------------
[01] [HIGH  ] Filter
     信号: A1
     类  : org.springframework.ServletRequestAujFilter
     Loader: ParallelWebappClassLoader (context: ROOT)
     原因: FilterDef 注册的类在磁盘无对应 class 文件（动态加载），高度疑似内存马
     证据: 核对 org.springframework.ServletRequestAujFilter 是否存在对应 class/jar
------------------------------------------
汇总: HIGH=1 MEDIUM=0 LOW=0 INFO=9 总计=10
```

### 作为 Agent 预挂载（事前巡检）

```bash
java -javaagent:/path/to/memshell-auditor.jar -jar app.jar
# premain 模式：启动时自动执行一次审计，配合基线比对
```

## 支持的中间件

- **Tomcat** 5-11（javax 与 jakarta 双命名空间，纯反射实现）
- **Spring Boot** 内嵌容器（StandardContext 同源）
- **类 Tomcat 国产中间件**（TongWeb/BES/InforSuite 等，容器 API 同源，部分需人工复核）
- 定位逻辑：`WebappClassLoader` 反查 + MBeanServer 辅助

## 判断标准体系

与应急响应方法论对齐（A=强信号，B=辅助信号）：

| 级别 | 含义 | 处置建议 |
|---|---|---|
| 🔴 HIGH | 命中 A1/A4 强信号 | 立即隔离 → 取证 → 清除 → 溯源 |
| 🟠 MEDIUM | 命中 A3/B1/B2 | 深度审计确认后升级 |
| 🟡 LOW | 无法解析组件 | 人工复核 |
| ⚪ INFO | 正常组件/信息 | 记录归档 |

## 项目结构

```
src/main/java/com/memshellauditor/
├── AgentMain.java           # agent 入口（premain/agentmain）
├── AuditorMain.java         # CLI 启动器（attach）
├── detect/
│   ├── ContainerAuditor.java    # 容器组件审计（Filter/Servlet/Listener/Valve）
│   ├── AgentAuditor.java        # 启动参数/Agent 型检测
│   ├── ClassLoaderAuditor.java  # ClassLoader 血缘
│   └── ClassFeatureAuditor.java # 类特征 + defineClass 检测
├── report/
│   ├── Finding.java         # 发现项（level/signal/category）
│   └── Report.java          # 报告聚合（控制台/JSON）
└── util/
    └── ReflectUtil.java     # 零依赖反射工具
```

## 局限性（坦诚声明）

1. **Agent 型内存马（Instrumentation transformer 注入）**：JDK 标准 API 无法枚举已注册的 ClassFileTransformer，目前通过启动参数 + 类特征间接检测；完整 transformer 审计需结合 JVMTI 工具
2. **容器定位依赖 WebappClassLoader**：极度精简的 classpath 模式（非 WAR 部署）可能定位不到 StandardContext，此时依赖 MBean 辅助与类特征检测
3. **误报需人工复核**：A3/B1/B2 为辅助信号，无包名等特征也可能来自合法动态代理
4. **运行时窗口**：attach 只能看到当前已加载的类；内存马在 attach 前已执行完的恶意行为不在检测范围（这是所有运行时检测的共性）

## License

MIT
