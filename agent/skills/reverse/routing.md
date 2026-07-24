# Reverse Engineering Routing Matrix

本文件只负责把逆向任务路由到仓库中实际存在的子 skill。授权、归档、真实
Android 设备和证据边界仍以 `agent/AGENT.md`、`reverse-security.md` 与当前任务
规则为准。

## 路由顺序

1. 识别目标类型、用户目标、当前阶段和已有材料。
2. 选择一个主 skill；只有跨层分析确有需要时再加载一个 supporting skill。
3. 读取目标 `SKILL.md` 后才执行分析。
4. 动态动作前读取 capability manifest 并运行能力探测；没有所需能力时使用
   静态 fallback 或记录材料阻塞。
5. 新证据改变目标类型或控制边界时重新路由，不把旧假设继续当作事实。

## 主入口

| 目标或意图 | 主 skill | 可选 supporting skill |
|---|---|---|
| 通用反编译、反汇编、算法或反混淆 | `reverse-engineering/SKILL.md` | `ida-reverse/SKILL.md` 或 `radare2/SKILL.md` |
| IDA 伪代码、交叉引用、数据流和函数语义 | `ida-reverse/SKILL.md` | `reverse-engineering/SKILL.md` |
| radare2/r2 CLI 快速侦察、脚本化分析或 patch | `radare2/SKILL.md` | `reverse-engineering/SKILL.md` |
| APK 解包、Manifest、jadx、apktool、smali | `apk-reverse/SKILL.md` | native `.so` 再选 `ida-reverse/` 或 `radare2/` |
| Android/iOS 动态插桩、Frida、证书绑定 | `mobile-reverse/SKILL.md` | `apk-reverse/SKILL.md` |
| JavaScript、前端签名、SourceMap、CDP/Hook | `js-reverse/SKILL.md` | `../js-runtime-analysis.md` |
| 跨版本函数匹配和符号迁移 | `binary-diff/SKILL.md` | `ida-reverse/SKILL.md` |
| N-day、补丁差分和漏洞点定位 | `patch-diff-exploit/SKILL.md` | `binary-diff/SKILL.md` |
| 栈、堆、ROP、ret2libc、内核 pwn | `pwn-chain/SKILL.md` | `reverse-engineering/SKILL.md` |
| 固件、IoT、文件系统和嵌入式线索 | `firmware-pentest/SKILL.md` | `reverse-engineering/SKILL.md` |
| 恶意样本、IOC、YARA 和反分析 | `malware-analysis/SKILL.md` | `reverse-engineering/SKILL.md` |

路由未命中时，先检查现有源码和方法是否只是上述入口的一个变体；确属新目标
类型时记录 route gap，再提出独立 skill 草案，不强行套用相邻模块。

## 阶段路由

```text
材料与范围确认
  → 静态识别与结构恢复
  → 关键函数/协议/数据流定位
  → 必要的动态验证
  → 最小复现与证据固化
  → 结论边界和可复用经验
```

- 静态识别阶段不加载动态绕过大全。
- 动态阶段只验证静态假设，并记录正控、负控和证据不变量。
- 缺少真实 Android 设备时不进入 Android 动态阶段，保留静态结论和待复测标记。
- 样本、反编译产物、PCAP 和运行日志按任务证据策略保存；可复用层只保存匿名
  结构、指纹和方法。

## Capability 路由

| 动作 | Capability ID | fallback |
|---|---|---|
| 真实页面和浏览器运行时 | `browser.interactive` | 保存页面/脚本后做静态分析 |
| 精确 HTTP 历史和重放 | `http.replay` | `cli.http` |
| CDP、Hook 和运行时参数 | `js.cdp` | SourceMap/AST/离线脚本 |
| HTTP/协议抓包 | `http.capture` | 任务提供的 PCAP/HAR/请求响应 |
| 带外回调观察 | `oast.callback` | 记录 capability 阻塞，不伪造回调证据 |
| 可复现命令行分析 | `cli.http` | 保存输入并记录缺失工具 |

工具是否存在、provider、版本和健康状态必须运行时发现。路由不得保存固定端口、
固定工具数量、个人绝对路径或“已安装”事实。

## 跨层组合

常见组合保持最小：

```text
APK
  apk-reverse → native .so 时选择 ida-reverse/radare2
  → 只有静态假设需要运行态证据时再进入 mobile-reverse

前端签名
  js-reverse → js-runtime-analysis
  → 必要时使用 http.replay 做单变量请求差分

补丁漏洞
  binary-diff → patch-diff-exploit
  → 需要利用稳定性分析时才进入 pwn-chain

固件
  firmware-pentest → 文件系统/二进制分类
  → 单个 native 组件再进入 ida-reverse/radare2
```

每轮只保留一个主路线。负控否定核心假设后，将该路线加入已排除集合并重新路由，
避免在同一证据上下文中反复加载。
