# Cybertest Reverse Security Skill

本 Skill 用于授权范围内的逆向工程、移动逆向、二进制分析、固件分析、恶意样本分析、pwn 和补丁差分任务。当前能力来自 `reverse-skill` 第一阶段文件复制导入，但入口、授权边界、任务归档和工具执行仍以 Cybertest 的 `agent/AGENT.md` 为准。

## 使用原则

- 先按本文件路由到 `agent/skills/reverse/` 下的具体子 Skill，不要一次性加载全部逆向模块。
- 不执行 `reverse-skill` 的全局注入、跨项目配置写入、强制社区贡献或强制自动安装规则。
- 工具缺失时先读取 `../capabilities/manifest.yaml` 并运行 `../../tool/detect_capabilities.py`；逆向 CLI 的补充探测可生成本地 `reverse/tool-index.md`。需要安装大型工具、GUI 工具或联网下载时，先向用户说明最小命令和影响。
- 样本分析、PoC、pwn、补丁差分和漏洞验证只在用户自有、CTF/靶场、授权测试或明确许可的样本/目标内执行。
- 单次任务临时脚本仍按 Cybertest 规则放入 `temporarytool/` 或对应任务目录的 `temporarytool/`。
- 逆向、固件、恶意样本、pwn 任务若属于授权安全测试、漏洞验证、资产探测或目标信息收集，应按 `agent/AGENT.md` 创建或选定 `tasks/` 归档目录。

## 路由表

| 场景 | 读取 |
|---|---|
| 通用逆向、反编译、反汇编、反混淆、算法还原、反分析判断 | `reverse/reverse-engineering/SKILL.md` |
| IDA Pro 分析、伪代码、函数命名、交叉引用、数据流追踪 | `reverse/ida-reverse/SKILL.md` |
| radare2/r2/rabin2/rasm2 CLI 快速分析、patch、脚本化侦察 | `reverse/radare2/SKILL.md` |
| APK/Android 反编译、jadx、apktool、smali、重打包、证书绑定初查 | `reverse/apk-reverse/SKILL.md` |
| Android/iOS 动态插桩、Frida、Objection、SSL Pinning、Root/越狱检测绕过 | `reverse/mobile-reverse/SKILL.md` |
| 跨版本符号迁移、BinDiff/Diaphora、旧版本符号推导 | `reverse/binary-diff/SKILL.md` |
| N-day、补丁差分、CVE 复现前的漏洞点定位和 PoC 分析 | `reverse/patch-diff-exploit/SKILL.md` |
| 栈/堆/内核 pwn、ROP、ret2libc、pwntools、利用稳定化 | `reverse/pwn-chain/SKILL.md` |
| 固件/IoT、binwalk/unblob、文件系统提取、QEMU/仿真、UART/JTAG 线索 | `reverse/firmware-pentest/SKILL.md` |
| 恶意样本、YARA/Sigma、IOC 提取、沙箱行为、反分析特征 | `reverse/malware-analysis/SKILL.md` |

## 工具索引

工具索引脚本只做本地探测，不自动安装工具。跨任务稳定事实使用 capability ID；本地生成索引仅作当前机器缓存，不提交 Git。

```bash
bash agent/skills/reverse/scripts/refresh-tool-index.sh
```

本地生成索引默认位于：

```text
agent/skills/reverse/tool-index.md
agent/skills/reverse/tool-index.json
```

索引只记录命令或 provider 标识，不记录本机绝对路径。若导入脚本仍假设 `reverse-skill/skills/` 为根目录，优先小改脚本的根路径推导逻辑；不要把个人路径硬编码进 Skill 文档。

## 能力探测与显式安装

统一入口默认只读探测，并同时复用 `require/profiles.json` 的 `reverse` profile
和 Agent capability detector：

```bash
bash agent/skills/reverse/scripts/bootstrap-reverse.sh --detect
bash agent/skills/reverse/scripts/bootstrap-reverse.sh --dry-run jadx apktool r2
```

只有显式 `--install` 才会把核心 reverse profile 委托给平台注册的安装器。
MCP 注册还必须显式使用 `--apply --mcp-config <file>`；HTTP provider 的 URL
来自环境变量或运行时发现，不设固定端口。脚本不会默认刷新索引、启动服务或写入
Claude、Codex 等客户端的全局配置。

## 路由补充

`reverse/routing.md` 是从 `reverse-skill` 复制的参考路由矩阵。它可以作为细分场景参考，但其中涉及未导入模块、全局配置、自动安装或跨项目规则时，以本文件和 `agent/AGENT.md` 为准。
