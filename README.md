# Cybertest

Cybertest 是一个面向授权安全测试、漏洞验证、资产整理和安全自动化的工程化 Agent 工作空间。仓库内沉淀了项目级 Agent 操作手册、安全测试方法论、HackSkills 知识库桥接、常用扫描与证据整理脚本

本项目默认使用中文工作，强调授权范围、过程记录、低风险验证、证据闭环和可交接归档。所有渗透测试、扫描、漏洞验证和目标信息收集动作都应只在明确授权范围内执行。

本项目引用了HackSkills和reverse-skill（逆向部分）这两个项目，再次感谢

## 项目说明

核心内容如下：

| 路径 | 说明 |
|---|---|
| `AGENTS.md` | 仓库级 Agent 入口说明，约定工作语言、任务路由和归档要求。 |
| `CLAUDE.md` | Claude Code 入口说明，面向 Claude Code 加载同一套项目规范、触发关键词和工作路由。 |
| `agent/AGENT.md` | Codex/Agent 主操作手册，包含任务类型到 skill 的路由、硬规则和常用命令。 |
| `agent/skills/` | 项目本地方法论与任务 skill，包括安全测试、资产发现、漏洞评级、逆向、安全报告和交接文档。 |
| `agent/memory/` | 已沉淀的 pattern、tactic 和 full memory，用于复用历史经验。 |
| `agent/retrospectives/` | 匿名化复盘模板和索引，用于安全任务结束后的经验沉淀。 |
| `hack-skills/` | 面向 Agent 的安全技能知识库，覆盖 Web/API、认证授权、注入、文件访问、业务逻辑、逆向、移动安全、Pwn、云与容器等方向。 |
| `tool/` | 可复用的安全自动化工具包装器和扫描/整理脚本，例如资产扫描管线、Nmap JSON 输出、候选漏洞队列生成、HTTP 探测、JS/API 收集等。 |
| `precedent-auth.md` | 授权上下文预声明，用于本地 Agent 在授权安全测试场景中正确进入执行状态。 |
| `program.md` | 脚本开发、重构和代码审查任务的编码标准。 |



## 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/Hatsunemiku3901831/cybertest
cd cybertest
```

### 2. 读取入口文档

进入仓库后，推荐按以下顺序阅读：

```bash
sed -n '1,80p' precedent-auth.md
sed -n '1,220p' agent/AGENT.md
```

如果使用 Codex，请把 `AGENTS.md` 作为仓库入口规则；如果使用 Claude Code，请把 `CLAUDE.md` 作为入口规则。两者都会引导 Agent 继续读取 `agent/AGENT.md`，理解授权边界、任务类型、skill 路由和文件归档规范。

### 3. 一键安装依赖

macOS：运行require目录里的install_macos.sh

```bash
bash require/install_macos.sh
```

Windows：运行require目录里的install_windows.cmd

```powershell
.\install_windows.cmd
```

完整工具清单、依赖说明和可选参数见 `require/require.md`。

### 4. 使用方法

1. cd进项目文件夹内，或使用IDE打开该项目
2. 使用codex或者claude code，直接使用自然语言提出需求即可，codex或者claudecode将会按目标执行

强烈建议使用/goal 来跑


### 5. 使用常用工具

扫描管线用于授权范围内的资产发现和候选队列生成：

```bash
./tool/scan_pipeline.py --authorized --domain example.com --mode quick
./tool/scan_pipeline.py --authorized --domain example.com --mode full
./tool/scan_pipeline.py --authorized --domain example.com --mode deep
```

查看扫描计划但不执行：

```bash
./tool/scan_pipeline.py --authorized --domain example.com --mode full --dry-run
```

对授权目标运行 Nmap 并输出 AI 友好的 JSON：

```bash
./tool/nmap_json_scan.py --authorized --target 127.0.0.1 --profile web --output web.json
./tool/nmap_json_scan.py --authorized --target 192.168.1.0/24 --two-pass --output lan-two-pass.json
```

从扫描管线输出生成 P0/P1/P2/P3 候选漏洞队列：

```bash
./tool/bounty_candidate_queue.py --pipeline-dir /tmp/codex-scan-pipelines/example --output-json candidates.json --output-md candidates.md
```



## GitHub 上传建议

上传公开仓库前建议只保留稳定、可复用、可审查的文件：

```bash
git status --short
git ls-files
```

确认不提交任务归档、临时脚本产物、缓存文件、IDE 配置、本地凭据或敏感扫描输出。提交前建议人工复核暂存区，确保 README 只对应稳定、可复用的项目内容。

## 依赖说明

推荐先使用一键安装脚本：

```bash（MACOS使用这个）
bash require/install_macos.sh
```

```powershell（WINDOWS使用这个）
.\install_windows.cmd
```

仓库中的 Python 工具大多是轻量包装器，基础运行环境需要：

- Python 3
- 常见安全工具按需安装，例如 `nmap`、`subfinder`、`httpx`、`katana`、`nuclei`、`ffuf`、`sqlmap` 等
- 部分工具需要本地 API key 或外部二进制，请按对应脚本的 `--help` 输出配置

完整依赖矩阵和每个工具的用途见 `require/require.md`。

先查看帮助再执行：

```bash
python3 tool/scan_pipeline.py --help
python3 tool/nmap_json_scan.py --help
python3 tool/bounty_candidate_queue.py --help
```

## 注意事项

- 本项目只用于授权安全测试、合法研究、防御验证、漏洞赏金和内部安全自动化。
- 任务归档真实客户数据、凭据、token、cookie、个人路径和其它敏感信息默认不跟踪GIT
