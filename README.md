# Cybertest

Cybertest 是一个面向授权安全测试、漏洞验证、资产整理和安全自动化的工程化 Agent 工作空间。仓库内沉淀了项目级 Agent 操作手册、安全测试方法论、HackSkills 知识库桥接、结构化 tactic/case/capability 契约，以及扫描、候选路由、动态验证和证据整理工具。

本项目默认使用中文工作，强调授权范围、过程记录、低风险验证、证据闭环和可交接归档。所有渗透测试、扫描、漏洞验证和目标信息收集动作都应只在明确授权范围内执行。

本项目复用了 HackSkills 与 reverse-skill 的部分方法和逆向能力，在此致谢。

## 项目说明

核心内容如下：

| 路径 | 说明 |
|---|---|
| `AGENTS.md` | 仓库级 Agent 入口说明，约定工作语言、任务路由和归档要求。 |
| `CLAUDE.md` | Claude Code 的精简入口，继续路由到统一项目手册。 |
| `agent/AGENT.md` | Codex/Agent 稳定操作手册，包含一级路由、政策入口和任务归档契约。 |
| `agent/skills/` | 项目本地方法论与任务 skill，包括安全测试、资产发现、漏洞评级、逆向、安全报告和交接文档。 |
| `agent/policies/` | 证据、敏感数据和可复用知识的统一治理规则。 |
| `agent/schemas/` | candidate、case、tactic、route、evidence 和 vulnerability 的版本化 schema。 |
| `agent/tactics/` | 可检索的结构化验证契约、负控、不变量、停止点和回滚计划。 |
| `agent/cases/` | 匿名化案例及按场景、实体、信任边界和根因生成的多维索引。 |
| `agent/capabilities/` | 浏览器、重放、CDP、抓包、OAST 和 CLI 的稳定能力声明。 |
| `agent/memory/` | 已沉淀的 pattern、tactic 和 full memory，用于复用历史经验。 |
| `agent/retrospectives/` | 匿名化复盘模板和索引，用于安全任务结束后的经验沉淀。 |
| `hack-skills/` | 面向 Agent 的安全技能知识库，覆盖 Web/API、认证授权、注入、文件访问、业务逻辑、逆向、移动安全、Pwn、云与容器等方向。 |
| `tool/` | 可复用的安全自动化工具包装器和扫描/整理脚本，例如资产扫描管线、Nmap JSON 输出、候选漏洞队列生成、HTTP 探测、JS/API 收集等。 |
| `tool/cybertest_core/` | 候选评分、路由、动态 adapter、证据归一化和 pipeline 纯函数。 |
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

### 3. 检测并按 profile 安装依赖

先运行只读检测和 dry-run，再安装所需 profile。两种预览模式都不会安装软件、
访问网络、写日志或修改 PATH。

macOS：

```bash
bash require/install_macos.sh --detect --profile web
bash require/install_macos.sh --dry-run --profile web
bash require/install_macos.sh --profile web
```

Windows：

```powershell
.\require\install_windows.cmd -Detect -Profile web
.\require\install_windows.cmd -DryRun -Profile web
.\require\install_windows.cmd -Profile web
```

可选 profile 为 `minimal`、`web`、`full` 和 `reverse`；兼容默认值是 `full`。
安装器默认不修改 shell 或用户 PATH，只有显式传入 `--update-path`（macOS）或
`-UpdatePath`（Windows）才会持久化。完整矩阵和兼容参数见
`require/require.md`。

安装完成后复核运行时 capability：

```bash
python3 tool/detect_capabilities.py --dry-run
```

探测结果区分 `installed`、`configured`、`reachable`、`healthy`、
`permitted`、`material_ready` 和派生的 `available`。PATH 中发现命令最多只会
得到 `health=installed_only`，不会直接成为可执行动态能力；MCP、浏览器或服务
provider 必须通过显式 runtime probe 输入证明连通和健康。只有旧版
`available=true` 的输入仍按 `source_compatibility=v1` 兼容读取。

### 4. 使用方法

1. `cd` 进入项目目录，或使用 IDE 打开该项目。
2. 使用 Codex 或 Claude Code 直接以自然语言提出需求，Agent 会按项目路由和任务约束执行。

较长任务可在支持该命令的 Codex 环境中使用 `/goal` 持续执行。


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

从扫描管线输出生成带 tactic 绑定的 v2 P0/P1/P2/P3 候选漏洞队列：

```bash
./tool/bounty_candidate_queue.py --pipeline-dir /tmp/codex-scan-pipelines/example --enable-tactics --output-json candidates.json --output-md candidates.md
```

不带 `--enable-tactics` 时仍保留 v1 兼容输出。扫描管线默认按
`js_intel → api_contract → control_gap → candidate_queue → tactic_match → semantic_quality_gate`
执行离线语义阶段；历史 `quality_gate` phase id 仍可显式使用。浏览器、Burp、JS
运行时和 OAST 阶段不在默认模式中，显式选择时也只为已有
candidate/tactic/RouteDecision 绑定生成 capability/材料门控的验证计划；缺少可执行路由时不会标记为 ready。
动态阶段结果的 `observations.dynamic_validation_plan` 是 schema-valid 的
`plan_status=draft` 草案，可直接作为下面执行入口的 `--plan` 输入，但在补齐
动作参数、policy、受控测试对象并改为 `plan_status=ready` 前会保持
`blocked_need_plan_completion`，不能调用 provider。

动态执行使用独立入口，默认仍是只读计划模式：

```bash
python3 tool/run_dynamic_validation.py \
  --authorized \
  --plan /path/to/dynamic-plan.json
```

只有同时提供显式执行开关和现有任务目录才会调用 adapter、写入 Evidence
Envelope 并更新绑定候选：

```bash
python3 tool/run_dynamic_validation.py \
  --authorized \
  --execute \
  --task-dir tasks/YYYY-MM-DD-HHMM-short-task-name \
  --plan /path/to/dynamic-plan.json
```

计划必须绑定 `candidate_id`、`tactic_id`、`route_decision_id`、健康 capability、
材料、policy、停止条件和回滚计划。Playwright、Burp replay、JS/CDP、抓包、
OAST 和 CLI HTTP 统一输出到同一 Evidence Envelope 契约。执行器不会信任计划中
缓存的 capability 状态：每次执行前都会重新探测 provider，并校验状态链和派生
`available`。动作的副作用语义同时由 operation 和 HTTP method 推导，不能用
`state_change=false` 把 DELETE、POST 等写动作伪装为只读。provider 后续超时或
失败时，已经完成且符合证据契约的动作仍会写入 Envelope 和候选历史；provider
错误不会被解释为目标或漏洞不存在。

## 验证与发布门禁

项目测试使用 Python 标准库 `unittest`，不依赖 pytest。标准离线验收命令为：

```bash
PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover -s tests -p 'test_*.py'
python3 tool/check_markdown_links.py --dry-run --fail-on-broken
python3 tool/build_case_index.py --check
python3 tool/scan_reusable_knowledge_leaks.py \
  --dry-run \
  --fail-severity medium \
  --fail-on-findings
python3 tool/scan_pipeline.py \
  --authorized \
  --domain example.com \
  --mode full \
  --dry-run
```

也可运行固定顺序的聚合门禁：

```bash
python3 tool/release_gate.py
```

聚合结果以 JSON 输出 `unit_tests`、`markdown_links`、`case_index`、
`reusable_knowledge`、`repository_hygiene` 和 `pipeline_dry_run`。任何必选检查
失败都会返回非零退出码。普通 CI 只运行离线门禁，不自动触发浏览器、Burp、
CDP、抓包、OAST 或真实网络验证。

macOS 安装器的 detect、dry-run 和 shell 语法可在 macOS 验证；Windows
cmd/PowerShell 安装器必须在 Windows 环境单独复验后，才能签收对应平台支持。



## GitHub 上传建议

上传公开仓库前建议只保留稳定、可复用、可审查的文件：

```bash
git status --short
git ls-files
```

确认不提交任务归档、临时脚本产物、缓存文件、IDE 配置、本地凭据或敏感扫描输出。提交前建议人工复核暂存区，确保 README 只对应稳定、可复用的项目内容。

## 依赖说明

推荐先检测和预览 `web` profile：

```bash
bash require/install_macos.sh --detect --profile web
bash require/install_macos.sh --dry-run --profile web
```

```powershell
.\require\install_windows.cmd -Detect -Profile web
.\require\install_windows.cmd -DryRun -Profile web
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
- 任务归档中的真实客户数据、凭据、token、Cookie、个人路径和其它敏感信息默认不纳入 Git。
