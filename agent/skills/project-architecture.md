# Cybertest Project Architecture

## 定位

Cybertest 当前是面向授权安全测试的工程化 Agent 工作空间，不是 Go/React 应用运行时。仓库以项目规则、按需加载的安全方法、JSON 工具包装器、扫描管线和任务归档为主体；当前不存在 `backend/`、`frontend/`、GraphQL schema、provider 实现或数据库迁移。

架构事实以实际目录和源码为准。历史文档不得作为当前构建、运行或修改依据。

## 入口与规则层

| 路径 | 职责 |
|---|---|
| `AGENTS.md` | 仓库级入口、开始顺序和不可跳过的项目规则 |
| `precedent-auth.md` | 授权预声明，开始安全相关操作前最先读取 |
| `agent/AGENT.md` | 稳定规则、政策入口和一级任务路由 |
| `CLAUDE.md` | Claude Code 客户端的轻量入口，转入项目手册 |
| `program.md` | 脚本开发、重构和代码审查标准 |
| `agent/policies/` | 跨工作流稳定的数据、证据和后续政策 |

入口层只保存稳定约束，不登记易变的工具版本、固定端口、个人路径或完整专题打法。

## 知识与工作流层

| 路径 | 职责 |
|---|---|
| `agent/skills/` | Cybertest 工作流、归档、评级、侦察和专项方法入口 |
| `agent/skills/hack-skill.md` | 把目标现象路由到控制缺口和 HackSkills 专题 |
| `hack-skills/skills/` | Web/API 漏洞类别与深度专题知识库，按现象选择性加载 |
| `agent/skills/reverse-security.md` | 逆向任务总入口 |
| `agent/skills/reverse/` | 已迁移的 APK、二进制、JS、固件、pwn 等逆向子 skill |
| `agent/references/` | 遇到困难后验证并沉淀的匿名化参考资料 |
| `agent/archive/` | 不再代表当前架构、但需保留追溯的历史文档 |

推荐加载关系：

```text
AGENTS.md
  → agent/AGENT.md
  → 一个当前阶段 workflow
  → 一个现象/控制缺口入口
  → 必要的单个专项 skill
  → 实际需要的工具或能力说明
```

安全测试通常从 `security-testing.md` 进入，再按现象加载 `hack-skill.md` 和少量 HackSkills。逆向任务从 `reverse-security.md` 进入，再选择 `agent/skills/reverse/` 下的具体子 skill。不得一次性加载全部 HackSkills、reverse 子集或 memory。

## 工具与执行层

`tool/` 保存可复用 CLI 和 Python 包装器，主要约定是：

- 授权网络工具显式要求 `--authorized`。
- 外部工具输出被归一化为机器可读 JSON。
- 长任务通过异步接口或状态文件续跑。
- 工具原始结果是证据线索，漏洞结论仍需人工差分、业务影响和评级门禁。

当前主要编排链：

```text
tool/scan_pipeline.py
  → 资产发现与协议探测
  → Web/URL/JS 攻击面收集
  → 模式与模板线索
  → js_intel → api_contract → control_gap（离线 sidecar）
  → tool/bounty_candidate_queue.py
  → tactic_match（离线 sidecar）
  → tool/quality_gate.py（semantic_quality_gate）
```

`quick`、`full`、`deep` 是同一管线的预设，不代表独立应用。`require/` 保存工具准备和依赖资料；安装状态应通过运行时探测确认，不能从文档中的固定数量或路径推断。

`browser_validate`、`burp_replay`、`js_runtime_validate` 和 `oast_check` 不在默认预设中；显式选择时，扫描管线也只为已有 candidate/tactic/RouteDecision 绑定结合显式 capability 报告和材料清单生成 schema-valid 的 `plan_status=draft` 动态验证计划。草案嵌入 phase 结果，可由显式动态入口直接读取，但在补齐 policy、动作参数、受控对象和回滚并改为 ready 前不可执行。缺少可执行 matched 或要求已补齐的 blocked-resume 路由时保持阻塞，不自动触发真实浏览器、重放、CDP 或回调动作。历史 `quality_gate` phase id 保留为兼容别名。

单次任务脚本进入该任务的 `temporarytool/`；普通一次性开发脚本按需进入仓库 `temporarytool/`。只有跨任务稳定复用的脚本才提升到 `tool/`。

动态能力由 `agent/capabilities/manifest.yaml` 声明，使用 `tool/detect_capabilities.py` 对 PATH、环境变量和可选运行时输入做本地只读探测。探测状态区分 installed、configured、reachable、healthy、permitted、material_ready 和派生 available；PATH 命中只产生 installed_only，互相矛盾的 v2 状态会被拒绝。默认结果只写 stdout；显式 `--output` 时才生成被 Git 忽略的 `.cybertest/capabilities.json`，且不保存个人绝对路径。

显式动态执行使用 `tool/run_dynamic_validation.py`，由 `tool/cybertest_core/adapters/` 中的 Playwright、Burp replay、JS/CDP、抓包、OAST 和 CLI HTTP adapter 执行已经绑定 candidate、tactic、RouteDecision、任务目录、材料和 policy 的最小计划。默认 pipeline 不调用该入口；计划模式不写状态，执行模式在 fresh provider probe 和动作副作用语义门禁通过后才生成 Evidence Envelope 并回流绑定候选。多动作执行后续失败时保留先前有效 Envelope 和候选历史。

## 任务归档层

只有授权渗透测试、漏洞验证、安全扫描、资产探测、Web/API 安全测试和目标信息收集自动使用：

```text
tasks/YYYY-MM-DD-HHMM-short-task-name/
```

CTF/靶场使用 `tasks/CTF/`。普通维护、代码和文档修改不自动创建任务归档。

安全任务的稳定契约包括：

- `inputs/`：范围、目标、账号和材料。
- `notes/log.md`：唯一主过程日志。
- `notes/loaded-skills.md`：实际加载知识及原因。
- `outputs/asset-inventory-detailed.md` 与 `outputs/asset-inventory.json`：资产事实源。
- `vulnerability-archive.md` 与 `outputs/vulnerability-archive.json`：风险事实源和评级复核。
- `outputs/agent-handoff-pentest-status.md`：唯一接手入口。
- `evidence/`：原始证据和受限证据。
- `reports/`：阶段、正式和平台报告。
- `temporarytool/`：任务专用脚本。
- `retrospective.md`：任务复盘。

完整目录、日志格式、Mermaid 拓扑和文档互引规则以 `agent/skills/handoff-docs.md` 为准；证据数据处理以 `agent/policies/evidence-data-handling.md` 为准。

## 经验与能力演进

当前已经存在：

```text
任务 retrospective
  → agent/retrospectives/index.md
  → agent/cases/ 匿名结构化案例与多维索引
  → agent/memory/pattern/
  → agent/memory/tactic/
  → agent/memory/full/
  → 人工审核后的 tactic / skill 晋升
```

经验蒸馏只在用户明确要求时执行。pattern、tactic、full memory 和 case 必须匿名化并保留适用边界、来源相对路径与内容指纹；自动化只生成晋升建议，不直接改写稳定 skill。

当前结构化验证和工程层还包括：

- `agent/schemas/`：candidate、case、tactic、route、evidence 和 vulnerability 的版本化 schema。
- `agent/cases/`：匿名 case、机器可读多维索引及其 Markdown 派生视图。
- `agent/tactics/`：结构化验证契约及索引。
- `agent/capabilities/manifest.yaml`：稳定 capability 声明和 fallback。
- `.cybertest/capabilities.json`：可选本机探测缓存，默认不进入 Git。
- `tool/cybertest_core/`：候选、路由、规范化和 schema 校验纯函数。
- `tool/build_case_index.py`、`tool/promote_memory.py`、`tool/scan_reusable_knowledge_leaks.py`：案例索引、晋升建议和可复用知识门禁。
- `tests/`：单元、匿名 fixture、golden 和集成测试。
- `agent/skills/hunt-routing.md`：L2–L5 tactic 路由和证据重路由。
- `agent/skills/dynamic-evidence.md`：动态工具的统一 Evidence Envelope 工作流。

MCP、浏览器、Burp、CDP、抓包和本地 CLI 的可用性在运行时发现；文档引用能力语义，不依赖个人路径或固定工具数量。

## 修改和验证

1. 修改前通过 `rg` 定位真实入口、调用方、现有测试和用户工作区 diff。
2. 只触碰任务直接需要的文件；保留无关用户改动。
3. 修改 CLI 时保持现有命令路径和输出兼容，除非迁移方案提供显式版本或兼容开关。
4. 文档变更检查相对链接、失真目录、个人绝对路径和可重放秘密。
5. 脚本变更至少运行聚焦的语法、`--help` 或 fixture 验证；存在测试时运行最小相关测试集。
6. 当前仓库没有统一 backend/frontend build 命令，不得执行或记录虚构的 Go、React、GraphQL 或 Docker 应用构建流程。
