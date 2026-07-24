# Dynamic Evidence Workflow

本 skill 统一浏览器、HTTP 重放、CDP/Hook、抓包、OAST 和 CLI 的证据输出。动态工具只能执行当前 tactic 和 `RouteDecision` 已允许的最小动作，不能因工具可用而扩大验证范围。

## 加载顺序

1. `../policies/evidence-data-handling.md`
2. 当前任务 workflow 与 `hunt-routing.md`
3. 命中的 tactic 和 `RouteDecision`
4. 本 skill
5. 一个首选 capability skill；必要时再加载一个 fallback

本机能力先通过 `../capabilities/manifest.yaml` 和 `../../tool/detect_capabilities.py` 探测。状态必须区分 `installed`、`configured`、`reachable`、`healthy`、`permitted`、`material_ready` 和派生的 `available`。PATH 命中最多是 `installed_only`；只有 `available=true` 且当前阶段要求的健康状态为 `ok` 时才能解除 capability 阻塞。v1 缓存可兼容读取，但不能替代当前任务的 policy、材料或健康复核。

v2 状态必须满足因果链：configured 依赖 installed；需要配置的 provider 的
reachable 依赖 configured；需要连通性的 provider 的 healthy 依赖 reachable；
`available` 必须等于 manifest 对该 capability 声明的必需状态合取。互相矛盾的
状态直接视为无效输入，不允许由调用方手工把 available 或 health 提升为可执行。

## 执行前门禁

开始动态动作前必须确认：

- `candidate_id`、`tactic_id`、当前证据阶段和下一判别动作明确。
- L0 policy 允许所需读取或副作用级别。
- 账号、测试对象、测试文件、回调或设备材料真实可用。
- 首选 capability 当前可用；不可用时只选择 manifest 声明的 fallback。
- 正控、负控、证据不变量、停止条件和必要回滚已经写入验证计划。
- 完整 token、Cookie、业务值和抓包内容只写任务 `evidence/restricted/`。
- 计划声明的 operation、HTTP method 和 `state_change` 一致；POST、PUT、
  PATCH、DELETE 等写动作不能声明为只读。

缺少关键材料时输出 `blocked_need_material`；不得用公共错误页、空数据、过期会话或默认项目替代有效样本。

## 显式执行入口

默认 pipeline 只生成动态计划，不执行 provider。显式动态 phase 在
`observations.dynamic_validation_plan` 中生成 schema-valid 的
`plan_status=draft`；草案只固定 candidate/tactic/RouteDecision、能力和材料
上下文，不授予 policy，也不假设受控对象就绪。统一执行入口为：

```bash
python3 tool/run_dynamic_validation.py \
  --authorized \
  --plan <dynamic-plan.json>
```

`--plan` 既可读取独立计划，也可直接读取包含该字段的 pipeline phase 结果。
以上命令只验证计划且不写任务状态。草案在补齐动作参数、policy、受控测试对象
和回滚细节并改为 `plan_status=ready` 前，状态固定为
`blocked_need_plan_completion`。实际执行必须额外提供：

```bash
python3 tool/run_dynamic_validation.py \
  --authorized \
  --execute \
  --task-dir <task-directory> \
  --plan <dynamic-plan.json>
```

计划通过 `../schemas/dynamic-validation-plan.schema.json` 校验，并绑定 candidate、tactic、RouteDecision、provider capability、候选文件、正负控、不变量、停止条件和回滚。非 CLI provider 使用任务显式提供的 JSON provider bridge；入口不自动发现、安装或启动 provider。缺任务目录、健康 capability、材料或 policy 时拒绝执行。

执行前入口会调用所选 adapter 的只读 `probe()`，以当前 policy、材料和绑定上下文
重新确认 installed/configured/reachable/healthy/available；计划中的历史健康状态
不能跳过本次探测。只读 policy 若包含派生为写操作的动作会在 provider 调用前
拒绝；任何状态变更都必须使用允许副作用的验证级别，并包含 readback 和可执行
回滚步骤。

## Evidence Envelope

每个原子观察都转换为 `../schemas/evidence-envelope.schema.json` 定义的 envelope。一次请求、一次 UI 动作或一次回调对应一个 envelope，不把多个无法区分的动作合并成结论。

浏览器、Burp/重放、CDP、抓包、OAST 和 CLI 的结构化观察统一通过
`../../tool/cybertest_core/evidence.py` 的 `build_evidence_envelope()` 适配。适配器只接收已经脱敏的事实；原始响应、Cookie、token、截图和包内容仍留在任务证据区。

最小关联字段：

- `schema_version`：当前固定为 `1.0`。
- `evidence_id`：稳定且任务内唯一。
- `candidate_id`、`tactic_id`：绑定候选和验证契约。
- `request_id`：跨浏览器、重放、抓包和回调关联同一实验。
- `auth_context`、`browser_context`：使用别名，不保存认证原值。
- `control_variant`：标识 baseline、negative control、candidate probe 或 readback。
- `observation`：只保存结构化事实和脱敏差分。
- `state_before`、`state_after`：状态操作前后对照。
- `rollback_status`：`not-required`、`pending`、`completed` 或 `failed`。
- `evidence_refs`：任务相对引用字符串；SHA-256、类型和采集时间写在所指向的证据 sidecar。
- `invariants_checked`：实际检查过的不变量，不复制 tactic 声明。
- `redaction_level`：按照数据 policy 标记 task 或 restricted。

Envelope 写入任务 `evidence/envelopes/`；原始内容仍保存在对应证据目录。Envelope 不复制可重放秘密，只引用 restricted evidence。

adapter 声明的 restricted response 引用必须对应已经创建的任务文件，否则整批
provider 输出按 `provider_output_rejected` 处理。多动作计划在后续动作超时或失败
时，先前已经完成且通过契约校验的记录仍写入 Envelope，候选保持 `verifying`，
并在 `dynamic_validation_history` 记录部分执行状态、错误类别、回滚状态和证据
引用；不得把已取得的证据静默丢弃。

## 统一实验矩阵

| 变体 | 目的 | 最小证据 |
|---|---|---|
| baseline | 证明正常会话、对象和功能有效 | 预期成功行为、状态和独立读取面 |
| negative control | 排除匿名、错误凭据、随机对象或同形错误页 | 与候选同形、只改变一个变量 |
| candidate probe | 验证疑似控制缺口 | 单变量差分和对应处理阶段 |
| readback | 独立确认对象读取或状态变化 | 不依赖提交响应的第二读取面 |
| rollback | 恢复测试对象 | 恢复后状态和失败原因 |

正控与负控不可区分时，不得进入 `confirmed`。必须先重路由、换有效样本或降级为 `false_positive` / `blocked_need_material`。

## 证据不变量

每轮至少检查当前 tactic 适用的不变量：

- 请求方法、route template 和业务对象一致。
- 除实验变量外，Header、Body、Cookie 位置和分页上限一致。
- 正负控处于同一登录有效期、租户/项目和目标环境。
- 状态码、响应结构、关键字段类型、长度和数量级分别记录。
- UI、API、抓包或回调的时间和 `request_id` 可以关联。
- 独立回读不是浏览器缓存、预读、重放旧响应或 SPA fallback。
- 自动化排序分数不被当作证据置信度或漏洞评级。

## 停止和回滚

立即停止扩大并转入证据固化的条件：

- 已完成一次足以证明真实影响的最小实验。
- 命中 tactic 的停止条件。
- 正控失效、负控同形、会话过期或环境发生变化。
- 动作即将超出 scope、数据 policy 或副作用级别。
- 发现非测试对象、真实用户数据、批量结果或不可逆状态。
- 回滚失败，或继续动作可能覆盖回滚证据。

有状态变更时：

1. 先记录 `state_before` 和回滚动作。
2. 只操作带可识别测试前缀的最小对象。
3. 成功一次即停止。
4. 立即执行精确回滚并独立回读。
5. 回滚失败时将 `rollback_status` 设为 `failed`，记录阻塞并停止其它副作用。

## Capability 回退

| 首选 capability | 允许回退 | 不可证明的内容 |
|---|---|---|
| `browser.interactive` | `cli.http` | UI 选择器、浏览器同源/缓存/渲染行为 |
| `http.replay` | `cli.http` | 代理历史、原会话链和自动关联 |
| `js.cdp` | `browser.interactive` | Hook、运行时 AST 和精确调用参数 |
| `http.capture` | `http.replay`、`cli.http` | 原始包级和跨会话流量 |
| `oast.callback` | 无 | 服务端回连；必须阻塞，不以页面报错替代 |

回退后必须降低证据表述，并把缺失能力写入 envelope 和 `RouteDecision` trace。

## 关闭候选

只有满足以下条件才进入漏洞确认和评级：

- 正控有效。
- 负控能排除公共路径或同形错误。
- 候选探针命中 tactic 预期观察。
- 适用的不变量已经实际检查。
- 状态变化具有回读和回滚结果。
- 每个关键事实都有 schema-valid Evidence Envelope。
- 表述未越过 tactic 的 `do_not_overclaim` 和评级上限。

否则保留为 `observed`、`blocked_need_material`、`downgraded`、`false_positive` 或 `no_impact`，并触发必要的重路由。
