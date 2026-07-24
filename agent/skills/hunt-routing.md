# Hunt Routing

本文件只定义从控制缺口到验证契约的确定性路由。详细验证方法位于
`agent/tactics/`；本文件不是漏洞知识库，也不替代授权范围、证据数据处理和
漏洞评级规则。

## 适用阶段

仅在安全任务进入 `triage` 或 `validation`，且已经形成可描述的观察信号时
使用。资产发现阶段继续使用 `security-testing.md`；归档和评级继续使用
handoff 与评级规则。

路由分工：

```text
L0 policy
  → L1 task phase
  → L2 control gap
  → L3 tactic ranking
  → L4 capability selection
  → L5 evidence feedback and reroute
```

## 输入契约

输入使用 `agent/schemas/route-context.schema.json`。至少记录：

- 当前任务类型和阶段。
- 目标、协议、业务对象、操作和信任边界。
- 已观察信号和怀疑缺失的控制。
- 当前证据阶段。
- 可用测试材料和 capability ID。
- 已排除路线和负控结果。

不得把 Cookie、JWT、密码、真实业务值或个人路径放入 RouteContext。认证材料
只记录受控身份类别，例如 `controlled_user_a`。

## 硬门禁

以下条件直接排除 tactic：

- tactic 已废弃。
- `excluded_routes` 已包含该 tactic。
- 该 tactic 的负控已经否定核心假设。
- 目标类型或技术协议明确不兼容。
- 新证据命中 tactic 的排除信号。
- 动作超出当前 policy 且没有只读降级路径。
- 必需测试材料缺失且没有只读降级路径。
- 必需 capability 及其注册 fallback 均不可用。

被排除的 tactic 写入 trace；相同证据上下文中不得再次进入 Top-K。
`readonly_fallback` 只是声明“可能存在只读降级思路”，不能自动改写验证契约；
缺少具体、可执行且受 schema 约束的只读请求矩阵时，材料缺失仍进入
`blocked_need_material`，策略级别不足仍进入 `policy_conflict`。

## 软排序

`tool/cybertest_core/routing.py` 按固定版本和权重排序：

| 维度 | 权重 |
|---|---:|
| 观察信号 | 30 |
| 控制缺口 | 25 |
| 业务对象 | 8 |
| 操作类型 | 7 |
| 信任边界 | 15 |
| 证据阶段 | 5 |
| capability 可执行性 | 5 |
| 跨任务历史验证 | 5 |

分数只决定加载顺序，不表示证据置信度、漏洞优先级或最终评级。相同分数按
tactic ID 排序，保证相同输入得到稳定结果。

业务对象、操作、信任边界和 capability 只能辅助排序，不能单独让 tactic
进入 Top-K。至少命中一个 tactic 专属控制缺口，或两个 tactic 专属观察信号，
才视为具备语义锚点；否则保留 `route_gap`，不以字母序选择错误契约。

默认返回 Top-3：

- Top-1：`load_mode=full`，作为当前唯一主验证契约。
- Top-2/Top-3：`load_mode=summary`，只保留判别条件。
- 其余匹配项：进入 `deferred_tactics`。

## Capability 路由

Tactic 描述所需动作，RouteDecision 选择 capability。每项 capability 可声明
fallback；只有首选或 fallback 实际可用时 tactic 才能执行。

Capability 只能改变执行方式，不能扩大 policy。缺失且无 fallback 时输出
`blocked_need_capability`，记录缺口，不猜测本机路径、端口或工具数量。

## 输出契约

输出使用 `agent/schemas/route-decision.schema.json`，关键字段包括：

- `decision_id` 和 `route_version`。
- `route_status`。
- Top-K tactic、匹配原因和加载模式。
- 下一项最小判别动作。
- 当前验证契约、停止点和报告边界。
- capability 与材料需求。
- 阻塞路线的 `resume_tactic_id`、精确缺失项和恢复动作。
- fallback 和完整 trace。

调用示例：

```python
from tool.cybertest_core.routing import load_tactics, rank_tactics

tactics = load_tactics()
decision = rank_tactics(route_context, tactics=tactics, top_k=3, policy=policy)
```

相同的 RouteContext、policy 和 tactic registry 必须生成相同的
`decision_id`、排序与 trace。

## 回退状态

| 状态 | 含义 | 下一步 |
|---|---|---|
| `matched` | 已选择主 tactic | 执行一个最小判别动作 |
| `matched_with_fallback` | 使用 tactic 已注册的 capability fallback | 按原验证级别和回退能力边界执行 |
| `route_gap` | 无 tactic 达到最低匹配条件 | 使用通用控制缺口方法并记录 gap |
| `blocked_need_material` | 缺少受控材料且无降级路线 | 记录材料和恢复后的第一步 |
| `blocked_need_capability` | 首选与 fallback 都不可用 | 记录能力缺口或改静态路线 |
| `policy_conflict` | tactic 超出政策边界 | 缩小动作范围，不执行冲突动作 |

回退不是漏洞结论。任何回退状态都不得进入确认或评级。
`validation_contract.execution_mode=capability_fallback` 只表示执行能力发生替换，
不代表动作自动降为只读；实际动作级别始终以 `safe_validation_level` 为准。
`blocked_need_material` 和 `blocked_need_capability` 必须给出
`resume_tactic_id`，以便材料或能力恢复后继续同一验证契约。

## L5 证据反馈

以下变化必须生成新的 RouteContext 和 RouteDecision：

- self 或正控基线失败。
- 固定错误认证与候选认证同形。
- 负控否定当前核心假设。
- 真实 UI 与 API 假设冲突。
- 默认项目、空数据或过期会话使样本无效。
- 新发现业务对象、信任边界或能力需求。
- capability 状态变化。
- 命中停止点或已经证明真实影响。

重路由必须保留：

- 已执行动作和证据引用。
- `excluded_routes`。
- 负控结论。
- 已消耗测试对象。
- 不得重复的副作用。

## 注意力预算

- 一个阶段只加载一个主 workflow。
- L2 最多加载一个漏洞类别入口。
- L3 最多保留三个 tactic 摘要。
- 只完整加载 Top-1 tactic。
- supporting skill 最多两个。
- capability 选择前不加载工具长文档。
- 只有 tactic 无法解释关键细节时才读取一个匿名 case。

每次决策应追加到任务目录的 `notes/route-decisions.jsonl`；人工接手摘要写入
`notes/loaded-skills.md`。原始证据仍留在任务证据区，不复制进路由记录。
