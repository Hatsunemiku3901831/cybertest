# Full Distillation：首批 Case 知识闭环治理

- 类型：full
- 生成日期：2026-07-24
- batch_id：`full-distillation-2026-07-24-knowledge-closure`
- selection_rule：响应 M4 升级，只治理首批结构化 case、由其生成的多维索引、同批 `draft` pattern 和证据契约 tactic memory；不把同一来源窗口的 pattern 重复计为独立样本，不把本次精选小样本外推为总体统计，也不自动修改稳定 skill。
- 来源窗口：首批 3 个匿名 case、case index、同批证据契约 pattern 与 tactic memory
- 来源 SHA-256：
  - `agent/cases/index.json`：`968bd0d2e231427bdbccc3ae89d0befa335e9c00b29d923dbae3052a7af44a70`
  - `agent/memory/pattern/pattern-memory-2026-07-24-case-evidence-contracts.md`：`149e47c8324a978453a3b0c458f0f04585201c3db37b9cb60d4ebcbdfb4702ff`
  - `agent/memory/tactic/tactic-memory-2026-07-24-evidence-contracts.md`：`d5e1a5378ac1e8ea243c77fed9ce19d56cc53d8a46bc1518f30a0b1da49f1696`
  - `agent/retrospectives/index.md`：`18c94db6f732dd703c06d2f1fc442c20a40463cf36385e14b002a1e223bcd7ca`
- 覆盖任务类型：Web/API 身份接受、对象授权、受控字段写入
- 状态：active

## 总体结论

1. `case → draft pattern → tactic memory → full distillation` 已形成可审计闭环，但当前每个根因家族只有 1 个结构化 case，且 pattern 与 case 共享同一来源窗口，尚不满足跨任务稳定性或 skill 晋升门槛。
2. 三个家族共有的稳定元规则是“证据契约先于漏洞结论”：单变量矩阵、适用的正负控、权威确认面、不变量、停止点和回滚状态缺一不可。
3. case index 已能按场景、目标类型、技术、业务对象、操作、信任边界、信号、根因、证据模式、材料和 tactic 检索；后续新增 case 应进入同一 schema 和生成链。
4. 自动化只应生成晋升建议。任何写入 `agent/skills/` 或主 Agent 硬规则的动作仍需人工核对跨任务稳定性、噪声和副作用边界。
5. Tactic 的 `source_cases` 只登记已迁移样本；三个家族目前都没有第二组独立任务来源，因此 `historical_validation_count` 有意保持为 `0`，不得获得路由的跨任务历史验证加分。

## 治理统计

统计口径限定为本轮 3 个精选 case；“噪声路径”是 case 中明确列出的无效路径数量，不是生产目标扫描结果。

| 项目 | 数量 | 结论 |
|---|---:|---|
| 结构化 case | 3 | 均通过 schema、来源 hash 和匿名化门禁 |
| 本批 draft pattern | 1 | 仅归纳同一来源窗口的重复结构，不增加独立样本数 |
| 根因家族 | 3 | 每个家族仅 1 个 case，存在选择偏差 |
| 有效路径 | 9 | 每个 case 3 条 |
| 明确噪声/无效路径 | 9 | 每个 case 3 条 |
| 请求矩阵变体 | 16 | 均包含负控；写入 case 含回滚 |
| 自动 skill 写入 | 0 | 强制保持为零 |

## 应晋升为 skill 的经验

本轮没有可直接晋升项。

| 经验 | 来源 tactic/pattern | 建议目标 | 当前结论 | 晋升边界 |
|---|---|---|---|---|
| 证据契约优先的验证闭环 | `pattern-memory-2026-07-24-case-evidence-contracts`、`tactic-memory-2026-07-24-evidence-contracts` | 人工 skill review | 暂不晋升 | 至少 5 个独立 case、2 个技术栈、2 个场景，且前置、负控、不变量、停止规则和低噪声均稳定 |
| 客户令牌到管理路由接受矩阵 | `CASE-AUTH-CUSTOMER-JWT-ADMIN-001` | 保留 case/tactic | 暂不晋升 | 再取得不同任务和不同网关实现的独立 case |
| UI 选择器与对象授权分离 | `CASE-AUTHZ-BOLA-UI-FALSE-POSITIVE-001` | 保留 case/tactic | 暂不晋升 | 再取得权威映射来源不同的独立 case，并观察共享对象模型 |
| 字段差集与单字段回读 | `CASE-AUTHZ-MASS-ASSIGNMENT-001` | 保留 case/tactic | 暂不晋升 | 再取得不同序列化/绑定实现的独立 case，并确认精确回滚可靠 |

## 应保留为 memory 的经验

- 所有候选先明确“改变什么、什么保持不变、由哪个权威面确认”。
- 身份接受、路由授权、对象授权和业务影响应分层记录。
- 空 self、失效会话、公共内容、统一错误和请求回显是高频误报边界。
- 命中一个真实影响即停止扩大，写入必须回读并恢复基线。
- 稳定来源身份、来源 hash、选择规则、粗略命中/噪声和晋升阻塞项必须与 memory 同文件保存；身份用于独立性判断，hash 只用于溯源。

## 应降权或删除的经验

- 仅凭 HTTP 2xx/3xx、静态路由、客户端字段或默认 UI 选项推断未授权：标记为高噪声，不进入确认链。
- 缺少固定无效材料却把候选令牌成功外推为鉴权缺口：降为静态候选。
- self 基线为空时把 cross 空响应写成“没有越权”：降为未判定。
- 统一 success 或请求对象回显而没有权威回读的写入结论：降为未确认。

## 已过拟合经验

- 当前 draft pattern 来自三个以 REST/JSON 为主的精选 case，不能直接外推到消息协议、GraphQL、RPC 或离线批处理。
- 三个 case 共享同一复盘索引与升级计划来源；独立性按 `source_alias + relative_path` 的稳定身份集合判断，来源 hash 数量或变化不能替代独立任务数量。
- BOLA case 使用双账号或权威映射，并不表示所有对象授权都必须具备双账号；公开/共享对象需要单独建模。
- 写入 case 的精确回滚适用于可逆测试字段，不适用于不可逆消息、支付、外部通知或长周期任务。

## 新增停止规则

- 负控与候选返回相同业务内容时，先重新分类匿名公开、缓存或路由错误，不继续扩大对象或字段。
- 账号健康、self 非空基线或权威读取面失败时停止验证并记录材料。
- 首个受控影响闭合后停止同类翻页、导出、跨对象扩张或多字段尝试。
- 无法证明精确回滚时不执行下一次状态变更。

## 主 Agent 规则建议

本轮不修改 `agent/AGENT.md`。现有规则已覆盖：

- 单次 2xx/3xx 不得直接写成未授权。
- 副作用必须记录停止点和回滚结果。
- 可复用知识不得包含真实目标标识或可重放秘密。

新增内容保持在 case、tactic memory 和 full governance 层，待跨任务稳定后再评审是否需要主入口硬化。

## 晋升审计边界

- `tool/promote_memory.py` 只读取 `agent/cases/index.json` 并生成 JSON 建议。
- 每条建议必须包含 case ID、稳定来源身份、来源 hash、场景、技术、信任边界、阻塞项、`independence_basis=source_identity` 和 `writes_stable_skill=false`。
- 单个 case 的最高自动建议为 `draft_pattern`。
- 达到数量门槛也只产生 `tactic_candidate` 或 `skill_review`，不得自动创建、修改或注册 skill。

## 下一轮观察点

1. 为 Guest Upload Ticket、Export/Log Field Boundary 和 WebSocket Path Identity 增加独立匿名 case。
2. 记录 case 在新任务中的实际命中、误匹配和材料阻塞，避免只统计精选成功样本。
3. 观察同一 tactic 在非 REST 技术栈中是否仍能保持单变量矩阵和不变量。
4. 当同一家族积累第二个独立任务来源时，重新运行晋升建议并人工复核来源独立性。
