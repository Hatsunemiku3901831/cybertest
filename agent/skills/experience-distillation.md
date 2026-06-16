# Codex Experience Distillation Skill

本 skill 用于维护 `agent/memory/` 中的 pattern、tactic 和 full distillation，让 Codex 能从授权安全测试、资产探测、Web/API 测试和目标信息收集任务的匿名化复盘中复用经验。

## 使用场景

- 按用户指定范围蒸馏 pattern memory。
- 按用户指定范围蒸馏 tactic memory。
- 按用户指定范围做 full distillation。
- 判断某条 memory 是否应晋升为正式 skill 或主 Agent 规则。
- 任务开始前根据 `agent/memory/index.md` 选择性加载经验。

## 加载策略

1. 先读取 `agent/retrospectives/index.md`，确认近期复盘范围和任务类型。
2. 再读取 `agent/memory/index.md`，按标签、适用场景、状态和优先级筛选 memory。
3. 默认只加载 3-8 个最相关的 pattern/tactic；不要一次性加载全部 memory。
4. 只有当 memory 摘要不足以支撑判断时，才打开对应原始复盘或更早的蒸馏文件。
5. `deprecated` 状态的 memory 默认不加载，除非任务是复核旧经验是否应恢复。

## 蒸馏触发

经验蒸馏不按复盘数量自动触发。只有用户明确要求蒸馏、整理 pattern/tactic/full memory、注册 memory 或晋升 skill 时，才执行本 skill。

用户没有指定范围时，先基于请求语义选择合理窗口，并在输出或写入文件中记录 selection_rule；不要因为 `agent/retrospectives/index.md` 新增了复盘就自行生成 memory。

## Pattern 蒸馏

pattern 只从最近一小批任务中抽取局部高频模式，默认状态为 `draft`，不要直接写成硬规则。

必须回答：

- 最近窗口里哪些打法反复出现。
- 哪些响应、错误、页面、接口或环境信号经常导致转向。
- 哪些误报反复浪费时间。
- 哪些停止规则应该马上固化为候选规则。
- 哪些条件下该 pattern 不适用。

## Tactic 蒸馏

tactic 从多个 pattern 中判断稳定性，默认状态为 `active`，可在同类任务中优先参考。

必须回答：

- 哪些 pattern 在多个目标或任务类型中稳定有效。
- 哪些 pattern 是偶然成功或依赖单一目标特征。
- 每条经验的粗略命中数、噪声数、命中率和噪声率。
- 是否具备默认优先执行或停止的条件。

## Full Distillation

full distillation 用于经验治理，不只是总结。

必须回答：

- 哪些 tactic 应晋升为正式 skill。
- 哪些经验只适合保留为 memory。
- 哪些经验应降权、合并、删除或标记为 `deprecated`。
- 哪些规则应写入 `agent/AGENT.md` 的硬规则或专项 skill。
- 哪些经验可能已经过拟合。

## 晋升为 Skill 的标准

只有同时满足以下条件的 memory 才建议晋升到 `agent/skills/` 或写入主 Agent 规则：

- 跨多个任务或多个目标稳定有效。
- 有清晰触发条件。
- 有明确停止规则。
- 有可复现操作流程。
- 误报边界清楚。
- 不依赖单一目标、单一厂商或单次偶然响应。
- 不会鼓励越权、破坏性操作、批量读取真实用户数据或违反授权范围。

## 注册和更新规则

- 小蒸馏经验注册到 `agent/memory/index.md`，不要直接注册成 skill。
- tactic/full 确认稳定后，可提出晋升建议；只有用户明确要求注册或修改时，才写入 `agent/skills/` 或 `agent/AGENT.md`。
- 修改 memory 状态时，同步更新对应文件头部状态和 `agent/memory/index.md`。
- 复盘和 memory 必须匿名化，不得记录真实凭据、token、cookie、JWT、私有域名、内部 IP、callback URL 或可识别客户信息。
