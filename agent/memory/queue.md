# Memory Queue

本文件用于记录用户主动要求的复盘蒸馏批次。安全任务结束并更新 `agent/retrospectives/index.md` 后，不要按数量自动触发蒸馏。

## 执行规则

- 只有用户明确要求蒸馏、整理 pattern/tactic/full memory、注册 memory 或晋升 skill 时，才新增或更新 memory。
- 用户指定范围时，按用户范围执行。
- 用户未指定范围时，基于请求语义选择合理窗口，并在输出文件中记录 `selection_rule`。
- 已完成批次保留在本文件，作为审计记录，不代表未来自动触发。

## 当前记录

- completed_pattern_batches: 1
- completed_tactic_batches: 0
- completed_full_batches: 0

## 批次记录

| 类型 | 复盘范围 | 状态 | 输出文件 | 备注 |
|---|---|---|---|---|
| pattern | 最近 10 个具备完成复盘的任务 | completed | [pattern/pattern-memory-2026-05-26-recent-10.md](pattern/pattern-memory-2026-05-26-recent-10.md) | batch_id: pattern-memory-2026-05-26-recent-10 |
