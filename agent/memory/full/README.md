# Full Distillation

每 100 个安全/信息收集任务做一次全量经验蒸馏。

full distillation 关注经验治理：

- 哪些经验高价值且稳定
- 哪些经验噪声高或已经过拟合
- 哪些 tactic 应晋升为 skill
- 哪些停止规则应写入主 Agent 或专项 skill
- 哪些旧 memory 应降权、合并或废弃

## 文件模板

```md
# Full Distillation: <范围或周期>

- 类型：full
- 生成日期：YYYY-MM-DD
- 来源窗口：复盘 <起始>-<结束>
- 覆盖任务类型：
- 状态：active

## 总体结论

## 应晋升为 skill 的经验

| 经验 | 来源 tactic/pattern | 晋升目标 | 理由 | 风险 |
|---|---|---|---|---|

## 应保留为 memory 的经验

## 应降权或删除的经验

## 已过拟合经验

## 新增停止规则

## 主 Agent 规则建议

## 下一轮观察点
```

