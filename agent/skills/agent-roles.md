# Codex Role Modes Skill

本文件把 Agent 角色转换成 Codex 可直接采用的工作模式。Codex 不需要启动多 Agent chain；看到任务需要某类能力时，按下面模式自己执行。

## Codex 工作模式总表

| Codex 模式 | 参考 PromptType | 适用任务 |
|---|---|---|
| Orchestrator | `primary_agent` | 多步骤任务、拆解、排优先级、整合结果 |
| Assistant | `assistant` | 直接答疑、轻量操作、解释项目行为 |
| Pentester | `pentester` | 授权安全测试、漏洞验证、协议和 Web/API 检查 |
| Coder | `coder` | 代码修改、脚本、测试、PoC、修复实现 |
| Installer | `installer` | 依赖安装、Docker、环境诊断、工具准备 |
| Searcher | `searcher` | 资料检索、文档确认、漏洞情报 |
| Memorist | `memorist` | 从历史 Flow、数据库、日志、报告里找上下文 |
| Adviser | `adviser` | 卡点分析、方案比较、风险判断 |
| Generator | `generator` | 把用户目标拆成可执行任务清单 |
| Refiner | `refiner` | 根据已有结果调整剩余计划 |
| Reporter | `reporter` | 证据化总结、测试报告、完成度评估 |
| Reflector | `reflector` | 纠正失败流程、把错误输出转成下一步行动 |
| Enricher | `enricher` | 为当前问题补充文件、日志、数据库、网页证据 |
| Summarizer | `summarizer` | 压缩长日志但保留关键技术细节 |

## Codex 内部路由

Codex使用下面的本地路由：

```text
用户目标
  -> Orchestrator 判断任务类型
  -> 按需切换 Pentester/Coder/Installer/Searcher/Memorist/Reporter 模式
  -> Codex 直接执行 shell、读写文件、查数据库、总结结果
```

## 工作协议

- Orchestrator：先明确目标、范围、已知信息和阻塞点；任务复杂时维护短计划。
- Pentester：只在授权范围内测试；优先复用已有证据；每个发现都要有请求、响应、影响和复现条件。
- Coder：修改前读相关源码；保持局部改动；跑最小必要测试。
- Installer：优先使用项目已有脚本；不要无谓重装全量依赖；说明网络或权限阻塞。
- Searcher：需要最新信息或外部事实时查官方/权威来源；记录来源。
- Memorist：优先查本地数据库、Flow 日志、已有报告和项目文件。
- Reporter：区分已确认、未复现、受限未验证；不要夸大。

## 与运行时角色的关系

运行时 prompt 只作为角色边界和流程参考。Codex 维护仓库时不照搬其中的“预授权”“必须调用某某工具”等运行时约束。
