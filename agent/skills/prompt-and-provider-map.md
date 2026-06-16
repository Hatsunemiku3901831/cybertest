# Prompt And Provider Map Skill

## Prompt 清单

运行时 prompt 位于 `backend/pkg/templates/prompts/`，由 `backend/pkg/templates/templates.go` 中的 `PromptType` 注册。

主要 prompt：

- `primary_agent.tmpl`：主编排。
- `assistant.tmpl`：对话助手。
- `pentester.tmpl`：安全测试。
- `coder.tmpl`：代码开发。
- `installer.tmpl`：环境维护。
- `searcher.tmpl`：信息检索。
- `memorist.tmpl`：长期记忆。
- `adviser.tmpl`：策略建议。
- `generator.tmpl`：subtask 生成。
- `refiner.tmpl`：subtask 优化。
- `reporter.tmpl`：最终评估。
- `reflector.tmpl`：tool-call 格式修复。
- `enricher.tmpl`：补充上下文。
- `summarizer.tmpl`：压缩长上下文。
- `toolcall_fixer.tmpl`：修复 JSON tool args。
- `tool_call_id_collector.tmpl` / `tool_call_id_detector.tmpl`：工具调用 ID 模板检测。
- `language_chooser.tmpl`、`image_chooser.tmpl`、`flow_descriptor.tmpl`、`task_descriptor.tmpl`：辅助分类和标题生成。

Graphiti prompt：

- `backend/pkg/templates/graphiti/agent_response.tmpl`
- `backend/pkg/templates/graphiti/tool_execution.tmpl`

示例 prompt：

- `examples/prompts/base_web_pentest.md`

## 修改 prompt 的检查点

改 prompt 时检查：

- `PromptType` 是否已有对应注册。
- `PromptVariables` 是否包含模板用到的变量。
- 变量名是否和 controller/provider 传入一致。
- 是否影响 function calling 或 barrier tool。
- 是否需要更新测试：`backend/pkg/templates/templates_test.go`、`backend/pkg/templates/validator/*`。

## Provider 清单

Provider 目录：

- `backend/pkg/providers/openai/`
- `backend/pkg/providers/anthropic/`
- `backend/pkg/providers/gemini/`
- `backend/pkg/providers/bedrock/`
- `backend/pkg/providers/ollama/`
- `backend/pkg/providers/deepseek/`
- `backend/pkg/providers/glm/`
- `backend/pkg/providers/kimi/`
- `backend/pkg/providers/qwen/`
- `backend/pkg/providers/custom/`

配置位置：

- `backend/pkg/config/config.go`
- `backend/pkg/providers/providers.go`
- `backend/pkg/providers/provider/provider.go`
- `backend/pkg/server/models/providers.go`
- `examples/configs/*.provider.yml`
- 前端 provider UI 和 icon。

## 新增 Provider 流程

1. 新建 `backend/pkg/providers/<name>/`。
2. 实现 `provider.Provider`。
3. 在 `pkg/providers/provider/provider.go` 增加 provider type/default name。
4. 在 `pkg/providers/providers.go` 注册默认配置和构造逻辑。
5. 在 `pkg/server/models/providers.go` 加入 REST 校验白名单。
6. 在 migration 中更新 provider enum。
7. 更新 `pkg/config/config.go` 环境变量。
8. 更新 GraphQL 类型和前端 provider 展示。
9. 增加测试或至少运行 provider 相关单测。

## 当前本地 Codex 改动

当前工作区已有本地 Codex Bridge 方案：

- `backend/pkg/graph/codex_flow.go`
- `scripts/codex-bridge.py`
- `CODEX_BRIDGE_URL`
- `CODEX_MODE`
- `CODEX_TIMEOUT`
- `CODEX_MAX_OUTPUT`

它不是标准 LLM provider，而是在 `createFlow` 时对 `modelProvider == "codex"` 做旁路处理，直接调用宿主机 Codex CLI bridge 并把结果写回 Flow。

