# Project Architecture Skill

## 总览

cybertest 是面向授权安全测试的工程化 Agent 工作空间，包含 Agent 操作手册、方法论 skill、工具包装器、任务归档和可选运行组件。

核心目录：

| 路径 | 职责 |
|---|---|
| `backend/cmd/cybertest/` | 主服务入口，初始化配置、数据库、server |
| `backend/pkg/config/` | 环境变量配置 |
| `backend/pkg/server/` | Gin router、中间件、auth、REST services |
| `backend/pkg/graph/` | gqlgen GraphQL schema、resolver、subscription |
| `backend/pkg/controller/` | Flow、task、日志等业务控制 |
| `backend/pkg/database/` | SQLC/GORM 访问层和模型 |
| `backend/migrations/sql/` | goose migration |
| `backend/pkg/providers/` | LLM provider 适配 |
| `backend/pkg/tools/` | Agent 可调用工具、工具 schema、执行器 |
| `backend/pkg/templates/` | 运行时 prompt 模板 |
| `frontend/src/` | React + TypeScript + Apollo Client UI |
| `observability/` | Grafana、Loki、Jaeger、OTel 等配置 |
| `examples/` | provider 配置、prompt 示例、报告示例 |

## 后端主路径

1. 用户通过 UI/GraphQL 创建 Flow。
2. Resolver 调用 controller 创建 Flow worker。
3. Controller 根据 provider、prompt、tools executor 运行 agent chain。
4. Agent 通过结构化 tool call 调用工具或委派 specialist。
5. 工具输出、Agent 日志、终端日志、搜索日志写入数据库。
6. GraphQL subscription 推送实时状态到前端。

关键文件：

- `backend/pkg/graph/schema.graphqls`
- `backend/pkg/graph/schema.resolvers.go`
- `backend/pkg/controller/flow.go`
- `backend/pkg/controller/task.go`
- `backend/pkg/tools/tools.go`
- `backend/pkg/tools/executor.go`

## 前端主路径

前端使用 React Router、Apollo Client 和 WebSocket subscription。

关键区域：

- Flow 创建页：`frontend/src/pages/flows/new-flow.tsx`
- Flow 详情页：`frontend/src/pages/flows/flow.tsx`
- Flow form：`frontend/src/features/flows/flow-form.tsx`
- Flow provider context：`frontend/src/providers/flow-provider.tsx`
- Provider 列表 context：`frontend/src/providers/providers-provider.tsx`
- Settings provider 页面：`frontend/src/pages/settings/settings-provider.tsx`

## 构建和运行注意点

- Docker Compose 默认用镜像，若要运行本地改动，需要 `docker-compose.override.yml` 配置 build 或显式 `docker compose up -d --build cybertest`。
- 前端 dev server 默认 `8000`，Docker 后端默认 `https://127.0.0.1:8443`。
- Go test 在沙箱或受限环境下可能需要指定 `GOCACHE=/tmp/go-build`。
- `.env` 是本地敏感配置，不能提交或输出。
