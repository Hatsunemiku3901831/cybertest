# Burp MCP 集成 Skill

本 Skill 用于在 Codex 中调用 Burp Suite MCP Server，实现代理抓包、请求重放、Repeater/Intruder 集成、编解码和配置管理等能力。适用于授权安全测试中的流量分析、漏洞验证和请求篡改场景。

## 1. 前置条件

- Burp Suite Professional / Community 已启动
- Burp Suite MCP Server 扩展已安装（BApp Store: `PortSwigger/mcp-server`）
- MCP 服务器端口 `9876` 在 Burp 中已启用
- Claude Code 项目已配置 Burp MCP 连接

### 1.1 项目 MCP 配置

当前 MCP 配置在 `/Users/umisonoda/.claude.json` 中。如需在当前项目独立启用，在 `.claude/settings.local.json` 添加：

```json
{
  "mcpServers": {
    "burp": {
      "type": "sse",
      "url": "http://127.0.0.1:9876"
    }
  }
}
```

MCP 工具在 Claude Code 中以 `mcp__burp__<tool_name>` 格式调用。

### 1.2 验证可用性

```bash
# 检查 Burp MCP 服务器端口
lsof -i :9876 -P | grep LISTEN

# 验证 SSE 连接
curl -s -m 3 http://127.0.0.1:9876/
```

## 2. 可用工具清单（24 个）

### 2.1 HTTP 请求工具

| 工具名 | 参数 | 用途 |
|--------|------|------|
| `send_http1_request` | `targetHostname`, `targetPort`, `usesHttps`, `content` | 发送 HTTP/1.1 请求并返回完整响应 |
| `send_http2_request` | `targetHostname`, `targetPort`, `usesHttps`, `pseudoHeaders`, `headers`, `requestBody` | 发送 HTTP/2 请求（现代 Web 目标优先使用） |

**`send_http1_request` 参数说明：**
- `targetHostname` (string): 目标主机名
- `targetPort` (integer): 目标端口
- `usesHttps` (boolean): 是否使用 HTTPS
- `content` (string): 原始 HTTP/1.1 请求（包含请求行、头部和正文，使用 `\r\n` 换行）

**示例：**
```json
{
  "targetHostname": "example.com",
  "targetPort": 443,
  "usesHttps": true,
  "content": "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Test/1.0\r\nAccept: text/html\r\nConnection: close\r\n\r\n"
}
```

### 2.2 Repeater / Intruder 工具

| 工具名 | 参数 | 用途 |
|--------|------|------|
| `create_repeater_tab` | `targetHostname`, `targetPort`, `usesHttps`, `content`, `tabName` | 创建 HTTP/1.1 Repeater Tab |
| `create_repeater_tab_http2` | `targetHostname`, `targetPort`, `usesHttps`, `pseudoHeaders`, `headers`, `requestBody`, `tabName` | 创建 HTTP/2 Repeater Tab |
| `send_to_intruder` | `targetHostname`, `targetPort`, `usesHttps`, `content`, `tabName` | 发送请求到 Intruder |

**`create_repeater_tab` 额外参数：**
- `tabName` (string): Repeater Tab 名称，便于人工识别

### 2.3 代理历史与 Organizer（分页查询）

| 工具名 | 参数 | 用途 |
|--------|------|------|
| `get_proxy_http_history` | `count`, `offset` | 获取代理 HTTP 历史 |
| `get_proxy_http_history_regex` | `count`, `offset`, `regex` | 按正则筛选代理 HTTP 历史 |
| `get_proxy_websocket_history` | `count`, `offset` | 获取代理 WebSocket 历史 |
| `get_proxy_websocket_history_regex` | `count`, `offset`, `regex` | 按正则筛选代理 WebSocket 历史 |
| `get_organizer_items` | `count`, `offset` | 获取 Organizer 中的项目 |
| `get_organizer_items_regex` | `count`, `offset`, `regex` | 按正则筛选 Organizer 项目 |

**⚠️ 使用注意：**
- `count=1` 性能最优，推荐先用小 count 验证再逐步增大
- `count >= 5` 时可能因历史数据量大导致超时（默认 30s），建议搭配 `get_proxy_http_history_regex` 用正则缩小范围
- `offset` 参数为必填

### 2.4 编码工具

| 工具名 | 参数 | 用途 |
|--------|------|------|
| `url_encode` | `content` | URL 编码 |
| `url_decode` | `content` | URL 解码 |
| `base64_encode` | `content` | Base64 编码 |
| `base64_decode` | `content` | Base64 解码 |
| `generate_random_string` | `length`, `characterSet` | 生成随机字符串（用于 payload 随机化） |

**`generate_random_string` 的 `characterSet` 选项：** `alphanumeric`、`alpha`、`numeric`、`hex`、`printable`

### 2.5 配置管理工具

| 工具名 | 参数 | 用途 |
|--------|------|------|
| `output_project_options` | 无 | 导出当前项目配置（JSON） |
| `output_user_options` | 无 | 导出用户级配置（JSON） |
| `set_project_options` | `json` | 设置项目级配置 |
| `set_user_options` | `json` | 设置用户级配置 |

⚠️ `set_*` 工具需要 Burp 中开启 "Enable tools that can edit your config" 选项。

### 2.6 状态控制工具

| 工具名 | 参数 | 用途 |
|--------|------|------|
| `set_proxy_intercept_state` | `intercepting` (boolean) | 开关代理拦截 |
| `set_task_execution_engine_state` | `running` (boolean) | 暂停/恢复任务执行引擎 |
| `get_active_editor_contents` | 无 | 获取当前活跃编辑器的内容 |
| `set_active_editor_contents` | `text` | 设置活跃编辑器内容 |

## 3. 通信协议

Burp MCP Server 使用 **SSE (Server-Sent Events) + JSON-RPC 2.0** 协议。

| 项目 | 值 |
|------|------|
| 地址 | `http://127.0.0.1:9876` |
| SSE 端点 | `GET /` |
| 消息端点 | `POST /?sessionId=<sid>` |
| 协议版本 | `2024-11-05` |
| 当前版本 | `burp-suite` v1.1.2 |

### 3.1 MCP 会话流程

```
1. GET / → 获取 SSE 流和 sessionId
2. POST /?sessionId=xxx → {"jsonrpc":"2.0","method":"initialize",...}
3. 从 SSE 读取 initialize 响应
4. POST /?sessionId=xxx → {"jsonrpc":"2.0","method":"notifications/initialized"}
5. POST /?sessionId=xxx → {"jsonrpc":"2.0","method":"tools/call",...}
6. 从 SSE 读取工具调用响应
```

### 3.2 SSE 事件格式

```
event: message
data: {"id":1,"jsonrpc":"2.0","result":{...}}

```

响应通过 `data` 字段返回 JSON-RPC 结果，`id` 与请求 `id` 对应。

## 4. 使用场景与模式

### 4.1 抓包 → 重放标准流程

```
场景：获取 Burp 代理中的流量，分析后重放或修改重放
```

**步骤 1：抓包（获取代理历史）**
```
工具: get_proxy_http_history
参数: {"count": 1, "offset": 0}
输出: JSON 对象，包含 request 和 response 字段
```

**步骤 2：分析请求**
- 检查 URL、方法、头部、参数、Cookie
- 识别认证机制（JWT、Session、API Key）
- 标记可测试参数

**步骤 3：重放（发送修改后的请求）**
```
工具: send_http1_request
参数: 修改自步骤 1 的请求内容
输出: 完整 HTTP 响应，包含状态码、头部和响应体
```

**步骤 4（可选）：发送到 Repeater 供人工继续测试**
```
工具: create_repeater_tab
参数: 使用修改后的请求 + tabName 描述测试目的
```

### 4.2 认证测试模式

```
场景：测试 API 的认证和授权
```

1. 使用 `send_http1_request` 发送无认证请求，记录 401/403 响应
2. 添加有效 Token/Cookie，验证正常访问
3. 修改 Token（删除签名、改 payload、改算法），验证 JWT 校验
4. 使用 `create_repeater_tab` 保存关键请求供人工确认

### 4.3 参数 Fuzz 准备模式

```
场景：从代理历史提取请求，准备参数 fuzz
```

1. `get_proxy_http_history_regex` 按域名/路径正则筛选目标请求
2. 提取请求中的参数位置（Query、Body、Header、Cookie）
3. 使用 `url_encode` / `base64_encode` 生成 payload 变体
4. 使用 `generate_random_string` 生成随机标记用于回显检测
5. 通过 `send_http1_request` 逐个发送

### 4.4 配置审查模式

```
场景：检查 Burp 项目配置是否符合测试规范
```

1. `output_project_options` 导出 JSON 配置
2. 检查代理监听器、TLS 穿透、scope 配置
3. `output_user_options` 检查用户级 platform/auth 设置
4. 对比安全测试最佳实践

### 4.5 WebSocket 测试模式

```
场景：测试 WebSocket 连接
```

1. 浏览器通过 Burp 代理建立 WebSocket 连接
2. `get_proxy_websocket_history` 获取 WebSocket 历史
3. 分析消息格式、认证方式
4. 使用 `send_http1_request` 升级连接后验证

## 5. 已知限制和注意事项

| 限制 | 说明 | 应对 |
|------|------|------|
| 代理历史大查询超时 | `count >= 5` 时可能 30s 超时 | 使用 `count=1` 或 `get_proxy_http_history_regex` |
| 无 Collaborator 工具 | 当前 Pro 版本的 Collaborator 工具在此 Burp 实例中不可用 | 使用外部 OOB 方案 |
| 无 Scanner Issues 工具 | 需要 Professional 版 Burp | 使用 nuclei/zap 替代 |
| Repeater Tab 创建不返回响应 | `create_repeater_tab` 仅确认执行 | 在 Burp UI 中查看 Repeater Tab |
| 配置编辑需显式开启 | `set_*_options` 需要 Burp 扩展设置中启用 | 默认关闭，需手动开启 |
| 单个 SSE 连接 | Burp MCP 同时只支持一个 SSE 长连接 | 避免并发连接 |

## 6. 与项目工具的配合

| 项目工具 | Burp MCP 配合方式 |
|----------|-------------------|
| `tool/sqlmap_safe.py` | Burp 抓包获取注入点 → sqlmap 验证 |
| `tool/dalfox_json.py` | Burp 抓包获取反射点 → Dalfox XSS 验证 |
| `tool/ffuf_json.py` | Burp 抓包获取目录/参数 → ffuf 字典 fuzz |
| `tool/katana_crawl.py` | Katana 爬虫发现端点 → Burp 代理验证和重放 |
| `tool/nuclei_json_scan.py` | Nuclei 扫描命中 → Burp Repeater 人工确认 |
| `tool/arjun_json.py` | Arjun 参数发现 → Burp 抓包 HTTP 方法/参数回显验证 |

## 7. 故障排查

### 7.1 检查 Burp MCP 服务器状态
```bash
lsof -i :9876 -P | grep LISTEN
# 应看到 JavaApplicationStub 监听在 localhost:9876
```

### 7.2 检查 Burp MCP 扩展是否安装
在 Burp Suite → Extensions → BApp Store → 搜索 "MCP Server" → 确认已安装

### 7.3 SSE 连接失败
- 检查 Burp 是否运行中
- 检查防火墙是否阻止 localhost:9876
- 重启 Burp Suite 和 MCP Server 扩展

### 7.4 工具调用超时
- `send_http1_request`：目标可能不可达，先用 `curl` 验证连通性
- `get_proxy_http_history`：减少 count 或使用 regex 过滤
- 检查 Burp 任务执行引擎是否暂停（使用 `set_task_execution_engine_state`）
