# 赏金候选队列与 ROI 分流 Skill

本 Skill 用于授权赏金、SRC、补天和厂商授权 Web/API 测试中的候选生成、排序和连续推进。目标是让 Cybertest 不平均审计所有接口，而是先大量生成候选，再按赏金 ROI 消耗 P0/P1/P2/P3 攻击队列。

## 启动条件

当任务是漏洞赏金、SRC、补天、授权高危优先测试，或用户要求“尽快出洞”“高危优先”“候选排序”时，读取本文件。启动前仍需读取 `agent/skills/security-testing.md`；补天式深度挖掘主流程已并入该文件。

## 高危优先原则

优先追踪可能通向高危或中危赏金结果的链路：

- 账号接管、认证绕过、OAuth/OIDC/SAML 认证链缺陷。
- 越权读取或修改核心业务数据，包括订单、运单、支付、员工、组织、网点、文件、token、权限树。
- 敏感信息批量泄露、SQL 注入可证明数据库信息。
- 文件上传到可利用位置，任意文件读、写、下载、导出任务越权。
- API 网关鉴权绕过、后台/管理端未授权。
- 测试环境连接生产身份、生产数据、生产对象或生产权限。
- OSS/STS 临时凭据滥用、对象存储权限边界缺陷。

快速降级低收益方向：

- 普通安全头、版本号、公开前端源码、公开配置。
- 无敏感数据的 health/info/actuator。
- CORS 无凭证读写影响。
- 只有 401/403/404 且无业务字段、无差异、无组合链。
- 普通营销跳转或不能携带 code/token/session 信任链的 Open Redirect。

## 候选来源

候选生成层应从以下来源自动汇总：

```text
子域名 / 存活 Web / 端口服务 / VHost / Host-SNI 差异 / 重定向链 /
目录爆破 / URL 爬取 / 历史 URL / JS chunk / source map /
API base / 前端路由 / Swagger/OpenAPI / Actuator/health/config /
登录和 SSO 配置 / OAuth/OIDC 配置 / 移动端 API /
对象存储链接 / 上传下载导入导出接口 / test/pre/dev/staging 环境
```

在 Cybertest 中，赏金任务默认通过 `scan_pipeline.py` 建立基线，并由末尾 `candidate_queue` 阶段自动调用 `bounty_candidate_queue.py` 汇总候选。若没有运行完整管线，必须至少把以下本地产物补喂给 `bounty_candidate_queue.py --task-dir` 或重复 `--input`：

- `subfinder`、证书透明度、被动 DNS、`dnsx`、可信解析和 Fake-IP 复核结果。
- `httpx`、TLS 指纹、端口/服务扫描、WAF/CDN/源站、VHost/Host-SNI 差异。
- `katana` URL、历史 URL、robots/sitemap、登录跳转链和重定向链。
- `gf_pattern_match.py` 的 14 类匹配结果，尤其 SQLi、SSRF、IDOR、redirect、LFI、debug_logic。
- `ffuf` 目录/参数/Host fuzz 结果，尤其 Swagger/OpenAPI、Actuator、备份、管理端、上传/导出入口。
- JS chunk、source map、`*-js-intel.json`、API base、前端路由、菜单权限、按钮权限、对象 ID 和接口 family。
- nuclei、手工脚本、Burp/Scrapling 取证、移动端 API、对象存储/OSS/STS、上传/下载/导入/导出接口验证产物。

缺少上述任何高收益来源时，不要把候选耗尽写成任务结论；应把它作为“未覆盖/受限项”或 `blocked_need_material` 的输入缺口。

JS 分析不是只找 secret，应还原业务攻击面：API base、路由表、菜单权限、按钮权限、角色枚举、接口 path、参数名、上传/下载/导出接口、登录与 SSO 配置、`appId/clientId/systemCode`、mock 数据、环境变量、测试域名和第三方服务地址。

## 候选类型

至少覆盖：

- `SQLi`
- `SSRF`
- `Open Redirect`
- `IDOR/BOLA`
- `File/Upload/Download/Import/Export`
- `Swagger/OpenAPI/Actuator`
- `OAuth/OIDC/SAML`
- `OSS/STS/Object Storage`
- `Admin/Management`
- `Test/Pre/Dev/Staging`
- `Mobile API/Deep Link`
- `API Gateway/Open Platform`
- `VHost/Host-SNI`
- `Directory Brute`
- `JS Attack Surface`
- `Core Business API`

## 结构化记录

每个候选必须形成机器可读记录：

```json
{
  "id": "BC-001",
  "name": "订单详情接口存在 BOLA 候选",
  "asset": "https://api.example.com",
  "url_or_endpoint": "/api/order/detail?orderId=1",
  "candidate_type": "IDOR/BOLA",
  "queue": "P0",
  "score": 92,
  "evidence_sources": ["katana", "js", "gf"],
  "related_params": ["orderId", "userId"],
  "unauth_reachable": true,
  "core_business": true,
  "business_object": "核心业务对象或资源类型",
  "business_capability": "state_transition|data_exchange|system_callback|async_task|external_resource|device_media|admin_permission|core_object",
  "operation_type": "read|write|delete|approve|export|import|sync|callback|schedule|publish|consume|preview|download|upload",
  "trust_boundary": "public_to_internal|user_to_admin|tenant_to_tenant|app_to_platform|machine_to_machine|frontend_to_backend|third_party_to_core",
  "machine_to_machine": false,
  "write_boundary_tested": "not-tested|readonly|empty-body|fake-object|test-object|authorized-side-effect",
  "impact_hypothesis": "可能影响的业务数据、权限、状态或系统动作",
  "upgrade_path": "信息泄露 -> 接口发现 -> 权限绕过 -> 业务影响",
  "safe_validation_level": "readonly|empty_body|fake_object|test_object|authorized_side_effect|log_confirmation",
  "reopen_condition": "需要测试对象ID/测试账号/测试AppKey或Secret/甲方日志",
  "do_not_overclaim": "只能证明当前证据已闭合的影响，不把进入业务逻辑写成已修改真实数据",
  "possible_impact": "越权读取订单或用户数据",
  "status": "high_value",
  "next_action": "使用授权 A/B 测试账号验证订单对象边界",
  "needs_material": true,
  "material_requirements": ["低权限账号A", "低权限账号B", "测试订单ID"],
  "downgrade_reasons": []
}
```

通用业务能力字段用于避免行业词锁死方向：

- `business_object`：订单、用户、组织、文件、资产、设备、记录、票据、合同、工单等核心对象或资源。
- `business_capability`：核心对象、状态流转、数据交换、系统回调、异步任务、外部资源、设备/媒体、管理权限。
- `operation_type`：读、写、删除、审批、导入、导出、同步、回调、任务调度、发布/消费、预览、下载、上传。
- `trust_boundary`：公网到内部、普通用户到管理员、租户到租户、应用到平台、机器到机器、前端到后端、第三方到核心系统。
- `safe_validation_level`：只读、空 body、fake-object、测试对象、授权副作用、日志侧确认。
- `do_not_overclaim`：记录报告边界，避免把匿名可达、进入处理器或测试对象验证夸大成真实业务篡改。

## 攻击队列

- `P0`：最可能直接产出高危或中危赏金结果。每轮优先消耗 P0。
- `P1`：高价值但需要少量补证、测试账号、对象 ID、AppKey/Secret 或测试文件。
- `P2`：低概率但仍有业务价值，或需要较多上下文才能闭合。
- `P3`：信息项、加固项、低收益方向，只做归档或组合链上下文。

只有当 P0 被确认、误报、降级、出 scope、无影响或进入材料阻塞后，才进入 P1/P2。

P0/P1 的高价值业务能力优先级：

- 核心业务对象未授权读写，或跨用户、跨租户、跨组织访问。
- 写操作、审批、删除、状态流转、任务触发可无权访问。
- 数据交换、开放平台、Webhook、Callback、SSO/OAuth 回调或签名边界缺陷。
- 上传、导入、预览、远程抓取形成文件链、SSRF、XXE、越权或执行风险。
- 管理面、中间件、任务调度、消息通道、事件消费者暴露。
- AppKey、Secret、Token、STS 泄露且可调用生产能力。
- 设备、媒体、边缘节点、客户端控制面暴露。

P1 通常包括：暴露 API family 但缺测试账号或对象；暴露权限字段、菜单、按钮、角色模型；暴露导出、报表、批处理、任务接口；暴露第三方对接配置但缺有效签名材料；疑似后台或管理 API 需要认证态继续。

## 状态机

```text
discovered
triaged
high_value
verifying
blocked_need_material
confirmed
false_positive
downgraded
out_of_scope
no_impact
archived
```

缺少测试账号、测试订单、测试运单、测试网点、测试 AppKey/Secret、可回滚文件或权限账号对时，不能直接归档为失败，应标记 `blocked_need_material`。

## 材料需求

材料清单必须说明：

- 当前为什么卡住。
- 需要什么账号、权限级别和业务对象。
- 拿到材料后第一步验证什么。
- 没有材料时是否仍值得继续。
- 是否应降级归档。

常见材料：

```text
测试账号 / 测试手机号 / 测试邮箱 / 测试订单 / 测试运单 /
测试网点或组织 ID / 测试 AppKey/Secret / 可回滚测试文件 /
可回滚业务对象 / 低权限和高权限账号对
```

## 连续推进规则

发现 401/403/404 后不要立即收尾，先判断：

- 是否需要固定 Host/SNI。
- 是否需要正确 method、Content-Type、Origin、Referer。
- 是否是 SPA fallback、网关路由或默认错误页。
- 是否需要从 JS、移动端或历史 URL 找真实 API path。
- 是否需要测试账号、低权限账号或对象样本。
- 是否可通过只读请求、空体、畸形体、fake-object 证明业务逻辑可达。

## 报告视图

赏金报告或阶段性归档应增加：

- Top P0 候选。
- Top P1 候选。
- 已确认漏洞。
- 已降级候选。
- 误报候选。
- 需要测试材料候选。
- 下一步最高 ROI 动作。
- 每个候选为什么没有闭合。
