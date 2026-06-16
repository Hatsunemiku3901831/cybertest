# HackSkills Project Bridge

本文件把仓库内的 `hack-skills/` 知识库注册为 Codex 可按需使用的项目本地技能入口。

## 使用场景

当任务涉及以下内容时，读取本文件后再按需加载 HackSkills：

- 授权 Web/API 渗透测试。
- 新目标安全测试路线规划。
- 漏洞线索分流与验证优先级判断。
- Exploit path planning。
- Bug bounty 方法论、攻击面枚举、漏洞类别选择。

## 加载顺序

1. 先读取 `agent/skills/security-testing.md`，确认授权边界、低影响原则和报告要求。
2. 再读取 `hack-skills/skills/hack/SKILL.md` 作为 HackSkills 总入口。
3. 参考“推荐加载参考表”读取与当前现象匹配的 HackSkills 分类入口或深度专题。
4. 建议在任务日志中记录本轮实际读取的 HackSkills 文件路径和触发原因，便于复盘。
5. 如果测试结束，按 `agent/retrospectives/TEMPLATE.md` 复盘并更新 `agent/retrospectives/index.md`。

不要一次性读取全部 `hack-skills/skills/`。只读取当前阶段会直接影响测试路线、验证手法或停止点判断的文件。

## 主要入口

- 总入口：`hack-skills/skills/hack/SKILL.md`
- 侦察：`hack-skills/skills/recon-for-sec/SKILL.md`
- API：`hack-skills/skills/api-sec/SKILL.md`
- 认证与授权：`hack-skills/skills/auth-sec/SKILL.md`
- 注入：`hack-skills/skills/injection-checking/SKILL.md`
- 文件访问：`hack-skills/skills/file-access-vuln/SKILL.md`
- 业务逻辑：`hack-skills/skills/business-logic-vuln/SKILL.md`

## 使用约束

- HackSkills 只用于明确授权目标、合法研究、防御验证和规则允许的漏洞赏金测试。
- 不要把 HackSkills 内容当成自动确认漏洞的证据；扫描器或 payload 命中必须结合人工判断、请求/响应证据和业务影响。
- 不要记录真实凭据、token、cookie、JWT、私有域名、内部 IP、callback URL 或可识别客户信息。
- 如果需要写临时脚本，放入 `temporarytool/`；如果沉淀为通用能力，再整理到 `tool/` 并注册到 `agent/AGENT.md`。

## 路由提示

优先根据观察到的行为选择专题：

- 输入反射到 HTML/JS：XSS / SSTI。
- 服务端请求 URL/主机名：SSRF。
- SQL 报错、布尔差异、时间差异、可疑查询参数：SQLi。
- VHost、Host/SNI 差异、源站、隐藏后台或测试域名：Recon / Host Header / 401-403 绕过。
- 重定向参数、登录回跳、OAuth callback：Open Redirect / OAuth OIDC。
- 目录爆破命中 Swagger、Actuator、备份、上传、导出、管理端：Recon / API Docs / File Access。
- JS chunk、source map、前端路由、API base、权限字段、对象 ID：Recon / API / BOLA。
- XML、Office、SVG 解析：XXE。
- 路径、文件名、下载参数可控：Path Traversal / LFI。
- API 中有对象 ID、租户 ID、用户 ID：IDOR / BOLA / BFLA。
- 登录、找回密码、2FA、会话、JWT、OAuth：Auth / Token / SSO。
- 支付、优惠券、库存、状态流转：Business Logic / Race Condition。
- 命令行工具、图片/视频处理、导入器：Command Injection。

## 推荐加载参考表

当任务中出现下列表现时，除了总入口 `hack-skills/skills/hack/SKILL.md`，建议优先考虑读取对应细分文件：

| 触发条件 | 读取文件 |
|---|---|
| 新目标、资产梳理、子域名、端口、目录、JS、接口发现 | `hack-skills/skills/recon-for-sec/SKILL.md` 或 `hack-skills/skills/recon-and-methodology/SKILL.md` |
| REST API、移动端后端、公开接口、接口版本、Swagger/OpenAPI | `hack-skills/skills/api-sec/SKILL.md` |
| API 中出现对象 ID、用户 ID、租户 ID、订单 ID、读者证、机构 ID | `hack-skills/skills/api-authorization-and-bola/SKILL.md` 或 `hack-skills/skills/idor-broken-object-authorization/SKILL.md` |
| 登录、注册、找回密码、验证码、会话、Cookie、JWT、OAuth、SSO | `hack-skills/skills/auth-sec/SKILL.md` |
| JWT、Bearer token、签名参数、Header 信任边界 | `hack-skills/skills/api-auth-and-jwt-abuse/SKILL.md` 或 `hack-skills/skills/jwt-oauth-token-attacks/SKILL.md` |
| CORS 回显、跨域凭据、Origin allowlist | `hack-skills/skills/cors-cross-origin-misconfiguration/SKILL.md` |
| 参数反射到 HTML、JS、属性、URL、富文本、预览页 | `hack-skills/skills/xss-cross-site-scripting/SKILL.md` |
| SQL 报错、布尔差异、时间差异、可疑查询参数 | `hack-skills/skills/sqli-sql-injection/SKILL.md` |
| URL、Webhook、图片抓取、远程导入、回调地址 | `hack-skills/skills/ssrf-server-side-request-forgery/SKILL.md` |
| VHost、Host/SNI 差异、源站业务、隐藏后台、测试域名 | `hack-skills/skills/recon-for-sec/SKILL.md`、`hack-skills/skills/http-host-header-attacks/SKILL.md` 或 `hack-skills/skills/401-403-bypass-techniques/SKILL.md` |
| 目录爆破命中 Swagger、Actuator、备份包、上传下载、导入导出、管理端 | `hack-skills/skills/api-recon-and-docs/SKILL.md`、`hack-skills/skills/file-access-vuln/SKILL.md` 或 `hack-skills/skills/unauthorized-access-common-services/SKILL.md` |
| JS chunk/source map 还原 API base、前端路由、权限字段、对象 ID、测试域名 | `hack-skills/skills/recon-for-sec/SKILL.md`、`hack-skills/skills/api-sec/SKILL.md` 或 `hack-skills/skills/api-authorization-and-bola/SKILL.md` |
| 文件名、下载路径、上传路径、模板路径、`../` 或编码绕过线索 | `hack-skills/skills/file-access-vuln/SKILL.md` 或 `hack-skills/skills/path-traversal-lfi/SKILL.md` |
| 上传、导入、图片/Office/SVG/压缩包处理、公开预览 | `hack-skills/skills/upload-insecure-files/SKILL.md` |
| XML、SOAP、Office、SVG、XSLT 解析 | `hack-skills/skills/xxe-xml-external-entity/SKILL.md` 或 `hack-skills/skills/xslt-injection/SKILL.md` |
| 优惠券、订单、支付、库存、状态流转、积分、票券 | `hack-skills/skills/business-logic-vuln/SKILL.md` 或 `hack-skills/skills/business-logic-vulnerabilities/SKILL.md` |
| 一次性动作、领取、兑换、重置、并发提交 | `hack-skills/skills/race-condition/SKILL.md` |
| WebSocket 升级、长连接、实时消息、订阅通道 | `hack-skills/skills/websocket-security/SKILL.md` |
| GraphQL、批量 JSON 数组、隐藏字段、未文档化参数 | `hack-skills/skills/graphql-and-hidden-parameters/SKILL.md` |
| 401/403、IP ACL、后台路径、Header 绕过候选 | `hack-skills/skills/401-403-bypass-techniques/SKILL.md` |
| Host、X-Forwarded-*、重置链接、绝对 URL 生成 | `hack-skills/skills/http-host-header-attacks/SKILL.md` |
| HTTP 前后端解析差异、代理、网关、CL/TE/H2 异常 | `hack-skills/skills/request-smuggling/SKILL.md` |
| 重定向参数、跳转 URL、OAuth redirect_uri | `hack-skills/skills/open-redirect/SKILL.md` 或 `hack-skills/skills/oauth-oidc-misconfiguration/SKILL.md` |

## 任务日志记录格式

实际加载细分 HackSkills 后，建议在任务目录 `notes/log.md` 或阶段性笔记中记录：

```text
- HackSkills 加载：读取 `hack-skills/skills/api-sec/SKILL.md`，触发原因：目标存在 REST API 和公开接口版本。
- HackSkills 加载：读取 `hack-skills/skills/api-authorization-and-bola/SKILL.md`，触发原因：接口参数出现 readerId/orderId/orgId，进入 BOLA/IDOR 验证。
```

如果参考表提示某个方向但最终没有加载，也可记录原因，例如：

```text
- HackSkills 未加载：未读取 `hack-skills/skills/race-condition/SKILL.md`，原因：当前未进行任何一次性状态变更或并发验证。
```
