# 授权赏金深度挖掘 Skill

本 Skill 用于明确授权的漏洞赏金、SRC、补天平台项目和厂商授权 Web/API 安全测试。目标是在不违反平台规则、项目 scope、法律合规和低影响原则的前提下，最大化资产面、接口面、权限面、业务面和攻击链覆盖。

默认采用深度模式：不按固定时间收尾，持续挖掘、复盘、组合线索，直到高收益路径耗尽、形成有效漏洞证据，或继续验证需要额外授权、账号、验证码、测试数据、报备或测试窗口。

## 启动条件

当任务出现以下任一描述时读取本文件：

- 目标是漏洞赏金平台、SRC、补天项目或厂商授权赏金挖掘。
- 用户明确要求深度挖掘、尽量挖透、不限时、长期挖洞、高危优先或成果导向。
- 用户要求在平台安全约束内最大化测试边界和挖洞效率。

启动前必须读取：

1. `agent/skills/security-testing.md`，确认授权边界、低影响原则、Web/API 测试流程、漏洞发现链、攻击链组合和影响边界停止规则。
2. `agent/skills/hack-skill.md`，按现象路由到 HackSkills 子技能。
3. `agent/skills/bounty-candidate-triage.md`，建立赏金候选生成、P0/P1/P2/P3 攻击队列、ROI 评分和材料需求状态。
4. `agent/skills/bounty-closure-playbooks.md`，按 SQLi、SSRF、OAuth/OIDC/SAML、IDOR/BOLA、文件链、网关、VHost、重定向、目录爆破和 JS 分析候选选择最小闭合流程。
5. 如任务强调高危优先，同时读取 `agent/skills/aggressive-high-impact.md`，并按本文件“激进与克制的基调协调”一节裁定边界。
6. 执行 SRC/赏金路径选择和证据闭环时，默认套用 `agent/skills/security-testing.md` 的“近期跨案例经验固化”规则；该规则覆盖前端 bundle 抽取、认证态 A/B 矩阵、未认证读到写边界、对象存储/Git/公开附件最小证明、误报过滤和证据闭合停止。

实际安全测试任务开始前，按项目规则创建或选定 `tasks/YYYY-MM-DD-HHMM-short-task-name/` 任务目录，并记录授权范围、平台规则、目标清单、账号边界、测试窗口、停止点、已加载技能，以及本文件“法律与授权工件”一节所列的最低授权凭据。

赏金任务开局必须先建立机器可读攻击面基线，再进入人工定向验证。默认流程：

1. 对每个 scope 根域或用户给定入口运行 `scan_pipeline.py --mode quick`。
2. 正式渗透或用户要求完整覆盖时，升级到 `--mode full`；SPA/API 网关、大量 JS、移动端 API 或 P0/P1 线索未清空时，升级到 `--mode deep`。
3. `scan_pipeline.py` quick/full/deep 会在质量门禁后自动运行 `candidate_queue` 阶段，产出 `phase_*_candidate_queue/result.json` 和 Markdown。
4. 若任务是从历史归档、手工脚本或外部工具产物续跑，则用 `--task-dir` 离线汇总，生成统一的 `outputs/bounty-candidates.json` 和 `outputs/bounty-candidates.md`。

```bash
./tool/scan_pipeline.py --authorized --domain example.com --mode quick
./tool/scan_pipeline.py --authorized --domain example.com --mode full
./tool/scan_pipeline.py --authorized --domain example.com --mode deep
```

从既有任务目录或额外产物补喂时运行：

```bash
./tool/bounty_candidate_queue.py --task-dir tasks/YYYY-MM-DD-HHMM-short-task-name \
  --output-json tasks/YYYY-MM-DD-HHMM-short-task-name/outputs/bounty-candidates.json \
  --output-md tasks/YYYY-MM-DD-HHMM-short-task-name/outputs/bounty-candidates.md
```

候选队列的输入应覆盖 VHost/Host-SNI 差异、目录爆破、重定向链、GF、历史 URL、katana URL、JS API family、Swagger/OpenAPI、Actuator、nuclei、端口服务、对象存储、上传下载导入导出、移动端 API 和手工验证产物。任何一类因平台规则、工具缺失或授权边界无法覆盖时，必须写入 `notes/log.md` 和最终报告的“未覆盖/受限项”。

候选队列不是漏洞确认结果。P0/P1/P2/P3 只表示赏金 ROI 和验证优先级；所有结论仍需请求、响应、状态码、业务字段和影响证明闭合。

未生成候选队列、未跑完等价资产发现基线、未处理完 P0 队列前，不得把任务结论写成“全资产穷尽”或“所有高收益方向耗尽”。

## 激进与克制的基调协调

本 Skill 主体是克制的，`aggressive-high-impact.md` 倾向高危优先。两者不冲突，但必须按下面的优先级裁定，避免 agent 行为不一致：

- “激进”指的是**线索挖掘的主动性与攻击链组合的想象力**：更广的资产面、更多假设、更深的链路推演、更坚持地寻找可组合条件。
- 任何时候， 本文件不可突破边界 > 低影响证明原则 > 高危优先偏好。前者覆盖后者。
- 当“证明更大影响”与“低影响、可回滚”冲突时，永远选择停在风险成立点，把扩大影响的部分写成“受限未验证 + 建议厂商内部验证方式”。
- 激进只允许把验证复杂度更高、ROI 更高的路径排到前面，不允许改变验证手段的安全等级。

## 合规边界最大化原则

在授权范围内允许更主动：

- 扩展 in-scope 资产：主域、子域、API、后台、移动端接口、对象存储、源站、历史资产、证书关联资产。
- 对 in-scope Web/API 做低速爬取、目录探测、参数发现、JS 分析和模板化安全扫描。
- 使用少量自有测试账号做 A/B 越权、BOLA、BFLA 和业务边界验证。
- 对对象 ID、租户 ID、订单 ID、文件 ID 只用已知样本和少量变体验证。
- 上传、写入、状态变更只在可回滚、低影响、必要时执行，并记录恢复方式。
- 高危链路证明到风险成立即停，不追求破坏力展示。

## 威胁建模前置

不要只按现象被动路由。进入侦察前先做轻量威胁建模，基于行业、业务关键资产、身份边界和架构线索生成攻击假设树，再用假设驱动资产收集和验证优先级。

攻击假设树模板：

```text
目标行业：
核心业务资产：交易 / 数据 / 身份 / 供应链 / 设备 / 内容分发
关键角色：匿名用户 / 普通用户 / 商户 / 员工 / 管理员 / 设备 / 第三方应用
信任边界：前端-API / 用户-租户 / App-服务端 / CDN-源站 / 云存储-业务系统 / 第三方回调 / 浏览器同源边界
高价值攻击假设：
- H1：
  - 依赖资产：
  - 可能入口：
  - 最小验证：
  - 停止点：
- H2：
  - 依赖资产：
  - 可能入口：
  - 最小验证：
  - 停止点：
当前优先级：
```

电商示例：

```text
核心资产：订单、支付、优惠券、库存、地址、商户后台
H1：优惠券/库存/订单状态存在业务逻辑或并发缺陷
H2：订单、发票、地址接口存在 BOLA/IDOR
H3：商户/运营后台存在低权限访问管理 API
优先入口：订单 API、优惠券领取、支付回调、发票/导出、商户后台、移动端 API
```

SaaS 示例：

```text
核心资产：租户数据、项目文件、成员权限、审计日志、集成 token
H1：tenantId/orgId/projectId 权限校验缺失导致跨租户读取
H2：导入/导出/模板/附件处理形成文件链或 SSRF
H3：集成 webhook、OAuth、API token 权限边界不清
优先入口：租户切换、项目对象 API、成员邀请、导入导出、webhook、OAuth 回调
```

金融/支付示例：

```text
核心资产：账户余额、交易流水、风控规则、KYC 资料、对账接口
H1：转账/提现/退款金额或状态机存在业务逻辑或竞态缺陷
H2：交易/账单/KYC 接口存在 BOLA 与水平越权
H3：风控/审批参数可被前端篡改或绕过
优先入口：下单/支付/退款 API、对账导出、KYC 上传、优惠/返现、绑卡回调
```

## HackSkills 路由

按观察选择子技能，不要一次性加载全部：

| 现象 | 读取 |
|---|---|
| 新目标、资产发现、JS/API 收集 | `hack-skills/skills/recon-for-sec/SKILL.md` |
| REST API、移动端后端、公开接口 | `hack-skills/skills/api-sec/SKILL.md` |
| 对象 ID、租户、订单、文件、用户字段 | `hack-skills/skills/api-authorization-and-bola/SKILL.md` 或 `hack-skills/skills/idor-broken-object-authorization/SKILL.md` |
| 登录、注册、重置、验证码、JWT、OAuth、SSO、2FA/MFA | `hack-skills/skills/auth-sec/SKILL.md` |
| 上传、导入、预览、转换、附件 | `hack-skills/skills/upload-insecure-files/SKILL.md` |
| 下载、文件名、路径参数、导出接口 | `hack-skills/skills/file-access-vuln/SKILL.md` 或 `hack-skills/skills/path-traversal-lfi/SKILL.md` |
| URL、webhook、远程导入、PDF/截图生成 | `hack-skills/skills/ssrf-server-side-request-forgery/SKILL.md` |
| CORS、Origin、cookie-only API | `hack-skills/skills/cors-cross-origin-misconfiguration/SKILL.md` |
| 优惠券、支付、库存、审批、状态流 | `hack-skills/skills/business-logic-vuln/SKILL.md` |
| 一次性领取、兑换、重置、库存扣减、提现/退款 | `hack-skills/skills/race-condition/SKILL.md` |
| GraphQL、批量 JSON、隐藏字段、批量查询 | `hack-skills/skills/graphql-and-hidden-parameters/SKILL.md` |
| 401/403、后台路径、Header 绕过候选 | `hack-skills/skills/401-403-bypass-techniques/SKILL.md` |
| 反射/存储/DOM 输入回显、富文本、postMessage、模板渲染 | `hack-skills/skills/client-side-injection/SKILL.md`（缺失时按本文件“现代 Web 与客户端攻击面”执行） |
| 缓存头、CDN 行为、`X-Forwarded-*`、未键入参数 | `hack-skills/skills/web-cache-deception-and-poisoning/SKILL.md`（缺失时按本文件相应小节执行） |
| 反向代理、前后端解析差异、`Content-Length`/`Transfer-Encoding` 异常 | `hack-skills/skills/request-smuggling/SKILL.md`（缺失时按本文件相应小节执行，且严守低影响） |
| 悬挂 DNS、指向第三方托管的子域 CNAME、404 服务页 | `hack-skills/skills/recon-for-sec/SKILL.md` 的子域接管小节 |
| JSON 合并、`__proto__`/`constructor`、客户端库版本 | 按本文件“原型链污染”小节执行 |
| XML 解析、SVG、DOCX/XLSX 解包、SAML | `hack-skills/skills/upload-insecure-files/SKILL.md` 的 XXE 小节 |
| 移动端 App、APK/IPA、deeplink、证书绑定、本地存储 | `hack-skills/skills/api-sec/SKILL.md`、`hack-skills/skills/auth-sec/SKILL.md`，必要时按接口现象继续路由 |
| 云存储、对象桶、Serverless、云公开配置 | `hack-skills/skills/recon-for-sec/SKILL.md`，发现文件/权限问题后转 `file-access-vuln` 或 `api-authorization-and-bola` |
| 公开仓库、CI/CD 产物、依赖版本、source map | `hack-skills/skills/recon-for-sec/SKILL.md`，发现泄露后转对应 API/Auth/File 专题 |

每次加载细分 HackSkills 后，在任务日志中记录文件路径和触发原因。若某子技能在仓库中尚未建立，按本文件对应小节执行，并在复盘中标记“缺失子技能，建议补建”。

## 深度挖掘循环

不限时任务按循环推进，而不是跑完一轮扫描就结束：

```text
1. P0 队列里当前最可能出高危/中危的候选是什么？
2. 它能否组合认证、权限、文件、上传、后台、网关、源站、缓存、客户端注入、SSRF、SQLi、VHost、重定向或业务状态？
3. 是否还有未测 sibling host、API version、hidden route、object ID、role boundary、缓存键、解析差异、目录命中或 JS 还原出的旧接口？
4. 当前验证是否会触碰平台红线？
5. 最小低影响证明是什么？
6. 如果不能继续，缺少的是账号、验证码、测试数据、AppKey/Secret、测试文件、报备、授权窗口还是对象样本？
7. 当前候选应进入 confirmed、false_positive、downgraded、blocked_need_material、out_of_scope、no_impact 还是继续 verifying？
```

每轮循环都要更新风险清单、攻击链假设、失败路径和下一轮优先级。

## 阶段一：全量可见面建模

输出并持续维护：

```text
资产清单：
行业和业务假设：
入口类型：
认证状态：
技术栈：
API 前缀：
高价值功能：
疑似后台：
疑似对象存储：
移动端入口：
云配置线索：
供应链/公开仓库线索：
ASN/IP/证书归属：
被动 DNS/历史 URL：
公开文档/员工信息 OSINT：
技术栈深度指纹：
CDN/缓存/WAF 归属：
悬挂 DNS / 可疑 CNAME：
需登录继续的入口：
平台规则限制：
```

优先动作：

- 被动收集 in-scope 子域、证书、ASN/IP 归属、被动 DNS、历史 URL、公开 JS、source map、Swagger/OpenAPI、sitemap、robots。
- 搜索公开 GitHub/GitLab commit、issue、CI/CD 产物、公开文档、员工信息和供应链线索；只做被动信息收集和已知 CVE/泄露匹配。
- 低速确认 Web 存活、标题、TLS、Server、框架、错误页面特征、JS 框架版本、字体/图标资源哈希、网关错误、WAF/CDN/源站线索。
- 提取高价值关键词：`upload`、`import`、`export`、`download`、`preview`、`convert`、`task`、`job`、`callback`、`webhook`、`url`、`fetch`、`render`、`pdf`、`excel`、`attachment`、`admin`、`role`、`permission`、`tenant`、`audit`、`config`、`graphql`、`internal`、`debug`。

### 子域接管检测

子域接管是 recon 阶段必查项，低影响、高价值：

- 枚举子域后逐一解析 CNAME，识别指向第三方托管（对象存储、CDN、PaaS、文档/状态页、邮件服务等）但目标服务已释放的悬挂记录。
- 通过对应平台的“未认领”指纹页面或错误响应判断可接管，**仅做指纹级确认**，不实际注册/占用第三方资源以避免影响第三方与他人。
- 证明可接管即停：记录子域、CNAME 目标、第三方服务、指纹证据；接管动作交厂商修复，不在 PoC 中真正夺取。

### 扩展攻击面

移动端仅做合规客户端分析和接口还原：

- APK/IPA 包名、域名、API base、证书绑定、deeplink/scheme、硬编码配置、本地存储键名。
- 不绕过平台未授权范围，不攻击第三方推送、支付、地图等非 scope 服务。
- 发现接口后按 Web/API 流程验证认证、越权、上传、文件和业务逻辑。

云配置仅限 in-scope 外部可见面：

- S3/OSS/COS bucket 访问策略、公开对象、静态网站托管、错误响应、对象命名规律。
- 公开 snapshot、Serverless 函数入口、云 API 网关、临时凭据泄露线索。
- 不尝试越权进入云控制台，不枚举非授权云账号资源。

供应链与依赖仅做被动和低交互：

- 公开仓库 secret、历史 commit、issue、release artifact、CI/CD 日志或产物。
- 依赖版本和公开 advisory/CVE 匹配，以版本、路径、行为证据支撑结论。
- 不投毒依赖包，不触发生产 CI/CD，不利用泄露凭据访问非授权系统。

## 阶段二：认证、权限和对象模型深挖

重点对象：

```text
userId, uid, accountId, orgId, tenantId, projectId, orderId, fileId,
documentId, invoiceId, roleId, permissionId, shopId, deviceId
```

验证原则：

- 只用自有测试账号或用户提供的测试账号。
- A/B 越权必须至少两个授权账号；无第二账号时记录为受限，不伪造结论。
- 读接口优先，写接口必须可回滚且必要。
- 只使用少量已知对象样本，不批量枚举 ID。
- 去 token、换 token、换对象 ID、换租户字段、换 HTTP 方法、低权限访问管理接口都要记录请求和响应差异。

认证专项补充（与 `auth-sec` 配合）：

- 2FA/MFA 绕过：登录态在二次验证前是否已下发、二次验证接口能否被跳过/重放、备份码/记住设备逻辑是否可滥用、强制开启 MFA 后旧 session 是否失效。
- OAuth/SSO：`redirect_uri` 校验、`state` 缺失或可预测、授权码复用、scope 越权、隐式流 token 泄露、`prompt`/`response_mode` 篡改、confused deputy。
- 会话管理：登出/改密后 session 与 token 是否吊销、并发会话策略、JWT 算法混淆与 `none`、kid 注入、密钥强度线索（不爆破真实密钥）。
- 账号枚举与重置：注册/登录/找回的响应差异、重置 token 熵与有效期、token 与账号绑定、host header 注入污染重置链接。

## 阶段三：高价值功能链深挖

优先路径：

1. **API 越权链**：登录态接口 -> 去 token -> 换对象 ID -> 换租户/用户字段 -> 低权限访问管理接口。
2. **认证链**：验证码绑定、验证码复用、账号枚举、找回密码 token、登录态提前下发、OAuth state/redirect_uri、MFA 绕过。
3. **上传链**：accept/store/process/serve 四阶段，验证公开访问、预览、处理器、越权读写。
4. **文件链**：download/preview/export 参数，证明可控路径、跨用户文件访问或敏感文件风险即停。
5. **SSRF 链**：证明服务端可请求、可达内网或 metadata 风险即停，不扩大内网扫描。
6. **CORS 链**：任意 Origin + credentials + 敏感 API 浏览器可读或可执行低影响写。
7. **网关/后台链**：401/403 差异、内部服务名、管理 API、低权限只读访问、Header 信任边界。
8. **源站链**：固定 Host/SNI 可访问真实业务，证明可绕过预期 CDN/WAF 或敏感 vhost 即停。
9. **业务逻辑链**：优惠券、订单、库存、审批、配额、邀请、试用、状态机绕过。
10. **客户端注入链**：输入回显/富文本/postMessage/模板渲染 -> 同源敏感操作 -> 自有账号自证（见下节）。
11. **缓存链**：未键入参数/路径混淆 -> 缓存投毒或缓存欺骗 -> 跨用户内容或敏感页面缓存（见下节）。
12. **竞态链**：一次性资源/额度/状态机 -> 并发触发 -> 重复领取/超额/状态错乱（见下节）。

## 现代 Web 与客户端攻击面

这是高产但服务端思维容易忽略的一块。全部以**自有账号、自有回连、自证浏览器上下文**为前提，禁止在真实用户上触发。

### XSS（反射/存储/DOM）

- 定位所有输入回显点：URL 参数、表单、header、富文本、文件名、错误信息、JSON 被当 HTML 渲染处、模板插值。
- 反射型：用唯一无害标记串确认上下文（HTML body / 属性 / JS 字符串 / URL / CSS），再判断能否突破上下文。
- 存储型：在自有账号的可控字段注入标记，验证渲染位置与受众边界；**只在自己能看到的页面验证执行，不投放到会渲染给真实用户的公共位置**。
- DOM 型：审计前端 source/sink（`location`、`postMessage`、`innerHTML`、`document.write`、框架危险绑定），用本地或自有页面复现。
- 影响证明上限：弹出自有标记、读取自有 cookie/CSRF token、调用一次自有账号的低影响同源接口即可，**不窃取真实用户会话、不挂载持久 payload**。
- 配套审计 CSP（缺失、`unsafe-inline`、可绕过的白名单、JSONP/AngularJS gadget），作为 XSS 影响放大或缓解的说明。

### postMessage 与跨窗口通信

- 列出所有 `addEventListener('message')` 监听器，检查是否校验 `event.origin` 与 `event.source`。
- 验证不校验 origin 的监听器能否被任意页面驱动敏感动作或写入 DOM，用自有外部页面做最小 PoC。

### 原型链污染（Prototype Pollution）

- 关注接收 JSON 并做深合并/递归赋值的接口与前端库（`lodash.merge`、`$.extend`、查询字符串解析器、配置合并）。
- 用 `__proto__` / `constructor.prototype` 键探测污染，观察是否影响后续逻辑分支、gadget（模板、命令拼接、属性默认值）。
- 服务端污染证明到“可影响全局对象属性并改变后续行为”即停；客户端污染证明可触达 DOM XSS 或权限判断 gadget 即停。

### Web 缓存投毒与缓存欺骗

- 缓存投毒：识别进入响应但未进入缓存键的输入（`X-Forwarded-Host`、`X-Forwarded-Scheme`、未键入查询参数、`Accept`/`Accept-Encoding` 行为差异），验证能否把恶意/异常内容写入共享缓存。
- 缓存欺骗：构造让动态敏感页面被当静态资源缓存的路径（`/account.php/nonexistent.css` 类混淆），验证敏感响应是否落入可被他人取到的缓存。
- **强约束**：投毒只用自有标记、最小 payload，证明“可污染共享缓存键/可缓存敏感响应”即停；**立即记录受影响缓存键并通知厂商清理，绝不投放真实恶意内容、不长期占用缓存、不影响真实用户访问**。这类验证天然有外溢风险，必要时先报备或仅做理论证明 + 单次受控验证。

### HTTP 请求走私 / Desync

- 当存在多层代理/CDN-源站架构时，关注前后端对 `Content-Length` 与 `Transfer-Encoding` 的解析差异（CL.TE / TE.CL / TE.TE / CL.0）。
- **最高优先级是低影响**：使用自有探测请求、配合明确超时差异或自有标记验证“存在前后端解析分歧”即停。
- 严禁队列投毒影响真实用户请求、严禁缓存中毒扩散、严禁高频发包。这类漏洞影响易失控，证明分歧成立后即转“受限未验证 + 建议厂商内部环境复现”，不在生产追求完整利用。

### XXE 与 XML 攻击面

- 关注接收 XML、SVG、SOAP、SAML、Office 文档（DOCX/XLSX/PPTX 解包）、RSS/Atom 的接口。
- 用自有 canary 外部实体验证解析器是否拉取外部实体（OOB），证明可外连或可读取**自有 canary 文件**即停；不读取系统敏感文件，不发展为 SSRF 内网扫描。

### SSTI（模板注入）

- 在用户输入进入服务端模板渲染处（邮件模板、报表、文档生成、自定义页面）测试模板语法回显。
- 用数学表达式/对象探测确认引擎与是否求值，证明“服务端模板可求值”即停；不执行系统命令、不读敏感文件。

### 不安全反序列化

- 识别序列化数据载体（cookie、隐藏字段、缓存、消息队列、Java/PHP/.NET/Python 特征串、`viewstate`、`__VIEWSTATE`、`O:`/`rO0`/`AC ED` 等指纹）。
- 仅做指纹与可控性判断、配合版本/库的公开 advisory 给出风险结论；不构造 RCE gadget chain 在生产执行。证明“可控反序列化输入 + 已知不安全库/版本”即可形成强线索，执行验证须有明确授权且仅用最小无害 canary。

## 竞态条件现代手法

竞态是高危但被低估的类目，且现代手法已超越“多线程并发”。

- 优先目标：一次性优惠券/兑换码、限领/限购、库存扣减、提现/退款、邀请额度、试用开通、状态机单向流转、限速/限次校验。
- **单包攻击（single-packet attack）**：对 HTTP/2 目标，将多个请求的最后一帧同时发出，消除网络抖动，是检测“检查-使用”窗口竞态的现代主力手法（Turbo Intruder 等工具的 single-packet 模式）。HTTP/1.1 目标用 last-byte 同步。
- **限影响**：仅用自有账号、自有可回滚资源做小批量（个位数到十几个）并发验证，证明“同一资源被重复消费/状态越界”即停。
- 严禁对真实库存、真实他人资源、支付清结算做并发轰炸，严禁把竞态发展成资源耗尽/批量薅取。证明窗口存在后，影响上限用计数与单次复现说明，不实际造成业务损失。

## GraphQL 深度

GraphQL 是独立攻击面，常承载大量隐藏对象与越权。

- introspection：尝试拉取 schema（开启时直接获取全部类型/字段/mutation；关闭时用字段建议、错误信息、常见命名推断）。
- 隐藏能力：枚举未在前端使用的 query/mutation、敏感字段（`role`、`isAdmin`、`email`、`token`、内部备注），按 BOLA/BFLA 思路验证授权。
- 别名与批量：用 alias 在单请求内重复同一查询，可被滥用于绕过限速、放大枚举或竞态——**仅做小规模存在性证明，不批量化**。
- 嵌套深度/复杂度：审计是否缺少深度/复杂度限制（DoS 风险），**只做理论判断与极小样本提示，绝不发起耗尽型查询**。
- 注入与透传：GraphQL 参数最终落到 SQL/NoSQL/OS 时同样可能注入，按对应专题低影响验证。

## 工具链编排参考

工具服务于阶段衔接，不把工具输出直接当漏洞结论。

| 阶段 | 工具类型 | 目的 | 输出 | 下一步 |
|---|---|---|---|---|
| 资产发现 | `subfinder/amass` -> `httpx` -> 证书/被动 DNS | 扩展 in-scope 主机并确认存活 | 存活资产、标题、技术栈、状态码 | 进入 JS/API 提取和高价值入口分流 |
| 子域接管 | `dnsx` + CNAME 解析 + 接管指纹库 | 发现悬挂 DNS 与可接管子域 | 子域、CNAME、第三方服务、指纹 | 指纹级确认即停，交厂商修复 |
| 历史与公开面 | `waybackurls/gau`、搜索引擎、公开文档检索 | 找旧接口、备份、参数、历史路径 | URL、参数、文件路径 | 去重后低速验证，避免全量刷接口 |
| Secret/仓库 | `truffleHog/gitleaks`、公开 Git 平台搜索 | 发现公开泄露和 CI/CD 线索 | 脱敏线索、文件位置、时间 | 判断 scope 和有效性，必要时申请确认 |
| Web/API 爬取 | Burp Suite、Katana、浏览器流量 | 建接口、参数、认证态资产清单 | endpoint、方法、参数、对象 ID | 进入 BOLA/Auth/File/Upload 专题 |
| 模板化扫描 | Nuclei、ZAP baseline、自定义 nuclei 模板 | 快速发现已知配置/CVE/暴露 | 候选风险和证据摘要 | 人工复核版本、配置和行为证据 |
| 参数/API | Arjun、OpenAPI/Swagger 解析、Burp 自动化 | 发现隐藏参数、版本漂移、未文档接口 | 参数和接口差异 | 小样本验证权限、注入和业务影响 |
| 客户端/XSS | 浏览器 DevTools、DOM Invader、source/sink 审计 | 定位回显点与 DOM source/sink | 上下文、可控点、sink | 自有上下文最小 PoC，证明即停 |
| 竞态 | Turbo Intruder（single-packet）、自定义并发脚本 | 验证检查-使用窗口 | 重复消费/状态越界证据 | 小批量自有资源验证，证明即停 |
| GraphQL | introspection 工具、Burp GraphQL 插件 | 还原 schema、枚举隐藏能力 | 类型、mutation、敏感字段 | 按 BOLA/BFLA/注入小样本验证 |

自动化默认低速、去重、限范围、保留原始请求响应。对核心写接口、验证码、短信、支付、订单、状态变更、缓存共享面和走私探测，禁止无差别自动化。

## ROI、时间盒与自校准

不限时不等于无限投入。每条路径都要用 ROI 决策是否继续：

```text
ROI = 历史高危产出概率 × 当前目标暴露程度 × 影响上限 ÷ 验证复杂度
```

评分参考：

| 因素 | 低 | 中 | 高 |
|---|---|---|---|
| 历史高危产出概率 | 普通静态页 | 常规表单/API | 上传、越权、导出、后台、SSRF、支付/租户、缓存、竞态、GraphQL |
| 暴露程度 | 单点弱信号 | 可访问但需条件 | 多入口、多版本、认证态可复现 |
| 影响上限 | 硬化项 | 单用户/单对象 | 跨用户、跨租户、敏感数据、执行、源站绕过、共享缓存 |
| 验证复杂度 | 需额外授权/账号 | 需少量样本 | 当前可低影响验证 |

建议时间盒：

- 单条弱信号：30-60 分钟无新增证据则降级归档。
- 单条高价值路径：2-4 小时仍缺关键前置条件则记录阻塞并切换。
- 单个资产面：完成威胁假设、端点清单、认证闭环、高价值功能分流后再换面。
- 重新升优先级条件：获得第二账号、验证码、测试数据、平台授权、源码线索、新资产或新接口版本。

### ROI 自校准

“历史高危产出概率”不应是固定拍脑袋值，而要随个人/团队真实战绩更新。每次任务结束把结果写入 `agent/retrospectives/index.md`，并维护以下指标，让权重逐渐贴近现实：

```text
按漏洞类目统计：
- 提交数：
- accepted / duplicate / N-A 比例：
- 平均奖励等级：
- 平均验证耗时：
- 误报率（自判有效但被判无效）：
按资产类型统计：
- 高危命中率：
- 平均覆盖到出洞的时间：
```

校准规则：

- accepted 率高、奖励高、耗时低的类目，调高其“历史高危产出概率”权重，下次优先排前。
- duplicate 率高的类目说明面太“卷”，在拥挤项目里降权、在冷门项目里维持。
- 误报率高的类目，强制在 ROI 评估前追加“行为证据是否已具备”的检查项。
- 每完成 5-10 个项目，回看权重与实际产出是否背离，显著背离则重排优先级模板。

量化停止信号：

- 连续两轮复盘没有新增资产、端点、权限差异或可组合条件。
- 高价值路径全部卡在同一外部条件，且无法由低影响手段补齐。
- 剩余发现只能形成安全头、版本猜测、普通信息泄露等低收益硬化项。
- 继续验证将触碰平台红线或需要额外报备。

## 阶段四：攻击链组合

每条线索都按链路记录：

```text
线索：
单点风险：
可组合条件：
已验证证据：
缺失证据：
最小下一步：
平台红线检查：
当前状态：
```

优先组合：

```text
API 信息泄露 + 对象 ID + BOLA
上传公开访问 + 预览/处理器 + XSS/XXE/SSRF/SSTI
CORS + Cookie-only API + 敏感读取
后台入口 + 401/403 差异 + 低权限 API
源站 IP + Host/SNI + WAF/CDN 绕过
Swagger/source map/GraphQL introspection + 隐藏接口 + 未授权
找回密码/OAuth + token/state 缺陷 + 账号接管
找回密码 + Host header 注入 + 链接劫持
公开文件/附件 + 隐藏路径/对象枚举 + 批量导出缺陷
反射 XSS + CSP 缺失 + 同源敏感接口
缓存欺骗/投毒 + 敏感页面 + 跨用户读取
原型链污染 + 危险 gadget + RCE/权限绕过线索
竞态窗口 + 一次性资源 + 重复消费
子域接管 + Cookie 作用域/OAuth 白名单 + 会话/凭据风险
```

不要把低危和中危孤立处理。所有低风险、信息泄露和受限线索都要尝试组合，并记录为什么能或不能升级。

## 阶段性复盘节奏

不限时任务每完成一个阶段、每发现一批新资产、每条主线受阻后，更新一次：

```text
当前最高价值路径：
已证明事实：
失败路径：
误报判断：
剩余高收益方向：
需要人工配合：
是否需要平台报备：
下一轮优先级：
```

如果尚未发现高危或严重风险，不得直接结束。先确认高收益方向是否已覆盖，未覆盖则继续深挖。

## 合规影响证明技巧

证明目标是让平台和厂商理解真实风险，不扩大影响。

| 场景 | 低影响证明 | 明确禁止 |
|---|---|---|
| SSRF | 使用自有 canary 域名/回调地址证明服务端可请求；用少量固定内网候选或 metadata 路径证明可达性；记录响应差异、DNS/HTTP 回连和时间差异 | 大范围内网扫描、利用 SSRF 攻击内网服务、读取云凭据正文、仅用 DNSLog 当唯一证明 |
| RCE | 在明确授权允许验证执行能力时，仅使用 `id`、`whoami`、`hostname`、写入自有无害 canary 文件等最小命令；证明可执行即停 | 反弹 shell、下载执行文件、读取敏感文件、持久化、提权、横向移动 |
| 数据泄露 | 用最少自有样本、计数字段、列表总数、首尾少量非敏感字段、对象边界差异证明批量风险 | 拖库、批量导出、保存真实用户隐私、绕过业务目的访问大批数据 |
| 越权 | 使用两个自有或授权测试账号交叉验证 BOLA/BFLA，保留 A/B 对照请求、状态码、对象归属和字段差异 | 触碰真实用户数据、批量枚举 ID、对真实对象做不可回滚写入 |
| 文件读取 | 读取非核心通用证明文件或自有上传 canary 文件；能证明路径控制即可停止 | 打包源码、读取配置密钥、读取业务数据文件 |
| XSS | 在自有账号/自有页面弹出唯一标记、读取自有 cookie/token、调用一次自有同源低影响接口 | 在公共/真实用户可见处投放、窃取真实用户会话、挂载持久化 payload |
| 缓存投毒/欺骗 | 自有标记 + 最小 payload 证明可污染共享键或缓存敏感响应，立即记录受影响键 | 投放真实恶意内容、长期占用缓存、影响真实用户访问 |
| 请求走私 | 自有探测请求 + 超时/标记差异证明前后端解析分歧即停 | 队列投毒真实请求、缓存扩散、高频发包、完整利用 |
| 竞态 | 自有可回滚资源小批量并发，证明重复消费/状态越界，用计数说明影响上限 | 对真实库存/支付/他人资源并发轰炸、批量薅取 |
| 子域接管 | 指纹级确认悬挂记录可被接管即停 | 实际注册/占用第三方资源、夺取子域 |

无法在红线内充分证明时，将状态标为“受限未验证”，写清缺失授权、所需测试数据和建议厂商内部验证方式。

## 证据数据生命周期与安全

挖掘过程会接触越权样本、SSRF 回显、文件读取内容、token、PII 片段等敏感数据。这些数据的处理与“不拖库”同等重要。

- **最小化采集**：只保留证明风险所必需的最小片段；能用计数/字段名/对象边界说明的，不保存真实内容；PII 一律脱敏（保留可证明性，遮蔽具体值）。
- **本地隔离**：证据集中放在任务目录，与日常环境隔离；含敏感片段的文件单独标注。
- **加密存储**：含 token、凭据、PII、内网信息的证据文件本地加密保存，不上传到无关云盘或第三方服务。
- **传输与提交**：仅通过平台/厂商指定通道提交；报告中嵌入脱敏后的关键请求/响应，不附带原始全量数据；canary 与回连地址使用自有可控资源。
- **保留与销毁**：明确证据保留期（通常到漏洞确认/修复/赏金结算后约定期限），到期或任务关闭后按规则销毁原始敏感数据，仅保留脱敏复盘摘要。
- **凭据卫生**：测试账号、API token、自有 canary 服务在任务结束后轮换或下线，避免遗留可被滥用的入口。

在任务复盘中记录：本次接触了哪些敏感数据、如何脱敏、存放与加密方式、销毁计划与时间。

## 证据固化

每条候选漏洞至少记录：

```text
标题：
目标：
平台 scope 依据：
类型：
前置条件：
最小验证步骤：
关键请求：
关键响应：
影响：
未执行的危险动作：
停止点：
数据处理：采集了什么 / 如何脱敏 / 销毁计划
修复建议：
状态：已确认 / 受限未验证 / 排除
```

正式漏洞归档或报告中，证据摘要必须自包含，不能只给证据文件路径。记录请求方法、路径、认证状态、HTTP 状态、关键响应字段、对照结果、复现条件、验证边界和影响判断。

## 报告与平台沟通

风险评级：

- 先按平台/SRC 自有标准判断奖励和等级，再用 CVSS 3.1/4.0 作为辅助说明。
- CVSS 要说明 Attack Vector、Privileges Required、User Interaction、Scope、Confidentiality/Integrity/Availability 的取值理由。
- 平台标准与 CVSS 冲突时，以业务影响、可利用条件、影响范围和平台规则解释争议点。

标题规范：

```text
[资产/模块] + [漏洞类型] + [影响对象] + [业务影响]
示例：商户后台订单详情接口 BOLA 导致跨商户读取订单与收货信息
示例：文件预览接口 SSRF 可访问内网 HTTP 服务并返回响应差异
示例：账户页缓存欺骗导致他人敏感信息被缓存读取
```

复现步骤黄金标准：

```text
环境：
账号/角色：
前置条件：
步骤：
预期结果：
实际结果：
关键请求/响应：
影响声明：
停止点：
修复建议：
```

降级或无法复现应对：

- 提供完整前置条件、账号角色、时间窗口、请求顺序、必要 Header/Cookie、对象归属和对照组。
- 说明是否依赖缓存、地域、灰度版本、租户配置、权限开关、HTTP 版本或一次性状态。
- 如平台降级，补充可组合攻击链、影响上限、批量风险证明方式和为何没有继续扩大验证。

多漏洞提交决策：

- 同一根因、同一修复点、同一资产族：倾向合并提交，突出影响范围。
- 不同根因、不同权限边界、不同业务影响：倾向拆分提交。
- 单点低危可与攻击链合并；独立可复现的中高危不要被低危噪声稀释。

## 对抗性与防御感知

授权测试也要考虑蓝队告警和业务稳定性。

可能触发的告警：

- WAF/网关：注入特征、路径穿越、异常编码、非常规方法、批量 404、User-Agent 异常、走私特征 header。
- RASP/应用审计：命令执行探测、模板注入、反序列化、文件读取关键字。
- 身份风控：异常登录、异地登录、频繁失败、验证码请求、账号锁定、OAuth 异常 state。
- API 限速：短时间高频请求、对象 ID 递增访问、并发状态变更、GraphQL 批量别名。

降低误触发原则：

- 使用稳定 UA、低频请求、明确测试账号、少量样本和可解释路径。
- 对验证码、短信、邮箱、登录失败、支付、订单、库存、缓存共享面、走私探测等接口设置更严格手动门槛。
- 被封禁、账号锁定或触发风控时停止该路径，记录时间、请求、状态和需要平台白名单/测试窗口。

WAF/CDN 基础判断框架：

- 出现同参数不同编码响应差异、边缘节点与源站响应差异、HTTP/1.1 与 HTTP/2 行为差异、Header 信任差异时，说明可能存在解析差异。
- 只记录可疑差异并做低影响确认；不要发展成通用绕过手册，不做破坏性分块、走私、协议降级或高频 payload 轰炸。
- 如果怀疑 WAF/CDN 阻断导致误判，优先寻找业务侧行为证据、源站授权验证或平台报备窗口。

## 结束条件

只有满足以下条件之一才结束：

- 已形成足够明确的高危或严重漏洞证据。
- scope 内高收益路径已系统覆盖，剩余为低收益硬化项。
- 继续验证需要平台报备、厂商授权、第二账号、验证码、测试数据或停服窗口。
- 继续验证会触碰 `规则.md` 红线。

结束时必须输出：

```text
为什么结束：
已覆盖范围：
最强发现：
未完成路径：
阻塞条件：
需要用户/平台/厂商提供什么：
下一步最可能出高危的方向：
本次敏感数据处理与销毁状态：
ROI 自校准更新项：
```

安全测试任务结束前按项目规则写入任务复盘，并同步匿名化摘要和 ROI 指标到 `agent/retrospectives/index.md`。
