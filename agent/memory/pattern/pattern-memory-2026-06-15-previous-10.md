# Pattern Memory: 2026-06-15 Previous 10 Tasks

- 类型：pattern
- batch_id：pattern-memory-2026-06-15-previous-10
- 生成日期：2026-06-15
- task_count：10
- covered_time_range：2026-06-02 至 2026-06-05
- selection_rule：在 `pattern-memory-2026-06-15-recent-10.md` 的最近窗口之前，继续按 `tasks/` 下 `2026-*` 目录名倒序选取 10 个任务目录；优先读取 `retrospective.md`，本窗口 10 个任务均有复盘；保留根目录 CTF 任务，排除 `tasks/CTF/` 子目录、非日期目录和普通维护任务。
- dominant_asset_types：赏金多根域、物流/商旅/金融/政务 Web/API、SPA 后台、API 网关、对象存储、邮件/边缘设备、云/CDN/WAF 后资产、域名资产、CTF 前端游戏。
- dominant_vulnerability_types：前端 API 情报、source map/JS 字符串数组、服务端鉴权绕过、未授权管理 API、CORS+Cookie 边界、对象存储边界、公开 API 文档边界、DWR/JSF 方法暴露、SM4/验证码/WAF 阻塞、域名劫持、CVE 阴性验证。
- overall_quality：高。多数复盘明确记录有效路径、无效路径、误报边界、阻塞材料和停止原因；样本覆盖面较广，但含一个 CTF 和多个同类赏金公开面任务，使用时应按任务类型筛选。
- main_learning_value：上一窗口的核心经验是“先用可信 DNS/CT/VHost 找到真实入口，再用前端/接口定义构建攻击面，最后用最小请求矩阵闭合边界”。高危成立通常来自服务端真实权限缺口、域名控制权异常或默认/未授权管理 API；公开配置、API 文档、CORS、source map、验证码前置、WAF 统一错误大多需要降级或材料阻塞。
- 标签：ct_dns_recon, vhost_pivot, spa_js_intel, api_gateway_mapping, frontend_auth_bypass, cors_cookie_boundary, object_storage_boundary, dwr_interface_intel, cve_negative_validation, waf_cdn_noise, captcha_block, crypto_boundary, domain_hijack, ctf_client_signature, material_block, stopping_rule
- 状态：draft

## Case Index

### CASE-01 ctf-client-signature

- 任务类型：CTF Web flag rush。
- 初始入口：前端游戏分数提交接口和混淆 JS。
- 有效路径：直接执行混淆 JS 还原自定义编码；确认签名完全由客户端计算且无服务端密钥；构造高分触发目标响应。
- 关键正向信号：已知提交接口、客户端编码函数、分数阈值。
- 关键负面信号：robots、备份、LFI/RFI、`.git` 均无结果。
- 停止点：已知接口存在时，不再优先通用路径爆破。
- 可迁移经验摘要：CTF 或弱业务签名场景中，客户端纯计算签名等同无签名；混淆代码应实际运行确认行为。

### CASE-02 new-domain-asset-recon

- 任务类型：外部资产信息收集。
- 初始入口：新注册不久的根域。
- 有效路径：可信 DNS、证书透明日志、固定 Host/SNI、前端配置文件、API 响应格式差异、JS bundle 关键词提取。
- 关键正向信号：前端 `app.config.js` 明文暴露 API 架构；不同 API JSON 风格可区分多套后端。
- 关键负面信号：subfinder 对新域 0 结果、SPA 爬虫 0 URL、WhatWeb 默认 UA 触发 WAF。
- 停止点：资产收集完成后转渗透测试材料，不继续依赖单一被动工具。
- 可迁移经验摘要：新域资产发现优先 CT 日志和前端配置；被动 DNS 工具 0 结果不是资产不存在。

### CASE-03 hotel-member-cors-cookie

- 任务类型：多根域赏金公开面、会员/商旅/活动 API。
- 初始入口：CT/DNS、首页链接、JS bundle、登录/个人中心链路。
- 有效路径：CORS 与 Cookie 行为联动分析；登录同步接口检查父域、属性拼接、SameSite；活动 API 用解析类接口做无效参数边界。
- 关键正向信号：任意 Origin + ACAC、父域 Cookie 写入、认证态接口、商旅/B2B 前端路由。
- 关键负面信号：未登录 401、空订单/发票/邀请列表、公开品牌字典、健康 JSON、边缘设备无版本。
- 停止点：没有 fresh A/B、真实 Cookie store、非空对象或可控活动参数时停止升级。
- 可迁移经验摘要：认证态 CORS 高危升级要同时证明真实浏览器 Cookie 自动发送和高影响数据对象；人工 SameSite 对照只证明条件。

### CASE-04 finance-public-boundary

- 任务类型：多根域金融/商家后台/对象存储赏金测试。
- 初始入口：被动子域、HTTP 存活、页面标题、前端 JS、高价值路径矩阵。
- 有效路径：大型 bundle 本地抽 URL/path 和 secret-like；匿名 session 回放到敏感接口；对象存储按 listing、OPTIONS、PUT/GET/DELETE 分层。
- 关键正向信号：商家/供应商菜单、对象存储域、邮件/Autodiscover/OWA 命名资产、第三方 SaaS 初始化数据。
- 关键负面信号：SPA fallback、公开 authConfig/证书/菜单路由、`ACAO:*+ACAC` 通配、上传场景名。
- 停止点：无账号、无可回滚对象时，不做对象存储写入/删除；无敏感响应不升级。
- 可迁移经验摘要：对象存储和匿名 session 要按证据层评级；初始化 token、菜单和公开配置不是登录态。

### CASE-05 logistics-public-auth-boundary

- 任务类型：物流 Web/API/移动端/后台公开面和报告整理。
- 初始入口：可信 DNS、固定 Host/SNI、公开静态包、开放平台文档、移动端入口。
- 有效路径：离线 API 情报提取；无 token/伪 token/空体/假对象/最小分页矩阵；开放平台文档配对真实网关边界。
- 关键正向信号：用户中心、网点后台、运输控制、自动分拣、开放平台、对象存储和 AI 类接口族。
- 关键负面信号：公开 API 文档、登录配置、OAuth AppKey、SDK 参数、客户端下载链接无法单独升级。
- 停止点：无测试账号、AppKey/Secret、官方包或可回滚对象时停止深挖。
- 可迁移经验摘要：开放平台“文档可读”与“API 可调用”是两层证据；伪造 AppKey 被注册关系拦截时应降级。

### CASE-06 gov-health-api-crypto-boundary

- 任务类型：政府医保 Web/API 赏金测试。
- 初始入口：证书透明日志、混淆 JS、网关路径。
- 有效路径：CT 子域发现、混淆 JS 字符串数组提取、路径前缀映射后端拓扑、响应字节数差异定位未授权端点、GET/POST 方法差异测试。
- 最终结果：中低危若干，高危受 SM4 加密、Token 和无账号阻塞。
- 关键正向信号：API 路径数组、不同路径前缀的 Spring/Tomcat/Gateway 响应差异、POST 可返回业务响应。
- 关键负面信号：Swagger UI 200 但 api-docs 404、状态 200 但 body 为统一异常、弱口令接近锁定。
- 停止点：SM4 登录和 token 获取未突破时，不继续凭据尝试；转 JS 逆向或测试账号。
- 可迁移经验摘要：国密/自定义加密是 API 测试的硬边界；先逆向加密或拿账号，再做业务越权。

### CASE-07 passive-domain-hijack

- 任务类型：授权资产/后台全面渗透，原始 IP 不可达。
- 初始入口：原始 IP、被动搜索、关联域名。
- 有效路径：原始 IP 不可达后转被动资产；CT/URLScan/SEO/WHOIS/RDAP 交叉；正确 Host header 突破 VHost 403；JS 内容确认异常用途。
- 最终有效发现：域名控制异常/域名劫持高危。
- 关键正向信号：域名解析到可达不同 IP、Host 403->200、页面内容与组织业务不符、注册归属确认。
- 关键负面信号：`nmap -Pn` 的 “Host is up” 误导、默认 nginx 404 泛 200、第三方异常页面不属于目标。
- 停止点：域名劫持证据闭合后停止端口穷扫。
- 可迁移经验摘要：原始 IP 全不可达时，被动资产和 VHost 可能比端口扫描更快找到高危。

### CASE-08 media-admin-frontend-auth-bypass

- 任务类型：中危优先 Web/API 测试。
- 初始入口：多个域名、前端代码、API 路由、CDN 多节点。
- 有效路径：直接调用服务端 API 绕过前端 JS 登录重定向；ThinkPHP 错误指纹；CSRF token 对证明端点可达；多 DNS 节点固定解析。
- 最终有效发现：未认证管理 API 泄露用户/角色/个人信息高危，另有密码重置候选和信息项。
- 关键正向信号：前端只做跳转检查、`GetGridJson` 类服务端 API 直接返回数据、错误消息暴露框架命名空间。
- 关键负面信号：公开营销 API、CORS `*` 且敏感 API 需 token、公开时间戳 API、视图错误不等于数据访问。
- 停止点：写操作和密码重置需要测试账号/授权窗口；高危读泄露已闭合即报告。
- 可迁移经验摘要：前端路由/重定向不是鉴权；后台 API 必须直接 no-token 调用确认服务端边界。

### CASE-09 tp6-cve-negative-validation

- 任务类型：授权 CVE LFI/WAF 绕过验证。
- 初始入口：ThinkPHP 版本/CVE 线索。
- 有效路径：Cookie/POST/Header 三通道并行；不存在语言包对照；body MD5 去重；URL query 层 WAF 单独确认。
- 最终结论：多语言中间件未启用，CVE 不可利用。
- 关键正向信号：全部响应 MD5 一致，语言参数完全被忽略。
- 关键负面信号：文档说明的 Cookie `think_lang` 需要中间件注册；pearcmd 值绕过 WAF 但应用不处理。
- 停止点：证明中间件未注册后停止更多 payload 枚举。
- 可迁移经验摘要：CVE 阴性闭环要证明前置组件未启用，而不是只证明单个 payload 失败。

### CASE-10 cargo-api-interface-intel

- 任务类型：多域物流/订舱 Web/API 赏金测试。
- 初始入口：176+ 子域、DWR/JSF/Oracle/SSO/WMS/API 网关。
- 有效路径：DWR interface 提取业务方法名；SPA/CDN chunk 构建 API 矩阵；gzip 空体解压确认；Keycloak/Spotfire/Cloudflare/451 分层归档。
- 最终结果：中低危/信息项为主，高危均被认证、验证码、WAF、IP 限制或 VPN 阻塞。
- 关键正向信号：DWR 方法名和参数结构、统一验证码服务配置、Service Mesh 网关统一 session 过期响应。
- 关键负面信号：DWR interface 不等于方法可调用、`; /` 变体返回框架错误页、gzip 20 字节解压为空。
- 停止点：无测试账号、验证码配合、WAF 白名单、VPN 或可回滚对象时停止公开匿名面扩张。
- 可迁移经验摘要：接口定义文件是攻击面情报，不是漏洞证据；HTTP 200 必须解压和读 body。

## Cross-Case Pattern Memory

### PAT-001 CT/DNS/VHost Before Scanning

- pattern_type：ct_dns_recon
- source_cases：CASE-02, CASE-05, CASE-06, CASE-07, CASE-08, CASE-10
- singleton：false
- trigger_signals：新域、系统 DNS Fake-IP、原始 IP 不可达、CDN/WAF、403 VHost、被动子域不足。
- decision_rule：IF 目标解析或可达性不稳定 THEN 先做可信 DNS/DoH、证书透明日志、URLScan/搜索引擎、WHOIS/RDAP、固定 Host/SNI 和 VHost 对照 BUT 不把 `-Pn`、CDN IP 或默认页面当真实服务证据。
- recommended_next_steps_low_impact：记录真实 A/CNAME、Host/SNI 响应、body hash、业务标题、证书 SAN。
- evidence_required：可信解析、Host header 对照、组织归属、非默认页面内容。
- false_positive_risks：Fake-IP、泛 200 默认页、CDN/WAF 页面、跨运营商过滤。
- stop_conditions：真实入口和归属闭合；或确认公网不可达并转材料/VPN。
- severity_hint：recon_priority
- confidence：0.91
- memory_statement：上一窗口多次证明，DNS/CT/VHost 基线比盲扫更能决定后续质量。

### PAT-002 Frontend Intelligence Must Become Server Boundary

- pattern_type：spa_js_intel
- source_cases：CASE-02, CASE-04, CASE-05, CASE-06, CASE-08, CASE-10
- singleton：false
- trigger_signals：SPA bundle、混淆字符串数组、`app.config.js`、DWR interface、API 文档、菜单路由、OAuth/AppKey 配置。
- decision_rule：IF 前端或接口定义暴露 API/方法/配置 THEN 将其用于攻击面建模和最小请求矩阵 BUT 不把路径、方法名、AppKey、菜单、文档可读直接写成漏洞。
- recommended_next_steps_low_impact：no-token/fake-token/空体/假对象/最小分页；只读方法优先；写入/发信/导出停在材料需求。
- evidence_required：服务端响应、认证状态、业务数据或业务码、邻近接口对照。
- false_positive_risks：mock、公开文档、SDK 参数、方法名不可调用、前端死代码。
- stop_conditions：服务端边界已归类；继续需账号、AppKey、对象或授权窗口。
- severity_hint：info_to_high_if_server_accepts
- confidence：0.92
- memory_statement：前端情报是地图，服务端响应才是证据。

### PAT-003 Direct API Beats Frontend Login Redirect

- pattern_type：frontend_auth_bypass
- source_cases：CASE-08, CASE-05, CASE-10
- singleton：false
- trigger_signals：后台前端有登录跳转、`GetGridJson`/列表接口、菜单路由、前端判断登录态。
- decision_rule：IF 登录检查看起来发生在前端 THEN 直接对服务端 API 做 no-token/fake-token 只读调用 BUT 不触发写操作或真实数据变更。
- recommended_next_steps_low_impact：优先列表/详情只读接口；page=1/limit=1；对照前端路由和 API 路径。
- evidence_required：无认证请求、返回用户/角色/业务对象、邻近接口认证差异。
- false_positive_risks：视图错误、公开营销数据、空列表、字段校验先于鉴权。
- stop_conditions：数据泄露闭合即停；写接口等待账号/授权窗口。
- severity_hint：confirmed_high_when_sensitive_data
- confidence：0.86
- memory_statement：前端跳转不代表服务端鉴权，后台列表 API 是高收益验证点。

### PAT-004 CORS/Cookie/Object Storage Layered Rating

- pattern_type：cors_cookie_boundary
- source_cases：CASE-03, CASE-04, CASE-05
- singleton：false
- trigger_signals：ACAC、Origin 反射、`ACAO:*`、父域 Cookie 设置、SameSite、对象存储 listing/OPTIONS/PUT/GET。
- decision_rule：IF CORS、Cookie 或对象存储存在异常 THEN 按层拆证：预检/响应头/真实浏览器凭据/敏感响应/对象读写 BUT 不用单一头部或公开配置定中高危。
- recommended_next_steps_low_impact：OPTIONS、无登录/认证态小样本、Cookie store 证据、listing 小样本、HEAD/Range、不做真实写入。
- evidence_required：浏览器是否自动带凭据、敏感数据、对象私有性、可回滚对象证据。
- false_positive_risks：`ACAO:*` 无可读凭据、负载均衡 Cookie、公开字典、统一空列表、对象存储静态站。
- stop_conditions：缺少账号/对象/真实 Cookie 时转候选或材料阻塞。
- severity_hint：low_to_high_by_layer
- confidence：0.88
- memory_statement：CORS、Cookie 和对象存储必须分层评级；头部异常只是入口。

### PAT-005 Body Semantics Over Status Code

- pattern_type：waf_cdn_noise
- source_cases：CASE-04, CASE-06, CASE-09, CASE-10
- singleton：false
- trigger_signals：HTTP 200/206、gzip 小 body、统一错误页、Swagger UI、SPA fallback、WAF challenge。
- decision_rule：IF 状态码看似成功 THEN 必须读取 body、解压 gzip、计算 body hash、检查业务码和真实内容 BUT 不把状态码或 UI 壳当数据访问。
- recommended_next_steps_low_impact：body hash 去重、gzip 解压、真实 404 对照、业务码分类、max-bytes 截断。
- evidence_required：响应体语义、大小、hash、解压内容、业务字段。
- false_positive_risks：Swagger UI 无 api-docs、空 gzip、框架错误页、Next/build manifest、统一异常。
- stop_conditions：确认 fallback/空体/统一错误后停止同类路径。
- severity_hint：noise_filter
- confidence：0.90
- memory_statement：200 不是证据，body 语义才是证据。

### PAT-006 Crypto/Captcha/WAF Are Material Boundaries

- pattern_type：crypto_boundary
- source_cases：CASE-06, CASE-10, CASE-03, CASE-05
- singleton：false
- trigger_signals：SM4/自定义加密、滑块验证码、SSO、WAF 451/418/403、IP 白名单、账号锁定。
- decision_rule：IF 关键流程被加密、验证码、WAF 或白名单阻塞 THEN 记录阻塞材料和下一步最小验证，不继续高频猜测或凭据测试。
- recommended_next_steps_low_impact：逆向加密逻辑、索取测试账号/验证码关闭/白名单/VPN、只保留无副作用请求。
- evidence_required：阻塞响应、前端加密线索、锁定策略、需要的材料。
- false_positive_risks：把无法构造请求写成系统安全；把 WAF 拦截当目标阴性。
- stop_conditions：所有高收益匿名方向已分类，继续需要外部材料。
- severity_hint：blocked
- confidence：0.87
- memory_statement：加密和验证码不是继续硬打的理由，而是转材料和逆向的明确边界。

### PAT-007 CVE Negative Closure By Preconditions

- pattern_type：cve_negative_validation
- source_cases：CASE-09, CASE-06, CASE-10
- singleton：false
- trigger_signals：框架版本/CVE、WAF 绕过、Actuator、Swagger、ThinkPHP/Oracle/WebLogic 等组件线索。
- decision_rule：IF 验证 CVE 失败 THEN 优先证明必要前置条件是否存在，如中间件启用、api-docs 可读、actuator 暴露、方法可调用 BUT 不无限变换 payload。
- recommended_next_steps_low_impact：不存在资源/参数对照、MD5 去重、组件前置路径、小样本模板。
- evidence_required：前置条件阴性证据、payload 被忽略或认证/WAF 阻塞的证据。
- false_positive_risks：只测一个 payload、只看版本、UI 壳误判文档泄露。
- stop_conditions：前置条件明确不存在或不可达。
- severity_hint：negative_validation
- confidence：0.84
- memory_statement：CVE 阴性不是 payload 不响，而是前置条件被证伪。

### PAT-008 Passive Pivot For Unreachable Targets

- pattern_type：vhost_pivot
- source_cases：CASE-07, CASE-02
- singleton：false
- trigger_signals：原始 IP 全 filtered/timeout、跨运营商不可达、目标给的是 IP 而非业务域。
- decision_rule：IF 原始目标不可达 THEN 立即转被动资产、关联域名、证书、搜索引擎、URLScan 和 VHost，而不是继续全端口等待。
- recommended_next_steps_low_impact：确认组织归属；尝试 Host header；分析页面 JS/跳转；记录不可达边界。
- evidence_required：关联关系、可达域名、Host 变体响应、业务或异常内容。
- false_positive_risks：同 IP 多租户无归属、默认页、第三方异常站。
- stop_conditions：找到可达关联入口或确认需要 VPN/网络接入。
- severity_hint：recon_to_high_when_hijack
- confidence：0.81
- memory_statement：不可达目标的突破常在被动资产和 VHost，不在更大的端口扫描。

### PAT-009 DWR/JSF/Interface Definition As Attack Map

- pattern_type：dwr_interface_intel
- source_cases：CASE-10
- singleton：true
- trigger_signals：DWR `.js` interface、JSF/Oracle 节点、Web Service、方法名包含 create/reset/send/export。
- decision_rule：IF interface 文件暴露方法名和参数 THEN 建立攻击面模型和材料清单 BUT 不调用副作用方法，不把方法名当可利用漏洞。
- recommended_next_steps_low_impact：只读接口定义保存；方法按读/写/发信/重置/导出分类；认证边界小样本。
- evidence_required：interface 文件、方法类别、认证响应、未调用副作用说明。
- false_positive_risks：方法名高危但 plaincall 403、需要 Session、WAF challenge。
- stop_conditions：认证边界确认；后续需要测试账号/对象/厂商窗口。
- severity_hint：attack_surface
- confidence：0.76
- memory_statement：DWR/JSF 定义是高价值路线图，但不是影响证明。

### PAT-010 Client-Side Signature And Obfuscation

- pattern_type：ctf_client_signature
- source_cases：CASE-01
- singleton：true
- trigger_signals：前端计算签名、混淆 JS、无服务端密钥、游戏/分数/提交接口。
- decision_rule：IF 签名逻辑全在客户端且无服务器密钥 THEN 通过执行 JS 还原算法并构造最小请求验证 BUT 不先做大范围路径爆破。
- recommended_next_steps_low_impact：Node/浏览器执行混淆函数；对照低分/高分；记录阈值和参数。
- evidence_required：算法行为、请求参数、服务端差异响应。
- false_positive_risks：服务端二次校验、隐藏 salt、动态 nonce。
- stop_conditions：目标响应闭合。
- severity_hint：ctf_solution
- confidence：0.80
- memory_statement：客户端无密钥签名在 CTF 和弱业务逻辑中是优先突破点。

## Immediate Draft Rules

- 新域、不可达 IP、CDN/WAF 多的任务先做可信 DNS、CT、固定 Host/SNI 和 VHost，对扫描结果先降噪。
- 前端、API 文档、DWR/JSF interface、source map 和配置文件只作为攻击面，不作为漏洞；必须转服务端最小响应。
- CORS、Cookie、对象存储、匿名 session、公开 key 按证据层拆分；没有真实敏感读取或可回滚写入就不升级。
- 状态码不能直接进入报告结论；必须读 body、解压 gzip、看业务码和 body hash。
- 加密、验证码、WAF、白名单、账号锁定是材料阻塞边界；不要用高频猜测代替测试账号、白名单或逆向。
- CVE 验证优先证明前置条件，前置条件阴性后停止 payload 变体扩张。

## Non-Applicability

- 不适用于已获得完整认证态和可回滚业务对象的深度业务逻辑测试；那类任务应优先做 A/B 权限矩阵和业务状态机。
- 不适用于需要大规模主动扫描的内网专项；本窗口经验主要来自公网公开面、CDN/WAF 后资产和低影响赏金测试。
- CTF 客户端签名经验只在签名完全客户端化且无服务端密钥时适用；真实业务系统必须额外考虑 nonce、会话绑定和服务端二次校验。
