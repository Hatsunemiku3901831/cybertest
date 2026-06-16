# Pattern Memory: 2026-06-15 Recent 10 Tasks

- 类型：pattern
- batch_id：pattern-memory-2026-06-15-recent-10
- 生成日期：2026-06-15
- task_count：10
- covered_time_range：2026-06-07 至 2026-06-13
- selection_rule：选取 `tasks/` 下按目录名排序最近的 10 个 `2026-*` 任务目录；优先读取 `retrospective.md`，缺少复盘时读取 `outputs/agent-handoff-pentest-status.md`、漏洞归档和资产清单；排除 `tasks/CTF/`、非日期目录和仅证据散落但无接手材料的目录。
- dominant_asset_types：物流/跨境业务后台、Demo/UAT 系统、API 网关、SPA 前端、开放平台、移动端下载页、云产品前端、静态后台资源、多后台/IDC 管理面。
- dominant_vulnerability_types：前端 API 情报、source map/lazy chunk 泄露、认证边界阻塞、凭据化 CORS 边界、硬编码第三方 token、静态 PII 泄露、默认凭据、WAF/CDN 噪声、开放平台/签名 URL 候选、资产优先级筛选。
- overall_quality：中高。近期任务中 6/10 以后部分目录尚无正式复盘，但接手文档和候选队列完整；多任务集中在同一行业和相近前端/API 架构，pattern 有明显可迁移价值但存在行业过拟合风险。
- main_learning_value：近期高收益不来自重复大扫描，而来自“可信 DNS/Host-SNI 基线 -> SPA/lazy/source map 离线覆盖差分 -> API family 映射 -> no-token/fake-token/空体小矩阵 -> 材料阻塞或评级降级”的闭环；一旦需要账号、对象、验证码、私有文件或白名单，应停止匿名扩张并写清下一步材料。
- 标签：spa_js_intel, source_map_gap, api_auth_matrix, material_block, waf_cdn_noise, cors_boundary, login_flow_fidelity, static_pii, mobile_static, asset_scoring, default_creds, token_leak_boundary, stopping_rule, report_quality
- 状态：draft

## Case Index

### CASE-01 logistics-public-auth-blocked-round

- 行业/资产类型：跨境物流多国后台、驿站系统、开放平台、CRM/API。
- 初始入口：多个前端登录页、子域名枚举、JS bundle、验证码/注册流程。
- 有效路径：DNS 基线、JS bundle 下载、API 端点/签名逻辑提取、source map 探测、敏感路径和 nuclei 中高危小样本、账号枚举与忘记密码流程探测。
- 关键正向信号：公开 SPA 暴露 API family、签名 header、后台路由和登录流程字段。
- 关键负面信号：CloudWAF 418、CDN SPA fallback、API 全局 `authToken`、无账号无法进入 BOLA/IDOR。
- 停止点：无账号、无业务对象、无验证码材料时停止匿名扩张；下一步转 A/B 账号和对象级矩阵。
- 可迁移经验摘要：当所有网关都统一 401/WAF/fallback 时，继续匿名扫同类路由 ROI 很低；应把材料需求写成可执行清单。

### CASE-02 logistics-yms-demovip-waf-round

- 行业/资产类型：物流 YMS、VIP demo、业务管理后台、API Gateway。
- 初始入口：存活前端、证书透明度、JS 源码分析。
- 有效路径：从 JS 找 API Gateway 和登录 DTO/参数 wrapper；对 API 端点做未认证、CORS、Actuator、穿越、SQLi、Host 头和方法覆盖小矩阵。
- 关键正向信号：API Gateway、业务系统标题、CaptchaDTO/参数 wrapper 类名。
- 关键负面信号：WAF 全拦、登录参数结构未知、CORS 无 ACAC、nuclei 0 命中。
- 停止点：登录流程未抓到浏览器真实请求前，不继续猜字段；建议用浏览器/Burp 补齐 CaptchaDTO。
- 可迁移经验摘要：登录测试必须先还原真实请求体结构，否则 500/参数错误只能说明格式不对，不能证明认证缺陷。

### CASE-03 logistics-large-api-closure-round

- 行业/资产类型：多系统物流后台、BMS/YMS/VIP/JMS、Spring Cloud Gateway、React/Vue SPA。
- 初始入口：4 个前端系统和多个 API 网关。
- 有效路径：lazy chunk 补抓、静态敏感面扫描、候选队列重建、高价值端点认证矩阵、P0/P1/P2 分批收口、剩余项材料阻塞。
- 最终有效发现：2 个中危、若干低危/信息项；大量高危候选被 401/未路由/业务无影响闭合。
- 关键正向信号：硬编码第三方 Bearer token 进入参数校验、Spring Gateway 栈泄露、公开字典/认证前置响应。
- 关键负面信号：P0 high_value 清零后剩余均需账号、对象、fileId/objectKey、可回滚文件或白名单窗口。
- 停止点：高价值匿名面无悬空项后停止扫 P3；转修复中危和索取认证态材料。
- 可迁移经验摘要：候选队列必须持续同步状态，避免“高分路由”重复探测；材料阻塞也是有效闭环。

### CASE-04 logistics-demo-sourcemap-round

- 行业/资产类型：Demo 物流系统、API 网关、开放平台。
- 初始入口：HTML 中的 JS 文件和 `.js.map`。
- 有效路径：直接追加 source map、从源码提取 API 网关、captcha/i18n 端点、authToken 认证方式和部署差异。
- 关键正向信号：source map 可下载、前端/网关分离、captcha/注册端点无需认证。
- 关键负面信号：SPA 爬虫低效、参数编码未逆向导致 500、shell 循环在环境受限时不稳定。
- 停止点：source map 只证明源码/接口暴露；无服务端敏感数据或认证绕过时按信息项/低中风险处理。
- 可迁移经验摘要：SPA 任务优先离线抓 JS/source map，胜过盲目爬虫；发现新端点后必须回到 API 边界矩阵。

### CASE-05 cloud-ai-asset-reverse

- 行业/资产类型：云产品前端、WebIM、Socket.IO、Kong 网关、公开 shareCode 流程。
- 初始入口：公开分享链接和多个 SPA 入口。
- 有效路径：下载约 10MB JS、枚举 500+ API Action、分析 WebSocket/Socket.IO 协议、识别潜在 SSRF/RCE 类 action。
- 关键正向信号：公开 bundle 中 action 名称高度语义化，能直接形成攻击面清单。
- 关键负面信号：未取得认证态 API 流量、浏览器完整交互和 Burp MCP 流量；不能把 action 名称直接定为漏洞。
- 停止点：认证后 API、SSRF、Socket.IO 绕过需要账号/浏览器流量；静态阶段只做资产测绘和候选分级。
- 可迁移经验摘要：云产品/低代码/AI 控制台的 JS action 枚举价值很高，但必须区分“危险能力存在”和“调用权限可达”。

### CASE-06 logistics-five-domain-auth-boundary

- 行业/资产类型：物流前端、API 网关、SSO、开放平台。
- 初始入口：5 个授权域名、scan pipeline quick、JS bundle。
- 有效路径：可信 DNS、固定 Host/SNI、前端 API 提取、CORS 前端/网关双层检查、验证码 bypass 客户端逻辑与服务端最小矩阵。
- 最终有效发现：低危/信息项和受限候选；无高危。
- 关键正向信号：300+ 端点、API 网关地址、认证方式、环境配置。
- 关键负面信号：CDN IP 扫描无意义、SPA fallback 200、WAF 页面伪 actuator、客户端 bypass ticket 服务端不接受。
- 停止点：P1 全部材料阻塞/降级/出 scope 后，不再匿名扩大 P3；转账号、验证码、对象、开放平台权限。
- 可迁移经验摘要：客户端验证码兼容代码必须用服务端小矩阵验证；前端能生成票据不等于认证绕过。

### CASE-07 logistics-asset-scoring

- 行业/资产类型：大量物流根域/子域、登录页、开放平台、后台、VIP 系统。
- 初始入口：200+ 条资产输入。
- 有效路径：根域分类、httpx 存活、技术栈和登录页抓取、按业务系统/状态码/WAF/页面大小/核心程度打分筛 Top 5。
- 关键正向信号：100+ 存活目标、核心业务标题、无 WAF、UAT/Demo、后台/API/开放平台语义。
- 关键负面信号：SPA fallback 200、纯官网、403 CMS、防护强的静态入口。
- 停止点：资产筛选完成后不要重复 httpx；下一步必须对 Top 目标做 JS bundle 和登录流程闭环。
- 可迁移经验摘要：资产探测阶段的产物应是“优先目标队列 + 具体攻击向量”，不是继续堆更多域名。

### CASE-08 logistics-cors-boundary

- 行业/资产类型：物流后台、SSO、API 服务、源站候选。
- 初始入口：5 个授权目标、JS 端点、子域名和历史 URL。
- 有效路径：CORS 利用评估、SSO/OIDC/SAML 探测、源站直连、服务协议验证、403 绕过、API 错误响应对照。
- 最终有效发现：1 个凭据化 CORS 中危验证中，多个低危/信息项。
- 关键正向信号：后端 API 反射 Origin 且 ACAC:true，OPTIONS 允许自定义 auth header。
- 关键负面信号：认证依赖自定义 header 而非 Cookie，无法自动跨域带 token；源站端口只 TCP 可达但协议超时。
- 停止点：无有效 token/XSS/账号态数据读取时，不把 CORS 单点拔高；源站只 TCP 握手不能报告服务未授权。
- 可迁移经验摘要：CORS 评级关键看 ACAC、凭据类型、敏感响应和可自动携带性；`ACAO:*` 多数只是低危配置观察。

### CASE-09 static-pii-mobile-followup

- 行业/资产类型：业务后台静态资源、移动下载页、APK、debug/push 端点。
- 初始入口：公开后台 HTML/JS、移动下载页。
- 有效路径：静态文件中搜索真实案件/个人字段类别，APK 静态分析补充 debug 上报和 push token 注册端点。
- 最终有效发现：公开静态资源包含单条敏感案件/个人信息，中危/高危候选。
- 关键正向信号：身份证、手机号、地址、案件编号等字段类别出现在公开静态资源。
- 关键负面信号：单条样例不足以证明批量泄露；debug 端点只暴露 RID/IP/UA 时不应过度升级。
- 停止点：立即脱敏固证；不使用泄露身份做登录；严格高危需要批量真实记录、未授权 API 或账号接管链。
- 可迁移经验摘要：静态资源审计不能只搜 API key，也要搜真实业务样例和 PII；发现后先脱敏，减少二次传播。

### CASE-10 multi-admin-default-creds

- 行业/资产类型：IDC/多后台/运维 API、LDAP/数据库/旧 Web 服务。
- 初始入口：单个后台端口及同 IP/证书/health-check 关联资产。
- 有效路径：可信 DNS + 固定 Host/SNI + 小端口识别、前端 API base 关联后台、递归懒加载 chunk、登录 POST+JSON 正确格式验证。
- 最终有效发现：默认凭据获得 superadmin JWT，高危；确认 MFA 未启用、token refresh 和大量运维数据只读访问。
- 关键正向信号：登录 API 需要 JSON body，JWT 中角色/MFA/权限字段清晰，refresh 可用。
- 关键负面信号：第一轮只用 GET 或错误 Content-Type 会漏报；公网端口/rootDSE/内网 IP 不能直接拔高。
- 停止点：确认 superadmin 和大量敏感只读数据后立即停止，不继续翻页、写操作、隧道或凭据深挖。
- 可迁移经验摘要：后台弱口令/默认凭据验证要覆盖真实方法和 Content-Type；命中高危后按停止规则固证，避免扩大影响。

## Cross-Case Pattern Memory

### PAT-001 SPA JS, Lazy Chunk, Source Map First

- pattern_type：spa_js_intel
- source_cases：CASE-01, CASE-02, CASE-03, CASE-04, CASE-05, CASE-06, CASE-07, CASE-10
- singleton：false
- trigger_signals：Vue/React/Vite/Webpack/umi/qiankun、登录页只有 SPA、API 网关域名与前端分离、`sourceMappingURL`、`rel=prefetch`、webpack runtime。
- decision_rule：IF 目标是 SPA/后台前端 THEN 先离线抓入口 JS、lazy chunk、source map 和 runtime 映射，抽 API family、认证字段、对象字段和高价值功能 BUT 不把路由名、变量名、action 名或 source map 本身直接当成漏洞。
- recommended_next_steps_low_impact：做已保存 JS 覆盖差分；按 score90/80/60 分批补点；将新端点回放 no-token/fake-token/空 JSON 小矩阵。
- evidence_required：JS URL/哈希、chunk 覆盖清单、API family、字段/认证上下文、最小服务端响应。
- false_positive_risks：mock、SDK、埋点、i18n、前端死代码、过期 signed URL、SPA fallback。
- stop_conditions：高价值 API family 已映射且匿名边界闭合；后续需要账号/对象/验证码/私有文件时停止。
- severity_hint：info_to_medium
- confidence：0.93
- memory_statement：近期 SPA 任务的最高 ROI 是离线前端覆盖差分，不是通用爬虫；所有静态发现必须回到服务端边界验证。

### PAT-002 Endpoint Auth Matrix For Candidate Closure

- pattern_type：api_auth_matrix
- source_cases：CASE-01, CASE-02, CASE-03, CASE-06
- singleton：false
- trigger_signals：大量候选接口、`authToken`/JWT/网关统一鉴权、订单/运单/用户/文件/导出/上传语义。
- decision_rule：IF 候选队列中存在高价值 API AND 无账号或 token THEN 用 no-token、fake-token、HEAD/GET/OPTIONS、空 JSON POST、无效对象 ID 小矩阵分类 BUT 不在无 self 基线时声称 BOLA/IDOR 阴性或阳性。
- recommended_next_steps_low_impact：每批限制请求数；记录 `auth_blocked`、`not_found_or_unrouted`、`business_error_no_impact`、`html_or_spa`；同步候选队列状态。
- evidence_required：请求方法、路径、认证状态、业务码/状态码、响应类别、邻近接口对照。
- false_positive_risks：字段缺失层错误、方法异常、空体内部错误、验证码前置、SPA HTML。
- stop_conditions：P0/P1/P2 无 triaged/high_value/verifying 悬空项；剩余全部材料阻塞/降级/出 scope。
- severity_hint：triage_control
- confidence：0.90
- memory_statement：端点矩阵的价值是收束候选和证明材料缺口；不是用匿名请求替代认证态越权测试。

### PAT-003 Material Block Is A First-Class Stop State

- pattern_type：material_block
- source_cases：CASE-01, CASE-02, CASE-03, CASE-06, CASE-07, CASE-08, CASE-09
- singleton：false
- trigger_signals：需要低权限 A/B 账号、验证码 ticket/randstr、私有对象 key、fileId/objectKey、可回滚文件、白名单 IP、测试订单/运单/客户对象。
- decision_rule：IF 下一步验证需要真实业务材料或可能造成状态变更 THEN 将候选标记 `blocked_need_material` 并写明拿到材料后的第一步 BUT 不继续扩大匿名低分扫描填时间。
- recommended_next_steps_low_impact：输出材料清单、优先接口、验证矩阵和停止条件；保留已失败路径。
- evidence_required：已完成匿名边界、缺失材料、材料到位后的最小验证请求。
- false_positive_risks：把“没账号”误写成“安全”；把空列表/空分页误写成数据不泄露。
- stop_conditions：材料缺口清楚且当前匿名面无高价值悬空项。
- severity_hint：blocked
- confidence：0.89
- memory_statement：材料阻塞是可审计结论。写清材料和第一步验证，比重复扫 P3 路由更有价值。

### PAT-004 CORS Severity Boundary

- pattern_type：cors_boundary
- source_cases：CASE-03, CASE-06, CASE-08
- singleton：false
- trigger_signals：`Access-Control-Allow-Origin:*`、Origin 反射、`Access-Control-Allow-Credentials:true`、允许自定义 auth header。
- decision_rule：IF CORS 反射且 ACAC:true THEN 继续判断认证凭据是否浏览器自动携带、是否有敏感响应、是否能跨域读到认证态数据 BUT 自定义 header token 场景不能单独报告为高危。
- recommended_next_steps_low_impact：分别测前端域和 API 网关；无 token/假 token/有效低权限 token 对照；检查 Cookie、SameSite、ACAC、Vary、OPTIONS。
- evidence_required：CORS 响应头、认证方式、是否自动携带凭据、敏感响应样本或无影响对照。
- false_positive_risks：无 ACAC 的 `*`、负载均衡 Cookie、公开字典接口、无敏感数据。
- stop_conditions：无有效认证态或无敏感响应时降级；需要 XSS/token 泄露组合时写清前置条件。
- severity_hint：low_to_medium
- confidence：0.86
- memory_statement：CORS 风险不是看头部是否“难看”，而是看浏览器能否自动带凭据并读到敏感数据。

### PAT-005 Login Flow Fidelity Before Auth Claims

- pattern_type：login_flow_fidelity
- source_cases：CASE-02, CASE-06, CASE-10
- singleton：false
- trigger_signals：登录返回 500、字段缺失、验证码错误、客户端 SDK 生成票据、GET 探测失败。
- decision_rule：IF 认证/验证码/默认凭据验证失败 THEN 先从前端 axios wrapper、浏览器流量或 JS DTO 还原方法、Content-Type、字段名和加密包装 BUT 不用错误格式响应判断认证绕过或安全。
- recommended_next_steps_low_impact：覆盖 POST+JSON、POST+form、真实字段名、captcha 字段、无票据/伪票据/bypass 票据小矩阵。
- evidence_required：前端请求构造证据、请求体、Content-Type、服务端业务码差异。
- false_positive_risks：`password` vs `pwd`、空体 500、验证码图片/ctoken 返回被误判成功、GET 登录漏报。
- stop_conditions：真实格式仍被验证码/鉴权拦截；继续需要验证码或账号。
- severity_hint：auth_triage
- confidence：0.88
- memory_statement：认证测试先讲格式忠实。错误 Content-Type 和缺字段会制造假阴性，也可能掩盖默认凭据。

### PAT-006 Static PII And Mobile Artifact Scan

- pattern_type：static_pii
- source_cases：CASE-09
- singleton：true
- trigger_signals：后台静态 HTML/JS、移动下载页、APK、debug/push 端点、案件/身份/地址/手机号字段。
- decision_rule：IF 公开静态资源出现真实或准真实 PII THEN 立即脱敏固证并按字段类别/数量级/可达性评级 BUT 不重复传播完整个人信息或使用泄露身份登录。
- recommended_next_steps_low_impact：离线扫描身份证/手机号/地址/姓名/案件编号；APK 静态分析 debug endpoint；生成脱敏样例。
- evidence_required：公开可达性、字段类别、记录数量、是否真实样例、脱敏证据。
- false_positive_risks：mock 样例、公开演示数据、单条不可扩展样本。
- stop_conditions：单条样本按中危/高危候选；严格高危需要批量 API、更多真实记录或账号接管链。
- severity_hint：medium_candidate
- confidence：0.78
- memory_statement：静态资源中的 PII 是高价值方向，但证据处理必须先脱敏，升级高危需要证明规模或可扩展读取。

### PAT-007 Asset Scoring Beats Flat Enumeration

- pattern_type：asset_scoring
- source_cases：CASE-07, CASE-01, CASE-06
- singleton：false
- trigger_signals：百级资产、多个国家/业务线、Demo/UAT、开放平台、VIP/JMS/YMS/驿站/后台标题。
- decision_rule：IF 资产数量很大 THEN 用业务核心度、存活状态、WAF/CDN、登录页、页面大小、技术栈、scope 关系和已排除轮次打分生成 Top 队列 BUT 不把评分写成漏洞结论。
- recommended_next_steps_low_impact：输出 Top 目标、攻击向量、为何不重复、下一步 JS/登录/API 验证。
- evidence_required：存活结果、标题、技术栈、WAF 状态、业务语义、队列排序依据。
- false_positive_risks：页面大小不等于功能丰富、Demo 不是必然弱、无 WAF 不是漏洞。
- stop_conditions：Top 队列已交付；进入定向验证而非继续扫更多相同资产。
- severity_hint：recon_priority
- confidence：0.82
- memory_statement：大范围资产收集的有效产物是可执行优先级，不是原始域名数量。

### PAT-008 Token, Signed URL, And Public Config Boundaries

- pattern_type：token_leak_boundary
- source_cases：CASE-03, CASE-04, CASE-06
- singleton：false
- trigger_signals：前端硬编码 Bearer/API key、signed URL、文件下载/上传签名接口、公共配置、QR 初始化 token。
- decision_rule：IF 静态 token 或签名 URL 候选出现 THEN 先验证 token 是否进入服务端参数校验、signed URL 是否能读私有对象、配置是否含敏感业务影响 BUT 不把公开 key/过期 URL/空初始化 token 直接升级。
- recommended_next_steps_low_impact：无 token/带 token 空 body 对照；已知 key/不存在 key/私有测试 key 对照；不创建短链、不下载私有对象。
- evidence_required：服务端差异、权限边界、对象私有性、是否造成创建/读取/写入。
- false_positive_risks：前端预期公开 key、过期 URL、公共字典、空列表、公开客户端安装包。
- stop_conditions：无私有对象或可回滚材料时转材料阻塞；有效第三方 token 可按滥用风险中低危处理。
- severity_hint：info_to_medium
- confidence：0.84
- memory_statement：token/签名线索要证明服务端接受和资源影响。能进入参数校验不等于已经造成数据泄露或写入。

### PAT-009 WAF/CDN/Fake-IP Noise Gate

- pattern_type：waf_cdn_noise
- source_cases：CASE-01, CASE-02, CASE-03, CASE-06, CASE-08
- singleton：false
- trigger_signals：198.18/198.19 假 IP、CDN 全站、CloudWAF 418/403、SPA fallback 200、nmap all-open 或只 TCP 握手。
- decision_rule：IF 扫描结果出现 CDN/WAF/Fake-IP 特征 THEN 先用可信 DNS、DoH、固定 Host/SNI、body hash 和协议级采样复核 BUT 不把 CDN IP 端口、fallback 200 或 TCP connect 当作真实服务漏洞。
- recommended_next_steps_low_impact：`dig +tcp @1.1.1.1`、固定解析 curl、body hash 去重、真实 404 对照、协议 banner 小样本。
- evidence_required：真实解析、Host/SNI 对照、响应体分类、协议层证据。
- false_positive_risks：WAF 页面伪 actuator、`.git/HEAD` SPA 200、端口应用层超时。
- stop_conditions：确认是防护层/静态 fallback 后停止同类探测。
- severity_hint：noise_filter
- confidence：0.91
- memory_statement：网络噪声先过门禁。近期多次误报都来自把防护层响应当成目标服务。

### PAT-010 Default Credential Verification With Immediate Stop

- pattern_type：default_creds
- source_cases：CASE-10
- singleton：true
- trigger_signals：公网后台、管理 API、默认用户名线索、登录 API 可定位、无 MFA 或可解码 JWT。
- decision_rule：IF 授权范围内后台登录可低频验证 THEN 必须按真实方法和 Content-Type 尝试极小默认凭据集 BUT 一旦获得高权限和敏感只读数据即停止扩展。
- recommended_next_steps_low_impact：POST+JSON/form 双格式、最小账号集、JWT 解码、whoami/refresh/只读列表证明。
- evidence_required：登录请求、JWT 权限字段、MFA 状态、refresh 可用、只读敏感数据类别和数量级。
- false_positive_risks：只 GET 登录页、错误 Content-Type、只看到后台入口或菜单。
- stop_conditions：superadmin/管理员权限确认后，不继续执行写操作、导出、隧道、命令或凭据深挖。
- severity_hint：confirmed_high_when_closed
- confidence：0.80
- memory_statement：默认凭据是高 ROI 验证项，但必须低频、格式正确、命中即停。

## Immediate Draft Rules

- SPA/API 任务优先做前端覆盖差分和 API family 映射；通用爬虫和 CDN 端口扫描排在后面。
- 对高价值候选统一用小矩阵分类，并同步 `blocked_need_material`、`downgraded`、`out_of_scope`，避免重复扫同一匿名面。
- 登录/验证码/默认凭据验证前必须还原真实请求格式，至少确认方法、Content-Type、字段名和客户端包装。
- CORS、公开配置、API key、signed URL、source map、开放字典默认不直接拔高中高危；必须闭合到凭据自动携带、敏感数据、私有对象或可用服务端权限。
- 静态 PII 证据必须脱敏；不要把真实个人信息复制进 memory、日志或最终摘要。
- 命中高影响权限或大量敏感只读数据后，立即停止扩大验证，只保留修复所需证据和下一步建议。

## Non-Applicability

- 不适用于 CTF 解题、二进制逆向 exploit、内网全端口高强度扫描或已有完整认证态测试账号的深度业务逻辑专项。
- 不适用于需要生产写入、真实订单/运单/短信/邮件、批量下载或数据导出的验证，除非用户提供明确测试窗口和可回滚对象。
- 对同一行业/同一厂商近期样本有过拟合风险；其它行业使用时应保留“前端优先”和“材料阻塞”思想，但不要复用具体业务假设。
