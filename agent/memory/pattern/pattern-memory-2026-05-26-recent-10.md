# Pattern Memory: 2026-05-26 Recent 10 Tasks

- 类型：pattern
- batch_id：pattern-memory-2026-05-26-recent-10
- 生成日期：2026-05-26
- task_count：10
- covered_time_range：2026-05-19 至 2026-05-26
- selection_rule：选取最近且具备 `retrospective.md` 完成标记的 10 个不重复任务归档；未纳入仅有过程归档但无完成复盘的任务。
- dominant_asset_types：政府门户、公共服务门户、商城/API、OA、Java/Tomcat 业务系统、消息代理、对象存储、关联官网/邮件/后台。
- dominant_vulnerability_types：前端泄露、未授权 API、对象存储公开列举、公开附件隐私边界、公开 Git 元数据、开放重定向、CORS 边界、上传链候选、错误信息泄露、边界设备/组件高危候选。
- overall_quality：高。多数归档包含正向证据、负向对照、停止规则和误报说明；少数长任务存在同源复盘拆分，需避免重复计数。
- main_learning_value：高价值路径不是“更大扫描”，而是从前端、公开配置、业务链接、对象 ID、未认证/认证态对照中快速闭合证据，同时在高影响证明后停止枚举。
- 标签：frontend_intel, api_auth_boundary, object_storage, privacy_publication_boundary, broker, asset_correlation, waf_cdn_noise, cors_boundary, redirect_risk, ci_cd_exposure, negative_validation, upload_boundary, report_quality, stopping_rule
- 状态：active

## Case Index

### CASE-01 czt-bounty-mall-auth-boundary

- 行业/资产类型：电商/会员商城/店主管理/API。
- 授权边界：通配 Web/API 域名；禁止爆破、驻留、真实业务写入和状态变更。
- 初始入口：被动 DNS、历史 URL、公开前端、登录/API 子域。
- 主要资产扩展路径：RapidDNS/urlscan/Wayback -> selector/config -> lazy chunk -> API base/path -> A/B 普通会员认证态矩阵。
- 最终有效发现：未确认高危；形成大量认证边界负向结论和一个订单结算预览业务逻辑候选。
- 最终漏洞类型：低危/信息项、受限业务逻辑候选、认证态 BOLA 阴性闭环。
- 关键转向点：拿到 fresh A/B 登录态后，从未认证路径转为 self/cross/no-token/fake-object 矩阵；登录态失效时先停健康检查。
- 关键正向信号：前端 chunk 暴露会员、订单、地址、上传、店主、邀请、结算等 API 上下文。
- 关键负面信号：自查基线失败、员工/报表 504、source map 404、API 返回 token 失效、普通会员 403。
- 证据闭环方式：A 自查、B 自查、A 查 B、B 查 A、无 token、fake 对象、参数污染、登录态健康检查。
- 停止点：不调用真实下单、支付、退款、开店、短信、提货、真实上传；状态变更只到假值或无效对象。
- 不应复用的目标特定细节：真实域名、会员号、token、商品/订单/地址 ID、验证码、具体 API host。
- 可迁移经验摘要：认证态测试必须先确认 self 基线有效；无非空对象样本时不能宣称 BOLA 全闭合；普通会员 403 不能代表店主/Plus/上传角色安全。

### CASE-02 gov-portal-privacy-storage-ci

- 行业/资产类型：政府门户/政务前端/公开附件/对象存储/边界设备。
- 授权边界：政府门户及 FOFA 高信号入口；报告中不得展开个人信息正文。
- 初始入口：用户提供 FOFA 资产结果。
- 主要资产扩展路径：FOFA -> 真实业务标题/子域筛选 -> 政务栏目附件 -> 前端 bundle -> 资源域/OBS 桶 -> 边界设备版本。
- 最终有效发现：开放重定向、公开附件个人信息边界、高影响公开名单隐私风险、前端 CI/CD 构建信息泄露、对象存储公开列举和敏感前缀公开读、高危边界设备候选。
- 最终漏洞类型：privacy_publication_boundary、object_storage、frontend_intel、redirect_risk、高危候选。
- 关键转向点：从通用扫描转向公开附件离线解析和资源域桶权限验证。
- 关键正向信号：公开 XLS/XLSX 大量字段类别、bundle 出现 CI/CD/仓库/环境信息、资源域根 404 但 `?max-keys` 可列举。
- 关键负面信号：CORS 无凭据链、后台上传候选 302 登录、FOFA/CDN/WAF 噪声、漏洞版本未做 PoC。
- 证据闭环方式：仅统计字段类别/数量级；对象存储用列表、前缀、HEAD 元数据闭环；版本候选用官方公告和静态指纹。
- 停止点：不下载敏感票据正文/大型归档，不翻页枚举对象，不执行边界设备利用。
- 不应复用的目标特定细节：真实附件内容、姓名/手机号/地址、cookie/secret-like 原文、桶名和对象 key。
- 可迁移经验摘要：政务公开要区分“依法公开”与“最小化脱敏不足”；对象存储高危证据通常不需要下载正文。

### CASE-03 public-library-multi-api-static-data

- 行业/资产类型：公共图书馆/OPAC/SSO/多租户前端/API。
- 授权边界：主站及业务链接关联资产；不提交真实业务记录。
- 初始入口：主站业务链接和 FOFA/证书发现。
- 主要资产扩展路径：主站 -> OPAC/SSO/U 微/DataESB/TCC -> SPA bundle -> API 关键词分流。
- 最终有效发现：公开前端静态包内嵌个人收货/订单类数据；多项低危/信息泄露；多个 IDOR/上传/短信/代理接口停在候选。
- 最终漏洞类型：frontend_intel、file_disclosure、api_auth_boundary 候选、cors_boundary 信息项。
- 关键转向点：从主站异常响应转向关联前端包敏感字段搜索。
- 关键正向信号：bundle 中出现订单、地址、读者、手机号等字段类别和样例数据。
- 关键负面信号：假 OAuth/openid 无法换 token；上传真实文件被鉴权拦截；WebForms 空响应和 SPA fallback。
- 证据闭环方式：静态包指纹、字段类别、最小响应、假 ID/缺字段/无 token 对照。
- 停止点：无账号/测试对象时不提交完整荐购、反馈、注册、短信或支付表单。
- 不应复用的目标特定细节：订单样例、读者证、手机号、机构 ID、token 或具体租户数据。
- 可迁移经验摘要：公开 bundle 不只抽接口，还要查 mock/样例/跨租户业务数据；字段校验先于鉴权不是漏洞闭环。

### CASE-04 grain-cloud-broker-unauth-api

- 行业/资产类型：粮食/园区运营平台、RabbitMQ、视频平台、车辆称重/API。
- 授权边界：授权多系统公网资产；高危证明后避免业务消息读取和生产写入。
- 初始入口：公网前端 chunk。
- 主要资产扩展路径：前端 chunk -> broker 凭据/API -> Management API -> 只读拓扑；前端业务 API -> 未认证读 -> 邻近写接口边界。
- 最终有效发现：消息代理管理员凭据可用、拓扑/用户哈希暴露；视频平台/摄像头配置泄露；车辆/同步业务未授权读；多个写操作未认证进入业务逻辑。
- 最终漏洞类型：frontend_intel、api_auth_boundary、message-broker exposure、sensitive config disclosure。
- 关键转向点：STOMP CONNECT 后立即检查 management whoami/权限，而不是读取业务队列。
- 关键正向信号：公网 JS 中出现 broker/video/camera/API 高敏配置；未认证业务接口返回第一页数据；邻近接口大量 token-expired 形成强对照。
- 关键负面信号：不订阅业务 topic，不调用 message-get/purge/delete；无所有者测试数据时不声称真实写入。
- 证据闭环方式：CONNECT/whoami/权限、只读拓扑、未认证/错误密码对照、page=1&limit=1、不存在 ID 写接口边界。
- 停止点：不读业务消息、不改权限、不关闭连接、不用有效生产 ID、不触发打印/同步/删除/设备控制。
- 不应复用的目标特定细节：broker 用户名/密码、vhost、topic、队列名、摄像头地址/账号、业务对象 ID。
- 可迁移经验摘要：前端泄露的控制面凭据要用最小协议认证和权限证明闭环；读泄露串联写边界时，只用不存在对象证明认证缺口。

### CASE-05 water-official-oa-negative-boundary

- 行业/资产类型：集团官网/OA/OpenAPI/ASP.NET 与 Java 错误面。
- 授权边界：官网及 DNS/业务明确关联资产；无账号时只做未认证只读边界。
- 初始入口：官网与关联 API/OA 主机。
- 主要资产扩展路径：官网 -> API/OA -> OpenAPI/opendoc bundle -> 路由列表 -> 错误处理探测。
- 最终有效发现：中危错误堆栈/内部链路信息泄露；明文 HTTP/Cookie/响应头问题；大量高危候选被负向闭合。
- 最终漏洞类型：file_disclosure/info disclosure、negative_validation、waf_cdn_noise。
- 关键转向点：高收益路由耗尽后，转向方法边界和错误处理。
- 关键正向信号：畸形只读文件请求返回 Java/Spring/Tomcat 栈、内部字段类别。
- 关键负面信号：API 路由 401、OpenAPI 静态响应不等于管理访问、all-open 端口无协议 banner。
- 证据闭环方式：body hash 去重、单个非敏感 fileId、OPTIONS/CORS 对照、协议级端口采样。
- 停止点：无 OA/backoffice 账号、测试附件、VPN/source 路径时，停止通用路径扩展。
- 不应复用的目标特定细节：内部 IP、employeeId、requestUri、真实附件 ID、主机名。
- 可迁移经验摘要：错误堆栈是中危信息泄露基座，只有结合文件读取、认证绕过或账号态影响才升级。

### CASE-06 park-jfinal-upload-reset-boundary

- 行业/资产类型：园区管理平台/JFinal/注册上传/找回密码。
- 授权边界：公网业务系统；不修改真实管理员密码，不向第三方发送短信。
- 初始入口：注册流程前端和后台登录/重置流程。
- 主要资产扩展路径：OCR/临时附件上传 -> 注册数据流 -> 取回/绑定/执行边界；找回密码 -> 单次验证码 -> 账号枚举对照。
- 最终有效发现：未认证临时图片上传中危；账号枚举/重置绑定异常低中危；若干服务/TLS/Cookie 信息项。
- 最终漏洞类型：upload_boundary、auth_flow_boundary、negative_validation。
- 关键转向点：上传成功后继续验证取回、覆盖、绑定、执行，而不是直接定高危。
- 关键正向信号：小图片上传成功并返回客户端可控附件标识；SVG/伪 JPEG SVG 被接受。
- 关键负面信号：非图片不接受、取回/预览/注册绑定失败、SPA/login fallback 稳定。
- 证据闭环方式：上传接受/拒绝对照、path-style attachId、body hash 分类、存在账号/不存在账号对照。
- 停止点：无测试手机号/账号/可回滚注册对象时，不继续重置、短信或真实注册。
- 不应复用的目标特定细节：attachId、验证码、账号名、上传返回值、真实手机号。
- 可迁移经验摘要：上传链必须拆成“接受、存储、可访问、绑定、执行/渲染”五段，缺哪段就不升级。

### CASE-07 group-official-linked-git-thinkphp

- 行业/资产类型：集团官网/关联景区站/PHP/WordPress/Git 暴露。
- 授权边界：通过官网业务链接支撑的关联资产；达到高影响证明后停止批量抓取。
- 初始入口：官网直接业务链接。
- 主要资产扩展路径：官网 -> 关联站 -> 框架错误页/版本 -> `.git` 元数据 -> index/refs/commit/tree 最小证明。
- 最终有效发现：安装程序未删除高风险；ThinkPHP 受影响版本高危候选；公开 Git 元数据/部分对象高风险；源码模板/后台路由等风险项。
- 最终漏洞类型：ci_cd_exposure/file_disclosure、framework version high_candidate、asset_correlation。
- 关键转向点：业务链接确认范围后，用最小 Git 元数据证明而非 clone。
- 关键正向信号：`.git/HEAD`、config、refs、logs、index、部分 object 可读；框架错误页暴露精确版本。
- 关键负面信号：未证明完整源码恢复、凭据泄露、RCE 或私有 Git 访问。
- 证据闭环方式：index 本地解析统计文件类别；单个 commit/tree object；版本证据配官方影响说明和无害负向请求。
- 停止点：不批量 clone、不抓全 object、不执行 RCE/OAST/webshell、不爆破后台。
- 不应复用的目标特定细节：repo 路径、commit hash、文件清单细节、版本站点真实域名。
- 可迁移经验摘要：Git 暴露闭环不需要完整源码下载；“可枚举部署结构 + refs/index/object”已足够支撑高优先级修复。

### CASE-08 official-mail-coremail-config-risk

- 行业/资产类型：官网关联邮件系统/Coremail/MX。
- 授权边界：通过公网邮箱/MX 证明关联；无测试邮箱时不做登录和中继测试。
- 初始入口：官网公开邮箱地址和 DNS MX。
- 主要资产扩展路径：官网 -> MX/webmail -> HTTP/HTTPS 登录行为 -> SPF/DMARC/HSTS。
- 最终有效发现：明文 HTTP 登录通道、HSTS 缺失、DMARC 缺失，中危配置风险。
- 最终漏洞类型：asset_correlation、transport/config risk。
- 关键转向点：使用不存在账号假登录证明 HTTP 登录处理分支，而不是测试真实凭据。
- 关键正向信号：HTTP 登录表单处理、HTTPS 可用但未强制、邮件安全 DNS 缺口。
- 关键负面信号：未证明账号接管、真实凭据捕获、SMTP relay、管理员访问或邮箱数据泄露。
- 证据闭环方式：HTTP/HTTPS 对照、HSTS/SPF/DMARC DNS 证据、不存在账号一次性登录。
- 停止点：无明确邮件测试规则和测试邮箱时，不做密码喷洒、账号枚举、SMTP relay。
- 不应复用的目标特定细节：真实邮箱域、账号样本、MX 主机名、响应体正文。
- 可迁移经验摘要：邮件面可作为关联风险，但配置风险不能写成应用攻陷或账号接管。

### CASE-09 seeyon-oa-product-boundary

- 行业/资产类型：OA/Seeyon/ASP.NET/IIS 关联面。
- 授权边界：OA 与同组织官方站；不触发短信/邮箱、上传 webshell、爆破账号。
- 初始入口：OA 静态 JS、版本信息、后台路径。
- 主要资产扩展路径：静态脚本 -> RJS/REST/M3/文件/Office/WPS 产品矩阵 -> CVE 线索对照。
- 最终有效发现：DOM XSS 中危；pre-auth 信息暴露低危；弱口令未确认；多个 CVE/文件读取/上传链负向闭合。
- 最终漏洞类型：frontend_intel、product-specific negative_validation、report_quality。
- 关键转向点：从版本匹配转为产品专项路由矩阵和 forced-logout/401/404 对照。
- 关键正向信号：真实 RJS 协议、版本/门户/辅助登录接口、DOM sink。
- 关键负面信号：REST/M3 401、历史路径 404、文件 ID 数字解析错误而非文件内容、唯一服务端口 closed。
- 证据闭环方式：静态 sink、少量只读 RJS、路径状态对照、锁定/剩余尝试次数作为停止信号。
- 停止点：端口关闭即停止；无账号/测试手机号时不继续利用链。
- 不应复用的目标特定细节：OA 版本具体部署、fileId、账号尝试、内部错误正文。
- 可迁移经验摘要：OA 高危不能靠版本和公网路径名成立；必须证明数据访问、文件读写、SSRF、SQLi 行为或认证态影响。

### CASE-10 fiscal-pageoffice-java-client-risk

- 行业/资产类型：财政评审系统/Java/Tomcat/PageOffice/客户端协议。
- 授权边界：公网业务系统；无隔离客户端/账号时不执行客户端链或管理操作。
- 初始入口：Java/Tomcat 目标和 PageOffice 运行时脚本。
- 主要资产扩展路径：PageOffice JS -> postMessage/eval -> link broker -> seal-admin servlet -> UEditor/Tomcat/AJP 负向闭合。
- 最终有效发现：PageOffice 跨源 message/eval 高风险客户端候选；未认证生成客户端协议 payload 候选；印章管理面公网暴露高影响候选。
- 最终漏洞类型：frontend_intel、client-side bridge risk、exposed management surface。
- 关键转向点：公网安装包结论撤回后，保留目标自身 runtime JS 和 servlet 映射证据。
- 关键正向信号：message listener、eval/method dispatch、可控 URL/scheme broker、seal 管理登录面。
- 关键负面信号：默认口令失败、image-ID 负向、高价值文件路径负向、SQLi 延时无差异、AJP 无有效响应。
- 证据闭环方式：静态危险模式、unknown-action 对照、单次无害 scheme 测试、默认口令最小负向。
- 停止点：不爆破 seal-admin，不新增/删除/下载印章，不安装插件，不声称服务端 RCE/SQLi。
- 不应复用的目标特定细节：客户端协议 payload、seal 路径细节、账号候选、脚本原文。
- 可迁移经验摘要：客户端桥接风险应写成“客户端/用户会话影响候选”，除非隔离终端证明本地执行或签章影响。

## Cross-Case Pattern Memory

### PAT-001 Frontend Bundle First-Pass Intelligence

- pattern_type：frontend_intel
- source_cases：CASE-01, CASE-02, CASE-03, CASE-04, CASE-09, CASE-10
- singleton：false
- trigger_signals：SPA/Vite/Webpack chunk、selector/config、lazy routes、sourceMappingURL、upload/file/order/pay/reader/member/broker/video 等关键词。
- decision_rule：IF 前端公开 bundle 暴露 API base、角色路由、业务对象字段或集成配置 AND 资产在授权范围内 THEN 优先做离线抽取和最小只读边界验证 BUT 不应把路径、变量名或 secret-like 字符串直接等同可利用漏洞。
- recommended_next_steps_low_impact：离线提取 API base/path/字段类别；按只读、上传、认证态、支付/状态变更分流；优先保存 bundle 指纹和上下文。
- evidence_required：bundle URL/哈希、字段类别、调用上下文、最小 API 响应、无 token/错误 token/认证态对照。
- false_positive_risks：mock 数据、废弃配置、测试环境残留、前端死代码、source map 404、变量名像 secret 但无有效性。
- stop_conditions：已定位高价值接口族并完成最小边界分类；后续需要账号/角色/测试对象时停止。
- severity_hint：medium
- confidence：0.92
- memory_statement：公开前端是高命中入口，但首先用于路径选择和证据分流。只有当配置可被服务端接受、数据可读、权限可达或凭据可用时，才升级为漏洞闭环。

### PAT-002 A/B Auth Boundary Matrix With Health Gate

- pattern_type：api_auth_boundary
- source_cases：CASE-01, CASE-03, CASE-04
- singleton：false
- trigger_signals：有两个低权限账号、对象 ID、地址/订单/银行卡/读者/车辆等对象接口。
- decision_rule：IF 需要验证 BOLA/IDOR AND 有 A/B 账号或对象样本 THEN 先做 A self、B self 健康检查，再做 cross/no-token/fake-object/parameter-alias 对照 BUT 不应在 self 失败时记录 cross 阴性。
- recommended_next_steps_low_impact：每轮矩阵前刷新登录态；只用第一页/limit=1；对写接口使用空体、畸形体或不存在对象。
- evidence_required：A/B self 成功、cross 差异、无 token 响应、fake 对象响应、响应状态和业务码。
- false_positive_risks：登录态过期、样本对象为空、角色不足、接口先校验字段再鉴权。
- stop_conditions：已证明 cross 返回目标数据或已证明 self 有效且 cross 被拒；缺少非空对象/角色时停止。
- severity_hint：confirmed_high_when_evidence_closed
- confidence：0.90
- memory_statement：认证态矩阵的第一证据是 self 基线，不是 cross 请求。没有健康基线的越权结论不可用。

### PAT-003 Read-Leak To Adjacent Write-Boundary Without Production Write

- pattern_type：api_auth_boundary
- source_cases：CASE-04, CASE-01, CASE-03
- singleton：false
- trigger_signals：未认证读接口暴露对象类别、ID 形状、同步配置、表名或业务 handler 名。
- decision_rule：IF 读泄露提供邻近写接口参数线索 AND 写操作可能影响生产 THEN 用不存在 ID、空对象或 no-op body 验证是否进入业务逻辑 BUT 不使用有效生产 ID 或触发真实状态变更。
- recommended_next_steps_low_impact：对比预期 401/403 与业务错误/反序列化错误；记录路由族模式；请求所有者日志侧确认。
- evidence_required：未认证状态、读泄露字段类别、写接口无效对象响应、邻近接口 token-required 对照。
- false_positive_risks：业务错误不等于真实写入；无效 ID success 不等于生产数据变更。
- stop_conditions：证明未认证请求到达业务 handler 即停；真实写影响需测试数据/窗口。
- severity_hint：high_candidate
- confidence：0.84
- memory_statement：读泄露可以安全引导写边界验证。生产写影响必须停在业务 handler 可达证明，不能越过授权边界。

### PAT-004 Object Storage Public Listing Closure

- pattern_type：object_storage
- source_cases：CASE-02
- singleton：true
- trigger_signals：前端配置出现资源域、bucket/CDN/fileBaseUrl；根路径 404 但像对象存储网关。
- decision_rule：IF 资源域可能是对象存储 AND 在授权业务配置中被引用 THEN 用列表参数、delimiter、单前缀和 HEAD 验证公开列举/读 BUT 不下载敏感正文或大型归档。
- recommended_next_steps_low_impact：请求根列表小样本、前缀列表、单对象 HEAD；只统计对象类型和敏感前缀。
- evidence_required：未认证列表响应、前缀/对象元数据、HEAD 公开可读、业务关联证据。
- false_positive_risks：公开 CDN 静态资源、默认公开图片桶、授权样例桶。
- stop_conditions：已证明列举 + 敏感前缀 + HEAD 可读；停止翻页和下载。
- severity_hint：high_candidate
- confidence：0.78
- memory_statement：对象存储风险的关键是“可列举 + 敏感业务前缀 + 公开读”。正文下载通常不是必要证据，反而增加数据暴露风险。

### PAT-005 Public Attachment Privacy Publication Boundary

- pattern_type：privacy_publication_boundary
- source_cases：CASE-02, CASE-03
- singleton：false
- trigger_signals：公开栏目附件、XLS/XLSX/PDF、名单/意见反馈/订单样例中出现个人字段类别。
- decision_rule：IF 附件位于公开栏目 AND 含个人字段 THEN 先判断依法公开、栏目目的和脱敏最小化边界 THEN 按字段类别/数量级报告 BUT 不展开个人信息正文。
- recommended_next_steps_low_impact：离线解析元数据和字段类别；统计行数/脱敏比例；保留少量脱敏样例。
- evidence_required：公开来源、无需鉴权证明、字段类别、数量级、法定公开上下文、脱敏缺口。
- false_positive_risks：法定公示内容、主动公开名单、公众服务必需字段。
- stop_conditions：数量级和字段类别足够；不继续下载更多同类附件。
- severity_hint：medium
- confidence：0.82
- memory_statement：公开不自动等于漏洞，也不自动等于安全。隐私类证据应证明公开目的与字段最小化之间的偏差。

### PAT-006 Broker Credential Closure Without Business Message Access

- pattern_type：evidence_closure
- source_cases：CASE-04
- singleton：true
- trigger_signals：前端出现 Web-STOMP/RabbitMQ URL、用户名、密码、vhost 或管理端口线索。
- decision_rule：IF broker 凭据出现在公网前端 AND 资产授权明确 THEN 只验证 CONNECT/whoami/权限/只读拓扑 BUT 不读取、发布、清空或删除业务消息。
- recommended_next_steps_low_impact：CONNECT/DISCONNECT；管理 API whoami；权限接口；只读队列/exchange 数量和类别。
- evidence_required：凭据来源、认证成功、权限范围、未认证/错误密码对照、无业务消息读取声明。
- false_positive_risks：测试凭据、只读低权限、vhost 不匹配、已失效凭据。
- stop_conditions：管理员权限或敏感拓扑已证明；立即停止扩展。
- severity_hint：confirmed_high_when_evidence_closed
- confidence：0.80
- memory_statement：消息代理凭据可用时，不需要读取业务消息证明高危。权限和拓扑已经足够闭环影响。

### PAT-007 Business-Link Asset Correlation

- pattern_type：asset_correlation
- source_cases：CASE-02, CASE-03, CASE-07, CASE-08
- singleton：false
- trigger_signals：官网业务链接、公开邮箱/MX、前端配置引用、证书/标题/品牌一致。
- decision_rule：IF 关联资产能由业务链接或公开配置证明归属 AND 授权边界允许关联测试 THEN 做只读指纹和最小风险验证 BUT 不把任意同名域名自动纳入范围。
- recommended_next_steps_low_impact：记录来源页面、链接关系、标题/证书/配置一致性；只做公开 GET/HEAD/OPTIONS。
- evidence_required：关联来源、业务标题、响应头/证书、入口截图或 HTML 证据。
- false_positive_risks：第三方托管、供应商服务、历史链接、同名无归属资产。
- stop_conditions：关联关系不足或范围不明确时停止并列为需确认。
- severity_hint：info
- confidence：0.86
- memory_statement：关联资产必须有证据链。业务链接、MX 和前端配置比单纯域名相似更可靠。

### PAT-008 WAF/CDN/All-Open Noise Filter

- pattern_type：waf_cdn_noise
- source_cases：CASE-01, CASE-02, CASE-03, CASE-05, CASE-06, CASE-09
- singleton：false
- trigger_signals：IP-only 全端口 open、极低延迟、tcpwrapped、连接 reset、相同 body hash 200、SPA fallback。
- decision_rule：IF 扫描结果显示异常全开或大量 200 THEN 用协议级请求、body hash、Host/SNI、公网 DoH 对照复核 BUT 不直接报告服务暴露。
- recommended_next_steps_low_impact：HTTP/TLS/banner 单样本；真实 404 对照；固定 Host/SNI；DoH 与本地 DNS 比对。
- evidence_required：协议响应、banner 或应用层握手、body hash 差异、DNS 可信解析。
- false_positive_risks：SYN proxy、SafeLine/tarpit、CDN 默认页、WAF challenge、Fake-IP。
- stop_conditions：协议样本为空或均为 fallback；记录噪声并停止端口面扩展。
- severity_hint：info
- confidence：0.94
- memory_statement：端口扫描不是漏洞证据。没有协议级响应的 all-open 结果应优先当作网络噪声处理。

### PAT-009 CORS Boundary Needs Credentialed Data Chain

- pattern_type：cors_boundary
- source_cases：CASE-01, CASE-02, CASE-03, CASE-05, CASE-06
- singleton：false
- trigger_signals：`Access-Control-Allow-Origin: *`、Origin 回显、OPTIONS 204/200、API CORS 宽松。
- decision_rule：IF CORS 宽松 AND 未见 credentials 或敏感认证态响应 THEN 作为配置观察或组合风险 BUT 不声称账号数据泄露。
- recommended_next_steps_low_impact：OPTIONS + GET/POST 对照；检查 credentials、认证头要求、敏感接口 no-token 响应。
- evidence_required：Origin 响应、credentials 标志、浏览器可读条件、认证态数据证明。
- false_positive_risks：公共 API、无 credentials、需要自定义 token header、预检不代表实际读取。
- stop_conditions：确认无凭据链或敏感接口需要 token；停止夸大。
- severity_hint：low
- confidence：0.90
- memory_statement：CORS 是组合条件，不是独立高危。没有凭据态可读敏感数据，就不要升级。

### PAT-010 Redirect Risk Needs Auth-Code Or Trust-Abuse Boundary

- pattern_type：redirect_risk
- source_cases：CASE-02, CASE-03
- singleton：false
- trigger_signals：redirectUrl、service、returnUrl、logout/login 跳转参数接受外部 URL。
- decision_rule：IF 开放重定向存在 AND 未证明携带授权码/token 或登录后信任链 THEN 按钓鱼/信任滥用中低风险记录 BUT 不声称会话泄露。
- recommended_next_steps_low_impact：外部 https、本域相对路径、javascript scheme 拒绝对照；不登录真实账号。
- evidence_required：Location 头、状态码、危险 scheme 负向、登录态/授权码边界说明。
- false_positive_risks：平台通用跳转组件、仅 logout、外部跳转有白名单但样本未覆盖。
- stop_conditions：证明跳转成立且敏感 token 未随跳转泄露；停止。
- severity_hint：low
- confidence：0.78
- memory_statement：开放重定向报告要说明“能跳去哪”和“带不带敏感材料”。没有授权码或会话材料时，不应拔高。

### PAT-011 Public Git Exposure Minimal Proof

- pattern_type：ci_cd_exposure
- source_cases：CASE-07
- singleton：true
- trigger_signals：`.git/HEAD`、`.git/config`、refs、logs、index、object 可读。
- decision_rule：IF Git 元数据公网可读 THEN 拉取最小 index/refs/object 证明存储结构可恢复 BUT 不执行批量 clone 或 secret 扫库。
- recommended_next_steps_low_impact：HEAD/config/index/refs；一个 commit/tree object；本地解析文件类别。
- evidence_required：未认证读取、tracked 文件数量/类别、refs/logs、单 object 成功与负向 object。
- false_positive_risks：空 Git 目录、只有 HEAD、无 object、公开开源站点。
- stop_conditions：元数据 + index + object 已证明；停止抓取源码。
- severity_hint：high_candidate
- confidence：0.76
- memory_statement：Git 暴露的最小闭环是元数据可读和对象可恢复性证明，不是完整源码复制。

### PAT-012 CI/CD Environment Leakage Is Not CI Takeover

- pattern_type：ci_cd_exposure
- source_cases：CASE-02
- singleton：true
- trigger_signals：前端 bundle 出现 Jenkins/Hudson、仓库、构建路径、环境变量、secret-like/cookie 名。
- decision_rule：IF 构建环境信息进入前端 THEN 报告构建泄露和清理重构需求 BUT 不测试内网 CI 或凭据有效性，除非明确授权。
- recommended_next_steps_low_impact：记录变量类别、构建路径类别、仓库可达最小只读检查。
- evidence_required：bundle 位置、变量类别、构建环境上下文、无凭据有效性声明。
- false_positive_risks：变量名无值、构建时无效残留、公开包元数据。
- stop_conditions：泄露类别和业务归属明确；停止凭据尝试。
- severity_hint：medium
- confidence：0.70
- memory_statement：前端 CI/CD 泄露能帮助攻击者定位供应链面，但不等于内网可打或 CI 被接管。

### PAT-013 Product-Specific Matrices Beat Generic Fuzz

- pattern_type：negative_validation
- source_cases：CASE-05, CASE-06, CASE-09, CASE-10
- singleton：false
- trigger_signals：OA、PageOffice、UEditor、ASP.NET/IIS、JFinal、Tomcat 等可识别产品。
- decision_rule：IF 产品族明确 THEN 构建产品专项路由/行为矩阵和少量对照 BUT 不重复通用路径 fuzz。
- recommended_next_steps_low_impact：静态脚本、厂商 servlet、只读接口、错误页、默认登录面少量对照。
- evidence_required：产品指纹、路由矩阵、正向/负向响应、停止原因。
- false_positive_risks：版本适用但补丁已装、fallback 200、静态组件与后端漏洞无关。
- stop_conditions：关键产品链均被 401/404/负向对照闭合；需要账号/客户端/测试环境时停止。
- severity_hint：medium
- confidence：0.88
- memory_statement：产品专项验证能显著降低误报。通用 fuzz 在 fallback 站点上很容易制造假 200。

### PAT-014 Upload Chain Segment Closure

- pattern_type：file_disclosure
- source_cases：CASE-03, CASE-06
- singleton：false
- trigger_signals：上传接口可进入参数校验、图片/SVG 被接受、返回附件 ID 或预签名候选。
- decision_rule：IF 上传被接受 THEN 分别验证接受、存储、取回、绑定、渲染/执行边界 BUT 不上传持久化载荷或 webshell。
- recommended_next_steps_low_impact：无害小文件、MIME/扩展名对照、取回 HEAD/GET、绑定负向。
- evidence_required：上传响应、拒绝对照、取回或不可取回证明、清理/残留说明。
- false_positive_risks：临时对象、仅内存校验、后端无存储、仅图片处理器。
- stop_conditions：缺少公开取回/绑定/执行路径；请求测试对象。
- severity_hint：medium
- confidence：0.82
- memory_statement：上传成功只是第一段证据。没有取回、绑定或执行影响，就不要写成任意文件上传高危。

### PAT-015 Candidate vs Confirmed High Severity Discipline

- pattern_type：report_quality
- source_cases：CASE-02, CASE-07, CASE-09, CASE-10
- singleton：false
- trigger_signals：精确版本落入 RCE 公告、边界设备组件版本、客户端危险模式、管理登录面暴露。
- decision_rule：IF 高危条件匹配但未执行无害利用或缺少账号/客户端 THEN 标为 high_candidate BUT 不写成已确认 RCE/接管/数据泄露。
- recommended_next_steps_low_impact：静态指纹、官方公告、入口可达、补丁状态请求、所有者侧确认。
- evidence_required：版本/组件、官方影响范围、未利用声明、限制条件。
- false_positive_risks：已打补丁、组件存在但不可达、WAF 阻断、客户端未安装。
- stop_conditions：版本和入口足够支撑修复优先级；利用验证需额外授权。
- severity_hint：high_candidate
- confidence：0.86
- memory_statement：候选高危的价值在于优先修复，不在于替代利用证明。报告语言必须清楚区分候选和已确认。

### PAT-016 Stop After Evidence Closure

- pattern_type：stopping_rule
- source_cases：CASE-02, CASE-04, CASE-07, CASE-10
- singleton：false
- trigger_signals：已证明公开列举、管理员权限、Git 元数据可恢复、管理面暴露或高危候选入口。
- decision_rule：IF 最小证据已能支撑修复和评级 THEN 停止主动扩展并转证据整理 BUT 不继续翻页、下载、读取消息、clone 或尝试写入。
- recommended_next_steps_low_impact：整理证据索引、写影响边界、列所有者侧复核项。
- evidence_required：正向证据、负向对照、未触碰边界声明、剩余验证条件。
- false_positive_risks：证据不足就过早停止；需确认最小证据足够自包含。
- stop_conditions：报告可复现、影响可理解、继续验证会增加数据暴露或生产影响。
- severity_hint：info
- confidence：0.90
- memory_statement：高质量停止规则能保护目标，也能提升报告可信度。证据闭环后继续枚举通常只增加风险，不增加价值。

## Anti-Pattern Memory

### AP-001 FOFA Result Equals Vulnerability

- observed_in_cases：CASE-02, CASE-03, CASE-05, CASE-06
- bad_behavior：把 FOFA 标题、端口、组件或 IP 结果直接当漏洞。
- why_bad：FOFA 包含 CDN/WAF、历史资产、默认页、连接 reset 和误标服务。
- safer_alternative：转成高信号入口清单，再用根路径、标题、JS、证书和协议级响应确认。
- detection_signal：只有 FOFA 截图/字段，没有目标响应证据。
- memory_statement：FOFA 是入口，不是漏洞证明。

### AP-002 401/403 As Final Truth

- observed_in_cases：CASE-01, CASE-03, CASE-04, CASE-09
- bad_behavior：把 401/403 直接当“安全”或“绕过成功/失败终点”。
- why_bad：可能是登录态失效、角色不足、字段校验顺序或路径族差异。
- safer_alternative：先做 self 健康检查，再做 cross/no-token/fake-object 和邻近接口对照。
- detection_signal：没有 self 基线或错误 token 对照。
- memory_statement：认证边界结论必须建立在有效基线上。

### AP-003 CORS Overstatement

- observed_in_cases：CASE-01, CASE-02, CASE-03, CASE-05, CASE-06
- bad_behavior：把 wildcard/回显 CORS 写成账号数据泄露。
- why_bad：缺少 credentials、认证态数据和浏览器可读链。
- safer_alternative：验证 OPTIONS、credentials、敏感接口认证方式和实际数据读取。
- detection_signal：只有 `Access-Control-Allow-Origin` 头。
- memory_statement：CORS 宽松通常是组合风险，不是单独高危。

### AP-004 Public Attachment Always High

- observed_in_cases：CASE-02, CASE-03
- bad_behavior：把所有公开附件含个人字段都直接定高危。
- why_bad：政务/公共服务存在依法公示和业务公开边界。
- safer_alternative：按栏目目的、法定公开、字段最小化、数量级和脱敏比例评估。
- detection_signal：报告只说“有个人信息”，没有公开上下文。
- memory_statement：隐私风险要同时看公开合法性和最小化。

### AP-005 Frontend CI/CD Leak Equals Internal Compromise

- observed_in_cases：CASE-02
- bad_behavior：把 Jenkins/仓库/变量名泄露写成内网可打或 CI 接管。
- why_bad：前端残留信息不能证明凭据有效或内网可达。
- safer_alternative：报告构建信息泄露和供应链辅助风险；凭据有效性需额外授权。
- detection_signal：只有变量名或路径，没有认证成功证据。
- memory_statement：CI/CD 泄露是线索和风险，不是接管证明。

### AP-006 PHP/Text Plain Or Installer Clue Equals RCE

- observed_in_cases：CASE-07
- bad_behavior：把 PHP 文件文本返回、安装器或版本线索直接写成 RCE。
- why_bad：需要执行、写入、配置保存或命令回显证明。
- safer_alternative：只写暴露/候选；达到配置步骤即可停在高风险候选或高优先级修复。
- detection_signal：没有执行结果或所有者侧确认。
- memory_statement：文件可见和代码执行之间有很长证据距离。

### AP-007 Sensitive File Download For Proof

- observed_in_cases：CASE-02, CASE-07
- bad_behavior：为证明对象存储/Git/附件风险而下载大量正文、票据、源码。
- why_bad：扩大数据暴露和合规风险。
- safer_alternative：列表、HEAD、index/refs、字段类别和数量级足够时停止。
- detection_signal：证据目录出现大量敏感正文或完整 clone。
- memory_statement：证明可访问不等于需要读取内容。

### AP-008 Continue Enumeration After High Evidence Closure

- observed_in_cases：CASE-02, CASE-04, CASE-07
- bad_behavior：已证明高风险后继续翻页、读消息、抓对象、扫库。
- why_bad：边际价值低，生产和隐私风险高。
- safer_alternative：转向证据整理、影响边界、修复建议和所有者侧复核。
- detection_signal：高危已成立后仍有大批量数据请求。
- memory_statement：闭环后停止是专业能力的一部分。

### AP-009 Generic Fuzz Against Product Fallback

- observed_in_cases：CASE-05, CASE-06, CASE-09
- bad_behavior：对 ASP.NET/OA/SPA fallback 反复跑通用路径字典。
- why_bad：制造大量假 200、空响应和无意义 404。
- safer_alternative：body hash 去重，转产品专项路由矩阵。
- detection_signal：命中大量相同响应体 200。
- memory_statement：先去重响应体，再谈命中。

### AP-010 Weak Password Probe Without Budget

- observed_in_cases：CASE-08, CASE-09
- bad_behavior：没有锁定重置和尝试预算就扩大弱口令/账号枚举。
- why_bad：容易触发锁定、扰动生产账号。
- safer_alternative：极小固定候选集；出现剩余次数或锁定提示立即停止。
- detection_signal：登录响应出现剩余尝试次数还继续请求。
- memory_statement：认证测试的停止信号比命中率更重要。

## Pattern Priority Table

| rank | pattern_id | pattern_name | why_priority | expected_value | expected_noise | required_caution | best_fit_asset_type |
|---:|---|---|---|---|---|---|---|
| 1 | PAT-001 | Frontend Bundle First-Pass Intelligence | 命中率最高，低影响，能引导 API/上传/对象/角色路径 | high | medium | 不把变量名当漏洞 | SPA/API/商城/OA |
| 2 | PAT-002 | A/B Auth Boundary Matrix | SRC 价值高，证据闭环强 | high | low | self 健康检查必须先做 | 会员/订单/读者/业务对象 |
| 3 | PAT-008 | WAF/CDN/All-Open Noise Filter | 大幅减少误报和无效扫描 | high | low | 需协议级复核 | 公网 IP/CDN/WAF |
| 4 | PAT-003 | Read-Leak To Write-Boundary | 能安全验证高危候选 | high | medium | 不用有效生产 ID | 业务 API/同步系统 |
| 5 | PAT-016 | Stop After Evidence Closure | 降低风险，提升报告可信度 | high | low | 别过早停止 | 对象存储/Git/broker |
| 6 | PAT-005 | Public Attachment Privacy Boundary | 政务/公共服务高频且报告敏感 | medium-high | medium | 区分依法公开 | 政务/公共服务 |
| 7 | PAT-014 | Upload Chain Segment Closure | 常见且易误报，分段后可控 | medium-high | medium | 不上传危险载荷 | 注册/附件/图片上传 |
| 8 | PAT-013 | Product-Specific Matrices | 比通用 fuzz 更准 | medium | low | 需产品知识 | OA/PageOffice/IIS/Tomcat |
| 9 | PAT-006 | Broker Credential Closure | 单次命中价值很高 | high | low | 不读取业务消息 | 消息代理/实时平台 |
| 10 | PAT-004 | Object Storage Public Listing | 证据容易闭环且低影响 | high | low | 不下载正文 | 资源域/OBS/OSS |
| 11 | PAT-011 | Public Git Exposure Minimal Proof | SRC 价值高但命中较低 | high | medium | 不 clone/扫 secret | PHP/WordPress/官网 |
| 12 | PAT-009 | CORS Boundary | 高频误报过滤 | medium | high | 必须有 credentials 链 | API/SSO |
| 13 | PAT-015 | Candidate vs Confirmed High | 报告质量关键 | medium | low | 语言边界精确 | 边界设备/组件版本 |
| 14 | PAT-010 | Redirect Risk | 常见中低危，证据简单 | low-medium | medium | 不夸大会话泄露 | SSO/登录/门户 |
| 15 | PAT-012 | CI/CD Environment Leakage | 单例但值得保留 | medium | medium | 不测内网 CI | 前端构建产物 |
| 16 | PAT-007 | Business-Link Asset Correlation | 扩面价值高 | medium | medium | 严格授权归属 | 官网/供应商/邮件 |

## Memory Update Patch

### 新增高价值模式

- 前端 bundle 优先抽取 API base/path/角色路由/对象字段/集成配置，并用最小请求闭环，不把变量名当漏洞。
- 认证态 BOLA/IDOR 使用 A self、B self、A->B、B->A、no-token、fake-object 六段矩阵；self 失败时停止。
- 未认证读泄露可引导邻近写接口验证，但只使用不存在对象或 no-op body，不触发生产写入。
- 对象存储公开列举用列表、前缀、HEAD、业务关联闭环，不下载敏感正文。
- 消息代理凭据泄露用 CONNECT/whoami/权限/只读拓扑闭环，不读业务消息。

### 新增负面模式

- FOFA/端口扫描/all-open 不等于漏洞。
- CORS 宽松不等于账号数据泄露。
- 公开附件含个人信息不自动高危，需要公开目的和最小化边界。
- 前端 CI/CD 信息泄露不等于 CI 接管。
- 高危候选版本不等于 RCE 成功。
- 上传成功不等于任意文件上传高危。

### 需要提高优先级的旧模式

- body hash 去重和 SPA/WAF fallback 过滤。
- 登录态健康检查作为认证态批量矩阵前置条件。
- 高危证据闭合后的主动停止规则。
- 产品专项路由矩阵替代通用 fuzz。

### 需要降低优先级的旧模式

- 大范围未认证路径字典扫描。
- IP 风险端口扫描直接出结论。
- 无账号条件下反复测试上传、支付、短信、找回密码完整流程。
- 仅凭 CVE/版本匹配推动利用验证。

### 需要废弃或标记过时的模式

- “HTTP 200 即路径存在”。
- “根路径 404 即对象存储安全”。
- “sourceMappingURL 出现即 source map 泄露”。
- “默认登录页公开即高危后台暴露”。

### 需要补充更多样本的低置信模式

- 对象存储公开列举到票据/归档前缀的评级边界。
- 前端 CI/CD 构建信息泄露在不同 SRC 中的接受度。
- PageOffice 客户端协议/postMessage 风险在隔离终端中的真实影响。
- 结算预览 `qty=0` 类业务逻辑候选是否能进入创建链。

## Open Questions / Data Gaps

- 多数 BOLA 负向结论缺少非空订单、银行卡、实名、券、流水等高价值对象样本。
- 店主/Plus/上传权限/员工后台角色缺失，无法推断垂直越权安全性。
- 对象存储和政务公开隐私问题的最终评级依赖业务合法公开边界。
- 高危候选组件需要资产方补丁状态、测试环境或日志侧确认。
- 客户端组件类风险需要隔离 Windows/Office/PageOffice 环境验证。
- 上传链需要可回滚测试对象来验证绑定和取回，而不是只看 handler。
- 邮件系统风险需要测试邮箱和明确邮件安全测试规则，不能自行扩展。

## Final Compression

- 前端 bundle 是路径选择的最高价值入口，但不是漏洞本身。
- BOLA/IDOR 先做 self 健康检查，再做 cross。
- 登录态过期时，所有认证态阴性结论作废。
- 无非空对象样本时，不要宣称对象边界完全闭合。
- 未认证读泄露后，可用不存在 ID 验证写 handler 鉴权边界。
- 写接口进入业务逻辑不等于真实生产写入已发生。
- 对象存储证明优先用列表、前缀和 HEAD，不下载正文。
- 公开附件隐私风险必须结合依法公开和最小化脱敏。
- Broker 凭据可用时，权限证明足够，不读业务消息。
- Git 暴露最小证明是 HEAD/config/index/refs/object，不需要 clone。
- CORS 没有 credentials 和敏感数据链，不升高危。
- FOFA、nmap、all-open、tcpwrapped 都必须协议级复核。
- body hash 去重能快速消灭 fallback 200 误报。
- 产品专项矩阵优于通用 fuzz。
- 上传风险按接受、存储、取回、绑定、执行分段评级。
- 高危候选版本要和已确认利用分开写。
- 弱口令测试出现锁定/剩余次数提示就停止。
- 高危证据闭合后停止主动枚举，转证据整理。
- 没有账号、测试对象、测试窗口或日志侧确认时，明确标阻塞。
- 报告只保留字段类别、数量级、证据类型和边界，不输出敏感正文。

