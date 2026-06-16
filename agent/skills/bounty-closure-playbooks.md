# 赏金高价值候选闭合 Playbook

本文件把高价值候选转成最小影响验证流程。它不替代 HackSkills 深度专题；当候选进入验证阶段时，按本文件确定最小闭合路径，再按 `agent/skills/hack-skill.md` 路由到对应 `hack-skills/skills/*/SKILL.md`。

所有流程默认用于明确授权赏金测试。禁止破坏性写入、批量枚举、真实支付/短信/改密/删除、未授权横向移动和拒绝服务。

## OAuth/OIDC/SAML

触发：

- 出现 `client_id`、`client_secret`、`redirect_uri`、`callback`、`authorize`、`token`、`code`、`state`、`nonce`、`saml`、`sso`、`systemCode`。
- JS、移动端、公开配置或历史 URL 暴露 OAuth/OIDC/SAML 链路。

最小验证：

1. 记录完整 authorize/callback/token/logout 链路。
2. 检查 `client_id/client_secret` 是否泄露且是否仍可用。
3. 检查 `redirect_uri` 是否严格匹配，覆盖外部域、子域注入、路径混淆、参数污染、fragment、开放重定向链。
4. 检查 PKCE 是否强制 S256，是否接受 `plain` 或空 `code_verifier`。
5. 检查 `state/nonce` 是否强制、绑定会话、不可重用。
6. 检查 authorization code 是否绑定 client、redirect_uri 和 session。
7. 检查 token endpoint 是否强制客户端认证，是否异常支持 grant_type。
8. 检查 CORS 是否扩大 token 暴露面。
9. 检查 callback/open redirect 是否可组合成 code/token 窃取链。

输出分类：

- 可独立利用。
- 需要低权限测试账号。
- 需要受控用户交互。
- 理论链路但无法闭合。
- 无实际危害。

需要材料时输出：测试账号、受控回调 URL、授权演练窗口、低权限/高权限账号对。

## SQLi

触发：

- GF `sqli`、Nuclei SQLi、SQL 报错、布尔差异、时间差异。
- 登录、搜索、列表、详情、报表、导出、排序、筛选、ID 参数、GraphQL/JSON 查询条件。

最小验证：

1. 只选择少量授权目标和单个参数。
2. 优先手工确认报错、布尔差异或时间差异。
3. 必要时使用 `tool/sqlmap_safe.py --authorized`，保持低风险 `risk=1`、`level=1`。
4. 证明 DBMS、数据库名、当前用户或可控差异即可停止。
5. 不 dump 数据、不读写文件、不执行命令、不扩大参数范围。

需要材料时输出：可测试账号、可查询对象 ID、可回滚筛选条件、允许测试的接口样本。

## SSRF

触发：

- 参数或路径包含 `url`、`uri`、`callback`、`webhook`、`redirect`、`next`、`target`、`image`、`avatar`、`file`、`import`、`fetch`、`render`、`pdf`、`preview`、`notify`。
- 上传/导入/预览/PDF/截图/远程拉取/第三方回调功能。

最小验证：

1. 确认是否存在服务端请求行为，而不是浏览器跳转。
2. 使用自有低影响回连地址或可控 DNS/HTTP 日志证明请求来源。
3. 若平台允许，再证明内网/metadata 风险可达的边界；证明风险成立即停。
4. 不做内网端口扫描、不抓取云凭据、不扩大协议探测。

需要材料时输出：授权回连域名、测试文件/导入对象、低权限账号、允许测试的内网/metadata 边界。

## IDOR/BOLA

触发参数：

```text
userId empId staffId orgId deptId corpId shopId siteId networkId
orderId waybillNo billCode fileId attachmentId parentId tenantId appId
```

触发动作：

```text
detail list export download preview update delete bind unbind reset approve audit import upload
```

最小验证：

1. 建立对象模型和 A/B 账号矩阵。
2. 优先只读接口：self、no-token、fake-object、A 查 B、B 查 A。
3. 垂直越权使用低权限访问管理 API，只证明边界缺失。
4. 写操作只在可回滚、必要且授权时执行。
5. 无第二账号、无对象样本或 self 基线失败时，标记 `blocked_need_material`。

需要材料时输出：账号 A/B、角色差异、测试对象 ID、测试组织/网点、可回滚对象。

## 文件/上传/下载/OSS/STS

触发：

- `upload`、`download`、`import`、`export`、`preview`、`convert`、`attachment`、`file`、`oss`、`sts`、`bucket`、`objectKey`、`fileKey`、`fileUrl`。

最小验证：

1. 判断是否未认证。
2. 上传链分段：accept、store、process、serve。
3. 检查是否返回 `fileKey/fileUrl/objectKey`，路径是否可预测。
4. 检查下载/预览/导出任务是否跨用户、跨租户或可猜测。
5. 检查导入解析是否触发 SSRF、XXE、CSV 公式、路径穿越或处理器风险。
6. 检查 OSS bucket、region、accessKey、STS token 是否暴露且是否有效。
7. 缺测试文件或测试账号时标记材料需求。

停止点：证明未授权读写、跨用户访问、STS 可用或处理链风险即可，不上传危险后门、不下载真实敏感文件全文。

## API 网关/开放平台

触发：

- `gateway`、`open`、`appkey`、`secret`、`signature`、`nonce`、`timestamp`、`from_appkey`、`to_appkey`、`apiId`。

最小验证：

1. 判断 AppKey/Secret 是否泄露且是否仍可用。
2. 验证签名算法、timestamp/nonce 重放、method/path/body 绑定。
3. 验证 API 权限是否绑定 app、租户、scope 和生产/测试环境。
4. 检查测试 app 是否可调用生产接口。
5. 检查未授权网关路由、Header 信任边界和后端服务错误差异。

需要材料时输出：测试 AppKey/Secret、测试 API 权限、测试订单/运单/手机号/网点、可回滚调用范围。

## VHost、重定向、目录爆破和 JS 分析

VHost/Host-SNI：

- 触发：证书 SAN、DNS、历史域名、JS 引用、默认站点、源站 IP、Host/SNI 差异。
- 只做低影响 Host/SNI 固定请求和响应差异分类。
- 隐藏后台、API、测试环境、源站业务进入 P0/P1；默认页、CDN/WAF 页、相同 body hash 降级。

重定向：

- 普通 Open Redirect 默认 P2/P3。
- 可组合登录回跳、OAuth callback、SSO ticket、移动端 deep link、token/code/session 信任链时升 P0/P1。

目录爆破：

- 重点关注 `/admin`、`/api`、`/swagger`、`/actuator`、`/upload`、`/download`、`/export`、`/internal`、`/test`、`/.git`、`/backup`。
- 空目录、403/404、SPA fallback、默认错误页快速降级。

JS 分析：

- 输出 API family、权限字段、核心对象参数、上传/下载/导入/导出、SSO/OAuth、测试域名、对象存储和移动端接口。
- 前端变量、公开配置和 source map 不是漏洞；只有服务端接受、凭据可用、数据可读或权限边界被证明才升级。

## 移动端

触发：

- 官方 Android/iOS 包、Deep Link、Universal Link、移动端 API base、旧接口、证书绑定、token、本地存储、日志和调试开关。

最小验证：

1. 先确认官方包来源，不从非官方渠道下载未知 APK/IPA。
2. 静态提取包名、域名、API base、Deep Link、Universal Link、证书绑定线索和本地存储键名。
3. 移动端 API 进入 Web/API 队列，验证认证、越权、文件、业务逻辑。
4. 动态绕过证书绑定、Frida/Hook 只在授权和测试设备边界内执行。

