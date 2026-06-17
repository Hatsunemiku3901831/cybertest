# Skill: SRC 信息收集与资产枚举

## 1. Skill 目标

本 Skill 用于指导 agent 在已授权的 SRC、企业安全测试、红队前置侦察或资产盘点场景中，执行信息收集与资产整理工作。

本 Skill 覆盖两个阶段：

被动信息收集：仅使用公开信息、搜索引擎、证书透明度、DNS 历史、空间测绘、公开代码仓库、应用商店、公开文档等来源，不直接访问或探测目标系统。

主动信息收集：对已确认资产进行低风险存活探测、DNS 解析、HTTP 指纹识别、TLS 证书读取、页面标题提取、低强度端口识别、公开 JS 与接口路径提取等操作。

本 Skill 的目标不是漏洞利用，而是形成准确、可追溯、可复核的资产清单，为后续分析或渗透测试提供基础。

---

## 2. 安全与边界原则

agent 必须遵守以下原则。


### 2.1 禁止行为

agent 不得执行以下行为：

- 不得尝试登录、爆破、撞库、枚举账号密码。
- 不得使用泄露的 token、cookie、AK/SK、密码、私钥或会话凭据。
- 不得执行漏洞利用、命令执行、SQL 注入验证、文件读取、反序列化测试、SSRF 回连测试等攻击性操作。（在本阶段不执行）
- 不得对登录、注册、找回密码、短信、邮件、支付等功能进行高频请求。
- 不得进行 DoS、压力测试、大规模端口扫描或高并发目录扫描。
- 不得对疑似第三方资产做深入测试，只能记录为“关联资产 / 需确认”。

### 2.2 主动探测限制

如允许主动探测，agent 应遵守：


- 控制请求频率，默认单主机不超过 1 请求 / 秒。
- 不进行参数 fuzz、漏洞 payload、身份绕过、批量提交表单。
- 端口识别只做服务发现，不做漏洞探测。
- 对 401、403、登录页、管理页只记录，不尝试登录。
- 对疑似敏感页面只做标题、状态码、响应头记录，不继续深入。

### 2.3 并行建模原则

agent 在收集每条资产时，必须同时完成三层记录，不得分阶段补记：

| 层次 | 动作 | 示例 |
|------|------|------|
| 资产层 | 记录资产属性（域名/IP/端口/标题/指纹） | `gygg.gztv.com` → nginx, Vue SPA |
| 信任边界层 | 观察认证方式、网络隔离、证书复用、部署差异 | 独立 wildcard 证书 ≠ 主站证书 → 可能不同团队/外包 |
| 攻击面标记 | 标注"这里可能有什么攻击面" | API 需签名 → 签名密钥可能在 JS 中 → 记录为 `sig_key_candidate` |

三条规则：

- 发现即标注：不能先收集完所有资产再回头补攻击面标记。
- 标注不验证：标注只是假设（"可能有"），验证在渗透阶段。
- 标注可废弃：渗透阶段证实标注无效的，正常归档不视为误报。

---

## 3. 输出要求

agent 最终必须输出以下结果。

### 3.1 资产总览

包含：

- 主域数量
- 子域数量
- 存活 Web 数量
- IP 数量
- 端口服务数量
- API 入口数量
- App / 小程序数量
- 第三方关联资产数量
- 高价值资产数量
- 待确认归属资产数量

### 3.2 资产明细表

每条资产至少包含以下字段：

json {   "asset_id": "唯一 ID",   "asset_type": "domain | subdomain | url | ip | port | app | mini_program | api | js | cloud | repo | third_party",   "asset": "资产值",   "root_domain": "根域名",   "url": "URL，如适用",   "ip": "IP，如适用",   "port": "端口，如适用",   "protocol": "http | https | tcp | udp | unknown",   "status": "alive | dead | redirect | forbidden | unauthorized | unknown",   "status_code": "HTTP 状态码，如适用",   "title": "页面标题，如适用",   "fingerprint": ["技术指纹"],   "cdn_or_waf": "CDN/WAF 信息",   "source": ["发现来源"],   "evidence": ["归属证据"],   "confidence": "high | medium | low",   "in_scope": "yes | no | unknown",   "risk_priority": "high | medium | low | unknown",   "notes": "备注" } 

### 3.3 高价值资产清单

至少列出：

- 管理后台
- 登录中心
- SSO / OAuth / Passport
- API 网关
- 开放平台
- Swagger / OpenAPI / GraphQL
- 测试环境 / 预发环境 / 灰度环境
- 文件上传 / 下载 / 导出功能
- 对象存储 / CDN 源
- 运维系统
- 监控系统
- CI/CD 系统
- 数据服务暴露面
- 老旧系统或历史域名

### 3.4 疑似越界资产清单

必须单独列出：

- 第三方 SaaS
- 供应商系统
- CDN 边缘节点
- 云厂商共享 IP
- 归属证据不足的 IP
- 员工个人仓库
- 非官方域名
- 仅品牌相似但无明确归属证据的站点

### 3.5 证据归档

每条关键资产尽量保存：

- 来源 URL
- DNS 记录
- 证书信息
- HTTP 响应头
- 页面标题
- 跳转链路
- 截图路径，如工具支持
- 发现时间
- 归属判断依据

### 3.6 攻击面关系图

必须输出资产间的关系图，至少包含以下边类型：

| 关系 | 含义 | 示例 |
|------|------|------|
| `resolves_to` | 域名解析到 IP | `gztv.com` → `119.32.4.92` |
| `shares_cert` | 共享 TLS 证书 | `www`, `mail`, `dev` 共享 `*.gztv.com` 证书 |
| `loads_js_from` | 页面加载 JS 资源 | `www.gztv.com` → `app.ecf2d1c9.js` |
| `calls_api` | JS 调用后端 API | `app.js` → `/plus-cloud-manage-app/liveChannel/...` |
| `redirects_to` | HTTP 重定向 | `oa.gztv.com` → `oa.gztv.com:7443` |
| `cname_to` | DNS CNAME 指向 | `www.gztv.com` → `bdsa.cdnbuild.net` (百度 CDN) |
| `contains_key` | JS/配置包含密钥 | `index-CpJWTnZ5.js` → `GZTVGYGGUCBYUN` |
| `is_third_party` | 属于第三方 | `upload.gztv.com` CNAME → 深信服 CDN |

JSON 格式：

```json
{
  "relationships": {
    "nodes": [
      {"id": "sub:gygg.gztv.com", "type": "subdomain", "label": "gygg.gztv.com", "attack_surface_tags": ["api_signature_required", "separate_cert"]},
      {"id": "js:gygg-index", "type": "js_file", "label": "index-CpJWTnZ5.js"}
    ],
    "edges": [
      {"from": "sub:gygg.gztv.com", "to": "js:gygg-index", "relation": "loads_js_from"},
      {"from": "js:gygg-index", "to": "secret:GZTVGYGGUCBYUN", "relation": "contains_key"}
    ]
  }
}
```

---

## 4. 全局执行流程

agent 应按以下顺序执行。

### 阶段 0：初始化与边界确认

检查：

- 是否存在明确目标。
- 是否存在排除范围。
- 是否允许主动探测。



输出：

- scope_summary
- allowed_actions
- blocked_actions
- initial_keywords

---

## 6. 被动信息收集清单

### 6.1 公司与品牌画像

收集内容：

- 公司中文名
- 公司英文名
- 公司简称
- 历史名称
- 子公司
- 关联公司
- 产品名
- App 名
- 开放平台名称
- 商标名
- 品牌缩写
- ICP 主体
- 统一社会信用代码，如公开可见
- 官方网站
- 帮助中心
- 开发者文档
- 隐私政策
- 用户协议
- 招聘页面
- 下载页面

判断目标：

- 建立品牌关键词字典。
- 建立业务线字典。
- 建立域名候选列表。
- 建立归属判断依据。

输出字段：

json {   "company_profile": {     "legal_names": [],     "brand_names": [],     "product_names": [],     "business_lines": [],     "official_sites": [],     "developer_sites": [],     "support_sites": [],     "evidence": []   } } 

---

### 6.2 主域名收集

来源：

- 用户提供的 SRC 范围。
- 官网链接。
- 帮助中心链接。
- 用户协议和隐私政策。
- 备案主体。
- 搜索引擎结果。
- 证书透明度。
- App 商店开发者页面。
- 公开代码仓库。
- 开发者文档。
- 开放平台。
- 招聘 JD 中的系统域名。
- 公众号、小程序、社交媒体官方链接。

记录：

- 主域名
- 发现来源
- 归属证据
- 是否在 SRC 范围内
- 是否疑似第三方
- 可信度

判断规则：

- 官方页面直接引用的域名可信度高。
- 备案主体一致的域名可信度高。
- 证书组织、页面版权、DNS、官方跳转多项一致时可信度高。
- 仅品牌名相似或页面 logo 相似，可信度低。
- CNAME 到第三方平台的域名需要标记第三方依赖。

---

### 6.3 子域名被动枚举

收集来源：

- 证书透明度日志。
- DNS 数据库。
- 历史 DNS 解析。
- 搜索引擎。
- 空间测绘平台。
- 公开网页爬取。
- sitemap.xml。
- robots.txt。
- JS 文件。
- GitHub / GitLab / Gitee 公开代码。
- App 静态资源。
- API 文档。
- 第三方安全平台历史数据。
- Web 缓存与归档页面。

高价值关键词：

text admin manager console dashboard backend internal intranet sso auth login passport oauth cas api gateway open developer partner merchant seller pay payment wallet cashier order user account profile upload download file static cdn img media assets docs doc wiki swagger openapi graphql yapi apifox test dev stage staging uat pre beta gray sandbox demo ops monitor grafana kibana prometheus jenkins gitlab nexus harbor sonar bi data report crm erp oa hr finance 

处理规则：

- 对收集到的子域名去重。
- 统一小写。
- 去除协议、路径、端口。
- 识别通配符 DNS。
- 记录来源。
- 对每个子域标记初始可信度。
- 对第三方 CNAME 标记 third_party_candidate。

输出：

json {   "subdomain": "api.example.com",   "root_domain": "example.com",   "sources": ["ct_log", "search_engine", "js"],   "confidence": "high",   "notes": "多来源命中" } 

**攻击面提示**：每发现一个子域名，同时记录：

- 是否使用独立证书（→ 可能独立部署/不同团队）
- 是否与已知 IP 重叠（→ 同一系统）或独立 IP（→ 新攻击面）
- 命名是否暗示环境类型（dev/test/staging/uat/admin/internal）

---

### 6.4 DNS 信息收集

对已确认域名收集：

- A 记录
- AAAA 记录
- CNAME 记录
- NS 记录
- MX 记录
- TXT 记录
- SOA 记录
- CAA 记录
- 历史解析记录
- DNS 服务商
- CDN / WAF 服务商
- 对象存储 CNAME
- 第三方 SaaS CNAME

重点关注：

- CNAME 指向云存储。
- CNAME 指向未配置第三方服务。
- TXT 暴露平台验证信息。
- MX 暴露企业邮箱服务商。
- 历史解析暴露老 IP。
- 多个子域解析到同一 IP，可能属于同一系统。
- 泛解析导致的假阳性。



---

### 6.5 证书透明度收集

收集内容：

- 证书 CN
- SAN 域名
- 证书颁发者
- 证书有效期
- 证书组织信息
- 首次发现时间
- 最近发现时间
- 通配符证书
- 历史测试域名

处理规则：

- 从 SAN 提取子域名。
- 去重。
- 识别历史环境。
- 识别内网命名习惯，但不得主动访问内网地址。
- 结合证书组织判断归属。
- 对过期证书中的域名标记为历史资产。

高价值特征：

- *.dev.example.com
- *.test.example.com
- *.staging.example.com
- admin.example.com
- internal.example.com
- vpn.example.com
- sso.example.com
- api.example.com

---

### 6.6 搜索引擎公开检索

搜索目标：

- 主域名
- 子域名
- 登录入口
- 后台入口
- API 文档
- 文件目录
- 错误页面
- 测试环境
- 公开文档
- 公开配置
- 开放平台
- 旧站点

建议搜索关键词组合：

text site:example.com site:*.example.com "example.com" "api" "example.com" "swagger" "example.com" "admin" "example.com" "login" "example.com" "staging" "example.com" "test" "example.com" "dev" "example.com" "upload" "example.com" "download" "example.com" "openapi" "example.com" "graphql" "example.com" "sourceMappingURL" "example.com" "accessKey" "example.com" "bucket" "公司名" "开发者平台" "公司名" "开放平台" "公司名" "API" "公司名" "后台" 



---

### 6.7 公开代码仓库收集

搜索范围：

- GitHub
- GitLab
- Gitee
- Bitbucket
- npm
- PyPI
- Maven
- Docker Hub
- 公共镜像仓库
- 公开 SDK 仓库
- 官方组织仓库
- 员工公开仓库，仅做归属谨慎判断

搜索关键词：

- 公司名
- 品牌名
- 产品名
- 主域名
- 子域名
- App 包名
- API 域名
- SDK 名称
- 备案主体
- 版权文本
- 邮箱域名

重点文件：

text .env .env.example config.yml config.yaml application.yml application.properties bootstrap.yml settings.py config.js config.ts package.json pom.xml build.gradle Dockerfile docker-compose.yml Jenkinsfile .gitlab-ci.yml .github/workflows/* k8s/*.yaml README.md docs/* openapi.json swagger.json postman_collection.json 

可提取信息：

- API 域名
- 测试环境域名
- 文档地址
- 对象存储桶名
- AppID
- ClientID
- SDK 配置
- 内部服务命名
- 路径结构
- 开放接口示例

敏感信息处理：

- 标记为 sensitive_exposure_candidate，交由人工确认。

**攻击面提示**：搜索到源码/配置时，除了记录资源本身，必须立即标注：

- 暴露了哪些内部域名/IP（→ 内网拓扑碎片）
- 暴露了哪些中间件/数据库连接信息（→ 基础设施攻击面）
- 是否包含 CI/CD 配置（→ 供应链攻击路径）

---

### 6.8 App 与移动端信息收集

被动来源：

- iOS App Store
- Google Play
- 国内安卓应用市场
- 官网下载页
- App 更新日志
- App 隐私政策
- App 用户协议
- SDK 文档
- 应用包公开元数据

收集字段：

- App 名称
- 包名
- Bundle ID
- 开发者名称
- 版本号
- 更新时间
- 下载来源
- 官网链接
- 隐私政策链接
- API 域名
- H5 域名
- 推送服务
- 统计 SDK
- 支付 SDK
- 地图 SDK
- 客服 SDK

允许的静态分析：

- 从公开安装包中提取字符串。
- 提取 URL、域名、接口路径、配置文件。
- 提取 SDK 名称。
- 提取 WebView 域名。
- 提取环境标识，例如 test、pre、uat、sandbox。

禁止：

- 不绕过加固。
- 不 Hook 生产接口。
- 不伪造设备或用户身份。
- 不使用真实用户数据。
- 不进行接口攻击测试。

**攻击面提示**：静态分析 APK/IPA 时，除了收集域名/API，同时标注：

- 硬编码密钥/证书（→ 认证绕过候选）
- 测试环境/内部环境域名（→ 通常防护较弱）
- 第三方 SDK 初始化的 AppID/Key（→ 越权使用第三方资源）

---

### 6.9 小程序与公众号信息收集

收集范围：

- 微信小程序
- 支付宝小程序
- 抖音小程序
- 百度小程序
- 快应用
- 公众号菜单
- 公众号文章链接
- H5 活动页

收集字段：

- 小程序名称
- 原始 ID
- 主体信息
- 关联公众号
- 服务类目
- 页面路径
- H5 域名
- API 域名
- 登录方式
- 支付能力
- 上传能力
- 活动页面

注意：

- 不抓取用户数据。
- 不高频访问接口。
- 不模拟非法身份。
- 仅记录公开入口和资产关系。

---

### 6.10 云资产与对象存储收集

被动识别：

- OSS
- COS
- OBS
- S3
- GCS
- Azure Blob
- CDN 回源
- 云函数入口
- API Gateway
- Serverless 域名
- Docker Registry
- Harbor
- Kubernetes Dashboard
- 云监控入口

可记录：

- 存储桶名称
- 区域
- 绑定域名
- CNAME 记录
- 静态资源 URL
- 公开访问状态
- 归属证据

禁止：


- 上传、删除、覆盖文件。


---

### 6.11 第三方与供应链资产识别

识别以下第三方依赖：

- 客服系统
- 问卷系统
- 表单系统
- 统计分析平台
- 支付平台
- 风控平台
- 登录身份服务
- CDN
- 云服务
- 邮件服务
- 短信服务
- 营销活动平台
- IM / 直播 / 推送 SDK
- 文档协作平台
- 工单系统

处理规则：

- 标记为 third_party.
- 记录其与目标的关系。
- 不进行主动测试。
- 如果 SRC 规则明确允许测试，再进入主动阶段。
- 否则输出到“疑似越界资产清单”。

---

## 6. 主动信息收集清单

主动信息收集只针对已确认授权资产执行。

### 6.1 存活探测

对已确认域名执行：

- DNS 解析。
- HTTP / HTTPS 请求。
- 状态码记录。
- 页面标题提取。
- 跳转链路记录。
- 响应头记录。
- TLS 证书读取。
- favicon hash 计算，如工具支持。
- 简单技术指纹识别。

请求方法：

- 优先 HEAD。
- HEAD 不支持时使用 GET。
- 不提交 POST 表单。
- 不携带攻击性 payload。
- 不自动跟随超过 5 层跳转。

记录字段：

json {   "url": "https://api.example.com",   "alive": true,   "status_code": 200,   "title": "API Gateway",   "redirect_chain": [],   "headers": {},   "tls": {},   "fingerprint": [],   "screenshot": "path/to/screenshot.png" } 

状态分类：

- alive: 200、204、301、302、307、308、401、403
- dead: 连接失败、DNS 不解析、长期超时
- forbidden: 403
- unauthorized: 401
- redirect: 301 / 302 / 307 / 308
- error: 500 / 502 / 503 / 504
- unknown: 无法判断

**攻击面提示**：存活探测结果需要立即分类标注：

- `403` + 非通用页面 → 标记为 `internal_system_candidate`
- `401` + `WWW-Authenticate` → 记录认证类型（Basic/NTLM/Bearer）
- `500/502/503` → 可能暴露内部错误信息/框架名/版本 → 记录为 `error_info_leak_candidate`
- 跳转链中域名变化 → 记录完整跳转路径，标注信任边界

---

### 6.2 HTTP 指纹识别

收集：

- Server header
- X-Powered-By
- Set-Cookie 名称
- 框架特征
- 前端框架
- 后端语言
- CDN / WAF
- 中间件
- CMS
- 网关
- 负载均衡
- 错误页面
- 静态资源路径
- favicon hash

常见指纹类型：

- Nginx
- Apache
- IIS
- Tomcat
- Jetty
- Spring Boot
- Express
- Next.js
- Nuxt
- Vue
- React
- Angular
- WordPress
- Drupal
- Jenkins
- GitLab
- Grafana
- Kibana
- Swagger
- Knife4j
- YApi
- Apifox
- GraphQL Playground

注意：

- 只做识别，不做漏洞版本利用。
- 如果发现版本号，仅记录版本和来源。
- 不执行 CVE 验证。

---

### 6.3 TLS / 证书读取

对 HTTPS 资产读取：

- 证书 CN
- SAN
- Issuer
- Not Before
- Not After
- 证书链
- 是否过期
- 是否通配符
- 是否与域名匹配
- 证书组织字段
- 证书序列号

用途：

- 验证资产归属。
- 发现同证书其他域名。
- 识别历史或测试环境。
- 判断是否为 CDN 证书。
- 识别多业务复用证书。

禁止：

- 不攻击 TLS 配置。
- 不进行弱加密利用。
- 不做中间人或降级测试。

---

### 6.4 端口与服务识别

仅当 allowed_port_scan = true 时执行。

原则：

- 只对确认授权 IP 执行。
- 优先扫描常见 Web 端口。
- 不做漏洞脚本扫描。
- 不做认证尝试。
- 控制速率和并发。
- 对第三方云共享 IP 谨慎处理。

默认端口清单：

text 80 443 8080 8443 8000 8001 8888 9000 9443 3000 5000 7001 7002 9090 

如规则允许，可扩展识别：

text 21 22 25 53 110 143 389 445 465 587 993 995 1433 1521 3306 3389 5432 5672 5900 6379 9200 9300 11211 15672 27017 50070 5601 9092 10250 

记录：

json {   "ip": "1.2.3.4",   "port": 443,   "protocol": "https",   "service": "nginx",   "version": "unknown",   "banner": "limited banner",   "source": "active_probe",   "risk_priority": "medium" } 

禁止：

- 不使用漏洞扫描脚本。
- 不使用默认密码尝试。
- 不访问数据库内容。
- 不连接 Redis / MongoDB / Elasticsearch 查询数据。
- 不操作 Jenkins、GitLab、Harbor、Kibana 等管理系统。
- 不扫描未确认归属网段。

---

### 6.5 Web 路径与公开文件识别

仅当目标允许低风险主动探测时执行。

允许检查的公开路径：

text / robots.txt sitemap.xml favicon.ico manifest.json security.txt humans.txt crossdomain.xml .well-known/security.txt .well-known/assetlinks.json .well-known/apple-app-site-association swagger-ui/ swagger-ui.html swagger/index.html api-docs v2/api-docs v3/api-docs openapi.json swagger.json graphql graphiql 

注意：

- 只检查少量公开常见路径。
- 不进行大字典目录爆破。
- 不使用敏感路径字典。
- 不递归爬取后台系统。
- 如果出现 401 / 403，记录后停止。
- 如果发现 API 文档，记录标题、URL、认证要求，不批量调用接口。

---

### 6.6 JS 文件与接口路径提取

对公开 Web 页面：

收集：

- HTML 中引用的 JS 文件。
- 异步加载 JS。
- source map 引用。
- 静态资源域名。
- API Base URL。
- 接口路径。
- 环境变量名。
- AppID / ClientID。
- WebSocket 地址。
- GraphQL 地址。
- 上传 / 下载路径。
- 第三方 SDK 地址。

提取正则目标：

text https?://[a-zA-Z0-9._~:/?#@!$&'()*+,;=%-]+ [a-zA-Z0-9.-]+\.[a-zA-Z]{2,} \/api\/[a-zA-Z0-9._~:/?#@!$&'()*+,;=%-]* \/v[0-9]+\/[a-zA-Z0-9._~:/?#@!$&'()*+,;=%-]* wss?:\/\/[a-zA-Z0-9._~:/?#@!$&'()*+,;=%-]+ sourceMappingURL=.*\.map 

敏感关键词：

text accessKey secretKey apiKey token Authorization Bearer client_secret private_key password bucket oss cos s3 endpoint internal debug test staging sandbox 

处理规则：

- 发现密钥只记录，不使用。
- 发现 source map 只记录公开暴露情况，不还原和审计完整源码，除非授权明确允许。
- 提取到的新域名回到被动归属判断流程。
- 提取到的新接口标记为 api_candidate。

**攻击面提示**：每提取到一个 API 端点或密钥，立即建立关系边：

- `api_path` → 所属 JS 文件 → 所属域名（调用链溯源）
- `key/secret` → 使用该密钥的 API（权限面评估）
- `sourceMappingURL` → 标记为 `source_map_candidate`（即使不下载也记录存在性）
- 不同 JS 文件中出现同一 API host → 标注为 `shared_backend`

---

### 6.7 API 入口识别

识别来源：

- 子域名。
- JS。
- App。
- 小程序。
- 开放平台。
- Swagger / OpenAPI。
- GraphQL。
- Postman Collection。
- SDK 示例。
- 文档页面。

记录：

- API Base URL
- 接口路径
- 方法
- 认证方式
- 版本
- 业务模块
- 是否需要登录
- 是否有文档
- 是否高价值
- 来源

高价值 API 类型：

- 用户信息
- 账号体系
- 登录注册
- 找回密码
- 订单
- 支付
- 钱包
- 发票
- 合同
- 文件上传
- 文件下载
- 导入导出
- 权限管理
- 组织架构
- 消息通知
- 后台管理
- 商家管理
- 开放平台授权

禁止：

- 不调用需要认证的接口。
- 不遍历 ID。
- 不测试越权。
- 不批量请求数据。
- 不发送修改类请求。
- 不构造异常参数。

---

## 7. 资产归属判断规则

### 7.1 高可信归属

满足以下任意多项时可标记高可信：

- SRC 范围明确包含。
- 官方网站直接链接。
- ICP 主体一致。
- 证书组织一致。
- DNS NS / TXT / CNAME 与目标一致。
- 页面版权包含目标公司。
- 登录页品牌与目标一致，且域名属于目标主域。
- App 官方页面引用。
- 开发者文档引用。
- 多个独立来源交叉验证。

### 7.2 中可信归属

满足：

- 域名与品牌高度相关。
- 证书或页面存在目标线索。
- 搜索结果显示关联。
- 历史 DNS 与目标 IP 相关。
- 公开代码中引用。
- 但缺少官方确认。

### 7.3 低可信归属

满足：

- 仅名称相似。
- 仅 logo 相似。
- 仅第三方页面出现目标名。
- 仅员工仓库出现。
- 仅 CNAME 指向目标相关服务。
- 归属主体不一致。

### 7.4 处理策略

- high: 可进入后续授权范围判断。
- medium: 可继续被动交叉验证，主动探测前需要确认。
- low: 不主动探测，仅记录。
- unknown: 放入待确认清单。

---

## 8. 资产优先级评分

agent 应为资产打优先级。

### 8.1 高优先级

包括：

- 测试环境。
- 预发环境。
- 灰度环境。
- 管理后台。
- SSO / 登录中心。
- API 网关。
- 开放平台。
- Swagger / OpenAPI / GraphQL。
- 文件上传下载。
- 对象存储绑定域名。
- 运维平台。
- 监控平台。
- CI/CD 平台。
- 老旧系统。
- 历史域名但仍存活。
- 暴露版本号的中间件。
- 403 / 401 的疑似内部系统。
- 错误页面暴露框架或服务名。

### 8.2 中优先级

包括：

- 普通业务系统。
- H5 活动页。
- App API。
- 小程序 API。
- 商家端。
- 开发者文档。
- 帮助中心中暴露的接口。
- 带登录的业务平台。
- 非核心但存活的子域。

### 8.3 低优先级

包括：

- 纯静态官网。
- CDN 静态资源。
- 图片域名。
- 帮助文档。
- 跳转页。
- 第三方 SaaS 关联页。
- 无业务功能页面。

### 8.4 评分字段

json {   "risk_priority": "high | medium | low | unknown",   "priority_reason": [     "test_environment",     "admin_login",     "api_documentation",     "file_upload",     "third_party_dependency"   ] } 

### 8.5 攻击路径组合评分

高优先级资产的判断不仅看资产本身，还要看组合潜力。满足以下任一组合条件，单条资产可升一级优先级：

| 组合条件 | 升权逻辑 |
|----------|----------|
| API 端点 + 同域 JS 含签名密钥 | 可构造合法请求 → 升为高 |
| 403 页面 + 同 IP 存在 200 资产 | 可能有路径绕过 → 升为中 |
| 独立证书子域 + 不同 IP | 独立部署系统 → 升一级 |
| dev/test/staging 子域 + 存活 | 测试环境通常弱防护 → 升为高 |
| CNAME 到第三方 + 第三方已知漏洞 | 供应链攻击路径 → 升为高 |
| 硬编码 AppID + 对应 SDK 初始化代码 | 可越权使用第三方服务 → 升为中 |

---

## 9. 去重、标准化与关联

### 9.1 域名标准化

处理：

- 转小写。
- 去除协议。
- 去除路径。
- 去除默认端口。
- Punycode 统一处理。
- 去除末尾点。
- 合并重复 CNAME。
- 合并重复 IP。
- 合并重复页面标题和 favicon。

### 9.2 URL 标准化

处理：

- 保留协议。
- 保留端口。
- 移除 fragment。
- 查询参数按需归一。
- 跳转前后都记录。
- HTTP 与 HTTPS 分开记录。
- 不同端口视为不同资产。

### 9.3 IP 关联

关联：

- 域名到 IP。
- IP 到端口。
- 端口到服务。
- 服务到 Web 标题。
- Web 到业务线。
- 证书到域名。
- JS 到 API。
- API 到业务模块。
- App 到 API。
- 小程序到 H5。
- H5 到接口。

### 9.4 关系图结构

json {   "nodes": [     {       "id": "domain:example.com",       "type": "domain",       "label": "example.com"     },     {       "id": "subdomain:api.example.com",       "type": "subdomain",       "label": "api.example.com"     }   ],   "edges": [     {       "from": "domain:example.com",       "to": "subdomain:api.example.com",       "relation": "has_subdomain"     }   ] } 

---


---

## 10. 质量检查

agent 完成信息收集后，必须检查：

- 是否覆盖所有用户提供的主域。
- 是否记录 SRC 范围和排除范围。
- 是否区分被动来源和主动来源。
- 是否识别并剔除泛解析假阳性。
- 是否记录每个资产的发现来源。
- 是否记录每个资产的归属证据。
- 是否标记第三方资产。
- 是否标记待确认资产。
- 是否标记高价值资产。
- 是否避免对越界资产主动探测。
- 是否避免使用敏感凭据。
- 是否避免漏洞利用和攻击性验证。
- 是否形成资产关系。
- 是否生成最终报告。
- 是否输出机器可读结果。
- 是否每条高价值资产都有对应的攻击面关系边。
- 是否所有独立证书子域都标注了信任边界。
- 是否所有提取到的密钥/AppID/Secret 都有使用场景标注。

---

## 11. 最终报告结构

agent 应输出以下报告结构。

markdown # 信息收集报告  ## 1. 执行摘要  - 目标： - 授权范围： - 排除范围： - 是否执行主动探测： - 执行时间： - 数据来源：  ## 2. 资产统计  | 类型 | 数量 | |---|---:| | 主域 |  | | 子域 |  | | 存活 Web |  | | IP |  | | 开放端口 |  | | API 入口 |  | | App |  | | 小程序 |  | | 第三方资产 |  | | 高价值资产 |  | | 待确认资产 |  |  ## 3. 高价值资产  | 资产 | 类型 | 状态 | 优先级 | 原因 | 证据 | |---|---|---|---|---|---|  ## 4. 主域与子域资产  | 域名 | 类型 | 状态 | IP | 标题 | 来源 | 归属可信度 | |---|---|---|---|---|---|---|  ## 5. Web 资产  | URL | 状态码 | 标题 | 指纹 | CDN/WAF | 优先级 | 备注 | |---|---:|---|---|---|---|---|  ## 6. API 资产  | API | 来源 | 认证方式 | 版本 | 业务模块 | 优先级 | 备注 | |---|---|---|---|---|---|---|  ## 7. IP 与端口资产  | IP | 端口 | 协议 | 服务 | 归属证据 | 优先级 | |---|---:|---|---|---|---|  ## 8. App / 小程序资产  | 名称 | 类型 | 包名/ID | 关联域名 | API | 来源 | |---|---|---|---|---|---|  ## 9. 云资产与对象存储  | 资产 | 类型 | 绑定域名 | 公开状态 | 归属证据 | 备注 | |---|---|---|---|---|---|  ## 10. 第三方与疑似越界资产  | 资产 | 类型 | 第三方服务商 | 与目标关系 | 处理建议 | |---|---|---|---|---|  ## 11. 待确认资产  | 资产 | 发现来源 | 疑点 | 需要确认的问题 | |---|---|---|---|  ## 12. 后续建议  - 建议优先分析： - 建议暂不测试： - 需要人工确认： - 需要补充授权： 

---

## 12. 机器可读输出格式

agent 应同时输出 JSON 结果，方便后续自动化处理。

json {   "target": {     "name": "",     "scope": [],     "out_of_scope": [],     "allowed_active_recon": false,     "allowed_port_scan": false   },   "summary": {     "root_domains": 0,     "subdomains": 0,     "alive_web": 0,     "ips": 0,     "ports": 0,     "apis": 0,     "apps": 0,     "mini_programs": 0,     "third_party_assets": 0,     "high_value_assets": 0,     "unknown_scope_assets": 0   },   "assets": [],   "high_value_assets": [],   "third_party_assets": [],   "unknown_assets": [],   "evidence": [],   "relationships": {     "nodes": [],     "edges": []   },   "warnings": [],   "next_steps": [] } 

---

## 13. 异常与停止条件

agent 遇到以下情况必须停止相关动作并记录：

- 目标范围不明确。
- 资产疑似第三方。
- 用户未允许主动探测。
- 出现登录页且需要凭据。
- 出现验证码、风控、频率限制。
- 请求导致错误率升高。
- 目标返回封禁、警告或异常提示。
- 资产归属无法确认。

记录格式：

json {   "event": "stopped_action",   "asset": "",   "reason": "",   "time": "",   "recommended_action": "manual_review" } 

---

## 14. 最小化验证原则

agent 对任何风险发现只做最小化验证。

允许：

- 记录 URL。
- 记录状态码。
- 记录页面标题。
- 记录响应头。
- 记录公开证书。
- 记录公开文档入口。
- 记录公开 JS 中的字符串。
- 记录对象存储绑定域名。
- 记录是否需要认证。

不允许：

- 下载大量数据。
- 遍历文件。
- 调用修改接口。
- 验证密钥权限。
- 使用他人凭据。
- 读取用户数据。
- 修改服务器状态。
- 上传文件。
- 删除文件。
- 执行命令。
- 利用漏洞。

---

## 15. 推荐执行顺序

agent 应按以下顺序执行完整流程：

1. 读取目标和授权范围。
2. 解析排除范围和测试限制。
3. 建立品牌关键词、公司主体和产品线。
4. 收集主域名。
5. 被动枚举子域名。
6. 收集 DNS、证书、历史解析。
7. 搜索公开网页、文档和代码仓库。
8. 收集 App、小程序、公众号、开放平台。
9. 识别第三方与供应链资产。
10. 进行资产归属判断。
11. 对授权资产执行存活探测。
12. 提取 HTTP 标题、响应头、证书、指纹。
13. 如允许，执行低风险端口识别。
14. 提取公开 JS、API 路径和文档入口。
15. 识别高价值资产。
16. 标记越界、第三方、待确认资产。
17. 去重、归并、建立资产关系。
18. 输出 Markdown 报告。
19. 输出 JSON 资产结果。
20. 输出后续人工确认事项。

以上 20 步不是严格线性的。agent 在执行中发现以下信号时，应即时回溯前置步骤：

- 发现新域名 → 回到步骤 4-5（主域名/子域名枚举）
- 发现新 API host → 回到步骤 11-12（存活探测/指纹）
- 发现密钥/凭据 → 回到步骤 14-15（JS 分析/高价值标注）
- 发现新 IP 段 → 回到步骤 13（端口识别，如授权允许）

目标不是按顺序完成 20 步，而是在所有信号收敛后覆盖所有 20 步。

---

## 16. Agent 输出风格要求

agent 输出应满足：

- 清晰区分“确认资产”和“疑似资产”。
- 清晰区分“授权范围内”和“待确认 / 越界”。
- 每个关键结论都给出来源或证据。
- 不夸大归属判断。
- 不把第三方资产误判为目标资产。
- 不输出敏感信息明文。
- 对敏感发现做脱敏展示。
- 对无法确认的信息明确标记为 unknown。
- 对被动收集和主动探测结果分开展示。

---

## 17. 示例任务输入

json {   "target_company": "Example Inc.",   "target_domain": "example.com",   "target_scope": [     "*.example.com",     "example.com"   ],   "out_of_scope": [     "third-party SaaS",     "employee personal assets",     "payment provider infrastructure"   ],   "allowed_active_recon": true,   "allowed_port_scan": false,   "rate_limit": "1 request per second per host",   "report_format": ["markdown", "json"] } 

---

## 18. 示例最终结论摘要

markdown 本次信息收集共发现 1 个主域、248 个候选子域、96 个存活 Web 资产、34 个 IP、17 个 API 入口、3 个 App 相关入口、12 个第三方关联资产。  其中高价值资产包括：登录中心、开放平台、API 网关、Swagger 文档入口、预发环境、文件上传服务和对象存储绑定域名。  共有 9 个资产归属证据不足，已标记为待确认。共有 12 个资产疑似属于第三方 SaaS 或供应商系统，未执行主动探测。 