# Skill: 基础信息收集（弱模型专用）

## 1. Skill 目标

本 Skill 是**弱模型**（deepseek/sonnet）专用的资产采集 Skill。只执行”采集”动作，不执行”分析”动作。

本 Skill 覆盖两个阶段：

被动信息收集：仅使用公开信息、搜索引擎、证书透明度、DNS 历史、空间测绘、公开代码仓库、应用商店、公开文档等来源，不直接访问或探测目标系统。

主动信息收集：对已确认资产进行低风险存活探测、DNS 解析、HTTP 指纹识别、TLS 证书读取、页面标题提取、低强度端口识别、JS 文件下载等操作。

**核心原则：采集不分析。** 本 Skill 产出结构化数据包（见第 4 节），交给 `search-modeling.md`（强模型）进行深度分析。

本 Skill 的目标不是漏洞利用，也不是攻击面建模，而是形成完整、可追溯、可复核的原始资产数据包。

设计模型：deepseek（极低成本执行采集）→ 产出 JSON → opus（仅消费数据包做分析）

---

## 2. 安全与边界原则

agent 必须遵守以下原则。


### 2.1 禁止行为

agent 不得执行以下行为：

- 不得尝试登录、爆破、撞库、枚举账号密码。
- 不得使用泄露的 token、cookie、AK/SK、密码、私钥或会话凭据。
- 不得执行漏洞利用、命令执行、SQL 注入验证、文件读取、反序列化测试、SSRF 回连测试等攻击性操作。
- 不得对登录、注册、找回密码、短信、邮件、支付等功能进行高频请求。
- 不得进行 DoS、压力测试、大规模端口扫描或高并发目录扫描。
- 不得对疑似第三方资产做深入测试，只能记录为”关联资产 / 需确认”。

### 2.2 主动探测限制

如允许主动探测，agent 应遵守：

- 控制请求频率，默认单主机不超过 1 请求 / 秒。
- 不进行参数 fuzz、漏洞 payload、身份绕过、批量提交表单。
- 端口识别只做服务发现，不做漏洞探测。
- 对 401、403、登录页、管理页只记录，不尝试登录。
- 对疑似敏感页面只做标题、状态码、响应头记录，不继续深入。

### 2.3 弱模型行为边界

本 Skill 使用弱模型。以下动作**故意不做**，留给强模型 (`search-modeling.md`)：

| 不做 | 原因 | 谁做 |
|------|------|------|
| 不分析 JS 内容（不找密钥/签名/API 逻辑） | 需要密码学/语义推理 | 强模型 |
| 不画攻击面关系图 | 需要多跳关联推理 | 强模型 |
| 不评资产优先级（高/中/低） | 需要组合判断 | 强模型 |
| 不做资产归属的 high/medium/low 判定 | 需要交叉验证推理 | 强模型 |
| 不判断”这个 403 是不是内部系统” | 需要上下文推断 | 强模型 |
| 不标注攻击面标记 (sig_key_candidate 等) | 需要攻击思维 | 强模型 |

**多采勿漏原则**：弱模型宁可多采、多存原文，也不要漏。漏掉的 JS 原文强模型无法凭空恢复。

- HTML 中所有 `<script src>` + 所有出现的 `.js` / `.map` 字面量路径 → 全部下载原文
- 所有响应头 → 全量保留
- 跳转链每跳 → 完整记录 URL + 状态码
- 所有 HTTP 响应 body → 保存前 500 + 后 200 字符（尾部常含错误信息）

### 2.4 TUN 模式 / 代理环境防护

若本机开启 TUN/虚拟网卡/代理，系统 DNS 可能返回 Fake-IP。必须遵守：

- DNS 解析公网域名优先用 `dig +tcp @1.1.1.1` 或 `dig +tcp @8.8.8.8`
- 端口扫描只输入真实 IP 并禁用 DNS：`nmap -n -Pn <real_ip>`
- Web 验证必须用固定 Host/SNI：`curl --resolve host:443:real_ip https://host/`
- 发现 `198.18.0.0/15` 或全端口异常开放结果 → 立即标记为 `fake_ip_noise`，不写入资产
- 所有从代理出口 IP 访问的 Web 响应，可能受 Geo/WAF 影响 → 标注 `tun_affected: true`

---

## 3. 输出要求

本 Skill 输出两部分：供人阅读的资产清单 + 供强模型分析的数据包。

### 3.1 资产总览

包含（仅填计数，不评高价值）：

- 主域数量
- 子域数量
- 存活 Web 数量
- IP 数量
- 端口服务数量
- 下载的 JS 文件数量
- App / 小程序数量
- 第三方关联资产数量
- 待确认归属资产数量

### 3.2 资产明细表

每条资产至少包含以下字段。标注 `[留空]` 的字段由强模型后续填写：

```json
{
  "asset_id": "唯一 ID",
  "asset_type": "domain | subdomain | url | ip | port | app | mini_program | api | js | cloud | repo | third_party",
  "asset": "资产值",
  "root_domain": "根域名",
  "url": "URL",
  "ip": "IP",
  "port": "端口",
  "protocol": "http | https | tcp | udp | unknown",
  "status": "alive | dead | redirect | forbidden | unauthorized | uncertain",
  "status_code": "HTTP 状态码",
  "title": "页面标题",
  "headers": {"server": "", "set-cookie": "", "x-powered-by": ""},
  "tls": {"cn": "", "san": [], "issuer": "", "not_after": ""},
  "cdn_or_waf": "CDN/WAF 信息",
  "source": ["发现来源"],
  "evidence": ["归属证据"],
  "confidence": "[留空]",
  "in_scope": "yes | no | unknown",
  "risk_priority": "[留空]",
  "js_files": ["url1", "url2"],
  "body_snippet": "前500+后200字符",
  "tun_affected": false,
  "notes": "备注"
}
```

注意：
- `confidence` 留空 — 弱模型不做资产归属判定
- `risk_priority` 留空 — 弱模型不做优先级评分
- `status` 新增 `uncertain` — 无法确定死活的（可能是 WAF/TUN/限流导致）不要标 dead
- `tun_affected` — TUN 模式下访问的资产，强模型需要知道可能受 Geo/WAF 影响

### 3.3 疑似越界资产清单

必须单独列出（弱模型能做：看 CNAME 指向第三方域名就标记）：

- 第三方 SaaS
- 供应商系统
- CDN 边缘节点
- 云厂商共享 IP
- 归属证据不足的 IP
- 员工个人仓库
- 非官方域名
- 仅品牌相似但无明确归属证据的站点

### 3.4 证据归档

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

### 3.5 不做的事（留给 search-modeling.md）

以下输出不在本 Skill 范围内：

- ❌ 高价值资产清单（需要组合评分，强模型做）
- ❌ 攻击面关系图（需要多跳推理，强模型做）
- ❌ 资产优先级评分（需要攻击路径判断，强模型做）

---

## 4. 传给深度建模的数据包规范

本 Skill 完成后，必须输出以下 JSON 给 `search-modeling.md` 使用。这是弱模型和强模型之间的唯一接口。

### 4.1 数据包格式

```json
{
  "pass1_meta": {
    "generated_at": "",
    "model": "deepseek | sonnet",
    "tun_mode": false,
    "total_subdomains": 0,
    "total_ips": 0,
    "total_js_files": 0
  },
  "domains": [
    {"domain": "", "registrar": "", "ns": [], "mx": [], "icp": ""}
  ],
  "subdomains": [
    {
      "domain": "",
      "ip": "",
      "cname": "",
      "status_code": 0,
      "title": "",
      "headers": {},
      "redirect_chain": [],
      "tls": {},
      "js_files": [],
      "js_content": {"url1": "<raw js content>", "url2": "<raw js content>"},
      "body_snippet": ""
    }
  ],
  "ips": [
    {"ip": "", "open_ports": [], "service_banners": {}}
  ],
  "certs": [
    {"cn": "", "san": [], "issuer": "", "not_after": "", "covers_domains": []}
  ],
  "dns_records": {},
  "historical_urls": [],
  "warnings": {
    "tun_affected": [],
    "rate_limited": [],
    "timeout": [],
    "fake_ip_detected": []
  }
}
```

### 4.2 数据包质量规则

- `js_content` 必须存 JS 原文，不是摘要。强模型需要看到混淆前的字面量字符串。
- `body_snippet` 存前 500 + 后 200 字符。对 500/502/503 响应，额外保存全量 body（错误信息常在中间甚至尾部）。
- `status` 为 `uncertain` 的资产不要丢弃。强模型可能结合其他信号判断死活。
- `warnings` 必须如实记录。TUN 影响、限流、超时的资产，强模型需要知道数据可能不可靠。

---

## 5. 全局执行流程

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

**注意**：记录以下原始信息（不分析含义，留给强模型）：
- 证书 CN/SAN（是否与主域共享泛域名证书）
- IP 是否与已知 IP 重叠
- 子域名命名中的环境关键词（如 dev/test/staging）

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

**注意**：搜索到源码/配置时，下载原文并保存在数据包中。不分析内容（由强模型分析）。标记文件类型和来源。

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

**注意**：APK/IPA 静态分析时，提取所有字符串/URL/域名原文，保存到数据包。不分析含义（由强模型完成）。

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

**对非 200 响应的处理**（弱模型只记录，不分类标注）：
- `403` → 记录，不判断是否为内部系统
- `401` → 记录 `WWW-Authenticate` 头原文（不分析认证类型）
- `500/502/503` → 保存全量 body（错误信息可能含框架/版本线索，由强模型提取）
- 跳转链 → 完整记录每跳 URL + 状态码（不标注信任边界，强模型判断）
- 所有非 200 标记 `status: uncertain`，不标 `dead`

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

### 6.6 JS 文件下载

弱模型只下载 JS 原文，不做内容分析。分析由强模型完成。

**下载范围**（多采勿漏）：

- HTML 中所有 `<script src="...">` 引用的 JS 文件
- HTML 中所有出现的 `.js` / `.map` 字面量路径（含懒加载 chunk、webpack 动态 import）
- source map 文件（若 URL 可访问则下载，不分析）
- 第三方 CDN 的 JS 不下载（如 cdn.jsdelivr.net、unpkg.com），但记录 URL

**存储格式**：

在数据包 `subdomains[].js_content` 中，以 `{url: raw_content}` 格式存储 JS 原文。不截断、不摘要、不分析。

**下载规则**：

- 单文件不超过 5MB（超过则截断并标注 `truncated: true`）
- 超时 15 秒/文件
- 下载失败的标记 `download_failed`，不阻塞其他文件

**禁止**：

- 不分析 JS 内容（不找密钥、不还原 API 逻辑、不识别签名算法）
- 不执行 JS
- 不提取字符串、不过滤、不分类
- 不建立任何关系边（那是强模型的事）

---

### 6.7 API 入口识别

弱模型只记录 API 入口的 URL 和发现来源，不分析认证方式/版本/业务模块/价值。

**记录内容**：

- API Base URL（从子域名、Swagger URL、JS 中出现的 API 路径字面量）
- 发现来源（哪个 JS、哪个页面、哪个文档）
- 是否需要认证才能调用（仅记录 HTTP 401/403 响应，不推断）

**禁止**：

- 不调用需要认证的接口
- 不遍历 ID
- 不测试越权
- 不发送修改类请求
- 不评"高价值"（那是强模型的事）

---

## 7. 资产归属判断规则（弱模型简化版）

弱模型不评 confidence (high/medium/low)。只做基础的归属标记：

**明确属于目标**：SRC 范围明确包含、ICP 主体一致、官方页面直接链接。

**疑似第三方**：CNAME 指向非目标域名（如 `aligfwaf.com`、`sangfordns.com`、`qiye.163.com`）、证书组织不一致。

**无法判断**：标记为 `unknown`，留给强模型判断。

弱模型不写 `confidence` 字段，只写 `in_scope` (yes/no/unknown) 和 `notes` 记录判断依据。

---

## 8. 资产优先级评分

弱模型不评优先级。所有 `risk_priority` 字段留空。本节仅保留作为参考，实际评分由 `search-modeling.md`（强模型）根据攻击路径组合规则完成。

### 8.4 评分字段

弱模型不评分。所有 `risk_priority` 字段留空。评分由 `search-modeling.md`（强模型）根据攻击路径组合规则完成。

### 8.5 攻击路径组合评分

本 Skill 不执行。由 `search-modeling.md`（强模型）完成。

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

弱模型不画关系图，只输出扁平的资产数据包（见第 4 节）。关系图由 `search-modeling.md`（强模型）绘制。

---

## 10. 质量检查

agent 完成信息收集后，必须检查：

- 是否覆盖所有用户提供的主域
- 是否记录 SRC 范围和排除范围
- 是否区分被动来源和主动来源
- 是否识别并剔除泛解析假阳性 (Fake-IP)
- 是否记录每个资产的发现来源
- 是否对非 200 响应使用 `uncertain` 而非 `dead`
- 是否标记第三方 CNAME（CNAME 指向非目标域 → third_party）
- 是否下载了所有可访问的 JS 文件原文
- 是否避免使用敏感凭据
- 是否避免漏洞利用和攻击性验证
- 是否输出数据包 JSON（第 4 节格式）
- 所有 `[留空]` 字段是否确实留空（没有猜测填写）

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

弱模型只执行采集，不执行分析。按以下 12 步执行（原 20 步中砍掉需要分析能力的 8 步）：

1. 读取目标和授权范围
2. 解析排除范围和测试限制
3. 建立品牌关键词、公司主体和产品线
4. 收集主域名
5. 被动枚举子域名
6. 收集 DNS、证书、历史解析
7. 搜索公开网页、文档和代码仓库（只下载原文，不分析）
8. 收集 App、小程序、公众号、开放平台（只记录包名/ID/域名，不逆向）
9. 识别第三方与供应链资产（只看 CNAME/证书差异，不做深度判断）
10. 对授权资产执行存活探测（非 200 → 标 `uncertain`）
11. 提取 HTTP 标题、响应头、证书、指纹（全量保留）
12. 下载所有 JS 文件原文 + 记录 API URL 字面量（不分析内容）
13. 如允许，执行低风险端口识别
14. 输出 Markdown 资产清单 + 数据包 JSON（第 4 节格式）

**砍掉的步骤**（留给 search-modeling.md 强模型）：
- ~~识别高价值资产~~ → 强模型
- ~~资产归属 confidence 判定~~ → 强模型
- ~~去重、归并、建立资产关系~~ → 强模型
- ~~攻击面关系图~~ → 强模型

**迭代原则**：弱模型发现新域名/新 IP/新 API host 时，回到对应采集步骤继续采集。但不做回溯分析 — 新信号只是"还有更多东西要下载"。

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