# Codex Main Agent For cybertest

本文件是给 Codex 直接使用的项目级操作手册。目标是让 Codex 在这个仓库里充当主 Agent：自己读取上下文、规划、执行命令、修改文件、验证结果，并在需要时参考本项目的 prompt/agent 设计，而不是再把任务交给其它 LLM 运行时。

它不是运行时 prompt 的逐字复制，而是根据本项目文档、provider 和工具结构整理出的 Codex 工作路由。



## 使用方式

Codex/claude code 进入仓库后先读本文件，再按任务类型加载 `skills/` 下的对应文件。不要一次性加载全部 skill，除非任务确实横跨多个方面。

| 任务类型                                      | 读取 |
|-------------------------------------------|---|
| 复杂任务需求理解、任务规划、任务拆分、接管续跑或动态重规划             | [skills/task-decomposition.md](skills/task-decomposition.md) |
| 理解项目架构、启动、构建、目录职责                         | [skills/project-architecture.md](skills/project-architecture.md) |
| 使用 Burp Suite MCP 进行代理抓包、请求重放、Repeater/Intruder 集成、编解码和配置管理 | [skills/burp-mcp.md](skills/burp-mcp.md) |
| 经验蒸馏、复盘聚合、pattern/tactic/full memory 维护、经验晋升 skill | [skills/experience-distillation.md](skills/experience-distillation.md) |
| 修改或审计 prompt、provider、模型配置                | [skills/prompt-and-provider-map.md](skills/prompt-and-provider-map.md) |
| 授权安全测试、Web/API 渗透测试、漏洞验证、资产探测、赏金/SRC、非生产高强度测试 | [skills/security-testing.md](skills/security-testing.md) |
| 漏洞评级、风险定级、报告定级、漏洞归档定级                    | [skills/漏洞评级.md](skills/漏洞评级.md) |
| 使用 HackSkills 做 Web/API 渗透测试路线规划、漏洞分流、深度专题方法论 | [skills/hack-skill.md](skills/hack-skill.md) |
| SRC 信息收集、资产枚举、被动/主动侦察、资产建模、攻击面发现          | [skills/search.md](skills/search.md) |
| 基础信息收集、资产采集（弱模型专用，只采集不分析，产出数据包交给强模型）         | [skills/basicsearch.md](skills/basicsearch.md) |
| 读取 security-testing.md 后需要细化候选队列、P0/P1/P2/P3、ROI 评分、材料需求识别 | [skills/bounty-candidate-triage.md](skills/bounty-candidate-triage.md) |
| 读取 security-testing.md 后需要细化 OAuth/OIDC/SAML、SQLi、SSRF、IDOR/BOLA、文件链、网关、VHost、重定向、目录爆破、JS 分析闭合 Playbook | [skills/bounty-closure-playbooks.md](skills/bounty-closure-playbooks.md) |
| 按 OWASP Top 10:2025 做 Web/API 风险建模、渗透测试思路 | [skills/OWASPtop10.md](skills/OWASPtop10.md) |
| CTF、靶场、授权训练环境的 Web/API 解题与目标物获取             | [skills/ctf-web-flag-rush.md](skills/ctf-web-flag-rush.md) |
| 逆向工程、移动逆向、二进制分析、IDA/radare2、APK、固件、恶意样本、pwn、补丁差分 | [skills/reverse-security.md](skills/reverse-security.md) |
| 明确授权测试中需要快速产出高影响发现或高危候选链             | [skills/aggressive-high-impact.md](skills/aggressive-high-impact.md) |
| 明确授权测试中需要中危优先、快速形成可报告成果             | [skills/medium-fast-win.md](skills/medium-fast-win.md) |
| 非生产、预发、演练或停服窗口内的高强度专项渗透测试             | [skills/nonprod-intensive-pentest.md](skills/nonprod-intensive-pentest.md) |
| 生成交接文档、接手文档、资产文档、资产清单、任务日志、漏洞归档，或要求新窗口/其它 Agent 快速接手 | [skills/handoff-docs.md](skills/handoff-docs.md) |

## 如果路由未命中 → 联网搜索该领域方法论 → 提议新增 skill

## Codex 主 Agent 工作原则

- Codex 自己是主执行者。优先直接读代码、查数据库、运行测试、修改文件、验证结果。
- `primary_agent`、`pentester`、`coder` 等角色只作为工作模式参考，不代表要实际调用项目里的 LLM chain。
- 如果任务需要“像 Pentester 一样做”，Codex 读取 `security-testing.md` 和 `agent-roles.md`，然后由 Codex 自己执行可控命令；其中 `security-testing.md` 是授权渗透测试的统一主入口，默认采用补天式深度挖掘循环，覆盖 Web/API 测试流程、动态信息收集、候选队列、ROI 分流、漏洞发现链、攻击链组合、影响边界停止规则和“近期跨案例经验固化”。
- 如果任务是授权 Web/API 渗透测试，推荐加载顺序是 `security-testing.md` → `hack-skill.md` → 具体 HackSkills 专题；可参考 `hack-skill.md` 的推荐加载参考表选择对应 `hack-skills/skills/*/SKILL.md`，并建议在任务日志记录文件路径和触发原因。Web/API 和 SRC 任务默认套用 `security-testing.md` 做路径选择、误报过滤、证据闭环和停止判断。`webskill.md` 仅作为历史兼容文件保留，不再作为主路由默认入口。
- 授权 Web/API/行业系统测试中，若目标出现后台管理、数据中台、数据交换、系统回调、开放平台、异步任务、消息通道、设备/媒体、移动端 API、Swagger/OpenAPI、JS 暴露 API base 或核心业务对象字段，默认按 `security-testing.md` 执行“高价值业务能力与信任边界建模”，不得只完成资产枚举、目录扫描或登录页简查就收工。
- 在渗透测试中，当模型完成资产建模（无论用 search.md 还是 basicsearch.md），必须读取 `search.md` 第 10 节（质量检查）和第 15 节（推荐执行顺序）进行自查，逐项确认覆盖度和缺失项，输出自查结论到任务日志。
- 如果任务涉及漏洞评级、风险定级、漏洞归档定级或报告定级，必须读取 `漏洞评级.md`；所有漏洞评级标准统一以该文档为准。发现任何新漏洞、风险候选或准备把线索从候选升级为漏洞时，必须立即执行 `漏洞评级.md` 复核门禁，未完成复核不得写入正式报告、不得标记为已确认中危/高危。
- 如果任务是漏洞赏金平台、SRC、补天项目、厂商授权赏金挖掘或普通授权渗透测试，统一读取 `security-testing.md`；补天式深度挖掘、候选队列、P0/P1/P2/P3、ROI 和材料阻塞状态已并入该主入口。需要更细的候选评分或漏洞类型闭合时，再按 `security-testing.md` 指示读取 `bounty-candidate-triage.md` 和 `bounty-closure-playbooks.md`。`bounty-deep-dig.md` 仅作为历史兼容文件保留，不再作为主路由入口。
- 如果任务明确要求高危优先、成果导向、快速找高影响漏洞或“至少挖一个高危”，读取 `aggressive-high-impact.md`。
- 如果任务明确要求中危优先、快速出成果、先拿可报告漏洞或阶段性快速摸底，读取 `medium-fast-win.md`，并仍需遵循 `security-testing.md`、`漏洞评级.md` 和授权边界。
- 如果任务明确说明目标是非生产、预发、演练环境或停服窗口专项测试，并允许更高强度操作，读取 `nonprod-intensive-pentest.md`。
- 如果任务要求生成交接文档、接手文档、资产文档、资产信息文档、资产清单、任务日志、漏洞归档，或要求“新窗口/其它 AI 快速接手”，读取 `handoff-docs.md`；安全测试类交接文档仍需同时遵循 `security-testing.md` 和相关授权边界。
- 如果授权测试目标是局域网地址、localhost/loopback、链路本地地址或用户明确说明的内网网段，默认读取 `nonprod-intensive-pentest.md`；除非用户明确要求低影响/常规强度。
- 如果任务明确是 CTF、靶场或授权训练环境解题/夺旗/获取目标物，读取 `ctf-web-flag-rush.md`；不要把该 skill 用于生产授权渗透测试或客户报告；禁止联网搜索题名、题面特征句、flag、writeup、平台题解或可直接替代解题的答案。
- 如果任务涉及逆向工程、移动逆向、二进制分析、IDA/radare2、APK、固件、恶意样本、pwn 或补丁差分，读取 `reverse-security.md`，再按该文件路由到 `agent/skills/reverse/` 下的具体子 Skill；不得执行 reverse-skill 的全局注入、跨项目配置写入或强制自动安装规则。
- 如果任务需要“像 Coder 一样改代码”，Codex 读取 `project-architecture.md`、相关源码和必要 skill，然后直接实现。
- 如果任务需要“像 Reporter 一样总结”，Codex 读取 `workflow-and-memory.md`，从数据库/日志/文件中抽取证据后生成报告。
- 如果任务是经验蒸馏、复盘聚合、pattern/tactic/full memory 维护，或判断经验是否晋升为 skill，读取 `experience-distillation.md`；小蒸馏经验应注册到 `agent/memory/index.md`，不要直接写入主 skill，除非用户明确要求晋升或注册。
- 想跳过步骤/偷懒时 → 读 agent-obedience-engineering.md 借口反驳表
- 在执行过程中遇到困难不要硬撑，执行以下工作流：执行过程中遇到困难 → 联网搜索解决方案 → 沉淀到 agent/references/
- 遇到准备使用“逆向/反编译/反汇编/反混淆/算法还原/签名还原/加密还原/编码还原/协议还原”等思路；分析 APK/IPA/JAR/dex/smali/so/native/固件/二进制/补丁差分/恶意样本/pwn；调用jadx、apktool、Frida、Objection、IDA、radare2、r2、binwalk、unblob 等工具；从 JS/Source Map/客户端代码中还原签名、验证码、加密、混淆控制流或协议状态机等场景时，调用`agent/skills/reverse-security.md`及对应子SKILL




## 硬规则

- 优先遵循当前仓库已有模式，不随意引入新架构。
- 授权漏洞归档、漏洞总结或正式报告中，任何作为证据材料采集到的凭据和敏感字段都不脱敏，正文应记录完整值，包括密码、密钥、`appkey`、`secret`、API key、token、cookie、JWT、Authorization、数据库连接材料、设备凭据、私有域名和可复现所需的业务数据；目标是只读报告即可完整复现和评估影响。
- 所有报告类输出默认使用中文生成；如需外文报告，必须由用户明确指定。
- 修改 GraphQL schema 后要重新生成 gqlgen 和前端 GraphQL 类型。
- 修改数据库结构要新增 goose migration，不要直接改历史 migration。
- 修改 provider 类型时要同时检查后端 enum、REST model 校验、GraphQL 类型、前端图标和设置页。
- 安全测试内容只用于明确授权目标；默认优先做验证、记录和报告，不做破坏性操作。
- 授权安全测试、资产探测和扫描任务中，若本机开启 TUN/虚拟网卡或代理，默认系统 DNS 解析结果不可信；遇到 `198.18.0.0/15`、`198.18.x.x`、`198.19.x.x` 等 Fake-IP 结果时，禁止把该地址作为真实目标扫描。解析公网域名时应优先用 `dig +tcp @1.1.1.1`、`dig +tcp @8.8.8.8`、DoH 或 `tool/origin_exposure_probe.py` 对比真实 A/CNAME；端口扫描只输入真实 IP 并禁用 DNS；Web 验证必须用固定 Host/SNI 的方式，例如 `curl --resolve` 或等价参数。发现扫描结果出现大量端口全开、极低延迟或目标落在 Fake-IP 网段时，应先按本规则复核后再继续。
- 漏洞评级默认分为高危、中危、低危三档；授权测试、漏洞归档和报告定级时，统一遵循 `agent/skills/漏洞评级.md`，并结合厂商权重、网站流量、攻击复杂度、对被测目标的影响、漏洞利用权限需求、影响范围、机密性和完整性进行调整。
- 漏洞评级是强制门禁，不是可选参考。发现新漏洞或风险候选时，必须先读取或回看 `agent/skills/漏洞评级.md`，在 `vulnerability-archive.md` 和 `outputs/vulnerability-archive.json` 中写入评级复核结论；缺少复核记录的条目只能标记为 `verifying`、`blocked_need_material`、`info` 或 `undetermined`，不得标记为 `confirmed`，不得进入正式报告中危/高危章节。
- 每条漏洞/风险的评级复核必须至少回答：是否具有实际危害、是否命中“不予奖励/无实际危害/证据不足”规则、证据是否闭合到真实业务影响、是否依赖过强前置条件、为什么不是更低等级、为什么不是更高等级、最终等级对应 `漏洞评级.md` 的哪一条标准。若这些问题任一无法回答，结论必须降级为候选或受限未验证。
- 输出漏洞总结、阶段报告、正式报告、接手文档或赏金提交前，必须逐条复核所有中危/高危条目是否已有 `rating_review`；没有 `rating_review` 的条目必须先补复核或从有效漏洞章节移到“候选/受限/信息项”。最终回复中不得声称“已按评级标准复核”，除非实际完成并写入归档。
- 赏金任务必须维护候选攻击队列，推荐输出到任务目录 `outputs/bounty-candidates.json` 和 `outputs/bounty-candidates.md`。候选来源应覆盖子域名、存活 Web、端口服务、VHost/Host-SNI、重定向链、目录爆破、URL 爬取、历史 URL、JS chunk/source map、API base、前端路由、Swagger/OpenAPI、Actuator/health/config、登录/SSO/OAuth 配置、移动端 API、对象存储链接、上传/下载/导入/导出接口、test/pre/dev/staging 环境。P0 优先追踪 SQLi、SSRF、账号接管、OAuth/OIDC/SAML、IDOR/BOLA、文件链、API 网关绕过、后台未授权、测试环境连生产数据、OSS/STS、核心业务对象越权、状态流转越权、数据交换/系统回调/异步任务信任边界缺陷、设备/媒体/边缘节点控制面暴露；普通安全头、版本号、公开配置、无敏感 health/info、无影响 CORS 和只有 401/403/404 的弱线索应快速降级。
- 赏金任务开局必须先建立机器可读资产发现基线。默认先跑 `./tool/scan_pipeline.py --authorized --domain <scope-root> --mode quick`；正式渗透或用户要求完整覆盖时升级 `--mode full`，SPA/API 网关/大型站点或前两轮仍有 P0/P1 线索时升级 `--mode deep`。只有在平台规则、时间窗口、工具缺失或目标形式不适合自动管线时，才可跳过，并必须在任务日志写明替代的手工输入来源。
- `scan_pipeline.py` 的 quick/full/deep 默认在质量门禁后运行 `candidate_queue` 阶段，离线把子域名、存活 Web、端口服务、TLS/DNS、VHost/Host-SNI 线索、重定向链、目录 fuzz、katana URL、历史 URL、GF、nuclei、JS/API family、Markdown 资产清单等本地产物汇总成 `phase_*_candidate_queue/result.json` 和同名 Markdown。若从既有任务目录续跑，必须用 `./tool/bounty_candidate_queue.py --task-dir <task-dir> --output-json <task-dir>/outputs/bounty-candidates.json --output-md <task-dir>/outputs/bounty-candidates.md` 生成统一队列。
- 未完成扫描管线或等价手工基线、未生成 `bounty-candidates.json/md`、未处理完 P0 队列前，报告中不得写“全资产穷尽”“所有 P0/P1/P2 已耗尽”或类似结论；只能写明“当前已覆盖范围”和“未覆盖/受限项”。
- 赏金候选状态统一使用 `discovered`、`triaged`、`high_value`、`verifying`、`blocked_need_material`、`confirmed`、`false_positive`、`downgraded`、`out_of_scope`、`no_impact`、`archived`。缺少测试账号、测试订单、测试运单、测试网点/组织 ID、测试 AppKey/Secret、可回滚测试文件或权限账号对时，不能直接归档失败，应标记 `blocked_need_material` 并写清拿到材料后的第一步验证动作。
- CTF/靶场夺旗任务禁止联网搜索题目答案、题解、flag、题名或页面特征句；必须基于目标响应、本地工具和题面信息独立解题，并在归档报告中详细记录观察、假设、验证步骤、失败路径和最终依据。
- 对运行中的用户改动保持尊重，不回滚未确认的工作区变更。
- Codex 执行测试或安全验证时，只触碰用户指定范围；未授权、越权、漏洞验证类任务必须保留证据和影响判断，避免扩大影响面。
- 渗透测试任务中不得留下任何个人信息和标识。所有命令输出、脚本、日志、截图、报告、归档文件、临时文件和工具输出中，必须避免出现操作系统的用户名（如 `/Users/umisonoda`、`/home/zhangsan`）、主机名、个人邮箱、个人 SSH 密钥路径、个人 API key、个人聊天记录路径等可追溯到具体测试人员的标识信息。发送到目标的指令和 payload 中也不得包含任何个人信息或标识（如用户名、主机名、个人路径等），避免在目标服务器日志、WAF 日志或应用日志中留下测试人员身份痕迹。如不可避免（例如路径来自工具默认输出），必须在归档或写入文件前做脱敏替换处理。
- 渗透测试中发现的所有风险都必须记录，包括低危、中危、信息泄露、配置缺陷和受限未验证线索；低风险至少保留在任务内部归档，中风险及以上应写入正式报告或阶段性报告。
- 当用户在任务中说明“默认授权”“写入规则”“提供账号可执行副作用验证”或等价表达时，默认允许在授权范围、提供账号、测试对象和可回滚条件内执行低频副作用验证，包括短信/邮件触发、导出、建号/创建对象、同步/任务调度、删除测试对象和上传测试材料。每类动作应使用最小次数、测试对象、可识别测试前缀、可审计证据和明确停止点；成功证明一次即停止扩大。仍禁止批量轰炸、批量导出、破坏真实业务数据、触碰未授权第三方系统、规避检测、持久化植入或清理日志。
- 遇到公开文档、附件、公示名单、政策文件、统计表、办事指南等类似文档时，先判断路径和栏目是否为非隐藏、公开用途：例如出现在公开栏目、公开索引、sitemap、页面正文附件、`/attachment/`、公示目录或政府信息公开目录中，且无需绕过鉴权、猜测隐藏 ID、遍历非公开目录或利用缺陷即可访问，通常应视为“预期公开内容”。这类内容即使包含个人信息或敏感业务字段，也不要直接作为高危漏洞；应按公开合规/脱敏边界问题做内部归档或中低风险观察，除非能证明存在隐藏路径泄露、未授权越权访问、非公开对象枚举、批量导出缺陷、超出栏目公开目的的明显敏感材料，或用户明确要求按隐私合规风险单独升级评估。
- 同一任务内的漏洞不得孤立分析；低危和中危发现也必须持续跟踪，尝试与认证缺陷、信息泄露、敏感文件下载、越权、上传、回调、网关路由等线索组合，评估是否能形成更高影响的攻击链。
- 授权测试中探测到与目标存在业务、域名、证书、前端路由、接口引用、同组织资产或用户指定关系的后台界面、管理入口、运营后台、管理 API、调试管理面或内置产品管理页时，应将其作为关联后台资产纳入完整 Web/API 渗透测试流程，而不是只做登录页简查。完整流程至少包括授权范围确认、被动信息收集、登录/认证流程闭环、后台页面/API/参数枚举、未授权访问、垂直越权、配置/文件/上传/导入导出/任务调度入口、验证码/找回密码/OAuth/二维码链路、技术栈/CVE 适用性和证据化报告。默认不做批量爆破、密码喷洒、短信/邮件轰炸、破坏性写入、配置修改、新增账号或真实管理操作；但用户提供账号并声明默认授权写入时，可按副作用写入默认授权规则执行低频、可回滚、可审计的测试账号/测试对象操作。命中高危管理功能入口或成功完成一次影响证明后停止扩大，并记录证据、对象 ID、回滚方式和剩余风险。
- 遇到登录、注册、找回密码、重置密码、验证码、短信/邮箱校验、OAuth/二维码登录或需要登录才能继续观察的场景时，应进行一次完整的低频登录/认证流程测试闭环。默认测试字段为手机号 `13333333333`、邮箱 `114514@gmail.com`、密码`12345678Abc`；成功或失败都必须记录请求、响应、状态码、关键字段、Cookie/Header、前端 JS 逻辑、验证码字段、错误提示和跳转差异，并分析可利用攻击面，如验证码明文传输、验证码复用、验证码未绑定会话/账号、账号枚举、找回密码 token 泄露、登录态提前下发、前端校验绕过、OAuth state/二维码 ticket 重放等。该闭环只做最小必要样本，不做批量爆破、短信/邮件轰炸或导致真实账号锁定的重复尝试；如继续验证需要真实验证码、测试手机号/邮箱、低权限账号或人工接收验证码，且用户未提供默认授权写入材料，必须明确列为人工配合事项；若用户已提供测试手机号/邮箱/账号并声明默认授权写入，则按副作用写入默认授权规则低频执行。
- 授权渗透测试、漏洞验证、安全扫描、资产探测、Web/API 安全测试和目标信息收集任务中，如果尚未发现高危或严重级别漏洞/风险就准备结束，必须先自我提问复盘：资产信息收集是否已经完善，高收益方向是否都已尝试，是否还有未做的高收益动作或未尝试方向。如果还有未完成的内容，则继续尝试和挖掘。只有上述均已完成或受限不可执行时，才可结束；结束时必须明确告诉用户为什么提前结束、阻塞点是什么、还缺哪些信息、哪些需要人工配合，并指明下一步验证方向。
- 以后新建或维护 `vulnerability-archive.md`、漏洞总结、风险总账类文件时，关键证据必须在正文内自包含记录请求方法、路径/接口、认证状态、HTTP 状态、关键响应字段、数量级、对照结果、复现条件、验证边界，以及完整凭据和敏感材料；证据文件路径只能作为追溯索引，不能替代正文证据摘要。目标是其它 AI 只读取该总结文件，也能生成漏洞报告和复现路径。
- 因单次任务产生的临时脚本统一存放在 `temporarytool/`，不要散落在仓库根目录或 `tool/`。
- 只有当脚本具备通用复用价值、能提升 Codex 后续能力时，才整理为通用脚本放入 `tool/` 并在本文件注册调用方式。
- 除非用户明确要求“注册 skill”或在看过草案后二次确认写入，否则新总结/生成的 skill 只输出草案，不写入 `agent/skills/`，也不注册到本文件。
- 只有授权渗透测试、漏洞验证、安全扫描、资产探测、Web/API 安全测试和目标信息收集任务，才自动创建或使用独立归档目录：`tasks/YYYY-MM-DD-HHMM-short-task-name/`。
- CTF/靶场夺旗相关任务归档统一放在 `tasks/CTF/` 目录内（如 `tasks/CTF/YYYY-MM-DD-HHMM-short-task-name/`）；其余安全/信息收集任务仍使用 `tasks/YYYY-MM-DD-HHMM-short-task-name/`。
- 上述安全/信息收集任务必须在任务开始时先创建或选定任务目录，不要等到结束才补归档；重要状态不要过度依赖会话记忆，应及时写入任务文件夹。
- 每个安全/信息收集项目目录在创建时必须同步初始化可接手归档骨架，并在任务推进中持续更新。固定目录和命名如下：
  - `inputs/`：授权范围、目标清单、账号/测试材料、外部输入；推荐文件名 `scope.md`、`targets.txt`、`accounts.md`、`materials.md`。
  - `notes/log.md`：唯一主过程日志，记录授权范围、目标清单、规划、关键命令、决策链、阶段结论、阻塞点、续跑 checkpoint；不要另起 `log2.md`、`notes.md`、`过程.md` 等分散文件。
  - `notes/loaded-skills.md`：记录本任务实际读取的 skill、触发原因和适用边界。
  - `outputs/asset-inventory-detailed.md`：唯一主资产收集文档，记录资产来源、域名/IP/端口/服务/入口/API/技术栈、授权状态、优先级、当前结论和证据索引。
  - `outputs/asset-inventory.json`：机器可读资产清单；能结构化时必须同步维护，字段至少包含 `asset`、`type`、`source`、`in_scope`、`status`、`priority`、`evidence`、`next_action`。
  - `vulnerability-archive.md`：唯一主漏洞归档/风险总账，记录所有确认漏洞、候选风险、低风险、阴性边界、受限未验证项、证据摘要、复现条件、影响、评级、评级复核、状态、修复建议和报告去向。
  - `outputs/vulnerability-archive.json`：机器可读漏洞/风险清单；能结构化时必须同步维护，字段至少包含 `id`、`title`、`asset`、`severity`、`status`、`evidence`、`impact`、`rating_review`、`next_action`、`report_target`。
  - `outputs/agent-handoff-pentest-status.md`：唯一主接手文档/新窗口入口，面向其它 AI 读取，必须写清当前状态、已做/未做、可复现证据、优先下一步、不要重复的失败路径和阻塞材料。
  - `evidence/`：原始证据；按类型放入 `http/`、`screenshots/`、`scan/`、`burp/`、`js/`、`files/`、`callbacks/`。证据文件命名使用 `YYYYMMDD-HHMMSS_asset_short-purpose.ext`，避免空格和个人标识。
  - `reports/`：阶段性报告、正式报告和提交材料；推荐 `stage-report.md`、`final-report.md`、`submission-<platform>.md`。
  - `temporarytool/`：本任务专用临时脚本；脚本输出写入 `outputs/` 或 `evidence/scan/`，不要散落到任务根目录。
  - `retrospective.md`：任务结束复盘，并同步匿名化摘要到 `agent/retrospectives/index.md`。
- 安全/信息收集任务的接手入口固定为 `outputs/agent-handoff-pentest-status.md`。当用户说“新窗口接手”“其它 AI 接手”“继续上次任务”时，优先读取该文件，再读 `notes/log.md`、`outputs/asset-inventory-detailed.md`、`vulnerability-archive.md`、`outputs/bounty-candidates.md/json` 和必要证据索引；不要从零重新扫描或只依赖聊天记录。
- 资产收集、漏洞归档、任务日志、接手文档必须互相引用而不互相替代：资产文档引用风险 ID 和证据路径；漏洞归档引用资产 ID 和证据路径；日志引用资产/漏洞 ID 和关键命令；接手文档汇总当前 checkpoint 与下一步。任何正式结论必须至少能在上述四类主文档之一中找到正文摘要。
- 同一任务不得随意改名或复制主文档。除非用户明确要求快照，固定主文件只更新原路径；快照命名使用 `outputs/archive/YYYYMMDD-HHMMSS-<canonical-name>.md`，并在主接手文档注明快照原因。
- 任务规划、任务拆分、授权范围、目标清单、资产/信息发现、关键假设、重要命令、阶段性结论和阻塞点，应优先保存到任务目录的 `notes/`、`inputs/`、`outputs/` 或 `evidence/` 中。
- 上述安全/信息收集任务的输入、输出、证据、过程笔记、临时脚本应归档到任务目录；推荐子目录为 `inputs/`、`outputs/`、`evidence/`、`notes/`、`temporarytool/`。
- 技能增加、脚本开发、代码修改、重构、文档注册、说明更新等普通维护任务，不自动创建任务归档目录，也不要求复盘；除非用户明确要求归档，或任务本身属于安全/信息收集范围。
- 单次安全/信息收集任务专用临时脚本优先放入该任务目录的 `temporarytool/`；普通脚本开发仍按复用价值决定放入 `temporarytool/` 或提升到 `tool/`。
- 授权渗透测试、漏洞验证、安全扫描、资产探测、Web/API 安全测试和目标信息收集任务结束前必须进行复盘；复盘可同时保存到任务目录 `retrospective.md`，并同步摘要到 `agent/retrospectives/index.md`。
- 开始类似安全测试或目标信息收集前，先读取 `agent/retrospectives/index.md` 和 `agent/memory/index.md`，根据当前任务类型、技术栈、测试阶段和标签，只加载少量相关 pattern/tactic memory；不要一次性加载全部 memory。必要时再读取相关复盘文件，避免重复失败路径。
- 不要根据复盘数量自动触发经验蒸馏；只有用户明确要求蒸馏、整理 pattern/tactic/full memory、注册 memory 或晋升 skill 时，才读取 `experience-distillation.md` 并更新 `agent/memory/`。
- 复盘必须匿名化，不得记录真实凭据、token、cookie、JWT、私有域名、内部 IP、callback URL 或可识别客户信息。
- 复盘需同时记录有效路径、无效路径、工具参数、环境限制、误报判断和下次优先步骤，并更新 `agent/retrospectives/index.md`。

## 常用命令

后端：

```bash
cd backend
go mod download
go build -trimpath -o cybertest ./cmd/cybertest
GOCACHE=/tmp/go-build go test ./pkg/graph
go test ./...
```

前端：

```bash
cd frontend
npm ci
npm run dev
npm run build
npm run graphql:generate
```

Docker：

```bash
docker compose up -d
docker compose up -d --build cybertest
docker compose ps
docker compose logs -f cybertest
```

本地安全测试工具：

```bash
# === 扫描管线（推荐入口）===
# quick: 首次侦察 — 子域名 → DNS 基线 → 存活 → 浅爬取 → GF 匹配 → nuclei 高危 → 质量门禁 → 赏金候选队列
./tool/scan_pipeline.py --authorized --domain example.com --mode quick

# full: 完整覆盖 — DNS/TLS/naabu/nmap + 深度爬取 + 历史 URL + 目录 fuzz + 质量门禁 + 赏金候选队列
./tool/scan_pipeline.py --authorized --domain example.com --mode full

# deep: 最长链 — full + headless 爬取 + 更深目录 fuzz + 赏金候选队列
./tool/scan_pipeline.py --authorized --domain example.com --mode deep

# 自定义阶段（跳过子域名枚举，直接从 URL 列表开始）
./tool/scan_pipeline.py --authorized --input alive_urls.txt --phases httpx,katana,gf,nuclei

# 预览执行计划
./tool/scan_pipeline.py --authorized --domain example.com --mode full --dry-run

# 从断点恢复
./tool/scan_pipeline.py --resume /tmp/codex-scan-pipelines/example.com-20260101T120000/pipeline_state.json

# 从扫描管线或任务目录离线生成赏金候选 P0/P1/P2/P3 攻击队列，不发起网络请求
# scan_pipeline quick/full/deep 会自动执行 candidate_queue；以下命令用于历史任务、断点续跑或额外产物补喂
./tool/bounty_candidate_queue.py --pipeline-dir /tmp/codex-scan-pipelines/example.com-20260101T120000 --output-json /tmp/bounty-candidates.json --output-md /tmp/bounty-candidates.md
./tool/bounty_candidate_queue.py --task-dir tasks/YYYY-MM-DD-HHMM-example-bounty --output-json tasks/YYYY-MM-DD-HHMM-example-bounty/outputs/bounty-candidates.json --output-md tasks/YYYY-MM-DD-HHMM-example-bounty/outputs/bounty-candidates.md

# 虚拟网卡/TUN/Fake-IP 环境下的真实解析基线：默认 dig 结果可能是 198.18.0.0/15 假地址，不得直接作为扫描目标
dig +tcp +short @1.1.1.1 example.com A
dig +tcp +short @8.8.8.8 example.com A
curl -sS -H 'accept: application/dns-json' 'https://dns.google/resolve?name=example.com&type=A'

# 固定真实 IP，但保留 Host/SNI；用于 Web 指纹、源站/入口验证和避免系统 DNS Fake-IP 污染
curl --noproxy '*' --resolve example.com:443:203.0.113.10 https://example.com/
curl --noproxy '*' --resolve example.com:80:203.0.113.10 http://example.com/
openssl s_client -connect 203.0.113.10:443 -servername example.com </dev/null
nmap -n -Pn -p 80,443 203.0.113.10

# 授权范围内的 Nmap 信息收集，输出 AI 可解析 JSON
./tool/nmap_json_scan.py --authorized --target 127.0.0.1 --profile default

# 局域网分阶段快扫：先发现主机，再扫常见 TCP 和重点风险端口
./tool/nmap_json_scan.py --authorized --target 192.168.31.0/24 --profile discover --output discover.json
./tool/nmap_json_scan.py --authorized --target 192.168.31.1 --profile lan-fast --output lan-fast.json
./tool/nmap_json_scan.py --authorized --target 192.168.31.1 --profile lan-deep --output lan-deep.json
./tool/nmap_json_scan.py --authorized --target 192.168.31.1 --profile risk-ports --output risk-ports.json

# 局域网两轮扫描：第一轮高性能发现主机，第二轮只精扫已发现设备
./tool/nmap_json_scan.py --authorized --target 192.168.31.0/24 --two-pass --output lan-two-pass.json

# 异步局域网两轮扫描：启动后返回 task_id，Codex 可先做其它分析，再轮询结果
./tool/nmap_json_scan.py --authorized --target 192.168.31.0/24 --two-pass --async-start
./tool/nmap_json_scan.py --async-status nmap-xxxxxxxxxxxx

# TCP 全端口信息收集
./tool/nmap_json_scan.py --authorized --target 127.0.0.1 --profile full --output tcp-full.json

# TCP 全端口快速开口确认；只作开放端口线索，不替代后续服务指纹和人工判断
./tool/nmap_json_scan.py --authorized --target 127.0.0.1 --profile full-fast --output tcp-full-fast.json

# Web 常见端口和 HTTP/TLS 信息收集
./tool/nmap_json_scan.py --authorized --target 127.0.0.1 --profile web --output web.json

# 常见 UDP 端口信息收集
./tool/nmap_json_scan.py --authorized --target 127.0.0.1 --profile udp --output udp.json

# UDP 快速线索扫描；UDP 误判率较高，命中后再做专项验证
./tool/nmap_json_scan.py --authorized --target 127.0.0.1 --profile udp-fast --output udp-fast.json

# Sploitus exploit 线索检索，默认输出 Markdown
./tool/sploitus.py --query "apache struts" --type exploits --max-results 10

# Sploitus 安全工具线索检索，输出 AI 可解析 JSON
./tool/sploitus.py --query "nuclei" --type tools --format json --output sploitus-tools.json

# HTTP/Web 资产探测，输出 AI 可解析 JSON
./tool/httpx_probe.py --authorized --target https://example.com --output httpx.json

# 被动子域名枚举，输出 AI 可解析 JSON
./tool/subfinder_json.py --authorized --domain example.com --all --recursive --output subdomains.json

# DNS 基线收集，输出 A/AAAA/CNAME/NS 并标记私网/Fake-IP
./tool/dnsx_json.py --authorized --input subdomains.txt --resolver 1.1.1.1 --resolver 8.8.8.8 --output dnsx.json

# TLS 指纹和证书信息收集，输出 AI 可解析 JSON
./tool/tlsx_json.py --authorized --input hosts.txt --output tlsx.json

# naabu 快速全端口开放候选发现；命中后仍需 nmap 确认，避免云/WAF SYN 噪声
./tool/naabu_json_scan.py --authorized --input hosts.txt --ports 1-65535 --verify --output naabu.json

# 历史 URL 收集（waybackurls），用于补充 katana 未覆盖的攻击面
./tool/url_history_collect.py --authorized --input hosts.txt --output history.json

# 扫描质量门禁：检查完整侦察阶段是否完成，未完成项不得写“所有方向穷尽”
./tool/quality_gate.py --pipeline-dir /tmp/codex-scan-pipelines/example-YYYYMMDDTHHMMSS --mode full --output quality-gate.json --markdown-output quality-gate.md

# FOFA 被动公网资产查询，输出 AI 可解析 JSON；API key 用 FOFA_KEY 环境变量或 --key 传入
./tool/fofa_query.py --authorized --query 'domain="example.com"' --fields host,ip,port,protocol,title --output fofa.json

# Nuclei 模板化漏洞线索扫描，默认 medium/high/critical，并自动附加 tool/nuclei-templates/ 本地高信号模板，输出 AI 可解析 JSON
./tool/nuclei_json_scan.py --authorized --target https://example.com --disable-update-check --output nuclei.json

# Nuclei 异步后台扫描（适合长时间扫描，绕过 Bash 工具 10 分钟超时限制）
./tool/nuclei_json_scan.py --authorized --target https://example.com --disable-update-check --async-start
./tool/nuclei_json_scan.py --async-status nuclei-xxxxxxxxxxxx

# Katana Web 爬虫和端点发现，输出 AI 可解析 JSON
./tool/katana_crawl.py --authorized --target https://example.com --js-crawl --known-files robotstxt,sitemapxml --output katana.json

# Katana 异步后台爬取
./tool/katana_crawl.py --authorized --target https://example.com --js-crawl --async-start
./tool/katana_crawl.py --async-status katana-xxxxxxxxxxxx

# GF 模式匹配：对 katana/waybackurls 产出的 URL 列表按 14 种漏洞模式分类，输出优先级排序的 JSON
./tool/gf_pattern_match.py --input katana_urls.txt --output gf-results.json

# GF 仅运行高优先级模式（P0+P1），减少噪音
./tool/gf_pattern_match.py --input urls.txt --min-priority P1

# GF 单个模式运行
./tool/gf_pattern_match.py --input urls.txt --pattern sqli

# Scrapling MCP 渲染抓取、正文抽取和截图；通过 Codex 工具调用，不是本地 shell 命令
# 示例能力：mcp__scrapling__.fetch / get / bulk_fetch / stealthy_fetch / open_session / screenshot

# ffuf 目录/参数/Host fuzz，默认低速率，输出 AI 可解析 JSON
./tool/ffuf_json.py --authorized --url https://example.com/FUZZ --wordlist words.txt --filter-code 404 --output ffuf.json

# Arjun HTTP 参数发现，输出 AI 可解析 JSON
./tool/arjun_json.py --authorized --target https://example.com/api/search --stable --output arjun.json

# Kiterunner API 路由发现，适合大型 SPA/API 网关，输出 AI 可解析 JSON
./tool/kiterunner_json.py --authorized --target https://api.example.com --wordlist routes.kite --output kiterunner.json

# Rustscan 快速端口发现 + Nmap 服务确认，输出 AI 可解析 JSON
./tool/rustscan_nmap.py --authorized --target 127.0.0.1 --range 1-65535 --output rustscan-nmap.json

# Masscan 高速端口扫描，适合大范围资产测绘，输出 AI 可解析 JSON；需要 sudo 权限
sudo ./tool/masscan_json_scan.py --authorized --target 203.0.113.0/24 -p 80,443,8080,8443 --output masscan.json

# Masscan 异步后台扫描（大网段必须使用异步模式）
sudo ./tool/masscan_json_scan.py --authorized --target 203.0.113.0/24 -p 1-65535 --async-start
sudo ./tool/masscan_json_scan.py --async-status masscan-xxxxxxxxxxxx

# WAF/CDN 指纹识别，区分安全防护与真实应用行为，输出 AI 可解析 JSON
./tool/wafw00f_json.py --authorized --target https://example.com --findall --output wafw00f.json

# WhatWeb Web 指纹识别，输出 AI 可解析 JSON
./tool/whatweb_json.py --authorized --target https://example.com --output whatweb.json

# hashcat 离线密码哈希破解，支持字典/掩码/规则攻击，输出 AI 可解析 JSON
./tool/hashcat_json.py --authorized -m ntlm -a 0 --hash-file hashes.txt --wordlist rockyou.txt --output hashcat.json

# hashcat 查看已破解和未破解哈希
./tool/hashcat_json.py --authorized --hash-file hashes.txt --show
./tool/hashcat_json.py --authorized --hash-file hashes.txt --left

# Gitleaks 源码/备份/泄露仓库 Secret 扫描，输出脱敏 JSON
./tool/gitleaks_json.py --source . --redact --output gitleaks.json

# 当前任务上下文打包为单个 Markdown，便于复制给其它大模型接手分析
./tool/task_context_bundle.py --task-dir tasks/YYYY-MM-DD-HHMM-short-task-name

# Dalfox XSS 检测，适合参数、预览、admin bot 链路，输出 AI 可解析 JSON
./tool/dalfox_json.py --authorized --target "https://example.com/search?q=test" --output dalfox.json

# Trivy 依赖、镜像、配置、Secret 扫描，输出 AI 可解析 JSON
./tool/trivy_json.py --mode fs --target . --scanners vuln,secret,misconfig --output trivy.json

# Semgrep 源码规则扫描，输出 AI 可解析 JSON
./tool/semgrep_json.py --target . --config auto --output semgrep.json

# OWASP ZAP baseline 被动基线扫描，输出 AI 可解析 JSON
./tool/zap_baseline.py --authorized --target https://example.com --minutes 1 --output zap.json

# sqlmap 低风险注入验证，不 dump 数据，不启用 OS/file 操作
./tool/sqlmap_safe.py --authorized --url "https://example.com/item?id=1" --output sqlmap.json

# HTTP 路径/路由低影响探测，默认不跟随跳转，可保存 header/body 证据
./tool/http_path_probe.py --authorized --base https://example.com --paths paths.txt --out-dir evidence/http --output http-paths.json

# 源站/公网入口暴露验证，输出 DNS、固定 Host/SNI、直连 IP 指纹 JSON
./tool/origin_exposure_probe.py --authorized --hostname example.com --ip 203.0.113.10 --output origin.json

# 网关路由响应分类，区分 SPA fallback、nginx 404、Java JSON 错误和 service-discovery 503
./tool/gateway_route_classifier.py --authorized --base-url https://api.example.com --path /app/tool/startup --output gateway-routes.json

# CORS + 上传 + 公开预览风险链证据收集，不证明或执行 shell/RCE
./tool/cors_upload_chain.py --authorized --cors-url https://api.example.com/upload --origin https://codex.invalid --output cors-upload.json

# ProjectDiscovery 工具管理器：查看/安装/更新 PD 工具，安装后仍需 wrapper 归一化输出
pdtm -list
pdtm -install dnsx,tlsx,naabu,subfinder,httpx,katana,nuclei

# 通用异步任务运行器：将任意长时间命令放入后台执行，绕过 Bash 工具 10 分钟超时限制
./tool/async_task_runner.py start -c "nuclei -u https://example.com -o nuclei.json"
./tool/async_task_runner.py status <task_id>
./tool/async_task_runner.py wait <task_id> --timeout 3600
./tool/async_task_runner.py list -n 10
./tool/async_task_runner.py clean --keep 20
```

- **扫描管线（`tool/scan_pipeline.py`）** 是授权 Web/API 渗透测试的推荐信息收集入口。它将 subfinder → dnsx → httpx → tlsx/naabu/nmap → katana/history → gf-patterns → nuclei → ffuf → quality_gate → candidate_queue 编排为一条命令行管线，支持 `--mode quick|full|deep` 三种预设深度，自动处理阶段间数据传递、异步长任务轮询、断点续跑、完整覆盖检查和赏金候选队列生成。
- quick 模式（7 阶段，~15-30 分钟）：子域名枚举 → DNS 基线 → 存活探测 → 浅爬取（depth=1）→ GF 模式匹配 → nuclei 高危扫描 → 质量门禁。适合首次侦察。
- full 模式（12 阶段，~1-3 小时）：quick + TLS 指纹 + naabu 全端口候选 + nmap Web 服务确认 + 历史 URL + ffuf quick 目录 fuzz。适合正式渗透测试。
- deep 模式（12 阶段，~2-6 小时）：full + headless 爬取（depth=5）和更深目录 fuzz。适合深度挖掘和 SPA/大型 API 网关。
- 管线支持 `--phases subfinder,httpx,katana,gf` 显式指定阶段列表（覆盖 --mode），也可通过 `--input` 跳过 subfinder 直接从已有资产列表开始。
- 每阶段输出写入 `phase_NN_<name>/result.json`，全局状态写入 `pipeline_state.json`，中断后可通过 `--resume <state_file>` 从断点续跑（已完成阶段自动跳过）。
- 管线默认假设工具已安装（subfinder/dnsx/httpx/tlsx/naabu/nmap/katana/waybackurls/nuclei/ffuf）；未安装的工具对应阶段会自动跳过并记录原因，最终由 quality_gate 输出 WARN/FAIL。gf_pattern_match 阶段始终可用（纯 Python 实现）。
- 建议在授权测试任务开始后立即运行一条 quick 管线建立信息收集基线；quick 产出后根据 `top_candidates` 的 P0/P1 信号决定是否升级到 full 或直接进入定向验证。

- `tool/nmap_json_scan.py` 是 Codex 可直接调用的 Nmap JSON 包装器，用于授权目标的信息收集。
- 调用前必须确认目标在用户授权范围内，并传入 `--authorized`。
- 互联网域名目标在开启 TUN/代理/Fake-IP 环境时，不要直接把域名传给 nmap/rustscan；先用可信解析器或 DoH 取得真实 IP，过滤 `198.18.0.0/15`，再对真实 IP 扫描。需要验证 Web 业务时，使用 `curl --resolve`、`openssl -servername` 或支持固定解析的工具保留 Host/SNI。
- 输出包含命令、时间、主机、端口、服务指纹、NSE 脚本、OS 识别、traceroute 和 runstats，便于后续 AI 分析使用。
- 常用 profile：`discover`、`lan-fast`、`lan-deep`、`risk-ports`、`full-fast`、`udp-fast`、`quick`、`default`、`full`、`udp`、`web`。
- 局域网排查优先使用分阶段策略：`discover` 找在线主机，`lan-fast` 做 top TCP 服务识别，`risk-ports` 查数据库/远程管理/打印/NFS/容器等高风险端口，再按命中服务使用 `web` 或指定 `--scripts` 深挖。
- 推荐常规局域网资产扫描直接使用 `--two-pass`：第一轮用 `discover` 广扫在线主机，第二轮默认用 `lan-deep` 只精扫发现的 IP，避免手工复制目标并减少慢目标拖累。
- 长时间扫描优先使用 `--async-start`，脚本会立刻返回 `task_id`、`result_path`、`stdout_path`、`stderr_path`；之后用 `--async-status <task_id>` 轮询状态和最终 JSON，Codex 可以在后台扫描期间继续分析已有证据。
- `lan-deep` 是两轮扫描的默认精扫 profile：top 1000 TCP、开放端口、完整版本探测、`default,safe` NSE，并设置主机超时；它刻意不默认启用 OS 识别和 traceroute。
- `default`、`full`、`udp` 会做更重的版本、OS、traceroute 或 NSE 探测，容易被慢主机、过滤端口、UDP 丢包拖住；只有需要深度证据时再用。
- `full-fast` 只用于快速开放端口线索，默认带 `--open --min-rate 2000 --max-retries 1 --host-timeout 120s`，命中端口后应再用 `--ports` 配合 `-sV`/脚本做确认。
- `tool/sploitus.py` 是 Codex 可直接调用的 Sploitus 搜索包装器，用于按产品、CVE、服务名检索 exploit 或 security tool 线索。
- Sploitus 支持 `--type exploits` 和 `--type tools`，支持 `--format markdown` 或 `--format json`。
- Sploitus 查询需要外部网络；遇到 HTTP 499/422 通常表示临时限流，稍后重试。
- `tool/httpx_probe.py` 是 Codex 可直接调用的 ProjectDiscovery httpx 包装器，用于把主机/URL 列表探测成 Web 资产清单。
- httpx 输出包含状态码、标题、技术栈、Web Server、长度、跳转位置等 JSONL 字段，脚本会归一化成 JSON。
- `tool/subfinder_json.py` 是 Codex 可直接调用的 ProjectDiscovery subfinder 包装器，用于授权域名的被动子域名枚举。
- subfinder 依赖本机安装 `subfinder`，部分数据源需要用户自己的 provider key 配置。
- `tool/fofa_query.py` 是 Codex 可直接调用的 FOFA API 包装器，用于授权范围内的被动公网资产发现和候选目标扩展。
- FOFA 查询必须传入 `--authorized`，并通过 `FOFA_KEY` 环境变量或 `--key` 提供 API key；脚本输出可默认脱敏 key，但授权漏洞归档、漏洞总结或正式报告按本文件硬规则记录完整证据材料。
- FOFA 输出是平台历史索引数据，只能作为资产线索；命中的 host、IP、端口、标题和指纹必须再用 `httpx`、`nmap`、`katana` 或人工方式实时验证。
- `tool/nuclei_json_scan.py` 是 Codex 可直接调用的 ProjectDiscovery nuclei 包装器，用于模板化漏洞线索扫描。
- nuclei 默认 severity 为 `medium,high,critical`；首次使用需要本机已有 nuclei templates，或通过 `--templates` 指定模板路径。
- nuclei 在 Codex 沙箱中默认使用 `/tmp/codex-projectdiscovery-home` 作为工具 HOME，避免写入用户配置目录失败。
- nuclei 扫描可能超过 10 分钟（尤其模板数量多或目标响应慢时），建议默认使用 `--async-start` 异步模式启动，再用 `--async-status <task_id>` 轮询结果。
- `tool/katana_crawl.py` 是 Codex 可直接调用的 ProjectDiscovery katana 包装器，用于 Web 爬虫、JS 端点解析、robots/sitemap 等已知文件发现。
- Katana 默认输出 JSONL，脚本会归一化成 JSON；默认排除 `raw,body` 大字段，必要时用 `--include-raw` 保留。
- Katana 支持 `--js-crawl`、`--headless`、`--form-extraction`、`--tech-detect`、`--known-files` 和作用域控制参数。
- Katana 依赖本机安装 `katana`，脚本在 Codex 沙箱中默认使用 `/tmp/codex-projectdiscovery-home` 作为工具 HOME。
- Katana 大型 SPA 爬取或 headless 模式可能超过 10 分钟，建议使用 `--async-start` 异步模式。
- Scrapling 是 Codex 当前可用的 MCP 爬取工具，适合需要浏览器渲染、正文/HTML/Markdown 抽取、CSS 选择器提取、批量抓取、截图或高保护页面抓取的场景。
- 调用 Scrapling 时优先使用低影响读取型方法：静态页面用 `mcp__scrapling__.get` 或 `bulk_get`，需要 JS 渲染用 `fetch` 或 `bulk_fetch`，遇到常规抓取失败或高保护页面再用 `stealthy_fetch` 或 `bulk_stealthy_fetch`。
- 需要连续访问、登录态、截图或多页面复用浏览器上下文时，先用 `mcp__scrapling__.open_session` 创建会话，再传入 `session_id` 调用 `fetch`、`bulk_fetch` 或 `screenshot`，结束后用 `close_session` 释放资源。
- 授权 Web/API 渗透测试、资产探测和目标信息收集任务中，Scrapling 只能用于用户授权范围内的页面抓取和证据采集；重要 URL、请求参数、认证状态、响应摘要和截图用途应写入任务归档。
- Scrapling 与 Katana 的分工：Katana 优先用于大规模端点发现、JS URL 抽取和 robots/sitemap 枚举；Scrapling 优先用于少量关键页面的真实渲染观察、动态页面内容抽取、选择器定位和截图取证。
- `tool/gf_pattern_match.py` 是 Codex 可直接调用的 Gf-Patterns 原生 Python 包装器，用于对 katana、waybackurls 等产出的 URL 列表按 14 种漏洞模式（sqli/rce/ssti/ssrf/lfi/idor/redirect/xss/debug_logic/img-traversal/interestingparams/interestingsubs/interestingEXT/jsvar）进行正则匹配和优先级排序，输出归一化 JSON。
- gf_pattern_match 不依赖外部 `gf` 二进制，直接从 `~/.gf/*.json` 读取模式定义；输出包含 `priority_summary`（P0–P3 统计）、`top_candidates`（P0+P1 样本 URL）和 `patterns`（逐模式完整匹配列表）。
- gf_pattern_match 的 14 种模式默认全部运行；用 `--min-priority P1` 收缩到高危模式，用 `--pattern sqli` 只跑单个模式，用 `--no-dedup-per-pattern` 保留模式内重复 URL。
- gf_pattern_match 的优先级映射为：P0 = sqli/rce/ssti（代码执行/数据泄露），P1 = ssrf/lfi/idor/redirect（服务端请求/文件访问/认证绕过），P2 = xss/debug_logic/img-traversal，P3 = interestingparams/interestingsubs/interestingEXT/jsvar（信息线索）。
- 建议管线顺序：katana 爬取 → gf_pattern_match 分类 → nuclei 验证 P0/P1 候选 → 手工定向验证。gf_pattern_match 提供「从 URL 参数特征反向推断漏洞类型」的能力，与 nuclei「已知漏洞模板匹配」互为补充。
- `tool/ffuf_json.py` 是 Codex 可直接调用的 ffuf 包装器，用于授权目标的目录、参数、Host Header 等 fuzz 发现。
- ffuf 默认 `--rate 20`、`--threads 10`，必须传入 `--authorized`；输出会把 ffuf JSON 文件归一化到 `results/config`。
- `tool/arjun_json.py` 是 Codex 可直接调用的 Arjun 包装器，用于授权 HTTP/API 目标的参数发现。
- Arjun wrapper 支持单 URL 或 URL 列表、GET/POST、Header、stable/passive 模式；必须传入 `--authorized`。
- `tool/kiterunner_json.py` 是 Kiterunner 包装器，用于 REST API、大型 SPA 后端和网关 API 路由发现；本机 `kr` 已安装，可用于大型 SPA/API 网关的路由枚举。
- Kiterunner wrapper 默认使用 `kr scan`、JSON 输出和可配置 miss 状态码；必须传入 `--authorized`，并需要用户提供 `.kite` 或路由 wordlist。
- `tool/rustscan_nmap.py` 是 Codex 可直接调用的快速端口发现链：先用 rustscan 找开放端口，再用 nmap 对命中端口做版本确认。
- Rustscan+nmap wrapper 适合局域网、非生产高强度窗口和大端口面快速压缩；必须传入 `--authorized`，输出包含开放端口和 nmap XML 解析结果。
- `tool/masscan_json_scan.py` 是 Codex 可直接调用的 masscan 高速端口扫描包装器，用于授权范围的大规模资产测绘和端口发现。
- masscan 需要 root/sudo 权限发送原始数据包；默认速率 2000 pps，支持单 IP、CIDR 网段和端口范围（如 `-p 1-65535`）。
- masscan 输出为归一化 JSON，包含 host→ports 汇总、开放端口总数、原始 masscan JSON 行数和命令元数据；适合 `/16` 以上大网段快速摸底。
- masscan 互联网目标同样遵循 Fake-IP 规则：先通过可信解析器获取真实 IP，过滤 `198.18.0.0/15`，再传入 `--target`；不要直接传域名。
- masscan 大网段全端口扫描可能超过 1 小时，必须使用 `--async-start` 异步模式。
- `tool/wafw00f_json.py` 是 Codex 可直接调用的 wafw00f 包装器，用于授权目标的 WAF/CDN/安全代理识别。
- wafw00f 可检测 150+ 种 WAF 产品（Cloudflare、AWS WAF、ModSecurity、阿里云 WAF 等）；`--findall` 模式找出所有匹配的 WAF，默认在第一个匹配后停止。
- WAF 识别结果直接影响后续扫描策略：已知 WAF 类型后，可选择对应绕过技术、调整扫描速率避免封禁、并正确区分 WAF 响应与真实应用行为。
- 支持多目标（重复 `--target`）、文件输入（`--input-file`）、Burp 代理串联（`--proxy`）和指定 WAF 针对性测试（`--test`）。
- `tool/whatweb_json.py` 是 Codex 可直接调用的 WhatWeb 包装器，用于授权目标的 Web 技术栈指纹识别（CMS、框架、服务器、CDN、JS 库等）。
- WhatWeb wrapper 支持多目标（重复 `--target`）、1-4 级激进程度、代理串联和自定义插件；本机 `whatweb` 已安装，可作为 httpx 技术栈识别的补充验证。
- `tool/hashcat_json.py` 是 Codex 可直接调用的 hashcat 离线密码哈希破解包装器，用于授权范围内的凭据强度验证和哈希泄露影响证明。
- hashcat wrapper 支持字典攻击（`-a 0`）、组合攻击（`-a 1`）、掩码/暴力破解（`-a 3`）和规则混合模式；内置常用哈希类型快捷方式（md5/sha1/ntlm/sha256/bcrypt/kerberos-tgs/wpa2 等）。
- hashcat 默认使用 GPU (Metal) 加速，可用 `--device-type cpu` 切换到 CPU；默认工作负载为 2，大量破解时可用 `--workload 4` 配合 `-O` 优化内核。
- `--show` 模式读取 potfile 输出已破解哈希和明文，不做实际破解；`--left` 模式列出尚未破解的哈希。需要 `--potfile-path` 指定持久化 potfile 路径以跨会话复用破解结果。
- hashcat 破解时间可能很长，默认超时 2 小时；超时后脚本会读取已破解的部分结果并退出。
- `tool/gitleaks_json.py` 是 Codex 可直接调用的 Gitleaks 包装器，用于源码、备份包、泄露仓库和配置目录的 Secret 扫描。
- Gitleaks wrapper 默认使用 `--redact`，并对 normalized JSON 中的 secret/match/line/offender 字段做二次脱敏。
- `tool/dalfox_json.py` 是 Codex 可直接调用的 Dalfox 包装器，用于授权目标的 XSS 参数验证和 admin bot/preview 链路候选验证。
- Dalfox wrapper 支持单 URL 或 URL 文件、Cookie/Header、blind callback 和 discovery-only 模式；必须传入 `--authorized`。
- `tool/trivy_json.py` 是 Codex 可直接调用的 Trivy 包装器，用于本地文件系统、镜像、仓库、配置和 secret 扫描。
- Trivy 支持 `--mode fs|image|repo|config|rootfs`、`--scanners vuln,secret,misconfig,license`，依赖本机安装 `trivy`。
- `tool/semgrep_json.py` 是 Codex 可直接调用的 Semgrep 包装器，用于源码安全规则扫描。
- Semgrep 默认 `--config auto`、`--metrics=off`，依赖本机安装 `semgrep`；远程规则配置可能需要网络。
- `tool/zap_baseline.py` 是 Codex 可直接调用的 OWASP ZAP baseline 包装器，用于授权 Web 目标的被动基线扫描。
- ZAP 支持本地 `zap-baseline.py` 或 `--docker` 方式运行；ZAP 的 0/1/2 返回码代表不同风险级别，不等同于脚本执行失败。
- `tool/sqlmap_safe.py` 是 Codex 可直接调用的保守 sqlmap 包装器，只用于授权目标的低风险注入验证。
- sqlmap wrapper 固定 `--risk 1 --level 1 --batch --smart`，并禁止 `--dump`、OS shell、SQL shell、文件读写、注册表操作等高风险参数。
- `tool/http_path_probe.py` 是 Codex 可直接调用的 HTTP 路径/路由低影响探测工具，由历史高频 `safe_path_probe.py` 和 `http_route_probe_nofollow.py` 合并沉淀而来。
- http path probe 支持 `--base/--bases + --path/--paths` 矩阵探测或 `--url/--urls` 直接 URL 列表，默认不跟随 30x，支持 Host/Header/Cookie、TLS `--insecure`、并发、header/body 证据保存和高信号标记。
- `tool/origin_exposure_probe.py` 是 Codex 可直接调用的源站/公网入口暴露验证工具，用于授权目标的 DNS A 记录、DoH 对比、固定 Host/SNI 访问和直连 IP 默认站点指纹收集。
- origin exposure 结果要区分“公网 nginx/网关入口 IP”和“私有应用 upstream IP”；前者可由外部验证，后者通常需要基础设施侧证据。
- `tool/gateway_route_classifier.py` 是 Codex 可直接调用的网关路由分类工具，用于少量明确路径的 GET/OPTIONS 等低影响探测，并标记 `spa_fallback_200`、`nginx_404`、`java_json_error`、`gateway_service_discovery_503` 等结果。
- gateway route classifier 的 `spa_fallback_200`、通用 404、curl timeout 不能作为漏洞命中；`gateway_service_discovery_503` 只能证明网关/service-discovery 处理路径，不等同于进入下游实例。
- `tool/cors_upload_chain.py` 是 Codex 可直接调用的 CORS + 上传 + 公开对象预览证据收集工具，用于验证任意 Origin 凭证化 CORS、上传响应、公开预览 URL、inline/attachment/nosniff 等浏览器风险信号。
- cors upload chain 的 `dangerous_suffix_public_inline_no_execution_proven` 只能作为 shell-risk 前置条件，不能写成直接 shell/RCE；命令元数据会脱敏 Cookie 和 Authorization。
- `tool/async_task_runner.py` 是通用后台任务管理器，用于绕过 Codex Bash 工具 10 分钟超时限制。任何长时间运行的命令（nmap 全端口、masscan 大网段、nuclei 完整模板集、katana headless 爬取）都应优先使用异步模式。
- async_task_runner 的子命令：`start`（启动后台任务）、`status`（查看状态和输出尾部）、`wait`（阻塞等待完成）、`list`（列出最近任务）、`clean`（清理已完成任务）。
- 工具 wrapper（nuclei_json_scan、katana_crawl、masscan_json_scan、nmap_json_scan）也内建了 `--async-start` / `--async-status` 接口，功能等价但更紧密集成（自动处理 --output 路径）。推荐优先使用 wrapper 的 --async-start，async_task_runner 作为通用后备。
- 所有异步任务存储在 `/tmp/codex-async-tasks/` 下，每个任务一个子目录，包含 `task.json`（元数据）、`stdout.log`、`stderr.log` 和 `result.json`（工具输出）。
- 扫描器输出只能作为线索，漏洞结论必须结合人工判断和业务影响验证。

本地 Codex Bridge：

```bash
CODEX_BRIDGE_HOST=0.0.0.0 scripts/codex-bridge.py
```


## 迁移到其它项目

如果把这套目录复制到其它项目：

```text
AGENTS.md
agent/
  AGENT.md
  skills/*.md
```

Codex 会优先读根目录 `AGENTS.md`，再进入 `agent/AGENT.md`。如果复制到其它目标项目，应把 `project-architecture.md` 和源码路径替换成目标项目自己的结构；其余角色/安全测试内容只能作为参考知识包。
