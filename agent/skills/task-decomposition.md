# Task Decomposition Skill

本文件用于 Codex 在任意项目中做复杂任务的需求理解、任务规划和任务拆分。它是自包含的通用工作方法，不依赖特定仓库、特定文件路径或其它 skill。

## 触发场景

当用户请求包含以下特征时读取本 skill：

- 需求较宽泛，需要先理解目标、范围、约束和验收标准。
- 需要把一个目标拆成多个可执行步骤、子任务或检查点。
- 需要接管、续跑、修正已有任务、计划、日志或执行结果。
- 需要在已有执行结果基础上重新规划剩余工作。
- 用户明确要求“任务规划”“任务拆解”“需求分析”“执行计划”。

## 通用任务模型

将复杂工作抽象成以下层级：

```text
Goal
  Milestone
    Task
      Subtask
        Evidence / Logs / Artifacts / Decisions
```

核心原则：

- `Goal` 是用户真正要达成的结果。
- `Milestone` 是能判断方向是否正确的阶段性成果。
- `Task` 是一组相关行动，通常对应一个模块、功能、报告章节或验证主题。
- `Subtask` 是可以在一个工作会话中完成的具体行动。
- `Evidence` 是证明结果的代码、测试、日志、截图、报告、命令输出或明确推理依据。

## 工作流

### 1. 需求理解

先把用户请求转成明确任务边界：

- `primary objective`：用户真正要达成的最终结果。
- `explicit requirements`：用户明说的功能、输出、格式、时间、范围。
- `implicit requirements`：为了达成目标必须满足但用户没明说的事项，例如测试、证据、兼容已有架构。
- `non-goals`：不该做的事情，避免扩大范围。
- `constraints`：环境、权限、网络、Docker、依赖、时间、不能破坏现有数据等限制。
- `acceptance criteria`：什么证据能证明任务完成。

如果信息不足但可以从项目中发现，先读代码、文档、配置和日志。只有当关键决策无法从上下文判断且错误假设会带来风险时，才向用户提问。

### 2. 上下文收集

按任务类型读取最小必要上下文，不要假设固定文件名或目录结构：

- 项目说明：README、CONTRIBUTING、AGENTS、CLAUDE、docs、design notes。
- 架构入口：启动文件、路由、服务层、模块索引、配置文件。
- 需求相关代码：通过搜索关键词、类型名、接口名、测试名定位。
- 历史上下文：issue、任务记录、日志、测试输出、已有报告。
- 约束来源：环境变量示例、部署脚本、CI、权限模型、安全说明。

源码调查优先使用快速搜索和小范围读取。不要一次性读取无关大目录。发现已有用户改动时保留并绕开无关变更。

### 3. 初始计划

为复杂任务生成短计划，保持 3-7 个高价值步骤。计划应按下面顺序组织：

1. 明确目标和验收标准。
2. 收集和验证必要上下文。
3. 选择最短可行实现或分析路径。
4. 执行核心改动、测试或验证。
5. 根据结果修正剩余步骤。
6. 输出证据化结论或交付物。

计划不是任务本身的最终产物；它应服务于执行。不要为简单任务制造多余计划。

## Subtask 拆分规则

每个 subtask 都应满足：

- 直接推进用户的 primary objective。
- 有清晰标题和可执行描述。
- 能在一个工作会话中完成。
- 有明确成功标准或可观察结果。
- 与其他 subtask 尽量不重叠。
- 顺序上能形成收敛：信息收集 -> 尝试/实现 -> 验证 -> 报告。
- 描述目标和结果，不把实现细节写死到无法根据发现调整。

避免生成以下 subtask：

- 只为了“获取授权”“等待确认”而存在的步骤，除非用户授权范围本身不清。
- GUI、交互式程序、不可自动化终端会话。
- 与用户目标无关的泛泛研究。
- 只重复已经失败的方法，且没有新的假设或参数变化。

## 推荐拆分形态

### 代码修改任务

```text
1. 定位相关模块、数据流和现有模式。
2. 确认需求影响面和验收标准。
3. 实现最小范围改动。
4. 补充或更新聚焦测试。
5. 运行最小必要验证。
6. 总结改动、测试结果和剩余风险。
```

### 项目理解/文档任务

```text
1. 读取入口文档和项目约定。
2. 建立目录职责和主执行链路。
3. 深挖与用户目标相关的关键实现。
4. 提炼可复用工作流或文档结构。
5. 校验文档与源码路径一致。
```

### 历史任务接管任务

```text
1. 识别目标任务、历史计划或执行记录。
2. 读取输入、状态、结果和关键日志。
3. 区分已完成、失败、未验证和阻塞项。
4. 生成最小剩余计划。
5. Codex 直接执行剩余验证或修复。
6. 输出历史证据与本次新验证的边界。
```

### 授权安全测试任务

赏金/SRC/渗透测试任务采用 4 阶段收敛模型。每个阶段完成后更新 `notes/log.md`，遇到阻塞立即写入 `outputs/agent-handoff-pentest-status.md`。

#### Phase 1: 入口确认（Intake）

1. 从用户输入或 `inputs/scope.md` 确认授权范围（通配符、排除项）。
2. 确认停止条件：发现新高危即停止 或 所有方向材料阻塞即停止。
3. 搜索公开赏金规则页面；未找到则以用户给定范围和 `漏洞评级.md` 为准。
4. 读取 `security-testing.md`、`hack-skill.md`、`handoff-docs.md`、`漏洞评级.md`；初始化任务归档目录。

**产出**：`inputs/scope.md`、`notes/loaded-skills.md`。

> 读取：`security-testing.md`、`handoff-docs.md`

#### Phase 2: 信息收集（Recon）

1. 运行 `scan_pipeline.py --mode quick` 或等价手工基线。
2. 执行 `search.md` 第 6.3.1 节全部 5 个被动源穷举（crt.sh / RapidDNS / urlscan / Wayback CDX / Common Crawl）。
3. 从 JS/前端/App 静态资源提取域名和 API 端点 → `outputs/js-api-inventory.json`。
4. 执行 `search.md` 第 6.3.2 节覆盖差分检查：确认每个已知域名都已进入探测或标记阻塞。
5. DOH 可信解析建立 DNS 基线，规避 Fake-IP。
6. 被动新增域名按语义分批消耗：
   - 第一批：高风险语义（SSO/auth/api/pay/op/jira/fileupload/virus/uncover/callback） → 根+15 路径。
   - 第二批：次级语义（driver/interface/antivirus/internal 命名） → 根+深度样本。
   - 第三批：剩余 → 根+6 路径最小探测。
   - 追加批：urlscan/Wayback 新增认证/回调入口 → 专项复核。
7. CNAME/子域接管风险检查：解析 CNAME 记录，排除 CDN/WAF/已知服务指向，对非典型样本实时 CNAME + 根路径复核，排除 GitHub Pages / Heroku / Netlify / Vercel / AWS S3 / Azure 等可接管指纹。
8. 多主机返回同字节数/同 SHA1 206/200 页面时，只做一次完整页面下载 + SHA1 对比，确认后整组标记 `static_fallback`，不再逐台深测。
9. 生成 `outputs/bounty-candidates.json/md`，所有候选按 P0/P1/P2/P3 分级。

**产出**：`outputs/asset-inventory-detailed.md`、`outputs/asset-inventory.json`、`outputs/js-api-inventory.json`、`outputs/bounty-candidates.json`。

> 发现新域名 → 回到 Phase 2 步骤 3-6 补充探测。发现新 API host → 回到存活+指纹。
> 读取：`search.md`

#### Phase 3: 高危优先挖掘（Hunt）

按 P0 → P1 → P2 → P3 顺序消耗候选队列。每个方向完成一轮只读边界后记录结论。

1. P0 优先：SQLi、SSRF、账号接管、OAuth/OIDC/SAML、IDOR/BOLA、文件链、API 网关绕过、后台未授权、测试环境连生产数据、云凭据泄露。
2. P1 其次：开放平台签名边界、移动端签名 API、AI/IM 会话越权、对象存储公开、认证回调跳转。
3. 每轮只做**低频只读**：GET/HEAD/OPTIONS、空参数、假对象 ID、假凭据、`example.com` 边界 URL。
4. 验证闭环后才进入副作用操作（短信/上传/写入），且只做最小次数，成功一次即停止。
5. 无法闭合的候选标记 `blocked_need_material`，**不直接归档失败**。写清缺失材料和拿到后的第一步验证动作。
6. 每条发现立即执行 `漏洞评级.md` 评级复核，写入 `vulnerability-archive.md` 和 `outputs/vulnerability-archive.json`。
7. 确认新高危 → 立即停止扩大，生成独立 PoC 和报告草稿。

**产出**：`vulnerability-archive.md`、`outputs/vulnerability-archive.json`、更新 `outputs/bounty-candidates.json`。

> 读取：`hack-skill.md`、`security-testing.md`、`漏洞评级.md`

#### Phase 4: 收尾与交接（Closure）

1. 所有低/中危信号尝试闭合到业务影响；闭合失败的按信息项或 `no_impact` 归档。
2. 过滤误报并记录误报边界（为何不是漏洞、下次如何识别）。
3. 按 `handoff-docs.md` 规范绘制 Mermaid 攻击面拓扑图，置于 `## 当前风险索引` 上方。
4. 更新 `outputs/agent-handoff-pentest-status.md`：当前状态、已做/未做、阻塞材料清单、优先下一步、失败路径禁止重复清单。
5. 写入 `retrospective.md`（有效路径、无效路径、可复用经验、工具改进建议）。
6. 匿名化复盘摘要到 `agent/retrospectives/index.md`。

**产出**：`outputs/agent-handoff-pentest-status.md`、`retrospective.md`、Mermaid 攻击面拓扑图。

> 读取：`handoff-docs.md`、`漏洞评级.md`

#### 材料阻塞处理

当所有 P0/P1 候选均标记 `blocked_need_material` 且无剩余高收益方向时：

- 停止主动探测，不重复已穷尽的路径。
- 在交接文档中写明：阻塞点、缺失材料、拿到材料后的验证序列（按 P0→P1 编号）。
- 明确告诉用户：为什么停止、缺什么、下一步需要什么配合。

## 动态重规划

每完成一个关键步骤后，对剩余计划做 delta 调整：

- `remove`：删除已被结果覆盖、已无必要或重复的步骤。
- `modify`：用新发现更新标题、描述、成功标准或执行路径。
- `add`：补上新发现的阻塞、验证缺口或替代路径。
- `reorder`：把高价值、低依赖、能快速降低不确定性的步骤提前。

失败分析要分类：

- `technical`：命令、参数、代码路径或工具使用问题；换具体方法重试。
- `environmental`：依赖、网络、权限、服务未启动；说明阻塞或准备环境。
- `conceptual`：假设错了；换思路而不是微调旧方法。
- `external`：目标系统或外部条件限制；记录限制并改做可验证替代结论。

同类方法连续失败两次后，必须换一条明显不同的路径，或者明确说明已到达当前环境的合理边界。

## 输出格式

当用户要“任务拆解”而不是直接执行时，优先输出：

```markdown
**需求理解**
- 目标：
- 范围：
- 约束：
- 验收标准：

**任务拆分**
1. 标题
   目标：
   执行要点：
   成功标准：
2. ...

**风险与待确认**
- ...
```

当用户要 Codex 直接完成任务时，不要停在拆解；先给必要的短计划，然后执行、验证、汇报。

## 完成度评估

最终结论必须对照用户原始需求，而不是只看步骤是否完成：

- `完成`：核心目标达成，并有代码、测试、日志、文件或报告证据。
- `部分完成`：有可用结果，但存在明确缺口或未验证范围。
- `未完成`：关键目标未达成，说明失败原因和最小后续步骤。

报告时区分事实、推断和未验证事项。不要把“计划了”“尝试了”“某个子任务成功了”等同于用户目标已经完成。
