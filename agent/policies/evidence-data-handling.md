# 证据与敏感数据处理策略

## 目的和适用范围

本策略是 Cybertest 保存证据、编写任务文档和沉淀可复用知识的单一事实源，适用于：

- 原始 HTTP、浏览器、Burp、CDP、抓包、CLI、截图和文件证据。
- `notes/`、资产清单、漏洞归档、handoff 和报告。
- `agent/cases/`、`agent/memory/`、`agent/tactics/`、`agent/skills/`、参考资料和测试 fixture。

授权范围决定“能否采集”，本策略决定“采集后放在哪里、如何引用、能否复用”。专项 skill 和工具默认值只能收紧本策略，不能绕过可复用知识的匿名化边界。

## 三层数据模型

### A. Restricted Raw Evidence

受限原始证据用于保存完成复现和影响评估确实需要的原始值，例如：

- 完整请求和响应。
- Cookie、JWT、Authorization、密码、密钥、API key、AppKey/Secret 和数据库连接材料。
- 可重放 token、回调标识、内部地址、真实业务对象和值。
- 含客户、账号、个人或组织身份的截图、导出文件和抓包。

保存要求：

- 放入任务目录的 `evidence/restricted/`；按需再分 `http/`、`burp/`、`capture/`、`files/` 或 `screenshots/`。
- 只保存完成当前任务所必需的最小样本，不因“可能以后有用”批量复制。
- 默认不进入 Git，不进入通用 fixture，不被 case、memory、tactic、skill 或公开材料引用原值。
- 目录和文件权限采用本机可行的最小权限；推荐目录 `0700`、文件 `0600`。
- 不在文件名中写秘密、账号、真实姓名、客户名、内部域名或个人绝对路径。
- 原始文件保持不可变；脱敏、分类和人工判断写入派生文件或 sidecar，不原地改写证据。

任务主文档引用受限证据时，默认只记录：

```yaml
path: evidence/restricted/http/20260724-120000_target_login.json
sha256: <sha256>
media_type: application/json
captured_at: 2026-07-24T12:00:00Z
auth_context: controlled-user-a
purpose: authentication-differential
```

路径必须相对任务目录，不记录操作系统用户名或个人目录。

### B. Task Archive

任务归档包括：

- `notes/log.md`
- 资产清单
- `vulnerability-archive.md` 及结构化 JSON
- `outputs/agent-handoff-pentest-status.md`
- 阶段报告、正式报告和提交材料

任务归档应自包含记录技术事实和影响判断，默认包括：

- 请求方法、路径或接口族。
- 认证上下文别名和角色，不复制完整认证材料。
- HTTP 状态、关键字段名、数据类型、长度、数量级和稳定差分。
- 正控、负控、回读、不变量、停止点和回滚结果。
- 已证明影响、未证明影响、评级复核和不可扩大表述。
- 受限证据的相对路径、SHA-256、类型和采集时间。

可重放秘密默认只记录：

- 秘密类型，例如 `JWT`、`session_cookie` 或 `app_secret`。
- 必要时的极短前后缀，且不得足以恢复原值。
- 长度、签发方/用途等非秘密元数据。
- 不可逆指纹，例如完整值的 SHA-256。

不得为了“报告方便”把完整秘密从受限证据复制到日志、handoff、Markdown 风险总账或普通 JSON。

如果用户或交付合同明确要求某份报告必须包含可重放原值：

1. 在任务范围或交付说明中记录该要求。
2. 只在必要章节保留最小原值。
3. 将整份交付物按 Restricted Raw Evidence 管理、限制访问并排除 Git。
4. 同时生成可日常流转的脱敏版本。
5. 该受限交付物不得作为 case、memory、tactic、skill 或 fixture 的来源原文传播。

### C. Reusable Knowledge

可复用知识包括：

- `agent/cases/`
- `agent/memory/`
- `agent/tactics/`
- `agent/skills/`
- `agent/references/`
- 测试 fixture、golden 数据和示例

必须满足：

- 只保留通用技术结构、触发信号、控制缺口、请求矩阵、负控、不变量、停止点、回滚和误报边界。
- 使用 `example.com`、RFC 5737/3849 示例地址、虚构账号和 `{placeholder}`。
- 来源只记录匿名任务别名、相对来源类别和内容 SHA-256；不得链接可重放原始证据。
- 禁止真实域名、IP、内部路径、客户/组织/个人标识、Cookie、JWT、密码、API key、Secret、callback URL 和业务原值。
- 禁止个人用户名、主机名、邮箱、SSH 路径、聊天记录路径和其它可识别测试人员的信息。
- 单个 case 不能自动晋升稳定规则；晋升仍遵循对应 memory/tactic/skill 门禁。

## 数据流

```text
原始观察
  → 判断是否需要保存
  → 必要原值进入 Restricted Raw Evidence
  → 提取脱敏事实进入 Task Archive
  → 匿名化并去目标化
  → 通过泄密与绝对路径检查
  → 才能进入 Reusable Knowledge
```

从受限证据生成派生内容时，应保留来源 SHA-256 和转换时间；派生内容不得覆盖原文件。

## 冲突和表述处理

- 需要复现不等于需要在主文档复制秘密；主文档通过受限证据引用保持可追溯。
- “完整证据”指证据链完整，不要求每个可重放原值出现在可流转文档中。
- 报告中的脱敏不得改变状态码、字段类型、长度、数量级、正负控差分或影响结论。
- 不得因匿名化把未确认线索改写成已确认漏洞。
- 若发现秘密误入 Git 或可复用知识，立即停止继续传播，记录受影响文件，移除可重放值，并提示轮换相关秘密；不要通过清理任务日志掩盖事件。
- 不自动删除用户原始证据。保留期、移交和销毁按照用户或任务约定执行。

## 写入前检查

### Task Archive

- [ ] 是否只保存当前任务必要事实。
- [ ] 完整秘密是否只在 `evidence/restricted/`。
- [ ] 主文档是否包含方法、认证别名、差分、影响和证据引用。
- [ ] 引用是否使用任务相对路径和 SHA-256。
- [ ] 是否避免个人绝对路径和测试人员标识。

### Reusable Knowledge

- [ ] 是否已替换真实域名、IP、客户、账号和业务对象。
- [ ] 是否不存在可重放 token、Cookie、密码、key、Secret 或 callback。
- [ ] 是否不存在个人路径、用户名、主机名或邮箱。
- [ ] fixture 是否完全虚构且无法回连真实目标。
- [ ] 是否运行覆盖 cases、memory、tactics、skills、references、fixtures 和 goldens 的默认泄密扫描。
- [ ] 默认扫描中 high/critical 命中必须阻断；domain/IP 等 medium 启发式命中必须人工复核。
- [ ] 允许项是否使用 `agent/policies/reusable-knowledge-allowlist.json` 中的精确值和最小路径范围，并具有理由、来源、复核日期和可选到期日。
- [ ] 正式发布是否执行以下严格门禁并确认退出码为 `0`：

  ```bash
  python3 tool/scan_reusable_knowledge_leaks.py \
    --dry-run \
    --fail-severity medium \
    --fail-on-findings
  ```

  `--fail-severity` 只决定报告中的 `PASS`、`REVIEW` 或 `FAIL` 分类，不单独改变退出码；`--fail-on-findings` 才使达到阈值的未豁免发现返回退出码 `1`。工具输入、schema 或读取错误返回 `2`。报告将允许项标记为 `suppressed` 并记录对应 allowlist ID，未豁免线索分别标记为 `review` 或 `blocking`。
- [ ] 是否运行 `tool/check_markdown_links.py --dry-run --fail-on-broken` 相对链接门禁。
