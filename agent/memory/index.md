# Memory Index

本索引用于让 Codex 在任务开始时按需加载经验蒸馏结果。不要一次性加载全部 memory；先按任务类型、技术栈、测试阶段和标签选择少量最相关条目。

## 状态约定

| 状态 | 含义 | 使用方式 |
|---|---|---|
| draft | 初次小蒸馏结果，样本少，可能过拟合 | 仅作参考，必须重新验证 |
| active | 已在相近任务中反复出现 | 同类任务可优先参考 |
| stable | 已被 tactic/full 蒸馏确认 | 可作为默认优先打法或停止规则 |
| deprecated | 已证伪、噪声过高或不再适用 | 默认不加载，只保留审计记录 |

## 调用优先级

```text
stable tactic > active pattern > draft pattern > 原始 retrospective
```

## Pattern Memory

| 文件 | 标签 | 适用场景 | 优先级 | 状态 | 最近确认 |
|---|---|---|---|---|---|
| [pattern/pattern-memory-2026-06-15-recent-10.md](pattern/pattern-memory-2026-06-15-recent-10.md) | spa_js_intel, source_map_gap, api_auth_matrix, material_block, waf_cdn_noise, cors_boundary, login_flow_fidelity, static_pii, mobile_static, asset_scoring, default_creds, token_leak_boundary, stopping_rule, report_quality | 最近 10 个授权 Web/API、物流后台、Demo/UAT、云产品前端、静态敏感资源、多后台管理面任务的局部高频模式；同类任务开始时按标签选择性加载 | high | draft | 2026-06-15 |
| [pattern/pattern-memory-2026-06-15-previous-10.md](pattern/pattern-memory-2026-06-15-previous-10.md) | ct_dns_recon, vhost_pivot, spa_js_intel, api_gateway_mapping, frontend_auth_bypass, cors_cookie_boundary, object_storage_boundary, dwr_interface_intel, cve_negative_validation, waf_cdn_noise, captcha_block, crypto_boundary, domain_hijack, ctf_client_signature, material_block, stopping_rule | 再往前 10 个授权 Web/API、赏金公开面、资产测绘、域名劫持、CVE 阴性验证和 CTF 前端签名任务的局部高频模式；同类任务开始时按标签选择性加载 | high | draft | 2026-06-15 |
| [pattern/pattern-memory-2026-05-26-recent-10.md](pattern/pattern-memory-2026-05-26-recent-10.md) | frontend_intel, api_auth_boundary, object_storage, privacy_publication_boundary, broker, asset_correlation, waf_cdn_noise, cors_boundary, redirect_risk, ci_cd_exposure, negative_validation, upload_boundary, report_quality, stopping_rule | 最近 10 个授权 Web/API、政务门户、公共服务、商城/API、OA、Java/Tomcat、消息代理、对象存储任务的局部高频模式；任务开始时按标签选择性加载 | high | active | 2026-05-26 |

## Tactic Memory

| 文件 | 标签 | 适用场景 | 优先级 | 状态 | 最近确认 |
|---|---|---|---|---|---|

## Full Distillation

| 文件 | 覆盖范围 | 关键结论 | 状态 | 日期 |
|---|---|---|---|---|
