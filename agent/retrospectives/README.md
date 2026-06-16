# 渗透测试复盘

本目录保存授权安全测试后的匿名化复盘。

使用这些记录避免重复无效路径，沉淀有效命令模式，并改进后续 Codex 测试流程。

规则：

- 完成任何授权渗透测试、漏洞验证、安全扫描、资产发现或 Web/API 安全测试任务前，都要创建复盘。
- 不要存储 secret、API key、cookie、JWT、密码、私有域名、内部 IP、callback URL 或可识别客户身份的细节。
- 使用 `{target_domain}`、`{target_ip}`、`{auth_cookie}`、`{api_token}`、`{callback_url}`、`{account_a}` 等占位符。
- 同时记录正向和负向结果。失败命令和无效路径能避免后续重复浪费时间，也有记录价值。
- 添加新复盘时同步更新 `index.md`。

文件命名：

```text
YYYY-MM-DD-short-target-alias-task.md
```

Example:

```text
2026-05-17-target-domain-authz-复测.md
```
