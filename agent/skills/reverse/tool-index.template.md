# Reverse Tool Index Template

本文件描述本地逆向工具探测结果的最小契约。稳定能力事实以
`agent/capabilities/manifest.yaml` 中的 capability ID 为准；本模板不保存
某台机器的安装路径、版本或可用状态。

## 本地生成

```bash
bash agent/skills/reverse/scripts/refresh-tool-index.sh
```

生成结果为：

```text
agent/skills/reverse/tool-index.md
agent/skills/reverse/tool-index.json
```

这两个文件是本机运行时缓存，已被 `.gitignore` 排除。探测脚本只读，不安装
工具，也不修改 PATH、shell 配置或 Agent 客户端配置。

## 输出约束

- `available` 只表示本轮探测发现命令或 provider，不代表 MCP 已注册或健康。
- `path` 兼容字段只允许保存命令/provider 标识，例如 `jadx` 或 `npx`；不得保存
  解析后的绝对路径。
- 版本和可用状态属于易变运行时信息，不得复制进主 skill 或路由规则。
- 浏览器、HTTP 重放、CDP、抓包和 OAST 使用 capability registry 与
  `tool/detect_capabilities.py` 探测。
- 需要安装时，先根据当前平台和任务所需 capability 给出最小安装建议；不自动
  安装大型工具或 GUI。

## 机器可读记录

```json
{
  "name": "jadx",
  "skill": "apk-reverse",
  "purpose": "APK Java/Kotlin decompiler",
  "available": true,
  "path": "jadx",
  "version": "detected",
  "install_hint": "platform-specific"
}
```
