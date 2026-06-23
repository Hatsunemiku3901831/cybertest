# Cybertest 工具清单与依赖

本文档汇总仓库内 `tool/` 目录的可复用工具、用途、外部依赖和典型使用方式，方便新环境初始化、GitHub 使用者快速理解工具能力。

## Windows 一键安装

Windows 用户优先使用根目录安装入口：

```powershell
.\install_windows.cmd
```

或在 PowerShell 中直接运行：

```powershell
powershell -ExecutionPolicy Bypass -File .\install_windows.ps1
```

脚本会优先使用 `winget`、`go install`、`pip` 自动安装可自动化处理的工具；`masscan`、`whatweb`、OWASP ZAP、Burp MCP、FOFA API key 等环境相关组件会在结束摘要中列为人工处理项。需要尝试 Chocolatey 补充安装时可运行：

```powershell
powershell -ExecutionPolicy Bypass -File .\install_windows.ps1 -InstallChocolatey
```

## macOS 一键安装

macOS 用户使用 `require/` 目录下的 shell 脚本：

```bash
bash require/install_macos.sh
```

脚本会优先使用 Homebrew、`go install`、`pipx`/`pip` 安装可自动化处理的工具。需要同时安装 OWASP ZAP 这类 GUI/cask 组件时可运行：

```bash
bash require/install_macos.sh --with-casks
```

## 基础运行环境

| 依赖 | 用途 |
|---|---|
| Python 3.10+ | 运行 `tool/*.py` 脚本。 |
| Node.js 18+ | 运行 `tool/burp_sse_mcp_bridge.js`。 |
| curl | HTTP 探测、CORS/上传链验证、网关路由探测、源站暴露探测。 |
| git | 代码仓库状态采集、上下文导出、提交前检查。 |
| 可写 `/tmp` | 扫描管线、异步任务和部分包装器会在临时目录生成中间文件。 |

所有主动探测类工具默认仅用于授权范围。执行前优先查看帮助：

```bash
python3 tool/<script>.py --help
```

## 推荐安装的外部安全工具

| 工具 | 被哪些脚本使用 | 说明 |
|---|---|---|
| `subfinder` | `subfinder_json.py`, `scan_pipeline.py` | 子域名枚举。 |
| `dnsx` | `dnsx_json.py`, `scan_pipeline.py` | DNS 解析与记录基线。 |
| `httpx` | `httpx_probe.py`, `scan_pipeline.py` | HTTP/HTTPS 存活、标题、状态码、技术指纹。 |
| `tlsx` | `tlsx_json.py`, `scan_pipeline.py` | TLS 证书和协议侧信息收集。 |
| `naabu` | `naabu_json_scan.py`, `scan_pipeline.py` | 快速端口发现。 |
| `nmap` | `nmap_json_scan.py`, `rustscan_nmap.py`, `scan_pipeline.py` | 端口扫描、服务识别和 NSE 安全脚本。 |
| `rustscan` | `rustscan_nmap.py` | 快速端口发现后交给 Nmap 复核。 |
| `masscan` | `masscan_json_scan.py` | 大范围高速端口发现。 |
| `katana` | `katana_crawl.py`, `scan_pipeline.py` | Web 爬取、JS 和接口路径发现。 |
| `nuclei` | `nuclei_json_scan.py`, `scan_pipeline.py` | 模板化漏洞与暴露面扫描。 |
| `ffuf` | `ffuf_json.py`, `scan_pipeline.py` | 目录、路径、参数和内容 fuzz。 |
| `waybackurls` | `url_history_collect.py`, `scan_pipeline.py` | 历史 URL 收集。 |
| `arjun` | `arjun_json.py` | HTTP 参数发现。 |
| `kiterunner` | `kiterunner_json.py` | API 路由发现与字典探测。 |
| `dalfox` | `dalfox_json.py` | XSS 发现与反射参数分析。 |
| `sqlmap` | `sqlmap_safe.py` | 低风险 SQL 注入验证。 |
| `wafw00f` | `wafw00f_json.py` | WAF/CDN 防护识别。 |
| `whatweb` | `whatweb_json.py` | Web 技术栈指纹识别。 |
| `zap-baseline.py` / OWASP ZAP | `zap_baseline.py` | ZAP baseline 扫描包装。 |
| `gitleaks` | `gitleaks_json.py` | 仓库密钥和敏感信息扫描。 |
| `semgrep` | `semgrep_json.py` | 静态代码规则扫描。 |
| `trivy` | `trivy_json.py` | 文件系统、镜像、仓库、配置和 rootfs 漏洞扫描。 |
| `hashcat` | `hashcat_json.py` | 授权离线哈希破解与结果结构化。 |

可选外部服务：

| 服务 | 被哪些脚本使用 | 配置 |
|---|---|---|
| FOFA | `fofa_query.py` | 使用 `FOFA_EMAIL`、`FOFA_KEY`、`--key-file` 或脚本参数传入。 |
| Sploitus | `sploitus.py` | 公共 exploit/tool 搜索 API，无需本地二进制。 |
| Burp Suite MCP | `burp_sse_mcp_bridge.js` | 默认连接 `127.0.0.1:9876`，可用 `BURP_MCP_HOST`、`BURP_MCP_PORT` 覆盖。 |

## 编排与通用支撑工具

| 文件 | 类型 | 用途 | 关键依赖 |
|---|---|---|---|
| `tool/scan_pipeline.py` | 编排器 | 串联子域名、DNS、HTTP、TLS、端口、爬取、历史 URL、GF、Nuclei、FFUF、质量门禁和候选队列。支持 `quick`、`full`、`deep`、断点恢复和 dry-run。 | Python 3、多个外部安全工具 |
| `tool/async_task_runner.py` | 编排器 | 后台运行长耗时命令，支持 start/status/wait/list/clean，避免交互超时。 | Python 3 |
| `tool/_async_utils.py` | 内部库 | 为扫描包装器提供异步启动和状态查询能力。 | Python 3 |
| `tool/quality_gate.py` | 质量门禁 | 读取扫描管线输出并评估阶段覆盖质量，可输出 JSON/Markdown。 | Python 3 |
| `tool/bounty_candidate_queue.py` | 候选队列 | 从扫描管线、本地输入和工具结果生成 P0/P1/P2/P3 漏洞候选队列。 | Python 3 |
| `tool/gf_pattern_match.py` | 离线匹配 | 内置 GF 风格规则，对 URL/路径进行漏洞类型归类与排序，无需外部 `gf`。 | Python 3 |
| `tool/task_context_bundle.py` | 上下文导出 | 导出任务上下文 Markdown，方便其它 LLM/Agent 接手。 | Python 3、git 可选 |

典型命令：

```bash
./tool/scan_pipeline.py --authorized --domain example.com --mode quick
./tool/scan_pipeline.py --authorized --domain example.com --mode full --dry-run
python3 tool/async_task_runner.py start --command "nuclei -u https://example.com -jsonl"
python3 tool/quality_gate.py --pipeline-dir /tmp/codex-scan-pipelines/example
./tool/bounty_candidate_queue.py --pipeline-dir /tmp/codex-scan-pipelines/example --output-json candidates.json --output-md candidates.md
```

## 资产发现与暴露面工具

| 文件 | 用途 | 外部依赖 |
|---|---|---|
| `tool/subfinder_json.py` | 调用 `subfinder` 枚举子域名并输出标准 JSON。 | `subfinder` |
| `tool/dnsx_json.py` | 调用 `dnsx` 对域名/主机做 DNS 解析并输出标准 JSON。 | `dnsx` |
| `tool/httpx_probe.py` | 调用 `httpx` 对主机或 URL 做 HTTP 存活、状态码、标题、技术栈和端口探测。 | `httpx` |
| `tool/tlsx_json.py` | 调用 `tlsx` 采集 TLS 证书、协议和端口信息。 | `tlsx` |
| `tool/naabu_json_scan.py` | 调用 `naabu` 做快速端口发现，支持 CDN 排除和结果验证。 | `naabu` |
| `tool/nmap_json_scan.py` | 调用 `nmap` 输出 AI 友好的 JSON，支持多 profile、two-pass、异步扫描和 NSE 参数。 | `nmap` |
| `tool/rustscan_nmap.py` | 先用 `rustscan` 快速发现端口，再用 `nmap` 做确认和服务识别。 | `rustscan`、`nmap` |
| `tool/masscan_json_scan.py` | 包装 `masscan` 进行高速端口发现并标准化输出。 | `masscan` |
| `tool/fofa_query.py` | 查询 FOFA 并输出授权资产发现 JSON。 | FOFA API |
| `tool/sploitus.py` | 查询 Sploitus exploit/tool 索引，输出 Markdown 或 JSON，用于公开漏洞资料和工具线索检索。 | Sploitus API |
| `tool/origin_exposure_probe.py` | 对候选源站 IP、Host/SNI 和边缘入口做低风险源站暴露验证。 | `curl` |
| `tool/url_history_collect.py` | 调用 `waybackurls` 收集历史 URL 并结构化输出。 | `waybackurls` |

典型命令：

```bash
./tool/subfinder_json.py --authorized --domain example.com --output subdomains.json
./tool/httpx_probe.py --authorized --input hosts.txt --output alive.json
./tool/nmap_json_scan.py --authorized --target 127.0.0.1 --profile web --output nmap-web.json
./tool/fofa_query.py --authorized --query 'domain="example.com"' --output fofa.json
./tool/sploitus.py --query "apache struts" --type exploits --format json
```

## Web/API 探测与漏洞验证工具

| 文件 | 用途 | 外部依赖 |
|---|---|---|
| `tool/katana_crawl.py` | 调用 `katana` 爬取页面、路由、JS 和 API 入口，支持深度、headless、JS crawl。 | `katana` |
| `tool/ffuf_json.py` | 调用 `ffuf` 做目录、路径、参数和内容 fuzz，并标准化输出。 | `ffuf` |
| `tool/arjun_json.py` | 调用 `arjun` 进行 HTTP 参数发现，支持 header、body、method 和速率控制。 | `arjun` |
| `tool/kiterunner_json.py` | 调用 `kiterunner` 做 API 路由发现。 | `kiterunner` |
| `tool/nuclei_json_scan.py` | 调用 `nuclei` 做模板扫描，支持 severity、tags、自定义模板路径和内置模板。 | `nuclei` |
| `tool/dalfox_json.py` | 调用 `dalfox` 做 XSS 与反射参数发现。 | `dalfox` |
| `tool/sqlmap_safe.py` | 包装 `sqlmap`，默认偏低风险验证，避免无控制 dump。 | `sqlmap` |
| `tool/http_path_probe.py` | 授权 HTTP 路径/路由探测，支持 base/path/url、并发、证据落盘、Host 和 Header 控制。 | Python 3 |
| `tool/gateway_route_classifier.py` | 对显式网关路径做方法、状态码、跳转和响应差异分类。 | `curl` |
| `tool/cors_upload_chain.py` | 收集 CORS、上传和公开预览信任边界证据，支持低频上传证明。 | `curl` |
| `tool/wafw00f_json.py` | 调用 `wafw00f` 识别 WAF/CDN 产品并输出 JSON。 | `wafw00f` |
| `tool/whatweb_json.py` | 调用 `whatweb` 识别 Web 技术栈、插件和响应指纹。 | `whatweb` |
| `tool/zap_baseline.py` | 包装 OWASP ZAP baseline 扫描并结构化输出。 | OWASP ZAP |

典型命令：

```bash
./tool/katana_crawl.py --authorized --input alive_urls.txt --output katana.json
./tool/ffuf_json.py --authorized --url https://example.com/FUZZ --wordlist words.txt --output ffuf.json
./tool/nuclei_json_scan.py --authorized --input alive_urls.txt --severity medium,high,critical --output nuclei.json
./tool/http_path_probe.py --authorized --base https://example.com --path /admin --output paths.json
```

## 代码、安全配置与供应链工具

| 文件 | 用途 | 外部依赖 |
|---|---|---|
| `tool/gitleaks_json.py` | 调用 `gitleaks` 扫描仓库密钥、token 和敏感信息泄露。 | `gitleaks` |
| `tool/semgrep_json.py` | 调用 `semgrep` 执行静态规则扫描并输出标准 JSON。 | `semgrep` |
| `tool/trivy_json.py` | 调用 `trivy` 扫描文件系统、镜像、仓库、配置和 rootfs。 | `trivy` |

典型命令：

```bash
./tool/gitleaks_json.py --source . --output gitleaks.json
./tool/semgrep_json.py --target . --config auto --output semgrep.json
./tool/trivy_json.py --mode fs --target . --output trivy.json
```

## 密码与离线验证工具

| 文件 | 用途 | 外部依赖 |
|---|---|---|
| `tool/hashcat_json.py` | 包装 `hashcat`，支持字典、掩码、规则、show/left、CPU/GPU 选择和 JSON 结果解析。 | `hashcat` |

典型命令：

```bash
./tool/hashcat_json.py --authorized -m 0 -a 0 --hash-file hashes.txt --wordlist rockyou.txt --output hashcat.json
./tool/hashcat_json.py --authorized --hash-file hashes.txt --show --output cracked.json
```

## Burp 与 MCP 工具

| 文件 | 用途 | 外部依赖 |
|---|---|---|
| `tool/burp_sse_mcp_bridge.js` | 将 Burp 官方 MCP 扩展的 SSE 服务桥接为行分隔 stdio MCP 客户端。 | Node.js、Burp MCP 扩展 |

典型命令：

```bash
BURP_MCP_HOST=127.0.0.1 BURP_MCP_PORT=9876 node tool/burp_sse_mcp_bridge.js
```

## Nuclei 模板

| 文件 | 用途 |
|---|---|
| `tool/nuclei-templates/frontend-attack-chain-exposure.yaml` | 前端攻击链暴露相关 Nuclei 模板，可通过 `nuclei_json_scan.py --templates` 或原生 `nuclei -t` 使用。 |

典型命令：

```bash
./tool/nuclei_json_scan.py --authorized --input alive_urls.txt --templates tool/nuclei-templates/frontend-attack-chain-exposure.yaml --output frontend-exposure.json
```

## 非工具产物

以下路径在历史工作区中可能被 Git 跟踪，但不是可执行工具或依赖要求：

| 路径 | 说明 |
|---|---|
| `tool/__pycache__/` | Python 解释器缓存产物，不作为工具入口，不建议继续提交。 |

## 最小可用工具集

如果只想先跑通授权 Web/API 资产发现，建议至少准备：

```text
Python 3
curl
subfinder
dnsx
httpx
katana
nuclei
nmap
ffuf
```

若要覆盖供应链、代码扫描和离线凭据验证，再补充：

```text
gitleaks
semgrep
trivy
hashcat
```

若要接入 Burp MCP，再补充：

```text
Node.js
Burp Suite MCP extension
```
