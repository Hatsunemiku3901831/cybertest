# CTF Web/API 快速夺旗 Skill

本 Skill 仅用于 CTF、靶场、授权训练环境、HackTheBox/TryHackMe、本地实验环境等明确允许利用的目标。它不适用于生产授权渗透测试、客户报告或真实业务系统。

目标是快速缩小攻击面、找到可利用路径并拿到题目目标物：flag、token、admin proof、隐藏答案、动态签名结果、源代码条件中的 secret，或题面指定的任意 proof。若任务目标不是夺旗或训练解题，改用 `security-testing.md` 和 `hack-skill.md`。

CTF、靶场、授权训练环境默认启用 `nonprod-intensive-pentest.md` 中的 L4 强度。该默认值仅适用于本 Skill 覆盖的夺旗/训练目标，不适用于生产授权渗透测试、客户真实业务系统或任何未明确授权的第三方目标。

## 核心原则

- 以拿到题目目标物为目标，不假设它一定叫 `flag`，也不假设它一定在文件系统根目录。
- 禁止联网搜索题名、题面特征句、flag、writeup、平台题解或可直接替代解题的答案；必须基于目标响应、本地工具和题面信息独立推进。
- 默认按 L4 强度推进，允许在授权靶场范围内进行真实利用、RCE、文件读取、数据库读取、上传执行、SSRF 内网访问和破坏边界验证；一旦发现目标不是 CTF/靶场/训练环境，立即退出本 Skill 并降级到常规授权测试流程。
- 优先低成本试错，快速淘汰没有利用价值的路径。
- 发现源码、配置、文件读、RCE、上传执行、SQLi、SSTI、SSRF、认证绕过等高收益信号时立即深挖。
- CTF 环境中可继续推进到命令执行、文件读取、数据库读取和 flag 定位；真实生产目标禁止使用本 Skill。
- 保留关键命令、有效 payload、失败尝试和判断依据，方便回溯；归档报告需要写清楚解题思路，但不需要生成完整客户式风险报告。
- 遇到难题时先抽象“题目要证明什么状态”，再决定攻击路径；不要只找明文 `flag.txt`。

## 时间分配

```text
0-10 分钟：端口、首页、技术栈、robots、常见路径
10-25 分钟：源码/备份/配置泄露、路径爆破、参数发现
25-45 分钟：文件读、RCE、SQLi、SSTI、上传、SSRF、认证绕过专项
45-60 分钟：公开 PoC、弱服务、默认口令、隐藏端口 Web
60 分钟后：换攻击面，避免卡死在单一路径
```

## 快速入口枚举

首轮确认：

```bash
curl -i http://TARGET/
curl -i http://TARGET/robots.txt
nmap -sV -p- --min-rate 5000 TARGET
```

关注：

- Web 框架、语言栈、Server、Cookie 名称、错误页。
- 302 跳转、登录页、管理页、调试页。
- 非 80/443 的隐藏 Web 服务。
- Redis、MongoDB、Elasticsearch、Docker API、Jenkins、Solr、Tomcat、Spring Boot、Grafana 等高收益服务。

## 目标物定位思路

CTF 难题常见目标物位置：

- 文件系统中的 flag、proof、secret、token、answer。
- 数据库、Redis、MongoDB、SQLite、本地文件型数据库。
- 环境变量、启动参数、容器 secret、CI/CD 变量。
- 源码注释、测试文件、备份文件、历史提交。
- 管理后台、管理员会话、机器人访问结果。
- 动态生成页面、一次性 token、签名校验通过后的响应。
- SSRF 可达的内网服务、metadata、admin-only endpoint。
- 前端构建产物、source map、wasm、加密常量。

拿到源码或文件读后，搜索不只限于 `flag`：

```bash
grep -RniE "flag|ctf|secret|token|key|proof|answer|admin|winner|congrat|success|reward" /var/www/html /app 2>/dev/null
```

也要搜索题目相关关键词、路由名、功能名、用户输入参数名和题面中的特殊字符串。

## 直接目标路径

优先探测：

```text
/flag
/flag.txt
/readflag
/app/flag
/var/www/html/flag
/home/*/flag*
/proc/self/environ
/secret
/secret.txt
/proof
/answer
/token
/admin
/debug
/internal
```

拿到文件读或 RCE 后优先执行：

```bash
id
pwd
ls -la
find / -iname '*flag*' -o -iname '*secret*' -o -iname '*proof*' -o -iname '*answer*' 2>/dev/null
cat /flag 2>/dev/null
cat /flag.txt 2>/dev/null
env
```

Web 目录优先：

```bash
ls -la /var/www/html
ls -la /app
grep -R "flag{" /var/www/html /app 2>/dev/null
```

如果没有明显文件，转向“程序逻辑目标”：

- 找到返回成功页、奖励页、管理员页、隐藏 API 的条件。
- 找到签名、JWT、session、role、permission、coupon、invite、reset token 等可伪造点。
- 找到 bot/admin 会访问的位置，构造 XSS、CSRF、open redirect、cache poisoning、request smuggling 等题型路径。
- 找到反序列化、模板、表达式、沙箱逃逸、文件包含等可转化为读 secret 的路径。

## 源码和配置泄露

快速探测：

```text
/.git/
/.svn/
/.DS_Store
/backup.zip
/www.zip
/src.zip
/app.tar.gz
/.env
/config.php
/application.yml
/settings.py
/package.json
/composer.json
/pom.xml
/WEB-INF/web.xml
/swagger.json
/openapi.json
```

发现源码后立即做：

- 提取路由、隐藏接口、管理接口。
- 搜索 `flag`、`secret`、`key`、`token`、`password`、`debug`。
- 搜索文件读、命令执行、模板渲染、SQL 拼接、反序列化、上传处理 sink。
- 检查认证中间件和路由权限绕过。
- 还原题目状态机：哪些条件会返回 success、admin、reward、proof、answer。
- 检查定时任务、bot 访问器、worker、队列消费者、webhook、回调处理器。

## 路径和参数发现

中小字典快速爆破：

```bash
ffuf -u http://TARGET/FUZZ -w WORDLIST -mc all -fc 404 -t 50
```

扩展名优先：

```text
.php,.bak,.zip,.tar.gz,.old,.swp,.txt,.json,.yml,.env
```

参数 fuzz：

```bash
ffuf -u 'http://TARGET/path?FUZZ=test' -w params.txt -mc all -fs BASELINE_SIZE
```

优先参数名：

```text
file,path,url,next,redirect,cmd,exec,ip,host,id,page,template,name,debug,include,module,action
```

## 高收益漏洞优先级

按这个顺序尝试：

1. 任意文件读取 / LFI / Path Traversal
2. 命令注入 / RCE
3. 文件上传到可执行目录
4. SQL 注入
5. SSTI
6. 反序列化
7. SSRF 访问本地服务或 metadata
8. JWT/Session 伪造
9. 认证绕过
10. IDOR/BOLA
11. 业务逻辑绕过、条件竞争、价格/积分/权限状态篡改
12. XSS 到 admin bot、CSRF 到管理员动作、open redirect 组合
13. Web cache poisoning、HTTP request smuggling、Host header 信任问题

低优先级：

- 安全头缺失。
- 弱 TLS。
- 普通 CORS。
- 普通目录 listing。
- 只有版本暴露但没有 exploit path。
- 纯静态资源和无敏感信息的模板文件。

## 常用 Payload 起手式

文件读取：

```text
../../../../etc/passwd
....//....//....//etc/passwd
/var/www/html/index.php
php://filter/convert.base64-encode/resource=index.php
file:///etc/passwd
```

命令注入：

```text
127.0.0.1;id
127.0.0.1|id
127.0.0.1&&id
`id`
$(id)
```

SSTI：

```text
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
```

SQLi：

```text
'
"
' or '1'='1
1 order by 1
1 union select null
```

SSRF：

```text
http://127.0.0.1:80/
http://localhost:80/
http://0.0.0.0:80/
http://169.254.169.254/
file:///etc/passwd
gopher://
```

## 深挖信号

看到这些信号立即推进：

- 报错包含绝对路径、栈信息、模板名、SQL 错误。
- 参数名像 `file`、`path`、`url`、`cmd`、`template`、`debug`。
- 上传后文件可访问，且扩展名或 Content-Type 可控。
- Cookie/JWT 可读、弱签名、空签名或算法可控。
- 管理接口只靠前端隐藏。
- 公开 PoC 与版本、框架、插件匹配。
- `/debug`、`/actuator`、`/console`、`/admin`、`/api/docs` 可访问。
- 响应出现 `success`、`congrat`、`reward`、`proof`、`admin only`、`forbidden unless` 等状态提示。
- 有 bot、report、preview、webhook、callback、import、fetch URL、render URL 等服务端访问功能。
- 有签名参数、时间戳、nonce、role、plan、price、score、coupon、invite、state 等可控业务字段。
- 有 source map、wasm、前端加密、隐藏路由、feature flag、实验开关。

看到这些信号快速跳过：

- 纯静态页面且无隐藏文件。
- 只有安全头问题。
- 只有 CORS 但没有敏感认证态接口。
- 只有版本号但没有可用利用路径。
- 目录爆破全是静态资源。
- SPA fallback 但 JS 里没有 API、secret 或业务线索。

## 利用后定位

拿到 RCE、文件读或源码后优先：

- 读环境变量、配置文件、启动参数。
- 找数据库账号密码。
- 连接本地数据库，查 `users`、`flag`、`secrets`、`config` 表。
- 搜索 Web 根目录、应用目录、用户 home 目录。
- 如果是容器，检查 `/proc/1/environ`、挂载点、`/run/secrets`。
- 如果目标物动态生成，找生成函数、比较函数、签名密钥、管理员权限判断和成功响应分支。

## 难题分流

如果 20-30 分钟没有直接入口，按题型分流：

- **源码型**：优先找隐藏路由、危险 sink、认证中间件、测试文件、构建产物。
- **逻辑型**：画出状态转移，重点看金额、权限、次数、时间、nonce、签名、回调。
- **Bot/XSS 型**：找 report/preview/admin bot，构造能让管理员带 cookie 访问的最小页面。
- **SSRF 型**：先扫本地端口和内网常见服务，再读 metadata、admin、本地 debug。
- **反序列化/模板型**：先证明表达式或对象链可控，再转文件读或命令执行。
- **密码学/签名型**：找硬编码 key、弱随机、长度扩展、算法混淆、JWT alg/none、时间窗口。
- **沙箱型**：先枚举语言/模板/过滤规则，再找编码、属性链、内置对象、文件描述符。
- **缓存/协议型**：检查 Host、X-Forwarded-*、Content-Length/Transfer-Encoding、缓存 key 差异。

## 输出格式

记录能推进夺旗的信息即可：

```text
入口：
技术栈：
高价值路径：
可疑参数：
已验证漏洞：
当前权限：
目标物/成功条件：
目标物位置：
下一步：
```
