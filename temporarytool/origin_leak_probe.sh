#!/usr/bin/env bash
set -o pipefail

TOKEN="${TOKEN:-}"
OUT_ROOT="${OUT_ROOT:-security_probes/out}"
STAMP="$(date '+%Y%m%d-%H%M%S')"
OUT_DIR="$OUT_ROOT/origin-leak-$STAMP"
REPORT="$OUT_DIR/report.md"
ERRLOG="$OUT_DIR/curl-errors.log"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-6}"
MAX_TIME="${MAX_TIME:-30}"

mkdir -p "$OUT_DIR/assets" "$OUT_DIR/http" "$OUT_DIR/dns"

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

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
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

write_line() {
  printf '%s\n' "$1" >> "$REPORT"
}

curl_headers() {
  local name="$1"
  local url="$2"
  shift 2
  local headers="$OUT_DIR/http/$name.headers"
  local body="$OUT_DIR/http/$name.body"
  local status
  status="$(curl "${CURL_BASE[@]}" "$@" -D "$headers" -o "$body" -w '%{http_code} %{remote_ip} %{ssl_verify_result} %{url_effective}' "$url" 2>> "$ERRLOG")" || status="000 - - $url"
  redact_file "$headers"
  redact_file "$body"
  printf '%s\n' "$status" > "$OUT_DIR/http/$name.meta"
}

doh_query() {
  local resolver="$1"
  local name="$2"
  local type="$3"
  local safe
  safe="$(sanitize_name "$resolver-$name-$type")"
  curl -sS --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" \
    -H 'accept: application/dns-json' \
    "$resolver?name=$name&type=$type" \
    -o "$OUT_DIR/dns/$safe.json" 2>> "$ERRLOG" || true
}

summarize_doh() {
  local file="$1"
  if [ ! -f "$file" ]; then
    printf 'no-file'
    return
  fi
  perl -MJSON::PP -0777 -ne '
    my $doc = eval { decode_json($_) };
    if (!$doc || !$doc->{Answer} || ref($doc->{Answer}) ne "ARRAY" || !@{$doc->{Answer}}) {
      print "no-answer";
      exit;
    }
    my @out = map { ($_->{type} // "?") . ":" . ($_->{data} // "") } @{$doc->{Answer}};
    print join(", ", @out);
  ' "$file"
}

asset_urls_from_html() {
  local base="$1"
  local html="$2"
  perl -nE 'while(/(?:src|href)=["'"'"']([^"'"'"'#?]+)(?:[?#][^"'"'"']*)?["'"'"']/g){ say $1 }' "$html" |
    sort -u |
    while IFS= read -r ref; do
      case "$ref" in
        http://*|https://*) printf '%s\n' "$ref" ;;
        //*) printf 'https:%s\n' "$ref" ;;
        /*) printf '%s%s\n' "$base" "$ref" ;;
        *) printf '%s/%s\n' "${base%/}" "$ref" ;;
      esac
    done
}

extract_indicators() {
  local file="$1"
  perl -ne '
    while (m#https?://[A-Za-z0-9._:-]+#g) { print "$&\n" }
    while (m#\b(?:[A-Za-z0-9-]+\.)+(?:5ug\.top|5ug\.com)\b#g) { print "$&\n" }
    while (m#\b(?:\d{1,3}\.){3}\d{1,3}\b#g) { print "$&\n" }
  ' "$file" | sort -u
}

{
  echo "# 源站泄露排查结果"
  echo
  echo "- 时间: $(date '+%Y-%m-%d %H:%M:%S %Z')"
  echo "- 边界: 只读 DNS/HTTP/前端资源检查；不上传、不执行任务、不调用破坏性接口"
  echo "- 认证: $([ -n "$TOKEN" ] && echo 'Bearer token 已使用，报告中不落盘 token' || echo '未提供 TOKEN')"
  echo
} > "$REPORT"

DOMAINS=(rbf.zss.5ug.top api.zss.5ug.top admin.zss.5ug.top ace.5ug.com i.5ug.top qiniu.5ug.top)
RESOLVERS=(https://cloudflare-dns.com/dns-query https://dns.google/resolve)

for domain in "${DOMAINS[@]}"; do
  for resolver in "${RESOLVERS[@]}"; do
    doh_query "$resolver" "$domain" A
    doh_query "$resolver" "$domain" CNAME
  done
done

write_line "## DNS 解析"
write_line
write_line "| Resolver | Domain | A | CNAME |"
write_line "|---|---|---|---|"
for domain in "${DOMAINS[@]}"; do
  for resolver in "${RESOLVERS[@]}"; do
    a_file="$OUT_DIR/dns/$(sanitize_name "$resolver-$domain-A").json"
    cname_file="$OUT_DIR/dns/$(sanitize_name "$resolver-$domain-CNAME").json"
    write_line "| \`$resolver\` | \`$domain\` | \`$(summarize_doh "$a_file")\` | \`$(summarize_doh "$cname_file")\` |"
  done
done

curl_headers rbf-root https://rbf.zss.5ug.top/
curl_headers api-loginuser https://api.zss.5ug.top/app/people/user/getLoginUser "${AUTH_ARGS[@]}"
curl_headers admin-root https://admin.zss.5ug.top/
curl_headers direct-ip-root https://14.17.80.138/
curl_headers rbf-resolve-14 https://rbf.zss.5ug.top/ --resolve rbf.zss.5ug.top:443:14.17.80.138
curl_headers api-resolve-14 https://api.zss.5ug.top/app/people/user/getLoginUser --resolve api.zss.5ug.top:443:14.17.80.138 "${AUTH_ARGS[@]}"
curl_headers admin-resolve-14 https://admin.zss.5ug.top/ --resolve admin.zss.5ug.top:443:14.17.80.138

write_line
write_line "## HTTP 固定解析验证"
write_line
write_line "| Probe | Result | Key Headers |"
write_line "|---|---|---|"
for meta in "$OUT_DIR"/http/*.meta; do
  name="$(basename "$meta" .meta)"
  result="$(cat "$meta")"
  headers="$OUT_DIR/http/$name.headers"
  key="$(tr -d '\r' < "$headers" | awk 'tolower($1)=="server:" || tolower($1)=="content-type:" || tolower($1)=="location:" || tolower($1)=="strict-transport-security:" || tolower($1)=="access-control-allow-origin:" || tolower($1)=="access-control-allow-credentials:" {printf "%s ", $0}' | sed 's/|/ /g')"
  write_line "| \`$name\` | \`$result\` | \`$key\` |"
done

root_body="$OUT_DIR/http/rbf-root.body"
if [ -s "$root_body" ]; then
  asset_urls_from_html "https://rbf.zss.5ug.top" "$root_body" |
    grep -E '\.(js|css)$' |
    head -n 30 |
    while IFS= read -r asset; do
      safe="$(sanitize_name "$asset")"
      curl "${CURL_BASE[@]}" -L -o "$OUT_DIR/assets/$safe" "$asset" 2>> "$ERRLOG" || true
    done
fi

write_line
write_line "## 前端资源暴露的域名/IP"
write_line
if find "$OUT_DIR/assets" -type f -size +0c | grep -q .; then
  indicators_tmp="$OUT_DIR/indicators.txt"
  : > "$indicators_tmp"
  while IFS= read -r -d '' asset_file; do
    extract_indicators "$asset_file" >> "$indicators_tmp"
  done < <(find "$OUT_DIR/assets" -type f -size +0c -print0)
  sort -u "$indicators_tmp" |
    while IFS= read -r indicator; do
      [ -n "$indicator" ] && write_line "- \`$indicator\`"
    done
else
  write_line "- 未提取到可解析的前端资源。"
fi

write_line
write_line "## 证据目录"
write_line
write_line "- \`$OUT_DIR\`"

printf '%s\n' "$REPORT"
