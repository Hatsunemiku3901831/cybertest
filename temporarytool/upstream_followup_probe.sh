#!/usr/bin/env bash
set -o pipefail

TOKEN="${TOKEN:-}"
TARGET_IP="${TARGET_IP:-14.17.80.138}"
API_HOST="${API_HOST:-api.zss.5ug.top}"
OUT_ROOT="${OUT_ROOT:-security_probes/out}"
STAMP="$(date '+%Y%m%d-%H%M%S')"
OUT_DIR="$OUT_ROOT/upstream-followup-$STAMP"
REPORT="$OUT_DIR/report.md"
ERRLOG="$OUT_DIR/curl-errors.log"

mkdir -p "$OUT_DIR/headers" "$OUT_DIR/bodies"

AUTH_ARGS=()
if [ -n "$TOKEN" ]; then
  case "$TOKEN" in
    Bearer\ *|bearer\ *) AUTH_ARGS=(-H "Authorization: $TOKEN") ;;
    *) AUTH_ARGS=(-H "Authorization: Bearer $TOKEN") ;;
  esac
fi

CURL_BASE=(-k -sS --connect-timeout 5 --max-time 12 -H "Tenant: master")

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
  ' "$file"
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
    print substr($s,0,240);
  ' "$body"
}

probe() {
  local label="$1"
  local mode="$2"
  local url="$3"
  shift 3
  local safe headers body status ctype summary
  safe="$(sanitize_name "$label-$mode-$url")"
  headers="$OUT_DIR/headers/$safe.headers"
  body="$OUT_DIR/bodies/$safe.body"
  if [ "$mode" = "auth" ]; then
    status="$(curl "${CURL_BASE[@]}" "${AUTH_ARGS[@]}" "$@" -D "$headers" -o "$body" -w '%{http_code}\t%{remote_ip}\t%{content_type}\t%{size_download}' "$url" 2>> "$ERRLOG")" || status="000\t-\t-\t0"
  else
    status="$(curl "${CURL_BASE[@]}" "$@" -D "$headers" -o "$body" -w '%{http_code}\t%{remote_ip}\t%{content_type}\t%{size_download}' "$url" 2>> "$ERRLOG")" || status="000\t-\t-\t0"
  fi
  redact_file "$headers"
  redact_file "$body"
  summary="$(body_summary "$body")"
  printf '%s\t%s\t%s\t%s\t%s\n' "$label" "$mode" "$url" "$status" "$summary" >> "$OUT_DIR/results.tsv"
}

printf 'label\tmode\turl\thttp_remote_type_len\tsummary\n' > "$OUT_DIR/results.tsv"

for path in / /app/people/user/getLoginUser /actuator/health /app/actuator/health; do
  probe "http80-api-host" "auth" "http://$API_HOST$path" --resolve "$API_HOST:80:$TARGET_IP"
  probe "http80-rbf-host" "auth" "http://rbf.zss.5ug.top$path" --resolve "rbf.zss.5ug.top:80:$TARGET_IP"
done

for path in /tool/startup /tool/message /tool/app/down /tool/location /tool/favorite /tool/footprint /tool/search /tool/map; do
  probe "tool-route-app-prefix" "noauth" "https://$API_HOST/app$path" --resolve "$API_HOST:443:$TARGET_IP"
  probe "tool-route-app-prefix" "auth" "https://$API_HOST/app$path" --resolve "$API_HOST:443:$TARGET_IP"
  probe "tool-route-root" "auth" "https://$API_HOST$path" --resolve "$API_HOST:443:$TARGET_IP"
done

{
  echo "# Upstream follow-up probe"
  echo
  echo "- 时间: $(date '+%Y-%m-%d %H:%M:%S %Z')"
  echo "- 入口 IP: $TARGET_IP"
  echo "- API Host: $API_HOST"
  echo
  echo "| 标签 | 模式 | URL | HTTP/Remote/Type/Len | 摘要 |"
  echo "|---|---|---|---|---|"
  awk -F '\t' 'NR>1 {printf "| %s | %s | `%s` | `%s` | %s |\n",$1,$2,$3,$4,$5}' "$OUT_DIR/results.tsv"
} > "$REPORT"

printf '%s\n' "$REPORT"
