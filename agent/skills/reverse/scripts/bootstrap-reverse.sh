#!/usr/bin/env bash
# Safe entry point for reverse capability detection and explicit bootstrap.
#
# Default behavior is read-only detection. Installation and MCP registration
# require explicit modes; this script never chooses a global client config.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$SKILL_ROOT/../../.." && pwd)"
PROFILE_PATH="$REPO_ROOT/require/profiles.json"
MACOS_INSTALLER="$REPO_ROOT/require/install_macos.sh"
CAPABILITY_DETECTOR="$REPO_ROOT/tool/detect_capabilities.py"

MODE="detect"
MODE_EXPLICIT=false
LIST_ONLY=false
MCP_CONFIG_PATH=""
START_SERVICES=false
CAPABILITIES=()

log_info() { printf '[INFO] %s\n' "$*"; }
log_ok() { printf '[OK] %s\n' "$*"; }
log_warn() { printf '[WARN] %s\n' "$*"; }
log_err() { printf '[ERR] %s\n' "$*" >&2; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }

print_usage() {
  cat <<'EOF'
Usage:
  bash agent/skills/reverse/scripts/bootstrap-reverse.sh [capability ...]
  bash agent/skills/reverse/scripts/bootstrap-reverse.sh --detect [capability ...]
  bash agent/skills/reverse/scripts/bootstrap-reverse.sh --dry-run [capability ...]
  bash agent/skills/reverse/scripts/bootstrap-reverse.sh --install [capability ...]
  bash agent/skills/reverse/scripts/bootstrap-reverse.sh --apply --mcp-config FILE [capability ...]
  bash agent/skills/reverse/scripts/bootstrap-reverse.sh --list

Modes:
  --detect       Read-only detection (default).
  --dry-run      Read-only detection plus an installation/registration plan.
  --install      Explicitly delegate core reverse tools to the platform installer.
                 It never writes MCP client configuration.
  --apply        Explicit install plus MCP registration for selected MCP providers.
                 Registration also requires --mcp-config FILE.

Options:
  --mcp-config FILE  Explicit MCP config target. No global path is assumed.
  --start-services   Unsupported compatibility flag; start providers separately
                     and expose their URL through environment/runtime discovery.
  --skip-refresh     Accepted compatibility no-op; index refresh is never implicit.
  --list, -l         List accepted capability names.
  --help, -h         Show this help.

Runtime endpoint variables:
  ANYTHING_ANALYZER_MCP_URL
  IDAPRO_MCP_URL
  GHIDRA_MCP_URL

Provider variables:
  CYBERTEST_BROWSER_PROVIDER
  CYBERTEST_JS_CDP_PROVIDER
  CYBERTEST_HTTP_CAPTURE_PROVIDER
  CYBERTEST_HTTP_REPLAY_PROVIDER
  BURPSUITE_MCP_COMMAND

Safety:
  detect and dry-run do not install, download, start services, refresh indexes,
  or write MCP configuration. Fixed ports are not used for discovery.
EOF
}

set_mode() {
  local requested="$1"
  if $MODE_EXPLICIT; then
    log_err "Choose exactly one mode: --detect, --dry-run, --install, or --apply."
    exit 2
  fi
  MODE="$requested"
  MODE_EXPLICIT=true
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --detect) set_mode "detect" ;;
    --dry-run) set_mode "dry-run" ;;
    --install) set_mode "install" ;;
    --apply) set_mode "apply" ;;
    --mcp-config)
      if [[ $# -lt 2 || -z "$2" ]]; then
        log_err "--mcp-config requires an explicit file path."
        exit 2
      fi
      MCP_CONFIG_PATH="$2"
      shift
      ;;
    --mcp-config=*)
      MCP_CONFIG_PATH="${1#*=}"
      ;;
    --start-services)
      START_SERVICES=true
      ;;
    --skip-refresh)
      ;;
    --list|-l)
      LIST_ONLY=true
      ;;
    --help|-h)
      print_usage
      exit 0
      ;;
    -*)
      log_err "Unknown option: $1"
      print_usage
      exit 2
      ;;
    *)
      CAPABILITIES+=("$1")
      ;;
  esac
  shift
done

if $START_SERVICES; then
  log_err "Automatic service start was removed. Start the selected provider explicitly,"
  log_err "then expose its endpoint through environment or runtime discovery."
  exit 2
fi

if [[ ! -f "$PROFILE_PATH" ]]; then
  log_err "Missing reverse profile: require/profiles.json"
  exit 2
fi
if ! has_cmd python3; then
  log_err "python3 is required to read the reverse profile and capability manifest."
  exit 2
fi

profile_capabilities() {
  python3 - "$PROFILE_PATH" <<'PY'
import json
import pathlib
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
for command in payload["profiles"]["reverse"]["commands"]:
    print(command)
PY
}

EXTRA_CAPABILITIES=(
  frida-ps idalib-mcp jshookmcp anything-analyzer idapro rabin2
  agent-browser ghidra-mcp seclists proxycat burpsuite-mcp nmap pentestswarm
)

PROFILE_CAPABILITIES=()
while IFS= read -r capability; do
  [[ -n "$capability" ]] && PROFILE_CAPABILITIES+=("$capability")
done < <(profile_capabilities)

KNOWN_CAPABILITIES=("${PROFILE_CAPABILITIES[@]}" "${EXTRA_CAPABILITIES[@]}")

contains_value() {
  local expected="$1"
  shift
  local candidate
  for candidate in "$@"; do
    [[ "$candidate" == "$expected" ]] && return 0
  done
  return 1
}

if $LIST_ONLY; then
  printf '%s\n' "${KNOWN_CAPABILITIES[@]}" | awk '!seen[$0]++'
  exit 0
fi

if [[ ${#CAPABILITIES[@]} -eq 0 ]]; then
  if [[ "$MODE" == "detect" || "$MODE" == "dry-run" ]]; then
    CAPABILITIES=("${KNOWN_CAPABILITIES[@]}")
  else
    CAPABILITIES=("${PROFILE_CAPABILITIES[@]}")
  fi
fi

for capability in "${CAPABILITIES[@]}"; do
  if ! contains_value "$capability" "${KNOWN_CAPABILITIES[@]}"; then
    log_err "Unknown capability: $capability"
    exit 2
  fi
done

capability_dependencies() {
  case "$1" in
    idapro) printf '%s\n' idalib-mcp idapro ;;
    frida-ps) printf '%s\n' frida frida-ps ;;
    rabin2) printf '%s\n' r2 rabin2 ;;
    *) printf '%s\n' "$1" ;;
  esac
}

EXPANDED=()
seen=" "
for capability in "${CAPABILITIES[@]}"; do
  while IFS= read -r dependency; do
    if [[ "$seen" != *" $dependency "* ]]; then
      EXPANDED+=("$dependency")
      seen+="$dependency "
    fi
  done < <(capability_dependencies "$capability")
done

capability_commands() {
  case "$1" in
    python) printf '%s\n' python3 python ;;
    r2) printf '%s\n' r2 radare2 ;;
    frida-ps) printf '%s\n' frida-ps ;;
    idalib-mcp) printf '%s\n' ida-pro-mcp ;;
    jshookmcp) printf '%s\n' npx ;;
    anything-analyzer) return 0 ;;
    idapro) printf '%s\n' idat ida ;;
    agent-browser) printf '%s\n' agent-browser ;;
    ghidra-mcp) printf '%s\n' ghidraRun ;;
    seclists) return 0 ;;
    burpsuite-mcp) return 0 ;;
    pentestswarm) printf '%s\n' pentestswarm ;;
    *) printf '%s\n' "$1" ;;
  esac
}

capability_environment() {
  case "$1" in
    jshookmcp) printf '%s\n' CYBERTEST_JS_CDP_PROVIDER ;;
    anything-analyzer)
      printf '%s\n' ANYTHING_ANALYZER_MCP_URL CYBERTEST_HTTP_CAPTURE_PROVIDER
      ;;
    idapro) printf '%s\n' IDAPRO_MCP_URL ;;
    agent-browser) printf '%s\n' CYBERTEST_BROWSER_PROVIDER ;;
    ghidra-mcp) printf '%s\n' GHIDRA_MCP_URL ;;
    burpsuite-mcp)
      printf '%s\n' CYBERTEST_HTTP_REPLAY_PROVIDER BURPSUITE_MCP_COMMAND
      ;;
  esac
}

capability_status() {
  local capability="$1"
  local variable value command_name
  while IFS= read -r variable; do
    [[ -z "$variable" ]] && continue
    value="${!variable:-}"
    if [[ -n "$value" ]]; then
      printf 'capability=%s status=declared source=environment provider=%s\n' \
        "$capability" "$variable"
      return 0
    fi
  done < <(capability_environment "$capability")

  while IFS= read -r command_name; do
    [[ -z "$command_name" ]] && continue
    if has_cmd "$command_name"; then
      printf 'capability=%s status=present source=path provider=%s\n' \
        "$capability" "$command_name"
      return 0
    fi
  done < <(capability_commands "$capability")

  printf 'capability=%s status=missing source=none provider=none\n' "$capability"
  return 1
}

run_agent_capability_detector() {
  if has_cmd python3 && [[ -f "$CAPABILITY_DETECTOR" ]]; then
    log_info "agent capability detector (read-only)"
    python3 "$CAPABILITY_DETECTOR" --dry-run
  else
    log_warn "agent capability detector unavailable"
  fi
}

print_detection() {
  local capability
  log_info "mode=$MODE platform=$(uname -s 2>/dev/null || printf unknown)"
  for capability in "${EXPANDED[@]}"; do
    capability_status "$capability" || true
  done
  run_agent_capability_detector
}

is_profile_capability() {
  contains_value "$1" "${PROFILE_CAPABILITIES[@]}"
}

is_mcp_capability() {
  case "$1" in
    jshookmcp|anything-analyzer|idapro|ghidra-mcp|burpsuite-mcp)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

print_plan() {
  local capability
  log_info "installation and registration plan"
  for capability in "${EXPANDED[@]}"; do
    if is_profile_capability "$capability"; then
      printf 'plan capability=%s action=require-profile-reverse\n' "$capability"
    elif is_mcp_capability "$capability"; then
      printf 'plan capability=%s action=runtime-provider-and-explicit-mcp-config\n' \
        "$capability"
    else
      printf 'plan capability=%s action=provider-specific-manual-setup\n' "$capability"
    fi
  done
  printf 'side_effects=none\n'
}

if [[ "$MODE" == "detect" ]]; then
  print_detection
  printf 'side_effects=none\n'
  exit 0
fi

if [[ "$MODE" == "dry-run" ]]; then
  print_detection
  print_plan
  exit 0
fi

needs_profile_install=false
needs_mcp_config=false
needs_provider_setup=false
for capability in "${EXPANDED[@]}"; do
  if is_profile_capability "$capability"; then
    needs_profile_install=true
  fi
  if is_mcp_capability "$capability"; then
    needs_mcp_config=true
  fi
  if ! is_profile_capability "$capability"; then
    needs_provider_setup=true
  fi
done

if [[ "$MODE" == "apply" ]] && $needs_mcp_config && [[ -z "$MCP_CONFIG_PATH" ]]; then
  log_err "--apply for MCP capabilities requires --mcp-config FILE."
  exit 2
fi

install_reverse_profile() {
  local platform
  platform="$(uname -s 2>/dev/null || printf unknown)"
  case "$platform" in
    Darwin)
      if [[ ! -f "$MACOS_INSTALLER" ]]; then
        log_err "Missing require/install_macos.sh"
        return 1
      fi
      log_info "delegating explicit installation to require profile=reverse"
      bash "$MACOS_INSTALLER" --profile reverse
      ;;
    *)
      log_err "No centralized reverse installer is registered for platform=$platform."
      log_err "Use require/profiles.json as the command contract and install manually."
      return 1
      ;;
  esac
}

if $needs_profile_install; then
  install_reverse_profile
fi

write_mcp_server() {
  local name="$1"
  local payload="$2"
  python3 - "$MCP_CONFIG_PATH" "$name" "$payload" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1]).expanduser()
name = sys.argv[2]
payload = json.loads(sys.argv[3])
if path.exists():
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit("MCP config root must be an object")
else:
    data = {}
data.setdefault("mcpServers", {})[name] = payload
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(
    json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
print(path)
PY
}

url_payload() {
  python3 - "$1" <<'PY'
import json
import sys
from urllib.parse import urlsplit

value = sys.argv[1]
parsed = urlsplit(value)
if parsed.scheme not in {"http", "https"} or not parsed.hostname:
    raise SystemExit("runtime MCP URL must be absolute http(s)")
print(json.dumps({"url": value}, separators=(",", ":")))
PY
}

command_payload() {
  python3 - "$1" <<'PY'
import json
import sys

print(json.dumps({"command": sys.argv[1]}, separators=(",", ":")))
PY
}

register_capability() {
  local capability="$1"
  local payload
  case "$capability" in
    jshookmcp)
      if ! has_cmd npx; then
        log_err "jshookmcp registration requires an available npx runner."
        return 1
      fi
      write_mcp_server \
        "jshook" \
        '{"command":"npx","args":["-y","@jshookmcp/jshook@latest"],"env":{"JSHOOK_BASE_PROFILE":"search"}}'
      ;;
    anything-analyzer)
      if [[ -z "${ANYTHING_ANALYZER_MCP_URL:-}" ]]; then
        log_err "Set ANYTHING_ANALYZER_MCP_URL from runtime discovery before apply."
        return 1
      fi
      payload="$(url_payload "$ANYTHING_ANALYZER_MCP_URL")"
      write_mcp_server "anything-analyzer" "$payload"
      ;;
    idapro)
      if [[ -z "${IDAPRO_MCP_URL:-}" ]]; then
        log_err "Set IDAPRO_MCP_URL from the active IDA provider before apply."
        return 1
      fi
      payload="$(url_payload "$IDAPRO_MCP_URL")"
      write_mcp_server "idapro" "$payload"
      ;;
    ghidra-mcp)
      if [[ -z "${GHIDRA_MCP_URL:-}" ]]; then
        log_err "Set GHIDRA_MCP_URL from the active Ghidra provider before apply."
        return 1
      fi
      payload="$(url_payload "$GHIDRA_MCP_URL")"
      write_mcp_server "ghidra" "$payload"
      ;;
    burpsuite-mcp)
      if [[ -z "${BURPSUITE_MCP_COMMAND:-}" ]]; then
        log_err "Set BURPSUITE_MCP_COMMAND from runtime discovery before apply."
        return 1
      fi
      payload="$(command_payload "$BURPSUITE_MCP_COMMAND")"
      write_mcp_server "burpsuite" "$payload"
      ;;
  esac
}

if [[ "$MODE" == "apply" ]]; then
  for capability in "${EXPANDED[@]}"; do
    if is_mcp_capability "$capability"; then
      register_capability "$capability"
    fi
  done
  log_ok "explicit apply complete"
else
  log_ok "explicit core profile install phase complete; MCP configuration was not modified"
  if $needs_provider_setup; then
    log_warn "provider-specific capabilities remain explicit manual/runtime setup"
  fi
fi

print_detection
