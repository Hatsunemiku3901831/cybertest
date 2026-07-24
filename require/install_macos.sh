#!/usr/bin/env bash
#
# Cybertest macOS installer.
#
# Usage:
#   bash require/install_macos.sh --detect --profile web
#   bash require/install_macos.sh --dry-run --profile web
#   bash require/install_macos.sh --profile web
#
# This script is best-effort. It installs common runtimes and security tools
# used by tool/*.py wrappers, then prints anything that still needs manual
# handling.

set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOG_PATH="${SCRIPT_DIR}/install_macos.log"

WITH_CASKS=0
SKIP_BREW=0
SKIP_GO_TOOLS=0
SKIP_PYTHON_TOOLS=0
UPDATE_PATH=0
PROFILE="full"
MODE="install"

INSTALLED=()
PRESENT=()
FAILED=()
MANUAL=()

usage() {
  cat <<'EOF'
Usage: bash require/install_macos.sh [options]

Options:
  --profile NAME        Install profile: minimal, web, full, reverse (default: full).
  --detect              Read-only command detection for the selected profile.
  --dry-run             Show detection and install plan without side effects.
  --update-path         Opt in to updating ~/.zshrc and pipx PATH hints.
  --with-casks          Also install GUI/cask packages such as OWASP ZAP.
  --skip-brew          Do not install Homebrew packages.
  --skip-go-tools      Do not install Go-based tools.
  --skip-python-tools  Do not install Python/pipx tools.
  --skip-path-update   Compatibility alias; PATH updates are already off by default.
  -h, --help           Show this help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      if [[ $# -lt 2 ]]; then
        echo "[!] --profile requires a value"
        exit 2
      fi
      PROFILE="$2"
      shift
      ;;
    --profile=*)
      PROFILE="${1#*=}"
      ;;
    --detect)
      if [[ "${MODE}" != "install" ]]; then
        echo "[!] Choose only one of --detect or --dry-run"
        exit 2
      fi
      MODE="detect"
      ;;
    --dry-run)
      if [[ "${MODE}" != "install" ]]; then
        echo "[!] Choose only one of --detect or --dry-run"
        exit 2
      fi
      MODE="dry-run"
      ;;
    --update-path)
      UPDATE_PATH=1
      ;;
    --with-casks)
      WITH_CASKS=1
      ;;
    --skip-brew)
      SKIP_BREW=1
      ;;
    --skip-go-tools)
      SKIP_GO_TOOLS=1
      ;;
    --skip-python-tools)
      SKIP_PYTHON_TOOLS=1
      ;;
    --skip-path-update)
      UPDATE_PATH=0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[!] Unknown option: $1"
      usage
      exit 2
      ;;
  esac
  shift
done

case "${PROFILE}" in
  minimal|web|full|reverse)
    ;;
  *)
    echo "[!] Unknown profile: ${PROFILE}"
    usage
    exit 2
    ;;
esac

profile_commands() {
  case "${PROFILE}" in
    minimal)
      printf '%s\n' git python curl
      ;;
    web)
      printf '%s\n' \
        git python curl node go nmap rustscan subfinder dnsx httpx tlsx \
        naabu katana nuclei ffuf waybackurls arjun wafw00f sqlmap dalfox kr \
        whatweb zap-baseline.py
      ;;
    full)
      printf '%s\n' \
        git python curl node go nmap rustscan masscan hashcat trivy gitleaks \
        semgrep sqlmap wafw00f whatweb subfinder dnsx httpx tlsx naabu \
        katana nuclei ffuf waybackurls arjun dalfox kr zap-baseline.py
      ;;
    reverse)
      printf '%s\n' git python curl java adb jadx apktool r2 frida
      ;;
  esac
}

profile_has() {
  local expected="$1"
  shift
  local candidate
  for candidate in "$@"; do
    [[ "${expected}" == "${candidate}" ]] && return 0
  done
  return 1
}

profile_command_available() {
  case "$1" in
    python)
      command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1
      ;;
    r2)
      command -v r2 >/dev/null 2>&1 || command -v radare2 >/dev/null 2>&1
      ;;
    *)
      command -v "$1" >/dev/null 2>&1
      ;;
  esac
}

show_profile_status() {
  local command_name
  printf 'Cybertest dependency mode=%s profile=%s\n' "${MODE}" "${PROFILE}"
  while IFS= read -r command_name; do
    if profile_command_available "${command_name}"; then
      printf 'present  %s\n' "${command_name}"
    elif [[ "${MODE}" == "dry-run" ]]; then
      printf 'planned  %s\n' "${command_name}"
    else
      printf 'missing  %s\n' "${command_name}"
    fi
  done < <(profile_commands)
  if [[ "${MODE}" == "dry-run" ]]; then
    printf 'path_update=%s (not applied in dry-run)\n' \
      "$([[ "${UPDATE_PATH}" -eq 1 ]] && printf enabled || printf disabled)"
    printf 'No installation, network access, PATH update, or log write was performed.\n'
  fi
}

if [[ "${MODE}" == "detect" || "${MODE}" == "dry-run" ]]; then
  show_profile_status
  exit 0
fi

mkdir -p "${SCRIPT_DIR}"
{
  echo "Cybertest macOS install log $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "Repository: ${REPO_ROOT}"
} > "${LOG_PATH}"

log_step() {
  printf '\n==> %s\n' "$1"
}

log_info() {
  printf '[*] %s\n' "$1"
}

log_ok() {
  printf '[+] %s\n' "$1"
}

log_warn() {
  printf '[!] %s\n' "$1"
}

add_unique() {
  local array_name="$1"
  local value="$2"
  eval "local existing=(\"\${${array_name}[@]:-}\")"
  local item
  for item in "${existing[@]}"; do
    [[ "${item}" == "${value}" ]] && return 0
  done
  eval "${array_name}+=(\"\${value}\")"
}

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

run_logged() {
  local label="$1"
  shift
  log_info "${label}"
  {
    echo
    echo ">>> ${label}"
    printf '%q ' "$@"
    echo
  } >> "${LOG_PATH}"

  if "$@" >> "${LOG_PATH}" 2>&1; then
    log_ok "${label}"
    return 0
  fi

  log_warn "${label} failed"
  return 1
}

ensure_path_line() {
  local line="$1"
  local target="${HOME}/.zshrc"
  [[ "${UPDATE_PATH}" -ne 1 ]] && return 0
  touch "${target}"
  if grep -Fqx "${line}" "${target}"; then
    return 0
  fi
  printf '\n%s\n' "${line}" >> "${target}"
  log_ok "Updated ${target}: ${line}"
}

install_homebrew() {
  if has_cmd brew; then
    add_unique PRESENT "Homebrew"
    return 0
  fi
  if [[ "${SKIP_BREW}" -eq 1 ]]; then
    add_unique MANUAL "Homebrew"
    return 0
  fi
  log_step "Installing Homebrew"
  if run_logged "install Homebrew" /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"; then
    add_unique INSTALLED "Homebrew"
  else
    add_unique FAILED "Homebrew"
  fi
}

load_brew_env() {
  if [[ -x /opt/homebrew/bin/brew ]]; then
    eval "$(/opt/homebrew/bin/brew shellenv)"
  elif [[ -x /usr/local/bin/brew ]]; then
    eval "$(/usr/local/bin/brew shellenv)"
  fi
}

install_brew_formula() {
  local command_name="$1"
  local formula="$2"
  local label="$3"

  if has_cmd "${command_name}"; then
    add_unique PRESENT "${label}"
    log_ok "${label} already present"
    return 0
  fi
  if [[ "${SKIP_BREW}" -eq 1 ]] || ! has_cmd brew; then
    add_unique MANUAL "${label} (brew:${formula})"
    log_warn "brew unavailable or skipped: ${label}"
    return 0
  fi

  if run_logged "brew install ${label}" brew install "${formula}"; then
    add_unique INSTALLED "${label}"
  else
    add_unique FAILED "${label} (brew:${formula})"
  fi
}

install_brew_cask() {
  local command_name="$1"
  local cask="$2"
  local label="$3"

  if has_cmd "${command_name}"; then
    add_unique PRESENT "${label}"
    return 0
  fi
  if [[ "${WITH_CASKS}" -ne 1 ]]; then
    add_unique MANUAL "${label} (brew cask:${cask}; rerun with --with-casks)"
    return 0
  fi
  if [[ "${SKIP_BREW}" -eq 1 ]] || ! has_cmd brew; then
    add_unique MANUAL "${label} (brew cask:${cask})"
    return 0
  fi

  if run_logged "brew install --cask ${label}" brew install --cask "${cask}"; then
    add_unique INSTALLED "${label}"
  else
    add_unique FAILED "${label} (brew cask:${cask})"
  fi
}

install_go_tool() {
  local command_name="$1"
  local module="$2"
  local label="$3"

  if has_cmd "${command_name}"; then
    add_unique PRESENT "${label}"
    log_ok "${label} already present"
    return 0
  fi
  if [[ "${SKIP_GO_TOOLS}" -eq 1 ]]; then
    add_unique MANUAL "${label} (${module})"
    return 0
  fi
  if ! has_cmd go; then
    add_unique MANUAL "${label} requires Go: ${module}"
    log_warn "Go unavailable: ${label}"
    return 0
  fi

  if run_logged "go install ${label}" go install "${module}"; then
    add_unique INSTALLED "${label}"
  else
    add_unique FAILED "${label} (${module})"
  fi
}

python_cmd() {
  if has_cmd python3; then
    printf 'python3'
  elif has_cmd python; then
    printf 'python'
  fi
}

install_python_tool() {
  local command_name="$1"
  local package="$2"
  local label="$3"

  if has_cmd "${command_name}"; then
    add_unique PRESENT "${label}"
    log_ok "${label} already present"
    return 0
  fi
  if [[ "${SKIP_PYTHON_TOOLS}" -eq 1 ]]; then
    add_unique MANUAL "${label} (python:${package})"
    return 0
  fi

  if has_cmd pipx; then
    if run_logged "pipx install ${label}" pipx install "${package}" --include-deps; then
      add_unique INSTALLED "${label}"
    else
      add_unique FAILED "${label} (pipx:${package})"
    fi
    return 0
  fi

  local py
  py="$(python_cmd || true)"
  if [[ -z "${py}" ]]; then
    add_unique MANUAL "${label} requires Python: ${package}"
    return 0
  fi
  if run_logged "pip install --user ${label}" "${py}" -m pip install --user --upgrade "${package}"; then
    add_unique INSTALLED "${label}"
  else
    add_unique FAILED "${label} (pip:${package})"
  fi
}

print_summary() {
  log_step "Summary"
  local section item
  for section in INSTALLED PRESENT FAILED MANUAL; do
    printf '\n%s:\n' "${section}"
    eval "local values=(\"\${${section}[@]:-}\")"
    if [[ "${#values[@]}" -eq 0 ]]; then
      echo "  none"
      continue
    fi
    printf '%s\n' "${values[@]}" | sort -u | while IFS= read -r item; do
      printf '  - %s\n' "${item}"
    done
  done
  printf '\nLog: %s\n' "${LOG_PATH}"
  if [[ "${UPDATE_PATH}" -eq 1 ]]; then
    printf 'Open a new terminal after installation so PATH changes take effect.\n'
  else
    printf 'Persistent PATH was not changed; rerun with --update-path to opt in.\n'
  fi
  printf 'Validate with:\n'
  printf '  python3 tool/detect_capabilities.py --dry-run\n'
  printf '  python3 tool/scan_pipeline.py --help\n'
  printf '  python3 tool/nmap_json_scan.py --help\n'
}

log_step "Cybertest macOS installer"
log_info "Profile: ${PROFILE}"
log_info "Repository: ${REPO_ROOT}"
log_info "Log file: ${LOG_PATH}"

install_homebrew
load_brew_env

if has_cmd brew; then
  run_logged "brew update" brew update || true
fi

log_step "Configuring PATH"
mkdir -p "${HOME}/go/bin" "${HOME}/.local/bin"
export PATH="/opt/homebrew/bin:/usr/local/bin:${HOME}/go/bin:${HOME}/.local/bin:${PATH}"
ensure_path_line 'export PATH="/opt/homebrew/bin:/usr/local/bin:$HOME/go/bin:$HOME/.local/bin:$PATH"'

log_step "Installing base runtime packages"
install_brew_formula git git Git
install_brew_formula python3 python Python
install_brew_formula curl curl curl
if profile_has "${PROFILE}" web full; then
  install_brew_formula node node "Node.js"
  install_brew_formula go go Go
fi
if profile_has "${PROFILE}" web full reverse; then
  install_brew_formula pipx pipx pipx
fi

if [[ "${UPDATE_PATH}" -eq 1 ]] && has_cmd pipx; then
  run_logged "pipx ensurepath" pipx ensurepath || true
fi

if profile_has "${PROFILE}" web full; then
  log_step "Installing Web security binaries"
  install_brew_formula nmap nmap Nmap
  install_brew_formula rustscan rustscan Rustscan
  install_brew_formula sqlmap sqlmap sqlmap
  install_brew_formula wafw00f wafw00f wafw00f
  install_brew_formula whatweb whatweb WhatWeb
  install_brew_cask zap-baseline.py owasp-zap "OWASP ZAP"

  log_step "Installing Python-based Web tools"
  install_python_tool arjun arjun Arjun

  log_step "Installing Go-based recon and Web tools"
  install_go_tool subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest subfinder
  install_go_tool dnsx github.com/projectdiscovery/dnsx/cmd/dnsx@latest dnsx
  install_go_tool httpx github.com/projectdiscovery/httpx/cmd/httpx@latest httpx
  install_go_tool tlsx github.com/projectdiscovery/tlsx/cmd/tlsx@latest tlsx
  install_go_tool naabu github.com/projectdiscovery/naabu/v2/cmd/naabu@latest naabu
  install_go_tool katana github.com/projectdiscovery/katana/cmd/katana@latest katana
  install_go_tool nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest nuclei
  install_go_tool ffuf github.com/ffuf/ffuf/v2@latest ffuf
  install_go_tool waybackurls github.com/tomnomnom/waybackurls@latest waybackurls
  install_go_tool dalfox github.com/hahwul/dalfox/v2@latest dalfox
  install_go_tool kr github.com/assetnote/kiterunner/cmd/kr@latest Kiterunner
fi

if [[ "${PROFILE}" == "full" ]]; then
  log_step "Installing full-profile security tools"
  install_brew_formula masscan masscan masscan
  install_brew_formula hashcat hashcat Hashcat
  install_brew_formula trivy trivy Trivy
  install_brew_formula gitleaks gitleaks gitleaks
  install_brew_formula semgrep semgrep Semgrep
fi

if [[ "${PROFILE}" == "reverse" ]]; then
  log_step "Installing reverse-engineering tools"
  install_brew_cask adb android-platform-tools "Android Platform Tools"
  install_brew_formula jadx jadx JADX
  install_brew_formula apktool apktool apktool
  install_brew_formula r2 radare2 radare2
  install_python_tool frida frida-tools "Frida tools"
fi

log_step "Post-install updates"
if profile_has "${PROFILE}" web full && has_cmd nuclei; then
  run_logged "nuclei template update" nuclei -update-templates || true
fi

log_step "Manual or environment-specific items"
if profile_has "${PROFILE}" web full; then
  add_unique MANUAL "FOFA API: set FOFA_EMAIL and FOFA_KEY when using tool/fofa_query.py"
  add_unique MANUAL "Burp MCP: install/enable Burp Suite MCP extension before using tool/burp_sse_mcp_bridge.js"
  if ! has_cmd zap-baseline.py; then
    add_unique MANUAL "OWASP ZAP baseline: install OWASP ZAP cask with --with-casks or use Docker-based ZAP"
  fi
fi
if [[ "${PROFILE}" == "reverse" ]] && ! has_cmd adb; then
  add_unique MANUAL "Android Platform Tools: rerun with --with-casks or install adb manually"
fi

print_summary

if [[ "${#FAILED[@]}" -gt 0 ]]; then
  exit 1
fi
exit 0
