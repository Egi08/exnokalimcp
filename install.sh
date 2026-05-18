#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${HOME}/.exnokalimcp"
CONFIG_PATH="${APP_DIR}/config.yaml"
VENV_DIR="${APP_DIR}/venv"
SERVER_PATH="${PROJECT_DIR}/server.py"
KEY_FILE="${APP_DIR}/auth_key"
PROFILE="server-only"
SKIP_APT=0
GO_MODE="auto"
PIPX_MODE="auto"

log() { printf '[exnokalimcp] %s\n' "$*"; }
warn() { printf '[exnokalimcp][warn] %s\n' "$*" >&2; }

usage() {
  cat <<'EOF'
Usage: ./install.sh [--server-only|--minimal|--full] [--skip-apt] [--with-go|--skip-go] [--with-pipx|--skip-pipx]

  --server-only Install only the MCP Python runtime and WSL integration. Default.
  --minimal     Install runtime plus a few safe CLI utilities. No Go/pipx tools by default.
  --full        Install the full Kali/bug bounty toolchain.
  --skip-apt    Do not install apt packages.
  --with-go     Install Go-based tools for the selected profile.
  --skip-go     Do not install Go tools.
  --with-pipx   Install pipx-based tools for the selected profile.
  --skip-pipx   Do not install pipx CLI tools.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server-only) PROFILE="server-only" ;;
    --minimal) PROFILE="minimal" ;;
    --full) PROFILE="full" ;;
    --skip-apt) SKIP_APT=1 ;;
    --with-go) GO_MODE="yes" ;;
    --skip-go) GO_MODE="no" ;;
    --with-pipx) PIPX_MODE="yes" ;;
    --skip-pipx) PIPX_MODE="no" ;;
    -h|--help) usage; exit 0 ;;
    *) warn "Unknown option: $1"; usage; exit 2 ;;
  esac
  shift
done

if [[ "${GO_MODE}" == "auto" ]]; then
  if [[ "${PROFILE}" == "full" ]]; then SKIP_GO=0; else SKIP_GO=1; fi
elif [[ "${GO_MODE}" == "yes" ]]; then
  SKIP_GO=0
else
  SKIP_GO=1
fi

if [[ "${PIPX_MODE}" == "auto" ]]; then
  if [[ "${PROFILE}" == "full" ]]; then SKIP_PIPX=0; else SKIP_PIPX=1; fi
elif [[ "${PIPX_MODE}" == "yes" ]]; then
  SKIP_PIPX=0
else
  SKIP_PIPX=1
fi

log "Install profile: ${PROFILE} (apt=$((1-SKIP_APT)), go=$((1-SKIP_GO)), pipx=$((1-SKIP_PIPX)))"

if ! grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null; then
  warn "This installer is optimized for Kali on WSL. Continuing anyway."
fi

if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  if [[ "${ID:-}" != "kali" ]]; then
    warn "Detected '${PRETTY_NAME:-unknown}', not Kali. Some packages may be unavailable."
  fi
fi

mkdir -p "${APP_DIR}/logs" "${HOME}/exnokalimcp-workspaces"

python3 - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit("Python 3.11+ is required. Install a newer python3 package in Kali WSL.")
PY

FULL_APT_TOOLS=(
  python3 python3-pip python3-venv pipx git curl wget jq unzip build-essential
  golang-go nmap masscan whois dnsutils netcat-openbsd socat sshpass proxychains4
  ffuf gobuster feroxbuster dirsearch nikto sqlmap wpscan joomscan whatweb wapiti
  wafw00f testssl.sh exploitdb metasploit-framework hashcat john hydra medusa
  aircrack-ng wifite wireshark tshark tcpdump netdiscover arp-scan seclists wordlists
  binwalk libimage-exiftool-perl steghide foremost volatility3 crunch cewl
  theharvester recon-ng sherlock
)

SERVER_APT_TOOLS=(
  python3 python3-pip python3-venv git curl wget jq unzip ca-certificates
)

MINIMAL_APT_TOOLS=(
  "${SERVER_APT_TOOLS[@]}"
  whois dnsutils netcat-openbsd tcpdump
)

install_apt() {
  local pkg="$1"
  if dpkg -s "$pkg" >/dev/null 2>&1; then
    return 0
  fi
  log "Installing apt package: ${pkg}"
  if ! sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"; then
    warn "apt package failed or unavailable: ${pkg}"
  fi
}

if [[ "${SKIP_APT}" -eq 0 ]]; then
  log "Updating apt package index"
  sudo apt-get update
  if [[ "${PROFILE}" == "server-only" ]]; then
    APT_TOOLS=("${SERVER_APT_TOOLS[@]}")
  elif [[ "${PROFILE}" == "minimal" ]]; then
    APT_TOOLS=("${MINIMAL_APT_TOOLS[@]}")
  else
    APT_TOOLS=("${FULL_APT_TOOLS[@]}")
  fi
  if [[ "${SKIP_GO}" -eq 0 ]]; then
    APT_TOOLS+=(golang-go)
  fi
  if [[ "${SKIP_PIPX}" -eq 0 ]]; then
    APT_TOOLS+=(pipx)
  fi
  for pkg in "${APT_TOOLS[@]}"; do
    install_apt "$pkg"
  done
else
  warn "Skipping apt package installation"
fi

GO_TOOLS=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "github.com/lc/gau/v2/cmd/gau@latest"
  "github.com/tomnomnom/waybackurls@latest"
  "github.com/hahwul/dalfox/v2@latest"
  "github.com/sensepost/gowitness@latest"
)
if [[ "${SKIP_GO}" -eq 0 ]]; then
  log "Installing Go-based recon tools"
  export PATH="${PATH}:${HOME}/go/bin"
  if command -v go >/dev/null 2>&1; then
    for tool in "${GO_TOOLS[@]}"; do
      if ! go install "$tool"; then
        warn "go install failed: ${tool}"
      fi
    done
  else
    warn "go is not installed; skipping Go tools"
  fi
else
  warn "Skipping Go tool installation"
fi

PIPX_TOOLS=(arjun paramspider corscanner ssrfmap xsstrike jwt-tool shodan)
if [[ "${SKIP_PIPX}" -eq 0 ]]; then
  log "Installing Python CLI tools with pipx where apt packages are commonly stale"
  python3 -m pip install --user --upgrade pipx >/dev/null 2>&1 || true
  python3 -m pipx ensurepath >/dev/null 2>&1 || true
  for tool in "${PIPX_TOOLS[@]}"; do
    if ! python3 -m pipx install "$tool" --force; then
      warn "pipx install failed: ${tool}"
    fi
  done
else
  warn "Skipping pipx tool installation"
fi

log "Creating Python virtual environment"
python3 -m venv "${VENV_DIR}"
"${VENV_DIR}/bin/python" -m pip install --upgrade pip wheel
"${VENV_DIR}/bin/python" -m pip install -r "${PROJECT_DIR}/requirements.txt"

if [[ ! -f "${KEY_FILE}" ]]; then
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24 > "${KEY_FILE}"
  else
    python3 - <<'PY' > "${KEY_FILE}"
import secrets
print(secrets.token_hex(24))
PY
  fi
  chmod 600 "${KEY_FILE}"
fi
AUTH_KEY="$(cat "${KEY_FILE}")"

if [[ ! -f "${CONFIG_PATH}" ]]; then
  cp "${PROJECT_DIR}/config.yaml" "${CONFIG_PATH}"
fi
python3 - "${CONFIG_PATH}" "${AUTH_KEY}" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
key = sys.argv[2]
text = path.read_text()
text = text.replace("change-me-exnokalimcp-key", key)
path.write_text(text)
PY

log "Initializing SQLite database"
(
  cd "${PROJECT_DIR}"
  EXNOKALIMCP_CONFIG="${CONFIG_PATH}" EXNOKALIMCP_AUTH_KEY="${AUTH_KEY}" "${VENV_DIR}/bin/python" - <<'PY'
from server import ExnoKaliMCPServices, load_config
services = ExnoKaliMCPServices(load_config())
services.sessions.create_workspace("default", "", "Default ExnoKaliMCP workspace")
print(services.store.db_path)
PY
)

log "Updating nuclei templates if nuclei is available"
if command -v nuclei >/dev/null 2>&1; then
  nuclei -update-templates || true
fi

DISTRO="${WSL_DISTRO_NAME:-kali-linux}"
CLAUDE_SNIPPET="${APP_DIR}/claude_desktop_config.snippet.json"
cat > "${CLAUDE_SNIPPET}" <<JSON
{
  "mcpServers": {
    "exnokalimcp": {
      "command": "wsl.exe",
      "args": [
        "-d",
        "${DISTRO}",
        "--",
        "${VENV_DIR}/bin/python",
        "${SERVER_PATH}"
      ],
      "env": {
        "EXNOKALIMCP_CONFIG": "${CONFIG_PATH}",
        "EXNOKALIMCP_AUTH_KEY": "${AUTH_KEY}"
      }
    }
  }
}
JSON

if command -v systemctl >/dev/null 2>&1; then
  mkdir -p "${HOME}/.config/systemd/user"
  cat > "${HOME}/.config/systemd/user/exnokalimcp-sse.service" <<SERVICE
[Unit]
Description=ExnoKaliMCP SSE server

[Service]
WorkingDirectory=${PROJECT_DIR}
Environment=EXNOKALIMCP_CONFIG=${CONFIG_PATH}
Environment=EXNOKALIMCP_AUTH_KEY=${AUTH_KEY}
ExecStart=${VENV_DIR}/bin/python ${SERVER_PATH} --transport sse
Restart=on-failure

[Install]
WantedBy=default.target
SERVICE
fi

log "Success"
cat <<EOF

ExnoKaliMCP server installed.

Config:        ${CONFIG_PATH}
Auth key:      ${KEY_FILE}
Server:        ${SERVER_PATH}
Python:        ${VENV_DIR}/bin/python
Claude JSON:   ${CLAUDE_SNIPPET}

Manual stdio test:
  cd "${PROJECT_DIR}"
  EXNOKALIMCP_CONFIG="${CONFIG_PATH}" EXNOKALIMCP_AUTH_KEY="${AUTH_KEY}" "${VENV_DIR}/bin/python" server.py

For Claude Desktop on Windows, merge this snippet into claude_desktop_config.json:
  ${CLAUDE_SNIPPET}

Add authorized scope before scanning:
  echo "example.com" >> "${APP_DIR}/scope.txt"

EOF
