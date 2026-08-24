#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_APP=true
SKIP_SYSTEM_TOOLS=false
SKIP_NUCLEI=false

usage() {
    cat <<'EOF'
Usage: ./setup.sh [options]

Install KMN Vulnerability Scanner and optionally start the dashboard.

Options:
  --no-run              Install everything but do not start the dashboard
  --skip-system-tools   Do not install Kali/Debian packages
  --skip-nuclei         Do not attempt the optional Nuclei install
  -h, --help            Show this help
EOF
}

for argument in "$@"; do
    case "$argument" in
        --no-run) RUN_APP=false ;;
        --skip-system-tools) SKIP_SYSTEM_TOOLS=true ;;
        --skip-nuclei) SKIP_NUCLEI=true ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'Unknown option: %s\n\n' "$argument" >&2; usage >&2; exit 1 ;;
    esac
done

if [[ "$(uname -s)" != "Linux" ]]; then
    printf '%s\n' 'This installer is intended for Kali/Debian-based Linux.' >&2
    exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64) NUCLEI_ARCH="amd64" ;;
    aarch64|arm64) NUCLEI_ARCH="arm64" ;;
    *) NUCLEI_ARCH="" ;;
esac

if [[ "$SKIP_SYSTEM_TOOLS" == false ]]; then
    if ! command -v apt-get >/dev/null 2>&1; then
        printf '%s\n' 'apt-get is required for automatic Kali/Debian setup. Install dependencies manually if apt-get is unavailable.' >&2
        exit 1
    fi

    if [[ "$(id -u)" -eq 0 ]]; then
        SUDO=""
    elif command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        printf '%s\n' 'sudo is required to install system packages. Re-run as root or install them manually.' >&2
        exit 1
    fi

    printf '%s\n' 'Installing required Kali/Debian packages...'
    $SUDO apt-get update
    $SUDO apt-get install -y --no-install-recommends python3 python3-venv python3-pip nmap openssh-client curl unzip ca-certificates

    if apt-cache show testssl.sh >/dev/null 2>&1; then
        $SUDO apt-get install -y --no-install-recommends testssl.sh
    else
        printf '%s\n' 'Optional package testssl.sh is not available in the configured repositories; continuing.'
    fi

    if apt-cache show trivy >/dev/null 2>&1; then
        $SUDO apt-get install -y --no-install-recommends trivy
    else
        printf '%s\n' 'Optional package trivy is not available in the configured repositories; install it manually for artifact scans.'
    fi
fi

if [[ "$SKIP_NUCLEI" == false && -n "$NUCLEI_ARCH" ]] && ! command -v nuclei >/dev/null 2>&1; then
    NUCLEI_VERSION="${NUCLEI_VERSION:-v3.4.10}"
    NUCLEI_NUMBER="${NUCLEI_VERSION#v}"
    NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${NUCLEI_NUMBER}_linux_${NUCLEI_ARCH}.zip"
    TEMP_DIR="$(mktemp -d)"
    trap 'rm -rf "$TEMP_DIR"' EXIT
    printf 'Installing optional Nuclei for %s...\n' "$NUCLEI_ARCH"
    if curl --fail --silent --show-error --location "$NUCLEI_URL" --output "$TEMP_DIR/nuclei.zip" \
        && unzip -q "$TEMP_DIR/nuclei.zip" -d "$TEMP_DIR" \
        && [[ -x "$TEMP_DIR/nuclei" ]]; then
        if [[ "$(id -u)" -eq 0 ]]; then
            install -m 0755 "$TEMP_DIR/nuclei" /usr/local/bin/nuclei
        else
            sudo install -m 0755 "$TEMP_DIR/nuclei" /usr/local/bin/nuclei
        fi
    else
        printf '%s\n' 'Nuclei download failed; continuing with Nmap-only capability. Install Nuclei manually later.'
    fi
fi

cd "$ROOT_DIR"
if [[ ! -f .env ]]; then
    cp .env.example .env
    chmod 600 .env
    printf '%s\n' 'Created .env from .env.example.'
else
    chmod 600 .env
    printf '%s\n' 'Keeping existing .env.'
fi

ensure_env_key() {
    local key="$1"
    local value="$2"
    if ! grep -q "^${key}=" .env; then
        printf '\n%s=%s\n' "$key" "$value" >> .env
        printf 'Added missing %s setting to .env.\n' "$key"
    fi
}

ensure_env_key "DASHBOARD_ROLE" "admin"
ensure_env_key "DASHBOARD_SESSION_SECRET" ""
ensure_env_key "AUTO_UPDATE_NUCLEI_TEMPLATES" "true"
ensure_env_key "TRIVY_SCAN_ROOT" "."
ensure_env_key "SSH_AUDIT_USER" ""
ensure_env_key "SSH_AUDIT_KEY_PATH" ""
ensure_env_key "SSH_AUDIT_KNOWN_HOSTS_PATH" "data/ssh_known_hosts"
ensure_env_key "NOTIFICATION_WEBHOOK_URL" ""
ensure_env_key "ALLOW_INSECURE_WEBHOOK" "false"
ensure_env_key "SMTP_HOST" ""
ensure_env_key "SMTP_PORT" "587"
ensure_env_key "SMTP_USER" ""
ensure_env_key "SMTP_PASSWORD" ""
ensure_env_key "SMTP_FROM" ""
ensure_env_key "SMTP_TO" ""
ensure_env_key "SMTP_STARTTLS" "true"
ensure_env_key "WINDOWS_AUDIT_USER" ""
ensure_env_key "WINDOWS_AUDIT_PASSWORD" ""
ensure_env_key "WINDOWS_AUDIT_TRANSPORT" "ntlm"
ensure_env_key "WINDOWS_AUDIT_SERVER_CERT_VALIDATION" "validate"
ensure_env_key "CLOUD_ALLOWED_PROVIDERS" "aws,azure,gcp"

./manage.sh install

printf '\n%s\n' 'KMN Vulnerability Scanner setup complete.'

if [[ "$RUN_APP" == true ]]; then
    exec .venv/bin/python app.py
fi

printf '%s\n' 'Run ./manage.sh run when you are ready to start the dashboard.'
