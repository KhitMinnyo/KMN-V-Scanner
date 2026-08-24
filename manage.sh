#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# Optional organization-wide runtime secrets. Keep this file root-owned with mode 600.
GLOBAL_ENV_FILE="${KMN_GLOBAL_ENV_FILE:-/etc/kmn-v-scanner.env}"
if [[ -r "$GLOBAL_ENV_FILE" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$GLOBAL_ENV_FILE"
    set +a
fi

usage() {
    printf '%s\n' \
        'Usage: ./manage.sh <command>' \
        '' \
        'Commands:' \
        '  install   Create a virtualenv and install dependencies' \
        '  run       Start the local dashboard on port 2025' \
        '  doctor    Check scanner binaries and architecture' \
        '  db        Initialize the local database'
}

activate_venv() {
    if [[ ! -d .venv ]]; then
        python3 -m venv .venv
    fi
    # shellcheck disable=SC1091
    source .venv/bin/activate
}

case "${1:-help}" in
    install)
        activate_venv
        python -m pip install --upgrade pip
        python -m pip install -r requirements.txt
        printf '%s\n' 'Installation complete.'
        ;;
    run)
        activate_venv
        exec python app.py
        ;;
    db)
        activate_venv
        python -c 'from app.database import init_db; init_db(); print("Database initialized.")'
        ;;
    doctor)
        printf 'Architecture: %s\n' "$(uname -m)"
        for tool in nmap nuclei testssl.sh zap-baseline.py trivy prowler ssh; do
            if command -v "$tool" >/dev/null 2>&1; then
                printf '  %-18s ready (%s)\n' "$tool" "$(command -v "$tool")"
            else
                printf '  %-18s unavailable\n' "$tool"
            fi
        done
        ;;
    help|--help|-h)
        usage
        ;;
    *)
        usage >&2
        exit 1
        ;;
esac
