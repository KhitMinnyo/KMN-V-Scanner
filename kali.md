# Kali Linux Guide

KMN Vulnerability Scanner v3 is designed to run on Kali Linux without root for its default TCP connect scan. Use elevated privileges only when a separately installed tool explicitly requires them.

## Install

```bash
sudo apt update
sudo apt install -y python3 python3-venv nmap testssl.sh
```

Install Nuclei from the official ProjectDiscovery release instructions if you want template checks. OWASP ZAP is optional; install it separately if you want the deep profile's baseline scan.

## Run Locally

```bash
./manage.sh install
cp .env.example .env
./manage.sh doctor
./manage.sh run
```

Open `http://127.0.0.1:2025`.

The default configuration permits private, loopback, and link-local targets only. For an explicitly authorized public target, set this in `.env`:

```env
ALLOW_EXTERNAL_TARGETS=true
```

Keep the dashboard bound to localhost unless authentication and a trusted reverse proxy are configured.

## Optional NVD Key

NVD CVE reference search works without a key at a slower rate. A personal free key can be placed only in the local `.env` file:

```env
NVD_API_KEY=your_personal_key
```

Never commit `.env`, place the key in a shell script, or share one key with repository users. If a key was ever committed, revoke it and issue a new one because deleting the current line does not remove it from git history.

## Docker

```bash
cp .env.example .env
```

The Dockerfile builds on both `linux/amd64` and `linux/arm64`. Scan data is stored in `data/scanner.db`.

## Troubleshooting

Check installed binaries with:

```bash
./manage.sh doctor
```

If a tool is unavailable, the dashboard shows it as unavailable and continues with the installed adapters. The Nmap adapter is required for network scans.
