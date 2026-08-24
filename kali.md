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

The generated `.env` enables external target scanning, but every scan still requires the bilingual authorization confirmation. For safer deployments, restrict explicitly authorized public targets with:

```env
ALLOW_EXTERNAL_TARGETS=true
AUTHORIZED_TARGETS=your-domain.example,203.0.113.10
```

The dashboard also requires an authorization confirmation for each scan. `AUTHORIZED_TARGETS` is optional but recommended; when set, an external target must match one of the listed hosts, IPs, or CIDR ranges. Keep the dashboard bound to localhost unless authentication and a trusted reverse proxy are configured.

Optional dashboard login protection:

```env
DASHBOARD_PASSWORD=choose_a_strong_local_password
AUTO_UPDATE_NUCLEI_TEMPLATES=true
TRIVY_SCAN_ROOT=/home/your-user/projects
SSH_AUDIT_USER=security-audit
SSH_AUDIT_KEY_PATH=/home/your-user/.ssh/kmn_audit
SSH_AUDIT_KNOWN_HOSTS_PATH=data/ssh_known_hosts
NOTIFICATION_WEBHOOK_URL=
```

The optional UDP scan normally requires elevated Nmap privileges. Trivy must be installed for filesystem/image scans. SSH audit requires a dedicated low-privilege account and key. Recurring schedules and webhook notifications operate only while the local application is running.

## Optional NVD Key

NVD CVE reference search works without a key at a slower rate. A personal free key can be placed only in the local `.env` file:

```env
NVD_API_KEY=your_personal_key
```

Never commit `.env`, place the key in a shell script, or share one key with repository users. If a key was ever committed, revoke it and issue a new one because deleting the current line does not remove it from git history.

## Troubleshooting

Check installed binaries with:

```bash
./manage.sh doctor
```

If a tool is unavailable, the dashboard shows it as unavailable and continues with the installed adapters. The Nmap adapter is required for network scans.
