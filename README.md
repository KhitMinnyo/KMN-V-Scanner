# KMN Vulnerability Scanner

<p align="center">
  <img src="logo.png" alt="KMN Vulnerability Scanner logo" width="180">
</p>

Version: **3.7.0**

See the [CHANGELOG](CHANGELOG.md) for release history.

Local-first vulnerability scanning dashboard for Kali Linux. It combines Nmap, Nuclei, testssl.sh, optional OWASP ZAP, and optional NVD CVE lookup.

Current coverage includes TCP service detection, CIDR live-host discovery, Nmap NSE checks, Nuclei templates, TLS checks, optional UDP scanning, service CPE-to-CVE matching, Trivy artifact scans, read-only SSH and Windows audits, AWS/Azure/GCP Prowler audits, recurring schedules, webhook/email notifications, scan comparison, dashboard login, and CSV/HTML reports.

Only scan systems and networks that you own or are explicitly authorized to assess. The dashboard displays a Burmese/English authorization warning before scanning is available. Unauthorized scanning may be a criminal or civil offense depending on your jurisdiction.

## 1. Setup

Run this section only the first time.

### Install on Kali Linux

```bash
git clone https://github.com/KhitMinnyo/KMN-V-Scanner.git
cd KMN-V-Scanner
./setup.sh --no-run
```

The setup script installs the required Kali packages, creates `.venv`, installs Python dependencies, creates a protected `.env`, adds missing configuration keys without overwriting existing values, and attempts to install Nuclei for the detected `amd64` or `arm64` architecture.

Check installed scanner tools:

```bash
./manage.sh doctor
```

Optional Phase 3/4 settings:

```env
TRIVY_SCAN_ROOT=/home/your-user/projects
SSH_AUDIT_USER=security-audit
SSH_AUDIT_KEY_PATH=/home/your-user/.ssh/kmn_audit
SSH_AUDIT_KNOWN_HOSTS_PATH=data/ssh_known_hosts
NOTIFICATION_WEBHOOK_URL=https://your-approved-webhook.example/path
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=security@example.com
SMTP_PASSWORD=use_an_app_password
SMTP_FROM=security@example.com
SMTP_TO=ops@example.com
SMTP_STARTTLS=true
WINDOWS_AUDIT_USER=DOMAIN\\audit-user
WINDOWS_AUDIT_PASSWORD=use_a_secret_store_value
WINDOWS_AUDIT_TRANSPORT=ntlm
WINDOWS_AUDIT_SERVER_CERT_VALIDATION=validate
CLOUD_ALLOWED_PROVIDERS=aws,azure,gcp
```

Use a dedicated read-only SSH account and a key that works with `BatchMode`; passphrase prompts are not supported by background jobs. Never put a private key's contents in `.env`.

Windows auditing uses `pywinrm` and fixed read-only PowerShell inventory checks. Cloud auditing uses Prowler and the provider CLI credentials already configured on the Kali host; KMN does not collect or persist cloud credentials. Configure SMTP only when email notification is required, and use an app password where the provider supports it.


### Configure External Targets

The generated `.env` enables external target scanning. Restrict it to approved targets whenever possible:

```bash
nano .env
```

```env
ALLOW_EXTERNAL_TARGETS=true
AUTHORIZED_TARGETS=your-domain.example,203.0.113.10
```

Use hostname, IP, or CIDR values only. Do not include `https://` or a port. `AUTHORIZED_TARGETS` can be left empty, but then any external target is allowed after the authorization confirmation.

### Optional NVD API Key

Nmap, Nuclei, testssl.sh, and ZAP do not require API keys. NVD CVE search works without a key at a slower rate.

To use a free personal NVD API key:

1. Create or sign in to an account at [nvd.nist.gov](https://nvd.nist.gov/).
2. Request a key from the [NVD API key page](https://nvd.nist.gov/developers/request-an-api-key).
3. Add it only to your local `.env` file:

```env
NVD_API_KEY=your_personal_nvd_api_key
```

Never commit `.env`, put the key in a script, or share it. If a key was previously exposed, revoke it and request a new one.

## 2. Run

After setup, use this section whenever you want to use the scanner again.

```bash
cd KMN-V-Scanner
./manage.sh run
```

Open the dashboard:

```text
http://127.0.0.1:2025
```

When the authorization popup appears:

- Select `OK, I Understand` only if you are authorized to scan the target.
- Select `Cancel` to lock the scanner interface.
- Select `Show authorization notice again` to reopen the popup without reloading the page.

Stop the local dashboard with `Ctrl+C`.

The `UDP top 100 ports` option is slower and normally requires running the application with privileges that permit Nmap UDP scanning. Version-based NVD matches are marked with low confidence and should be verified before remediation.

Open a completed scan's `Details` view to export CSV, open an HTML report, or compare it with the previous completed scan of the same target.

Trivy filesystem targets must be inside `TRIVY_SCAN_ROOT`. Recurring schedules prevent overlapping runs and operate only while the application is running. Webhook payloads contain target names and finding counts, so use HTTPS and configure only a trusted endpoint. Email notifications require SMTP settings and an app password where the provider supports it.

NVD CPE matches require a concrete detected version and are stored as low-severity `candidate` records, not confirmed open vulnerabilities. Confirm the installed version and affected range before acting on them. Scan comparison reports fixed findings only when both scans completed with equivalent profiles/options and comparable successful tool coverage.

## 3. Troubleshooting

If a scanner tool is unavailable, check it with:

```bash
./manage.sh doctor
```

Nmap is required for network scans. Nuclei, testssl.sh, and ZAP are optional adapters.

If the authorization screen is already blocked, select `Show authorization notice again`, then select `OK, I Understand` only when you have permission to scan the target.

If the repository was previously installed, update it before running setup again:

```bash
git pull origin main
./setup.sh --no-run
```

The application is released under the MIT License. External tools and templates retain their own licenses.
