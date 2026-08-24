# KMN Vulnerability Scanner

<p align="center">
  <img src="logo.png" alt="KMN Vulnerability Scanner logo" width="180">
</p>

Version: **3.0.0**

Local-first vulnerability scanning dashboard for Kali Linux. It combines Nmap, Nuclei, testssl.sh, optional OWASP ZAP, and optional NVD CVE lookup.

Only scan systems and networks that you own or are explicitly authorized to assess. The dashboard displays a Burmese/English authorization warning before scanning is available. Unauthorized scanning may be a criminal or civil offense depending on your jurisdiction.

## 1. Setup

Run this section only the first time.

### Install on Kali Linux

```bash
git clone https://github.com/KhitMinnyo/KMN-V-Scanner.git
cd KMN-V-Scanner
./setup.sh --no-run
```

The setup script installs the required Kali packages, creates `.venv`, installs Python dependencies, creates a protected `.env`, and attempts to install Nuclei for the detected `amd64` or `arm64` architecture.

Check installed scanner tools:

```bash
./manage.sh doctor
```

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
