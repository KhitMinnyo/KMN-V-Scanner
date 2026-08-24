# KMN Vulnerability Scanner

<p align="center">
  <img src="logo.png" alt="KMN Vulnerability Scanner logo" width="180">
</p>

Version: **3.0.0**

KMN Vulnerability Scanner is a local-first security scanning dashboard for Kali Linux. It combines Nmap, Nuclei, testssl.sh, optional OWASP ZAP, and optional NVD CVE lookup.

Only scan systems and networks that you own or are explicitly authorized to assess. When the dashboard opens, a Burmese/English authorization warning appears before scanning is available. Unauthorized scanning may be a criminal or civil offense depending on your jurisdiction.

## 1. Setup

Run this section only the first time.

### Kali Linux

```bash
git clone https://github.com/KhitMinnyo/KMN-V-Scanner.git
cd KMN-V-Scanner
./setup.sh --no-run
```

The setup script installs Python, Nmap, testssl.sh when available, project dependencies, and the optional Nuclei binary for the detected `amd64` or `arm64` architecture. It creates a local `.env` file and never overwrites an existing one.

Check installed tools:

```bash
./manage.sh doctor
```

### Docker

Docker supports `amd64` and `arm64` hosts.

```bash
git clone https://github.com/KhitMinnyo/KMN-V-Scanner.git
cd KMN-V-Scanner
cp .env.example .env
sudo docker compose build
```

The Docker image downloads the matching Nuclei release binary automatically. Docker data is stored in `data/scanner.db`.

## 2. Run

After setup, use only one of these commands whenever you want to use the scanner again.

### Run on Kali

```bash
cd KMN-V-Scanner
./manage.sh run
```

### Run with Docker

```bash
cd KMN-V-Scanner
sudo docker compose up
```

Open the dashboard:

```text
http://127.0.0.1:2025
```

When the authorization popup appears:

- Select `OK, I Understand` only if you are authorized to scan the target.
- Select `Cancel` to lock the scanner interface.

## 3. External Targets

The generated `.env` enables external target scanning, but the authorization popup and backend confirmation are still required. For safer use, restrict scans to approved targets:

```bash
nano .env
```

```env
ALLOW_EXTERNAL_TARGETS=true
AUTHORIZED_TARGETS=your-domain.example,203.0.113.10
```

Use hostname, IP, or CIDR values only. Do not include `https://` or a port. Restart the application after changing `.env`.

## 4. Optional NVD API Key

Nmap, Nuclei, testssl.sh, and ZAP do not require API keys. NVD CVE search works without a key at a slower rate.

To use a free personal NVD API key:

1. Create or sign in to an account at [nvd.nist.gov](https://nvd.nist.gov/).
2. Request a key from the [NVD API key page](https://nvd.nist.gov/developers/request-an-api-key).
3. Add the key only to your local `.env` file:

```env
NVD_API_KEY=your_personal_nvd_api_key
```

Never commit `.env`, put the key in a script, or share the key. If a key was previously exposed, revoke it and request a new one.

## 5. Stop and Restart

Stop the local dashboard with `Ctrl+C`.

Stop Docker:

```bash
sudo docker compose down
```

Start Docker again:

```bash
sudo docker compose up
```

## License

The KMN application is released under the MIT License. External tools and templates retain their own licenses.
