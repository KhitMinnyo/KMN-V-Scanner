# Changelog

All notable changes to KMN Vulnerability Scanner are documented here.

## [3.6.0] - 2026-08-24

### Added

- Nmap TCP service discovery with quick, standard, and deep scan profiles
- CIDR live-host discovery before network service scans
- Nmap NSE vulnerability script adapter with positive-state filtering
- Optional UDP top-100 port scan
- Nuclei safe-template adapter with automatic template update
- TLS checks through testssl.sh
- Optional OWASP ZAP baseline scanning
- Service CPE to NVD CVE candidate matching
- Scan comparison for new, fixed, and persistent findings
- Trivy filesystem and container image scanning
- Read-only SSH audit with key-only authentication
- Read-only Windows WinRM audit
- Optional AWS, Azure, and GCP cloud posture scanning through Prowler
- Recurring scan schedules with overlap protection
- Webhook and SMTP email notifications
- CSV export and HTML scan reports
- Bilingual authorization gate for the dashboard
- Optional dashboard authentication with expiring signed sessions
- Local users with `admin`, `operator`, and `viewer` roles
- Admin user management from the dashboard
- `amd64` and `arm64` Kali setup support

### Security

- External targets require explicit configuration and per-scan authorization confirmation
- Optional `AUTHORIZED_TARGETS` allowlist for external targets
- Scanner subprocesses use argument arrays, timeouts, cancellation, and process cleanup
- SSH scans use `IdentitiesOnly=yes` and a scanner-specific known-hosts file
- Webhook notifications require HTTPS except for loopback endpoints unless explicitly overridden
- Trivy filesystem scans are restricted to `TRIVY_SCAN_ROOT`
- Version-based NVD matches are stored as low-confidence candidates rather than confirmed vulnerabilities
- `.env` values are never included in the repository

### Fixed

- Python 3.14 installation failure caused by an outdated Pydantic/PyO3 dependency
- Nmap NSE false positives from `NOT VULNERABLE` output
- UDP services being sent to TCP-only NSE checks
- Scan comparison reporting findings as fixed when scans were incomplete or used different coverage
- Trivy malformed JSON being reported as a clean scan
- Existing `.env` files losing settings during setup
- Authorization overlay remaining visible after accepting the dashboard notice

## [3.5.0]

- Added local dashboard users and role-based access controls.
- Added read-only Windows, cloud, and artifact scan foundations.

## [3.4.0]

- Added Trivy, Windows, cloud, SMTP, and recurring scan foundations.

## [3.3.0]

- Added Phase 3 scanner adapters and local automation foundations.

## [3.2.0]

- Added CPE matching, scan comparison, Nuclei template updates, and UDP scanning.

## [3.1.0]

- Added authorization confirmation, scan exports, and report generation.

## [3.0.0]

- Rebuilt the scanner around a persistent FastAPI job and adapter architecture.
