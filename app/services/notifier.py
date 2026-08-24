"""Optional generic webhook notifications for completed scan jobs."""

from __future__ import annotations

from collections import Counter
import ipaddress
from urllib.parse import urlparse

import requests

from .. import database
from ..config import settings


FINAL_STATUSES = {"completed", "failed", "cancelled"}


def notify_scan(scan_id: str) -> None:
    url = settings.notification_webhook_url
    if not url:
        return
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        print("Notification skipped: NOTIFICATION_WEBHOOK_URL is invalid")
        return
    if parsed.scheme == "http" and not settings.allow_insecure_webhook and not _is_loopback(parsed.hostname):
        print("Notification skipped: non-loopback webhooks require HTTPS")
        return
    scan = database.get_scan_details(scan_id)
    if not scan or scan["status"] not in FINAL_STATUSES:
        return
    severities = Counter(item["severity"] for item in scan["findings"])
    summary = (
        f"KMN scan {scan['status']}: {scan['target']} - {len(scan['findings'])} findings "
        f"(critical {severities['critical']}, high {severities['high']}, medium {severities['medium']})"
    )
    payload = {
        "event": f"scan.{scan['status']}",
        "text": summary,
        "content": summary,
        "scan": {
            "id": scan["id"],
            "target": scan["target"],
            "profile": scan["profile"],
            "status": scan["status"],
            "message": scan.get("message"),
            "error": scan.get("error"),
        },
        "findings": {
            "total": len(scan["findings"]),
            "critical": severities["critical"],
            "high": severities["high"],
            "medium": severities["medium"],
            "low": severities["low"],
            "info": severities["info"],
        },
    }
    try:
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
    except requests.RequestException as exc:
        print(f"Scan notification failed: {exc}")


def _is_loopback(hostname: str | None) -> bool:
    if not hostname:
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False
