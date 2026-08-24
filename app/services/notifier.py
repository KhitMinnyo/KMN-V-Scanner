"""Optional generic webhook notifications for completed scan jobs."""

from __future__ import annotations

from collections import Counter
from email.message import EmailMessage
import ipaddress
import smtplib
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
    _send_email(summary, scan, severities)


def _send_email(summary: str, scan: dict, severities: Counter) -> None:
    if not all((settings.smtp_host, settings.smtp_from, settings.smtp_to)):
        return
    message = EmailMessage()
    message["Subject"] = f"KMN scan {scan['status']}: {scan['target']}"
    message["From"] = settings.smtp_from
    message["To"] = settings.smtp_to
    message.set_content(
        f"{summary}\n\n"
        f"Critical: {severities['critical']}\n"
        f"High: {severities['high']}\n"
        f"Medium: {severities['medium']}\n"
        f"Low: {severities['low']}\n"
        f"Info: {severities['info']}\n"
    )
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as client:
            if settings.smtp_starttls:
                client.starttls()
            if settings.smtp_user:
                client.login(settings.smtp_user, settings.smtp_password)
            client.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        print(f"Email notification failed: {exc}")


def _is_loopback(hostname: str | None) -> bool:
    if not hostname:
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False
