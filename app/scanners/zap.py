"""Optional OWASP ZAP baseline adapter."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import threading

from .runner import CommandResult, command_available, run_command


def scan(url: str, timeout: int, cancel_event: threading.Event) -> tuple[CommandResult, list[dict]]:
    binary = "zap-baseline.py" if command_available("zap-baseline.py") else "zap-baseline"
    if not command_available(binary):
        return run_command(["zap-baseline.py"], timeout=1, cancel_event=cancel_event), []
    with tempfile.TemporaryDirectory(prefix="kmn-zap-") as directory:
        report = Path(directory) / "report.json"
        result = run_command(
            [binary, "-t", url, "-J", str(report), "-I", "-T", "5"],
            timeout,
            cancel_event,
        )
        findings = parse_report(report, url)
    return result, findings


def parse_report(path: Path, url: str) -> list[dict]:
    if not path.exists():
        return []
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    findings = []
    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            risk = str(alert.get("riskcode", "0"))
            severity = {"3": "high", "2": "medium", "1": "low"}.get(risk, "info")
            findings.append(
                {
                    "host": url,
                    "port": None,
                    "protocol": "tcp",
                    "title": alert.get("name", "ZAP alert"),
                    "severity": severity,
                    "confidence": str(alert.get("confidence", "medium")).lower(),
                    "cwe_id": alert.get("cweid") if alert.get("cweid") not in {"0", 0} else None,
                    "description": alert.get("desc", ""),
                    "evidence": alert.get("instances") or alert.get("uri", ""),
                    "remediation": alert.get("solution", "Review the OWASP ZAP alert guidance."),
                    "source_tool": "owasp-zap",
                    "rule_id": alert.get("pluginid"),
                    "reference_url": alert.get("reference"),
                    "fingerprint": f"zap:{alert.get('pluginid')}:{alert.get('uri')}",
                }
            )
    return findings
