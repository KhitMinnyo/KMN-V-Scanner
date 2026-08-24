"""testssl.sh adapter for HTTPS services."""

from __future__ import annotations

import json
import threading

from .runner import CommandResult, command_available, run_command


def scan(host: str, port: int, timeout: int, cancel_event: threading.Event) -> tuple[CommandResult, list[dict]]:
    binary = "testssl.sh" if command_available("testssl.sh") else "testssl"
    if not command_available(binary):
        return run_command(["testssl.sh"], timeout=1, cancel_event=cancel_event), []
    result = run_command(
        [binary, "--quiet", "--color", "0", "--jsonfile", "-", f"{host}:{port}"],
        timeout,
        cancel_event,
    )
    return result, parse_output(result.stdout, host, port)


def parse_output(output: str, host: str, port: int) -> list[dict]:
    findings = []
    try:
        data = json.loads(output)
        entries = data if isinstance(data, list) else data.get("scanResult", [])
        for item in entries:
            if str(item.get("severity", "")).lower() not in {"ok", "info", "not vulnerable"}:
                findings.append(_finding(host, port, item.get("id", "TLS check"), str(item), item.get("severity", "medium")))
        return findings
    except (json.JSONDecodeError, AttributeError):
        pass
    lowered = output.lower()
    checks = [
        ("TLS 1.0 enabled", "tlsv1", "medium"),
        ("TLS 1.1 enabled", "tlsv1.1", "medium"),
        ("Weak cipher or protocol detected", "weak", "medium"),
        ("Certificate warning", "certificate", "low"),
    ]
    for title, marker, severity in checks:
        if marker in lowered:
            findings.append(_finding(host, port, title, output[-4000:], severity))
    return findings


def _finding(host: str, port: int, title: str, evidence: str, severity: str) -> dict:
    severity = str(severity).lower()
    if severity not in {"info", "low", "medium", "high", "critical"}:
        severity = "medium"
    return {
        "host": host,
        "port": port,
        "protocol": "tcp",
        "title": title,
        "severity": severity,
        "confidence": "medium",
        "description": "TLS configuration issue reported by testssl.sh.",
        "evidence": evidence,
        "remediation": "Disable obsolete protocols and weak cipher suites, then re-test the endpoint.",
        "source_tool": "testssl.sh",
        "rule_id": title,
        "fingerprint": f"testssl:{host}:{port}:{title}",
    }
