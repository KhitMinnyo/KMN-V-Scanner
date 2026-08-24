"""Nuclei safe-template adapter."""

from __future__ import annotations

import json
import threading

from .runner import CommandResult, command_available, run_command


SEVERITIES = {"info", "low", "medium", "high", "critical"}


def scan(url: str, timeout: int, cancel_event: threading.Event) -> tuple[CommandResult, list[dict]]:
    args = [
        "nuclei",
        "-u",
        url,
        "-jsonl",
        "-silent",
        "-no-interactsh",
        "-rate-limit",
        "50",
        "-timeout",
        "10",
        "-severity",
        "info,low,medium,high,critical",
    ]
    if not command_available("nuclei"):
        return run_command(["nuclei"], timeout=1, cancel_event=cancel_event), []
    result = run_command(args, timeout, cancel_event)
    if result.status not in {"completed", "failed"}:
        return result, []
    return result, parse_jsonl(result.stdout, url)


def parse_jsonl(output: str, default_url: str) -> list[dict]:
    findings = []
    for line in output.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = item.get("info", {})
        classification = info.get("classification") or {}
        references = info.get("reference") or []
        if isinstance(references, str):
            references = [references]
        severity = str(info.get("severity", "info")).lower()
        if severity not in SEVERITIES:
            severity = "info"
        extracted = item.get("extracted-results") or []
        matched = item.get("matched-at") or item.get("host") or default_url
        findings.append(
            {
                "host": item.get("host") or default_url,
                "port": item.get("port"),
                "protocol": "tcp",
                "title": info.get("name") or item.get("template-id", "Nuclei finding"),
                "severity": severity,
                "confidence": "high",
                "cve_id": _first(classification.get("cve-id")),
                "cwe_id": _first(classification.get("cwe-id")),
                "description": info.get("description", ""),
                "evidence": f"Matched: {matched}\nExtracted: {', '.join(map(str, extracted))}",
                "remediation": info.get("remediation") or "Review the template guidance and vendor documentation.",
                "source_tool": "nuclei",
                "rule_id": item.get("template-id"),
                "reference_url": references[0] if references else None,
                "fingerprint": f"nuclei:{item.get('template-id')}:{matched}",
            }
        )
    return findings


def _first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value
