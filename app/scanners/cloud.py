"""Optional Prowler cloud configuration scan adapter."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import threading

from ..config import settings
from .runner import CommandResult, command_available, run_command


PROVIDERS = {"aws", "azure", "gcp"}


class CloudTargetError(ValueError):
    pass


def validate_provider(provider: str) -> str:
    provider = provider.strip().lower()
    if provider not in PROVIDERS:
        raise CloudTargetError("Provider must be aws, azure, or gcp")
    if settings.cloud_allowed_providers and provider not in settings.cloud_allowed_providers:
        raise CloudTargetError("Provider is not listed in CLOUD_ALLOWED_PROVIDERS")
    return provider


def scan(provider: str, timeout: int, cancel_event: threading.Event) -> tuple[CommandResult, list[dict]]:
    if not command_available("prowler"):
        return run_command(["prowler"], timeout=1, cancel_event=cancel_event), []
    with tempfile.TemporaryDirectory(prefix="kmn-prowler-") as directory:
        result = run_command(
            ["prowler", provider, "-M", "json-ocsf", "-o", directory],
            timeout,
            cancel_event,
        )
        findings = parse_directory(Path(directory), provider)
    return result, findings


def parse_directory(directory: Path, provider: str) -> list[dict]:
    findings: list[dict] = []
    for path in directory.rglob("*.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        records = payload if isinstance(payload, list) else payload.get("findings", payload.get("Findings", []))
        if isinstance(records, dict):
            records = [records]
        for item in records:
            status = str(item.get("status_code", item.get("Status", item.get("status", "")))).lower()
            if status in {"pass", "passed", "compliant", "success"}:
                continue
            rule_id = str(item.get("finding_info", {}).get("uid", item.get("CheckID", item.get("check_id", "cloud-check"))))
            title = str(item.get("finding_info", {}).get("title", item.get("CheckTitle", item.get("title", rule_id))))
            severity = str(item.get("severity", item.get("Severity", "medium"))).lower()
            if severity not in {"critical", "high", "medium", "low", "info"}:
                severity = "medium"
            findings.append({
                "host": provider,
                "port": None,
                "protocol": None,
                "title": title,
                "severity": severity,
                "confidence": "medium",
                "description": str(item.get("finding_info", {}).get("desc", item.get("Description", "Cloud configuration finding"))),
                "evidence": json.dumps(item, ensure_ascii=True)[:8000],
                "remediation": str(item.get("Remediation", item.get("remediation", "Review the cloud control and apply the provider guidance."))),
                "source_tool": "prowler",
                "rule_id": rule_id,
                "fingerprint": f"prowler:{provider}:{rule_id}:{item.get('resource_uid', item.get('ResourceId', ''))}",
            })
    return findings
