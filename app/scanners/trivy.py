"""Trivy filesystem and container image scanning adapter."""

from __future__ import annotations

import json
from pathlib import Path
import re
import threading

from ..config import settings
from .runner import CommandResult, command_available, run_command


IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@:-]{0,254}$")


class TrivyTargetError(ValueError):
    pass


class TrivyParseError(ValueError):
    pass


def validate_target(mode: str, value: str) -> str:
    target = value.strip()
    if not target:
        raise TrivyTargetError("Artifact target is required")
    if mode == "image":
        if not IMAGE_RE.fullmatch(target) or target.startswith("-"):
            raise TrivyTargetError("Invalid container image reference")
        return target
    root = Path(settings.trivy_scan_root).expanduser().resolve()
    path = Path(target).expanduser()
    if not path.is_absolute():
        path = root / path
    path = path.resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise TrivyTargetError(f"Filesystem target must be inside TRIVY_SCAN_ROOT ({root})") from exc
    if not path.exists():
        raise TrivyTargetError("Filesystem target does not exist")
    return str(path)


def scan(mode: str, target: str, timeout: int, cancel_event: threading.Event) -> tuple[CommandResult, list[dict]]:
    args = [
        "trivy",
        mode,
        "--format",
        "json",
        "--scanners",
        "vuln,secret,misconfig",
        "--quiet",
        target,
    ]
    if not command_available("trivy"):
        return run_command(["trivy"], timeout=1, cancel_event=cancel_event), []
    result = run_command(args, timeout, cancel_event)
    if result.status != "completed":
        return result, []
    try:
        return result, parse_json(result.stdout, target)
    except TrivyParseError as exc:
        result.status = "failed"
        result.stderr = f"{result.stderr}\n{exc}".strip()
        return result, []


def parse_json(output: str, target: str) -> list[dict]:
    try:
        payload = json.loads(output)
    except json.JSONDecodeError as exc:
        raise TrivyParseError("Trivy returned invalid JSON") from exc
    if not isinstance(payload.get("Results"), list):
        raise TrivyParseError("Trivy JSON response does not contain a Results list")
    findings: list[dict] = []
    for result in payload.get("Results", []):
        component = result.get("Target") or target
        for item in result.get("Vulnerabilities") or []:
            vuln_id = item.get("VulnerabilityID") or "trivy-vulnerability"
            package = item.get("PkgName") or "unknown package"
            findings.append(
                _finding(
                    target,
                    f"{vuln_id} in {package}",
                    item.get("Severity"),
                    item.get("Title") or item.get("Description") or "Package vulnerability",
                    (
                        f"Component: {component}\nPackage: {package}\n"
                        f"Installed: {item.get('InstalledVersion') or 'unknown'}\n"
                        f"Fixed: {item.get('FixedVersion') or 'not published'}"
                    ),
                    f"Upgrade {package} to {item.get('FixedVersion') or 'a vendor-fixed release'}.",
                    vuln_id,
                    vuln_id if str(vuln_id).upper().startswith("CVE-") else None,
                    item.get("PrimaryURL"),
                    f"{component}:{package}:{item.get('InstalledVersion') or ''}",
                )
            )
        for item in result.get("Misconfigurations") or []:
            rule_id = item.get("ID") or "trivy-misconfiguration"
            findings.append(
                _finding(
                    target,
                    item.get("Title") or rule_id,
                    item.get("Severity"),
                    item.get("Description") or "Configuration issue detected by Trivy.",
                    f"Component: {component}\n{item.get('Message') or ''}",
                    item.get("Resolution") or "Apply the secure configuration recommended by Trivy.",
                    rule_id,
                    None,
                    item.get("PrimaryURL"),
                    f"{component}:{rule_id}",
                )
            )
        for item in result.get("Secrets") or []:
            rule_id = item.get("RuleID") or "trivy-secret"
            findings.append(
                _finding(
                    target,
                    item.get("Title") or f"Potential secret: {rule_id}",
                    item.get("Severity") or "high",
                    "Potential secret material was found in the scanned artifact.",
                    f"Component: {component}\nCategory: {item.get('Category') or 'secret'}",
                    "Revoke exposed credentials, remove them from the artifact, and use a secret manager.",
                    rule_id,
                    None,
                    None,
                    f"{component}:{rule_id}:{item.get('StartLine') or ''}",
                )
            )
    return findings


def _finding(
    target: str,
    title: str,
    severity: str | None,
    description: str,
    evidence: str,
    remediation: str,
    rule_id: str,
    cve_id: str | None,
    reference_url: str | None,
    occurrence: str,
) -> dict:
    normalized_severity = str(severity or "medium").lower()
    if normalized_severity not in {"critical", "high", "medium", "low", "info"}:
        normalized_severity = "medium"
    return {
        "host": target,
        "port": None,
        "protocol": None,
        "title": title,
        "severity": normalized_severity,
        "confidence": "high",
        "cve_id": cve_id,
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
        "source_tool": "trivy",
        "rule_id": rule_id,
        "reference_url": reference_url,
        "fingerprint": f"trivy:{rule_id}:{target}:{occurrence}",
    }
