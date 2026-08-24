"""Version-based CVE matching for discovered service CPEs."""

from __future__ import annotations

import threading
import time

from .. import database
from . import nvd
from .nvd import NvdError


MAX_CPE_LOOKUPS = 8
_CPE_CACHE: dict[str, list[dict]] = {}


def severity_from_score(score) -> str:
    if score is None:
        return "low"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def normalize_cpe(cpe: str) -> str:
    """Convert the legacy CPE 2.2 form emitted by Nmap to CPE 2.3."""
    if cpe.startswith("cpe:2.3:"):
        return cpe
    if not cpe.startswith("cpe:/"):
        return cpe
    parts = cpe[5:].split(":")
    parts.extend(["*"] * (11 - len(parts)))
    return "cpe:2.3:" + ":".join(parts[:11])


def has_concrete_version(cpe: str) -> bool:
    normalized = normalize_cpe(cpe)
    parts = normalized.split(":")
    return len(parts) > 5 and parts[5] not in {"", "*", "-"}


def match_services(
    scan_id: str,
    services: list[dict],
    cancel_event: threading.Event | None = None,
) -> int:
    """Match unique service CPEs to NVD records and persist low-confidence findings."""
    cache: dict[str, list[dict]] = {}
    added = 0
    deadline = time.monotonic() + 60
    lookup_limit = MAX_CPE_LOOKUPS if nvd.has_api_key() else 2
    for service in services:
        if (cancel_event and cancel_event.is_set()) or time.monotonic() >= deadline:
            break
        raw_cpe = (service.get("cpe") or "").strip()
        if not raw_cpe or not has_concrete_version(raw_cpe):
            continue
        cpe = normalize_cpe(raw_cpe)
        if cpe not in cache:
            if len(cache) >= lookup_limit:
                continue
            if cpe in _CPE_CACHE:
                cache[cpe] = _CPE_CACHE[cpe]
            else:
                try:
                    cache[cpe] = nvd.lookup_cpe(cpe, cancel_event=cancel_event)
                except NvdError:
                    cache[cpe] = []
                _CPE_CACHE[cpe] = cache[cpe]
        records = cache[cpe]
        for cve in records:
            cve_id = cve.get("id")
            if not cve_id:
                continue
            if database.add_finding(
                scan_id,
                {
                    "host": service["host"],
                    "port": service["port"],
                    "protocol": service.get("protocol", "tcp"),
                    "title": f"Potential {cve_id} version match",
                    "severity": "low",
                    "confidence": "low",
                    "cve_id": cve_id,
                    "description": cve.get("description", ""),
                    "evidence": (
                        f"Service CPE {raw_cpe} matched vulnerability intelligence records. "
                        f"NVD CVSS (not local risk): {cve.get('cvss_score') or 'N/A'} "
                        f"{cve.get('cvss_vector') or ''}. This is an unconfirmed version-based candidate."
                        f" Source: {cve.get('source', 'NVD')}. KEV: {'yes' if cve.get('exploited_in_wild') else 'no'}. "
                        f"EPSS: {cve.get('epss_score') or 'N/A'}."
                    ),
                    "remediation": "Verify the exact running version and upgrade to a vendor-fixed release.",
                    "source_tool": "nvd-cpe",
                    "rule_id": cve_id,
                    "status": "candidate",
                    "reference_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "fingerprint": f"cpe:{cve_id}:{service['host']}:{service['port']}:{service.get('protocol', 'tcp')}",
                },
            ):
                added += 1
    return added
