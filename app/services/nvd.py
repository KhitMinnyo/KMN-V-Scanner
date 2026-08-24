"""Optional NVD CVE search client.

The API key improves NVD rate limits but is deliberately optional. Search is
not used as proof that a detected service is vulnerable; scanner evidence is
still required for a finding.
"""

from __future__ import annotations

from threading import Lock
import threading
import time
from typing import Any

import requests

from ..config import settings


BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_rate_lock = Lock()
_last_request = 0.0


class NvdError(RuntimeError):
    pass


def has_api_key() -> bool:
    return bool(settings.nvd_api_key)


def _get(
    params: dict[str, Any],
    cancel_event: threading.Event | None = None,
) -> dict[str, Any]:
    global _last_request
    with _rate_lock:
        interval = 0.7 if settings.nvd_api_key else 6.1
        wait = interval - (time.monotonic() - _last_request)
        while wait > 0:
            if cancel_event and cancel_event.is_set():
                raise NvdError("NVD request cancelled")
            delay = min(wait, 0.25)
            time.sleep(delay)
            wait -= delay
        headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
        try:
            response = requests.get(
                BASE_URL,
                params=params,
                headers=headers,
                timeout=30,
            )
            _last_request = time.monotonic()
        except requests.RequestException as exc:
            raise NvdError(f"NVD request failed: {exc}") from exc
    if response.status_code == 429:
        raise NvdError("NVD rate limit reached; wait and try again, or configure NVD_API_KEY")
    if response.status_code == 403:
        raise NvdError("NVD rejected the request; verify the API key or retry without it")
    try:
        response.raise_for_status()
        return response.json()
    except (requests.RequestException, ValueError) as exc:
        raise NvdError("NVD returned an invalid response") from exc


def search(query: str, limit: int = 20) -> dict[str, Any]:
    query = query.strip()
    if not query:
        raise NvdError("Search query is required")
    limit = max(1, min(limit, 50))
    payload = _get({"keywordSearch": query, "resultsPerPage": limit})
    return {
        "total_results": payload.get("totalResults", 0),
        "results": [normalize(item.get("cve", {})) for item in payload.get("vulnerabilities", [])],
        "authenticated": bool(settings.nvd_api_key),
    }


def lookup_cpe(
    cpe: str,
    limit: int = 50,
    cancel_event: threading.Event | None = None,
) -> list[dict[str, Any]]:
    """Return CVE records matching an exact CPE name."""
    cpe = cpe.strip()
    if not cpe:
        return []
    payload = _get(
        {"cpeName": cpe, "resultsPerPage": max(1, min(limit, 50))},
        cancel_event=cancel_event,
    )
    return [normalize(item.get("cve", {})) for item in payload.get("vulnerabilities", [])]


def normalize(cve: dict[str, Any]) -> dict[str, Any]:
    descriptions = cve.get("descriptions") or []
    description = next((item.get("value", "") for item in descriptions if item.get("lang") == "en"), "")
    metrics = cve.get("metrics") or {}
    metric = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or metrics.get("cvssMetricV2") or [{}])[0]
    cvss = metric.get("cvssData") or {}
    references = [item.get("url") for item in cve.get("references", []) if item.get("url")]
    return {
        "id": cve.get("id"),
        "description": description,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "cvss_score": cvss.get("baseScore"),
        "cvss_vector": cvss.get("vectorString"),
        "references": references[:5],
    }
