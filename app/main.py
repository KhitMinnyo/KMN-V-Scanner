"""FastAPI entrypoint for KMN Vulnerability Scanner v3."""

from __future__ import annotations

import csv
import hashlib
import html
import hmac
import io
import secrets
import threading
import time
from pathlib import Path

from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import database
from .config import ROOT_DIR, settings
from .schemas import ArtifactScanRequest, CloudScanRequest, LoginRequest, ScanRequest, ScheduleRequest, ScheduleStateRequest, WindowsScanRequest
from .scanners.runner import command_available, run_command
from .services.jobs import job_manager
from .services.nvd import NvdError, search as search_nvd
from .services.scheduler import schedule_manager


app = FastAPI(title=settings.app_name, version=settings.version)
app.mount("/static", StaticFiles(directory=ROOT_DIR / "static"), name="static")
database.init_db()

PUBLIC_API_PATHS = {"/api/health", "/api/login"}
SESSION_TTL_SECONDS = 60 * 60 * 12


def _create_session_token() -> str:
    timestamp = str(int(time.time()))
    signature = hmac.new(
        settings.dashboard_password.encode(),
        timestamp.encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"{timestamp}.{signature}"


def _valid_session_token(token: str | None) -> bool:
    if not token or "." not in token:
        return False
    timestamp, signature = token.split(".", 1)
    try:
        age = int(time.time()) - int(timestamp)
    except ValueError:
        return False
    if age < 0 or age > SESSION_TTL_SECONDS:
        return False
    expected = hmac.new(
        settings.dashboard_password.encode(),
        timestamp.encode(),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(signature, expected)


@app.middleware("http")
async def auth_middleware(request, call_next):
    if settings.dashboard_password and request.url.path.startswith("/api"):
        if request.url.path not in PUBLIC_API_PATHS:
            token = request.cookies.get("kmn_session")
            if not _valid_session_token(token):
                return JSONResponse(status_code=401, content={"detail": "Login required"})
    return await call_next(request)


@app.on_event("startup")
def startup() -> None:
    database.init_db()
    schedule_manager.start()
    if settings.auto_update_nuclei_templates and command_available("nuclei"):
        threading.Thread(target=_update_nuclei_templates, daemon=True).start()


@app.on_event("shutdown")
def shutdown() -> None:
    schedule_manager.stop()


def _update_nuclei_templates() -> None:
    result = run_command(["nuclei", "-update-templates", "-silent"], timeout=600)
    if result.status not in {"completed", "unavailable"}:
        print(f"Nuclei template update failed: {result.stderr}")


@app.get("/", response_class=HTMLResponse)
def index() -> FileResponse:
    return FileResponse(ROOT_DIR / "templates" / "index.html")


@app.get("/logo.png")
def logo() -> FileResponse:
    return FileResponse(ROOT_DIR / "logo.png", media_type="image/png")


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "version": settings.version, "auth_required": bool(settings.dashboard_password)}


@app.post("/api/login")
def login(body: LoginRequest, response: Response) -> dict:
    if not settings.dashboard_password:
        return {"status": "ok", "message": "No dashboard password configured"}
    if not secrets.compare_digest(body.password, settings.dashboard_password):
        raise HTTPException(status_code=401, detail="Invalid password")
    token = _create_session_token()
    response.set_cookie(
        "kmn_session",
        token,
        httponly=True,
        samesite="strict",
        max_age=SESSION_TTL_SECONDS,
    )
    return {"status": "ok"}


@app.post("/api/logout")
def logout(response: Response) -> dict:
    response.delete_cookie("kmn_session")
    return {"status": "ok"}


@app.get("/api/tools")
def tools() -> dict:
    return {
        "nmap": command_available("nmap"),
        "nuclei": command_available("nuclei"),
        "testssl.sh": command_available("testssl.sh") or command_available("testssl"),
        "owasp-zap": command_available("zap-baseline.py") or command_available("zap-baseline"),
        "trivy": command_available("trivy"),
        "ssh": command_available("ssh"),
        "prowler": command_available("prowler"),
    }


@app.get("/api/dashboard")
def dashboard() -> dict:
    return {"version": settings.version, **database.dashboard_summary()}


@app.post("/api/scans", status_code=202)
def create_scan(request: ScanRequest) -> dict:
    try:
        job_id = job_manager.start(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"id": job_id, "status": "queued"}


@app.post("/api/artifacts/scans", status_code=202)
def create_artifact_scan(request: ArtifactScanRequest) -> dict:
    try:
        job_id = job_manager.start_artifact(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"id": job_id, "status": "queued"}


@app.post("/api/windows/scans", status_code=202)
def create_windows_scan(request: WindowsScanRequest) -> dict:
    try:
        job_id = job_manager.start_windows(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"id": job_id, "status": "queued"}


@app.post("/api/cloud/scans", status_code=202)
def create_cloud_scan(request: CloudScanRequest) -> dict:
    try:
        job_id = job_manager.start_cloud(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"id": job_id, "status": "queued"}


@app.post("/api/schedules", status_code=201)
def create_schedule(request: ScheduleRequest) -> dict:
    try:
        schedule_id = schedule_manager.create(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"id": schedule_id, "status": "scheduled"}


@app.get("/api/schedules")
def schedules() -> dict:
    return {"schedules": database.list_schedules()}


@app.delete("/api/schedules/{schedule_id}")
def remove_schedule(schedule_id: str) -> dict:
    if not database.delete_schedule(schedule_id):
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"status": "deleted"}


@app.patch("/api/schedules/{schedule_id}")
def update_schedule_state(schedule_id: str, request: ScheduleStateRequest) -> dict:
    if not database.set_schedule_enabled(schedule_id, request.enabled):
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"status": "updated", "enabled": request.enabled}


@app.get("/api/scans")
def scans() -> dict:
    return {"scans": database.list_jobs()}


@app.get("/api/scans/{scan_id}")
def scan_details(scan_id: str) -> dict:
    scan = database.get_scan_details(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.get("/api/scans/{scan_id}/diff")
def scan_diff(scan_id: str) -> dict:
    scan = database.get_job(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan["status"] != "completed":
        raise HTTPException(status_code=409, detail="Only completed scans can be compared")
    previous = database.get_previous_scan(scan_id)
    if not previous:
        return {"previous": None, "comparable": False, "reason": "No previous equivalent completed scan", "new": [], "fixed": [], "persistent_count": 0}
    current_tools = database.get_tool_statuses(scan_id)
    previous_tools = database.get_tool_statuses(previous["id"])
    previous_completed = {tool for tool, states in previous_tools.items() if "completed" in states}
    current_completed = {tool for tool, states in current_tools.items() if "completed" in states}
    missing_coverage = sorted(previous_completed - current_completed)
    if missing_coverage:
        return {
            "previous": {"id": previous["id"], "created_at": previous["created_at"], "status": previous["status"]},
            "comparable": False,
            "reason": f"Current scan is missing successful tool coverage: {', '.join(missing_coverage)}",
            "new": [],
            "fixed": [],
            "persistent_count": 0,
        }
    current_findings = database.get_finding_fingerprints(scan_id)
    previous_findings = database.get_finding_fingerprints(previous["id"])
    new_findings = [item for key, item in current_findings.items() if key not in previous_findings]
    fixed_findings = [item for key, item in previous_findings.items() if key not in current_findings]
    persistent = [key for key in current_findings if key in previous_findings]
    return {
        "previous": {
            "id": previous["id"],
            "created_at": previous["created_at"],
            "status": previous["status"],
        },
        "comparable": True,
        "new": new_findings,
        "fixed": fixed_findings,
        "persistent_count": len(persistent),
    }


@app.post("/api/scans/{scan_id}/cancel")
def cancel_scan(scan_id: str) -> dict:
    scan = database.get_job(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan["status"] not in {"queued", "running"}:
        return {"status": scan["status"]}
    job_manager.cancel(scan_id)
    return {"status": "cancelling"}


@app.get("/api/findings")
def findings() -> dict:
    return {"findings": database.list_findings()}


@app.get("/api/cves/search")
def cve_search(q: str, limit: int = 20) -> dict:
    try:
        return search_nvd(q, limit)
    except NvdError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/api/scans/{scan_id}/export.csv")
def export_scan_csv(scan_id: str) -> Response:
    scan = database.get_scan_details(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([
        "severity", "title", "host", "port", "protocol", "source_tool",
        "rule_id", "cve_id", "confidence", "description", "evidence", "remediation",
    ])
    for finding in scan["findings"]:
        writer.writerow([
            finding.get("severity", ""),
            finding.get("title", ""),
            finding.get("host", ""),
            finding.get("port") or "",
            finding.get("protocol") or "",
            finding.get("source_tool", ""),
            finding.get("rule_id") or "",
            finding.get("cve_id") or "",
            finding.get("confidence", ""),
            finding.get("description") or "",
            finding.get("evidence") or "",
            finding.get("remediation") or "",
        ])
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="kmn-scan-{scan_id[:8]}.csv"'},
    )


@app.get("/api/scans/{scan_id}/report", response_class=HTMLResponse)
def scan_report(scan_id: str) -> HTMLResponse:
    scan = database.get_scan_details(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    esc = html.escape
    service_rows = "".join(
        f"<tr><td>{esc(str(s['port']))}/{esc(s['protocol'])}</td>"
        f"<td>{esc(s['service'] or 'unknown')}</td>"
        f"<td>{esc(s['product'] or '')} {esc(s['version'] or '')}</td></tr>"
        for s in scan["services"]
    ) or '<tr><td colspan="3">No open services</td></tr>'
    finding_blocks = "".join(
        f"<div class='finding sev-{esc(f['severity'])}'>"
        f"<h3>{esc(f['severity'].upper())} · {esc(f['title'])}</h3>"
        f"<p class='meta'>{esc(f['source_tool'])} · {esc(f['host'])}"
        f"{':' + esc(str(f['port'])) if f.get('port') else ''} · confidence {esc(f['confidence'])}</p>"
        f"<pre>{esc(f['evidence'] or f['description'] or 'No evidence')}</pre></div>"
        for f in scan["findings"]
    ) or "<p>No findings reported.</p>"
    body = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>KMN Scan Report {esc(scan['target'])}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 40px auto; max-width: 900px; color: #17231f; }}
h1 {{ letter-spacing: -.03em; }} table {{ border-collapse: collapse; width: 100%; }}
td, th {{ border-bottom: 1px solid #dfe7e1; padding: 8px 6px; font-size: 14px; text-align: left; }}
.finding {{ border-left: 4px solid #b7c1bb; margin: 14px 0; padding: 10px 14px; background: #f8faf7; }}
.sev-critical {{ border-left-color: #d94a42; }} .sev-high {{ border-left-color: #df7c3b; }}
.sev-medium {{ border-left-color: #b18a24; }} .sev-low {{ border-left-color: #4d8e80; }}
.finding h3 {{ margin: 0 0 4px; font-size: 15px; }} .meta {{ color: #6f7c77; font-size: 12px; margin: 0 0 8px; }}
pre {{ background: #fff; padding: 8px; font-size: 12px; white-space: pre-wrap; }}
.muted {{ color: #6f7c77; font-size: 13px; }}
</style></head><body>
<h1>KMN Scan Report</h1>
<p class="muted">Target: <strong>{esc(scan['target'])}</strong> · Profile: {esc(scan['profile'])} ·
Status: {esc(scan['status'])} · Created: {esc(scan['created_at'])} · Version: {esc(settings.version)}</p>
<h2>Services ({len(scan['services'])})</h2>
<table><tr><th>Port</th><th>Service</th><th>Version</th></tr>{service_rows}</table>
<h2>Findings ({len(scan['findings'])})</h2>
{finding_blocks}
</body></html>"""
    return HTMLResponse(content=body)
