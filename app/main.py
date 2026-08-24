"""FastAPI entrypoint for KMN Vulnerability Scanner v3."""

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from . import database
from .config import ROOT_DIR, settings
from .schemas import ScanRequest
from .scanners.runner import command_available
from .services.jobs import job_manager
from .services.nvd import NvdError, search as search_nvd


app = FastAPI(title=settings.app_name, version=settings.version)
app.mount("/static", StaticFiles(directory=ROOT_DIR / "static"), name="static")
database.init_db()


@app.on_event("startup")
def startup() -> None:
    database.init_db()


@app.get("/", response_class=HTMLResponse)
def index() -> FileResponse:
    return FileResponse(ROOT_DIR / "templates" / "index.html")


@app.get("/logo.png")
def logo() -> FileResponse:
    return FileResponse(ROOT_DIR / "logo.png", media_type="image/png")


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "version": settings.version}


@app.get("/api/tools")
def tools() -> dict:
    return {
        "nmap": command_available("nmap"),
        "nuclei": command_available("nuclei"),
        "testssl.sh": command_available("testssl.sh") or command_available("testssl"),
        "owasp-zap": command_available("zap-baseline.py") or command_available("zap-baseline"),
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


@app.get("/api/scans")
def scans() -> dict:
    return {"scans": database.list_jobs()}


@app.get("/api/scans/{scan_id}")
def scan_details(scan_id: str) -> dict:
    scan = database.get_scan_details(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


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
