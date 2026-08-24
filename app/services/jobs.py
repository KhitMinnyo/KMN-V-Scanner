"""Persistent scan job orchestration."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import threading
import uuid

from .. import database
from ..config import settings
from ..scanners import nmap, nuclei, target, tls, zap
from ..scanners.runner import command_available


class JobManager:
    def __init__(self) -> None:
        self.executor = ThreadPoolExecutor(max_workers=settings.max_workers, thread_name_prefix="kmn-scan")
        self.cancel_events: dict[str, threading.Event] = {}
        self.lock = threading.Lock()

    def start(self, request) -> str:
        normalized = target.normalize_target(request.target)
        job_id = str(uuid.uuid4())
        database.create_job(job_id, request.target, normalized, request.profile)
        cancel_event = threading.Event()
        with self.lock:
            self.cancel_events[job_id] = cancel_event
        self.executor.submit(self._run, job_id, normalized, request, cancel_event)
        return job_id

    def cancel(self, job_id: str) -> bool:
        with self.lock:
            event = self.cancel_events.get(job_id)
        if not event:
            return False
        event.set()
        database.update_job(job_id, status="cancelling", message="Cancellation requested")
        return True

    def _run(self, job_id: str, normalized: str, request, cancel_event: threading.Event) -> None:
        try:
            database.update_job(
                job_id,
                status="running",
                stage="discovery",
                progress=5,
                message="Starting service discovery",
                started_at=database.utc_now(),
            )
            result, services = nmap.scan(normalized, request.profile, settings.command_timeout, cancel_event)
            database.add_tool_run(job_id, self._tool_run("nmap", result))
            if result.status == "cancelled":
                self._cancelled(job_id)
                return
            if result.status == "unavailable":
                raise RuntimeError("nmap is not installed. Install it on Kali or use the Docker image.")
            if result.status != "completed":
                raise RuntimeError(result.stderr or "Nmap scan failed")
            for service in services:
                database.add_service(job_id, service)

            database.update_job(job_id, stage="checks", progress=45, message=f"Found {len(services)} open services")
            web_services = [service for service in services if service.get("url")]
            total_checks = max(1, len(web_services))
            completed_checks = 0
            for service in web_services:
                if cancel_event.is_set():
                    self._cancelled(job_id)
                    return
                url = service["url"]
                if request.include_nuclei:
                    self._run_optional(job_id, "nuclei", lambda: nuclei.scan(url, settings.command_timeout, cancel_event), url)
                if request.include_tls and url.startswith("https://"):
                    self._run_optional(
                        job_id,
                        "testssl.sh",
                        lambda: tls.scan(service["host"], service["port"], settings.command_timeout, cancel_event),
                        url,
                    )
                if request.include_zap and request.profile == "deep":
                    self._run_optional(job_id, "owasp-zap", lambda: zap.scan(url, settings.command_timeout, cancel_event), url)
                completed_checks += 1
                progress = 45 + int((completed_checks / total_checks) * 50)
                database.update_job(job_id, progress=progress, message=f"Checked {completed_checks}/{total_checks} web services")
            if cancel_event.is_set():
                self._cancelled(job_id)
                return
            database.update_job(
                job_id,
                status="completed",
                stage="complete",
                progress=100,
                message=f"Scan completed with {len(services)} services",
                completed_at=database.utc_now(),
            )
        except Exception as exc:
            database.update_job(
                job_id,
                status="failed",
                stage="error",
                message="Scan failed",
                error=str(exc),
                completed_at=database.utc_now(),
            )
        finally:
            with self.lock:
                self.cancel_events.pop(job_id, None)

    def _run_optional(self, job_id: str, tool_name: str, callback, url: str) -> None:
        result, findings = callback()
        database.add_tool_run(job_id, self._tool_run(tool_name, result))
        if result.status == "unavailable":
            database.update_job(job_id, message=f"{tool_name} is unavailable; continuing with installed scanners")
            return
        for finding in findings:
            database.add_finding(job_id, finding)

    @staticmethod
    def _tool_run(tool_name, result):
        return {
            "tool": tool_name,
            "status": result.status,
            "command": result.command,
            "started_at": result.started_at,
            "completed_at": result.completed_at,
            "exit_code": result.exit_code,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    @staticmethod
    def _cancelled(job_id: str) -> None:
        database.update_job(job_id, status="cancelled", stage="cancelled", message="Scan cancelled", completed_at=database.utc_now())


job_manager = JobManager()
