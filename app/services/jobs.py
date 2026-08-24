"""Persistent scan job orchestration."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import threading
import uuid

from .. import database
from ..config import settings
from ..scanners import nmap, nse, nuclei, ssh_audit, target, tls, trivy, zap
from ..scanners.runner import command_available
from . import cve_match
from . import notifier


class JobManager:
    def __init__(self) -> None:
        self.executor = ThreadPoolExecutor(max_workers=settings.max_workers, thread_name_prefix="kmn-scan")
        self.cancel_events: dict[str, threading.Event] = {}
        self.lock = threading.Lock()

    def start(self, request) -> str:
        normalized = target.normalize_target(request.target, request.authorization_confirmed)
        job_id = str(uuid.uuid4())
        options = request.model_dump(exclude={"target", "profile", "authorization_confirmed"})
        database.create_job(job_id, request.target, normalized, request.profile, options)
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

    def start_artifact(self, request) -> str:
        if not request.authorization_confirmed:
            raise ValueError("Confirm that you own or are authorized to scan this artifact")
        normalized = trivy.validate_target(request.mode, request.target)
        job_id = str(uuid.uuid4())
        database.create_job(job_id, request.target, normalized, f"trivy-{request.mode}", {"mode": request.mode})
        cancel_event = threading.Event()
        with self.lock:
            self.cancel_events[job_id] = cancel_event
        self.executor.submit(self._run_artifact, job_id, request.mode, normalized, cancel_event)
        return job_id

    def _run_artifact(self, job_id: str, mode: str, target_value: str, cancel_event: threading.Event) -> None:
        try:
            database.update_job(
                job_id,
                status="running",
                stage="trivy",
                progress=10,
                message=f"Scanning {mode} target with Trivy",
                started_at=database.utc_now(),
            )
            result, findings = trivy.scan(mode, target_value, settings.command_timeout, cancel_event)
            database.add_tool_run(job_id, self._tool_run("trivy", result))
            if result.status == "cancelled":
                self._cancelled(job_id)
                return
            if result.status == "unavailable":
                raise RuntimeError("trivy is not installed; install it before artifact scanning")
            if result.status != "completed":
                raise RuntimeError(result.stderr or "Trivy scan failed")
            for finding in findings:
                database.add_finding(job_id, finding)
            database.update_job(
                job_id,
                status="completed",
                stage="complete",
                progress=100,
                message=f"Trivy scan completed with {len(findings)} findings",
                completed_at=database.utc_now(),
            )
        except Exception as exc:
            database.update_job(
                job_id,
                status="failed",
                stage="error",
                message="Artifact scan failed",
                error=str(exc),
                completed_at=database.utc_now(),
            )
        finally:
            try:
                notifier.notify_scan(job_id)
            except Exception as exc:
                print(f"Artifact scan notification failed: {exc}")
            with self.lock:
                self.cancel_events.pop(job_id, None)

    def _run(self, job_id: str, normalized: str, request, cancel_event: threading.Event) -> None:
        try:
            database.update_job(
                job_id,
                status="running",
                stage="discovery",
                progress=5,
                message="Starting discovery",
                started_at=database.utc_now(),
            )
            scan_target = normalized
            if "/" in normalized:
                database.update_job(job_id, message="Discovering live hosts")
                disc_result, live_hosts = nmap.discover_hosts(normalized, settings.command_timeout, cancel_event)
                database.add_tool_run(job_id, self._tool_run("nmap-discovery", disc_result))
                if disc_result.status == "cancelled":
                    self._cancelled(job_id)
                    return
                if disc_result.status == "unavailable":
                    raise RuntimeError("nmap is not installed. Install it with: sudo apt install nmap")
                if disc_result.status != "completed":
                    raise RuntimeError(disc_result.stderr or "Host discovery failed")
                if not live_hosts:
                    database.update_job(
                        job_id,
                        status="completed",
                        stage="complete",
                        progress=100,
                        message="No live hosts found in the target range",
                        completed_at=database.utc_now(),
                    )
                    return
                scan_target = " ".join(live_hosts)
                database.update_job(job_id, progress=15, message=f"Found {len(live_hosts)} live hosts")

            result, services = nmap.scan(scan_target, request.profile, settings.command_timeout, cancel_event)
            database.add_tool_run(job_id, self._tool_run("nmap", result))
            if result.status == "cancelled":
                self._cancelled(job_id)
                return
            if result.status == "unavailable":
                raise RuntimeError("nmap is not installed. Install it with: sudo apt install nmap")
            if result.status != "completed":
                raise RuntimeError(result.stderr or "Nmap scan failed")
            for service in services:
                database.add_service(job_id, service)

            if request.include_udp:
                database.update_job(job_id, stage="udp", progress=25, message="Scanning top UDP ports")
                udp_result, udp_services = nmap.scan_udp(scan_target, settings.command_timeout, cancel_event)
                database.add_tool_run(job_id, self._tool_run("nmap-udp", udp_result))
                if udp_result.status == "cancelled":
                    self._cancelled(job_id)
                    return
                if udp_result.status == "completed":
                    for service in udp_services:
                        database.add_service(job_id, service)
                    services.extend(udp_services)
                else:
                    database.update_job(
                        job_id,
                        message="UDP scan skipped or failed; run the scanner with appropriate privileges",
                    )

            if request.include_cve_match and services:
                database.update_job(job_id, stage="cve-match", progress=30, message="Matching service CPEs against NVD")
                matched = cve_match.match_services(job_id, services, cancel_event)
                if matched:
                    database.update_job(job_id, message=f"Added {matched} version-based CVE candidates")

            if request.include_nse and services:
                database.update_job(job_id, stage="nse", progress=35, message="Running Nmap NSE vulnerability scripts")
                tcp_ports = sorted({service["port"] for service in services if service.get("protocol") == "tcp"})
                if not tcp_ports:
                    nse_findings = []
                    nse_result = None
                else:
                    ports = ",".join(str(port) for port in tcp_ports)
                    nse_result, nse_findings = nse.scan(scan_target, ports, settings.command_timeout, cancel_event)
                if nse_result is None:
                    database.update_job(job_id, message="No TCP services available for NSE checks")
                else:
                    database.add_tool_run(job_id, self._tool_run("nmap-nse", nse_result))
                    if nse_result.status == "cancelled":
                        self._cancelled(job_id)
                        return
                for finding in nse_findings:
                    database.add_finding(job_id, finding)

            if request.include_ssh_audit:
                ssh_services = {
                    (service["host"], service["port"])
                    for service in services
                    if service["port"] == 22 or service.get("service") == "ssh"
                }
                for host, port in sorted(ssh_services)[:20]:
                    database.update_job(job_id, stage="ssh-audit", progress=40, message=f"Running read-only SSH audit on {host}")
                    ssh_result, ssh_findings = ssh_audit.scan(host, port, settings.command_timeout, cancel_event)
                    database.add_tool_run(job_id, self._tool_run(f"ssh-audit:{host}", ssh_result))
                    if ssh_result.status == "cancelled":
                        self._cancelled(job_id)
                        return
                    for finding in ssh_findings:
                        database.add_finding(job_id, finding)

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
            try:
                notifier.notify_scan(job_id)
            except Exception as exc:
                print(f"Scan notification failed: {exc}")
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
