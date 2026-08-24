"""Recurring scan schedule manager."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import threading
import uuid

from .. import database
from ..schemas import ScanRequest
from ..scanners.target import normalize_target
from .jobs import job_manager


def _next_run(interval_minutes: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=interval_minutes)).isoformat()


def _lease_until() -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat()


class ScheduleManager:
    def __init__(self) -> None:
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None

    def create(self, request) -> str:
        normalize_target(request.target, request.authorization_confirmed)
        schedule_id = str(uuid.uuid4())
        options = request.model_dump(exclude={"target", "profile", "interval_minutes"})
        database.create_schedule(
            schedule_id,
            request.target,
            request.profile,
            options,
            request.interval_minutes,
            _next_run(request.interval_minutes),
        )
        return schedule_id

    def start(self) -> None:
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._loop, daemon=True, name="kmn-scheduler")
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
        self.thread = None

    def _loop(self) -> None:
        while not self.stop_event.wait(15):
            try:
                schedules = database.claim_due_schedules(database.utc_now(), _lease_until())
            except Exception as exc:
                print(f"Schedule polling failed: {exc}")
                continue
            for schedule in schedules:
                next_run = _next_run(schedule["interval_minutes"])
                try:
                    if schedule.get("last_scan_id"):
                        previous_job = database.get_job(schedule["last_scan_id"])
                        if previous_job and previous_job["status"] in {"queued", "running", "cancelling"}:
                            database.update_schedule_run(
                                schedule["id"],
                                next_run,
                                last_scan_id=previous_job["id"],
                                last_error="Previous scheduled scan is still active; overlapping run skipped",
                            )
                            continue
                    request = ScanRequest(
                        target=schedule["target"],
                        profile=schedule["profile"],
                        **schedule["options"],
                    )
                    scan_id = job_manager.start(request)
                    database.update_schedule_run(schedule["id"], next_run, last_scan_id=scan_id)
                except Exception as exc:
                    database.update_schedule_run(schedule["id"], next_run, last_error=str(exc))


schedule_manager = ScheduleManager()
