"""Safe subprocess execution for external scanner binaries."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
import shutil
import signal
import subprocess
import threading
import time
from typing import Sequence


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class CommandResult:
    status: str
    exit_code: int | None
    stdout: str
    stderr: str
    started_at: str
    completed_at: str
    command: str


def command_available(name: str) -> bool:
    return shutil.which(name) is not None


def display_command(args: Sequence[str]) -> str:
    return " ".join(repr(str(arg)) for arg in args)


def run_command(
    args: Sequence[str],
    timeout: int,
    cancel_event: threading.Event | None = None,
) -> CommandResult:
    started_at = now()
    command = display_command(args)
    process: subprocess.Popen[str] | None = None
    try:
        process = subprocess.Popen(
            [str(arg) for arg in args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=(os.name == "posix"),
        )
        deadline = time.monotonic() + timeout
        while True:
            if cancel_event and cancel_event.is_set():
                _terminate(process)
                stdout, stderr = process.communicate()
                return CommandResult("cancelled", process.returncode, stdout, stderr, started_at, now(), command)
            if time.monotonic() >= deadline:
                _terminate(process)
                stdout, stderr = process.communicate()
                return CommandResult("timeout", process.returncode, stdout, stderr, started_at, now(), command)
            try:
                stdout, stderr = process.communicate(timeout=0.25)
                status = "completed" if process.returncode == 0 else "failed"
                return CommandResult(status, process.returncode, stdout, stderr, started_at, now(), command)
            except subprocess.TimeoutExpired:
                continue
    except FileNotFoundError as exc:
        return CommandResult("unavailable", None, "", str(exc), started_at, now(), command)
    except Exception as exc:  # pragma: no cover - defensive boundary around OS processes
        if process:
            _terminate(process)
        return CommandResult("failed", None, "", str(exc), started_at, now(), command)


def _terminate(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=3)
    except Exception:
        try:
            process.kill()
        except OSError:
            pass
