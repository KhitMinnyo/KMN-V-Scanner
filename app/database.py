"""Small SQLite persistence layer used by the API and scan workers."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any, Iterator

from .config import settings


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _database_path() -> Path:
    path = Path(settings.database_url)
    if path.is_absolute():
        return path
    return Path.cwd() / path


@contextmanager
def connection() -> Iterator[sqlite3.Connection]:
    path = _database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scan_jobs (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                normalized_target TEXT NOT NULL,
                profile TEXT NOT NULL,
                status TEXT NOT NULL,
                progress INTEGER NOT NULL DEFAULT 0,
                stage TEXT NOT NULL DEFAULT 'queued',
                message TEXT,
                error TEXT,
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT
            );

            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                state TEXT NOT NULL,
                service TEXT,
                product TEXT,
                version TEXT,
                url TEXT,
                raw_json TEXT,
                UNIQUE(scan_id, host, port, protocol)
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
                host TEXT NOT NULL,
                port INTEGER,
                protocol TEXT,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL DEFAULT 'medium',
                cve_id TEXT,
                cwe_id TEXT,
                description TEXT,
                evidence TEXT,
                remediation TEXT,
                source_tool TEXT NOT NULL,
                rule_id TEXT,
                reference_url TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                fingerprint TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(scan_id, fingerprint)
            );

            CREATE TABLE IF NOT EXISTS tool_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
                tool TEXT NOT NULL,
                status TEXT NOT NULL,
                command TEXT,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                exit_code INTEGER,
                stdout TEXT,
                stderr TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_jobs_created ON scan_jobs(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            """
        )


def create_job(job_id: str, target: str, normalized_target: str, profile: str) -> None:
    with connection() as conn:
        conn.execute(
            """
            INSERT INTO scan_jobs
                (id, target, normalized_target, profile, status, stage, created_at)
            VALUES (?, ?, ?, ?, 'queued', 'queued', ?)
            """,
            (job_id, target, normalized_target, profile, utc_now()),
        )


def update_job(job_id: str, **values: Any) -> None:
    allowed = {
        "status",
        "progress",
        "stage",
        "message",
        "error",
        "started_at",
        "completed_at",
    }
    values = {key: value for key, value in values.items() if key in allowed}
    if not values:
        return
    assignments = ", ".join(f"{key} = ?" for key in values)
    with connection() as conn:
        conn.execute(
            f"UPDATE scan_jobs SET {assignments} WHERE id = ?",
            (*values.values(), job_id),
        )


def get_job(job_id: str) -> dict[str, Any] | None:
    with connection() as conn:
        row = conn.execute("SELECT * FROM scan_jobs WHERE id = ?", (job_id,)).fetchone()
    return dict(row) if row else None


def list_jobs(limit: int = 50) -> list[dict[str, Any]]:
    with connection() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_jobs ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(row) for row in rows]


def add_service(scan_id: str, service: dict[str, Any]) -> None:
    with connection() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO services
                (scan_id, host, port, protocol, state, service, product, version, url, raw_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                service["host"],
                service["port"],
                service["protocol"],
                service.get("state", "open"),
                service.get("service", ""),
                service.get("product", ""),
                service.get("version", ""),
                service.get("url"),
                json.dumps(service.get("raw", {}), ensure_ascii=True),
            ),
        )


def add_finding(scan_id: str, finding: dict[str, Any]) -> bool:
    with connection() as conn:
        cursor = conn.execute(
            """
            INSERT OR IGNORE INTO findings
                (scan_id, host, port, protocol, title, severity, confidence,
                 cve_id, cwe_id, description, evidence, remediation, source_tool,
                 rule_id, reference_url, fingerprint, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                finding["host"],
                finding.get("port"),
                finding.get("protocol"),
                finding["title"],
                finding.get("severity", "info"),
                finding.get("confidence", "medium"),
                finding.get("cve_id"),
                finding.get("cwe_id"),
                finding.get("description", ""),
                finding.get("evidence", ""),
                finding.get("remediation", "Review the finding and apply the vendor-recommended fix."),
                finding["source_tool"],
                finding.get("rule_id"),
                finding.get("reference_url"),
                finding["fingerprint"],
                utc_now(),
            ),
        )
    return cursor.rowcount > 0


def add_tool_run(scan_id: str, run: dict[str, Any]) -> None:
    with connection() as conn:
        conn.execute(
            """
            INSERT INTO tool_runs
                (scan_id, tool, status, command, started_at, completed_at, exit_code, stdout, stderr)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                run["tool"],
                run["status"],
                run.get("command", ""),
                run.get("started_at", utc_now()),
                run.get("completed_at", utc_now()),
                run.get("exit_code"),
                run.get("stdout", "")[-200_000:],
                run.get("stderr", "")[-50_000:],
            ),
        )


def get_scan_details(scan_id: str) -> dict[str, Any] | None:
    with connection() as conn:
        job = conn.execute("SELECT * FROM scan_jobs WHERE id = ?", (scan_id,)).fetchone()
        if not job:
            return None
        services = conn.execute(
            "SELECT * FROM services WHERE scan_id = ? ORDER BY port", (scan_id,)
        ).fetchall()
        findings = conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY CASE severity "
            "WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 "
            "WHEN 'low' THEN 4 ELSE 5 END, id",
            (scan_id,),
        ).fetchall()
        tool_runs = conn.execute(
            "SELECT id, tool, status, command, started_at, completed_at, exit_code "
            "FROM tool_runs WHERE scan_id = ? ORDER BY id",
            (scan_id,),
        ).fetchall()
    result = dict(job)
    result["services"] = [dict(row) for row in services]
    result["findings"] = [dict(row) for row in findings]
    result["tool_runs"] = [dict(row) for row in tool_runs]
    return result


def dashboard_summary() -> dict[str, Any]:
    with connection() as conn:
        jobs = conn.execute("SELECT COUNT(*) FROM scan_jobs").fetchone()[0]
        running = conn.execute(
            "SELECT COUNT(*) FROM scan_jobs WHERE status IN ('queued', 'running')"
        ).fetchone()[0]
        services = conn.execute("SELECT COUNT(*) FROM services").fetchone()[0]
        findings = conn.execute(
            "SELECT severity, COUNT(*) AS count FROM findings WHERE status = 'open' GROUP BY severity"
        ).fetchall()
    return {
        "scans": jobs,
        "active_scans": running,
        "services": services,
        "findings": {row["severity"]: row["count"] for row in findings},
    }


def list_findings(limit: int = 100) -> list[dict[str, Any]]:
    with connection() as conn:
        rows = conn.execute(
            "SELECT * FROM findings ORDER BY CASE severity "
            "WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 "
            "WHEN 'low' THEN 4 ELSE 5 END, created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]
