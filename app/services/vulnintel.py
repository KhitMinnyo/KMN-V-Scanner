"""Bridge from the scanner to the bundled source-aware vulnerability DB."""

from __future__ import annotations

from pathlib import Path

from ..config import ROOT_DIR, settings


DEFAULT_DB_PATH = ROOT_DIR / "vulnerability-db" / "data" / "vulnerabilities.sqlite3"


def lookup_cpe(cpe: str) -> list[dict]:
    path = Path(settings.vulnerability_db_path or DEFAULT_DB_PATH).expanduser()
    if not path.is_file():
        return []
    try:
        from vulndb.db import VulnerabilityDB
        with VulnerabilityDB(path) as database:
            return database.match_cpe(cpe)
    except (ImportError, OSError, ValueError):
        return []
