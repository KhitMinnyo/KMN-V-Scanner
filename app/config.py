"""Application configuration loaded from environment variables."""

from dataclasses import dataclass
import os
from pathlib import Path

from dotenv import load_dotenv

from version import __version__


ROOT_DIR = Path(__file__).resolve().parent.parent
load_dotenv(ROOT_DIR / ".env")


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name: str) -> tuple[str, ...]:
    return tuple(item.strip().lower().rstrip(".") for item in os.getenv(name, "").split(",") if item.strip())


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("APP_NAME", "KMN Vulnerability Scanner")
    version: str = os.getenv("APP_VERSION", __version__)
    host: str = os.getenv("HOST", "127.0.0.1")
    port: int = int(os.getenv("PORT", "2025"))
    database_url: str = os.getenv("DATABASE_URL", str(ROOT_DIR / "data" / "scanner.db"))
    max_workers: int = int(os.getenv("MAX_SCAN_WORKERS", "2"))
    command_timeout: int = int(os.getenv("SCAN_COMMAND_TIMEOUT", "900"))
    allow_external_targets: bool = _env_bool("ALLOW_EXTERNAL_TARGETS", False)
    max_target_ports: int = int(os.getenv("MAX_TARGET_PORTS", "65535"))
    nvd_api_key: str = os.getenv("NVD_API_KEY", "").strip()
    authorized_targets: tuple[str, ...] = _env_list("AUTHORIZED_TARGETS")
    dashboard_password: str = os.getenv("DASHBOARD_PASSWORD", "").strip()


settings = Settings()
