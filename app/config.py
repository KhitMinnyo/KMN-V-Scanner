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
    version: str = __version__
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
    auto_update_nuclei_templates: bool = _env_bool("AUTO_UPDATE_NUCLEI_TEMPLATES", True)
    trivy_scan_root: str = os.getenv("TRIVY_SCAN_ROOT", str(ROOT_DIR))
    ssh_audit_user: str = os.getenv("SSH_AUDIT_USER", "").strip()
    ssh_audit_key_path: str = os.getenv("SSH_AUDIT_KEY_PATH", "").strip()
    ssh_audit_known_hosts_path: str = os.getenv(
        "SSH_AUDIT_KNOWN_HOSTS_PATH",
        str(ROOT_DIR / "data" / "ssh_known_hosts"),
    ).strip()
    notification_webhook_url: str = os.getenv("NOTIFICATION_WEBHOOK_URL", "").strip()
    allow_insecure_webhook: bool = _env_bool("ALLOW_INSECURE_WEBHOOK", False)
    smtp_host: str = os.getenv("SMTP_HOST", "").strip()
    smtp_port: int = int(os.getenv("SMTP_PORT", "587"))
    smtp_user: str = os.getenv("SMTP_USER", "").strip()
    smtp_password: str = os.getenv("SMTP_PASSWORD", "")
    smtp_from: str = os.getenv("SMTP_FROM", "").strip()
    smtp_to: str = os.getenv("SMTP_TO", "").strip()
    smtp_starttls: bool = _env_bool("SMTP_STARTTLS", True)
    windows_audit_user: str = os.getenv("WINDOWS_AUDIT_USER", "").strip()
    windows_audit_password: str = os.getenv("WINDOWS_AUDIT_PASSWORD", "")
    windows_audit_transport: str = os.getenv("WINDOWS_AUDIT_TRANSPORT", "ntlm").strip().lower()
    windows_audit_server_cert_validation: str = os.getenv(
        "WINDOWS_AUDIT_SERVER_CERT_VALIDATION", "validate"
    ).strip().lower()
    cloud_allowed_providers: tuple[str, ...] = _env_list("CLOUD_ALLOWED_PROVIDERS")


settings = Settings()
