"""Read-only Linux host audit over SSH using a configured key."""

from __future__ import annotations

from pathlib import Path
import re
import threading

from ..config import settings
from .runner import CommandResult, command_available, display_command, now, run_command


USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}$")
REMOTE_COMMAND = (
    "printf '__KMN_OS__\\n'; cat /etc/os-release 2>/dev/null; "
    "printf '__KMN_SSH__\\n'; "
    "EFFECTIVE=$(sshd -T 2>/dev/null); "
    "if [ -n \"$EFFECTIVE\" ]; then printf '__KMN_SSH_MODE_EFFECTIVE__\\n'; printf '%s\\n' \"$EFFECTIVE\" | "
    "grep -Eis '^(permitrootlogin|passwordauthentication|permitemptypasswords|protocol)[[:space:]]+'; "
    "else printf '__KMN_SSH_MODE_RAW__\\n'; grep -Eis '^[[:space:]]*(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|Protocol)[[:space:]]+' "
    "/etc/ssh/sshd_config 2>/dev/null; fi; "
    "printf '__KMN_UPDATES__\\n'; "
    "if command -v apt >/dev/null 2>&1; then apt list --upgradable 2>/dev/null; fi"
)


def scan(host: str, port: int, timeout: int, cancel_event: threading.Event) -> tuple[CommandResult, list[dict]]:
    if not command_available("ssh"):
        return _unavailable("ssh is not installed"), []
    user = settings.ssh_audit_user
    key_path = Path(settings.ssh_audit_key_path).expanduser() if settings.ssh_audit_key_path else None
    if not user or not USER_RE.fullmatch(user):
        return _unavailable("SSH_AUDIT_USER is not configured or invalid"), []
    if not key_path or not key_path.is_file():
        return _unavailable("SSH_AUDIT_KEY_PATH does not point to a readable private key"), []
    if key_path.stat().st_mode & 0o077:
        return _unavailable("SSH audit private key permissions are too open; run chmod 600 on the key"), []
    known_hosts = Path(settings.ssh_audit_known_hosts_path).expanduser()
    known_hosts.parent.mkdir(parents=True, exist_ok=True)
    known_hosts.touch(mode=0o600, exist_ok=True)
    known_hosts.chmod(0o600)
    args = [
        "ssh",
        "-i",
        str(key_path),
        "-p",
        str(port),
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ConnectionAttempts=1",
        f"{user}@{host}",
        REMOTE_COMMAND,
    ]
    result = run_command(args, timeout, cancel_event)
    if result.status != "completed":
        return result, []
    return result, parse_output(host, port, result.stdout)


def parse_output(host: str, port: int, output: str) -> list[dict]:
    ssh_text = _section(output, "__KMN_SSH__", "__KMN_UPDATES__")
    effective_config = "__KMN_SSH_MODE_EFFECTIVE__" in ssh_text
    ssh_text = ssh_text.replace("__KMN_SSH_MODE_EFFECTIVE__", "").replace("__KMN_SSH_MODE_RAW__", "")
    updates_text = output.split("__KMN_UPDATES__", 1)[1] if "__KMN_UPDATES__" in output else ""
    findings: list[dict] = []
    checks = {
        "permitrootlogin yes": (
            "SSH root login is enabled",
            "high",
            "Set PermitRootLogin no and use a named administrative account.",
        ),
        "passwordauthentication yes": (
            "SSH password authentication is enabled",
            "medium",
            "Use key-based authentication and set PasswordAuthentication no where operationally possible.",
        ),
        "permitemptypasswords yes": (
            "SSH permits empty passwords",
            "critical",
            "Set PermitEmptyPasswords no immediately.",
        ),
        "protocol 1": (
            "Obsolete SSH protocol 1 is configured",
            "critical",
            "Remove Protocol 1 and permit SSH protocol 2 only.",
        ),
    }
    normalized_lines = [" ".join(line.lower().split()) for line in ssh_text.splitlines()]
    for marker, (title, severity, remediation) in checks.items():
        if marker in normalized_lines:
            findings.append(
                _finding(
                    host,
                    port,
                    title,
                    severity,
                    ssh_text,
                    remediation,
                    marker,
                    "high" if effective_config else "low",
                )
            )
    updates = [line for line in updates_text.splitlines() if line.strip() and not line.lower().startswith("listing")]
    if updates:
        findings.append(
            _finding(
                host,
                port,
                f"{len(updates)} operating system packages have updates available",
                "low",
                "\n".join(updates[:100]),
                "Review and apply security updates using the host's approved patch process.",
                "pending-updates",
                "high",
            )
        )
    return findings


def _section(output: str, start: str, end: str) -> str:
    if start not in output:
        return ""
    value = output.split(start, 1)[1]
    return value.split(end, 1)[0] if end in value else value


def _finding(
    host: str,
    port: int,
    title: str,
    severity: str,
    evidence: str,
    remediation: str,
    rule_id: str,
    confidence: str,
) -> dict:
    return {
        "host": host,
        "port": port,
        "protocol": "tcp",
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "description": "Read-only authenticated SSH audit finding.",
        "evidence": evidence[:8000],
        "remediation": remediation,
        "source_tool": "ssh-audit",
        "rule_id": rule_id,
        "fingerprint": f"ssh-audit:{rule_id}:{host}:{port}",
    }


def _unavailable(message: str) -> CommandResult:
    timestamp = now()
    return CommandResult("unavailable", None, "", message, timestamp, timestamp, display_command(["ssh"]))
