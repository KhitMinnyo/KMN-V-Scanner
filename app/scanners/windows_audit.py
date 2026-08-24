"""Optional read-only Windows audit through WinRM."""

from __future__ import annotations

import json
import threading

from ..config import settings
from .runner import CommandResult, display_command, now


REMOTE_SCRIPT = r'''
$ErrorActionPreference = 'Stop'
$os = Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,LastBootUpTime
$hotfixes = @(Get-HotFix | Select-Object HotFixID,InstalledOn,Description)
$smb = Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol,EnableSecuritySignature,RequireSecuritySignature
$rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue | Select-Object fDenyTSConnections
[PSCustomObject]@{OS=$os; Hotfixes=$hotfixes; SMB=$smb; RDP=$rdp} | ConvertTo-Json -Depth 5 -Compress
'''.strip()


def scan(host: str, port: int, timeout: int, cancel_event: threading.Event) -> tuple[CommandResult, list[dict]]:
    timestamp = now()
    if not settings.windows_audit_user or not settings.windows_audit_password:
        return _unavailable("WINDOWS_AUDIT_USER and WINDOWS_AUDIT_PASSWORD are not configured"), []
    if settings.windows_audit_transport not in {"ntlm", "kerberos", "credssp", "plaintext"}:
        return _unavailable("Unsupported WINDOWS_AUDIT_TRANSPORT"), []
    try:
        import winrm
    except ImportError:
        return _unavailable("pywinrm is not installed"), []
    endpoint = f"https://{host}:{port}/wsman" if port == 5986 else f"http://{host}:{port}/wsman"
    try:
        session = winrm.Session(
            endpoint,
            auth=(settings.windows_audit_user, settings.windows_audit_password),
            transport=settings.windows_audit_transport,
            server_cert_validation=settings.windows_audit_server_cert_validation,
        )
        response = session.run_ps(REMOTE_SCRIPT)
        result = CommandResult(
            "completed" if response.status_code == 0 else "failed",
            response.status_code,
            response.std_out.decode(errors="replace"),
            response.std_err.decode(errors="replace"),
            timestamp,
            now(),
            display_command(["winrm", endpoint, "<read-only PowerShell audit>"]),
        )
    except Exception as exc:  # WinRM libraries expose several platform-specific exceptions.
        result = CommandResult("failed", None, "", str(exc), timestamp, now(), display_command(["winrm", endpoint]))
    if result.status != "completed":
        return result, []
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        result.status = "failed"
        result.stderr = "WinRM returned invalid JSON"
        return result, []
    return result, parse_payload(host, port, payload)


def parse_payload(host: str, port: int, payload: dict) -> list[dict]:
    findings: list[dict] = []
    smb = payload.get("SMB") or {}
    if smb.get("EnableSMB1Protocol") is True:
        findings.append(_finding(host, port, "SMBv1 is enabled", "high", "Disable SMBv1 on the Windows host.", "smb1"))
    if smb.get("RequireSecuritySignature") is not True:
        findings.append(_finding(host, port, "SMB signing is not required", "medium", "Require SMB security signatures through approved policy.", "smb-signing"))
    rdp = payload.get("RDP") or {}
    if rdp.get("fDenyTSConnections") == 0:
        findings.append(_finding(host, port, "Remote Desktop is enabled", "low", "Disable RDP if it is not required and restrict access if it is required.", "rdp-enabled"))
    if len(payload.get("Hotfixes") or []) == 0:
        findings.append(_finding(host, port, "No Windows hotfix inventory was returned", "info", "Verify Windows Update and endpoint management reporting.", "hotfix-inventory"))
    return findings


def _finding(host: str, port: int, title: str, severity: str, remediation: str, rule_id: str) -> dict:
    return {
        "host": host,
        "port": port,
        "protocol": "tcp",
        "title": title,
        "severity": severity,
        "confidence": "high",
        "description": "Read-only Windows audit finding.",
        "evidence": title,
        "remediation": remediation,
        "source_tool": "windows-audit",
        "rule_id": rule_id,
        "fingerprint": f"windows:{rule_id}:{host}:{port}",
    }


def _unavailable(message: str) -> CommandResult:
    timestamp = now()
    return CommandResult("unavailable", None, "", message, timestamp, timestamp, display_command(["winrm"]))
