"""Nmap NSE vulnerability script adapter."""

from __future__ import annotations

import re
import threading
import xml.etree.ElementTree as ET

from .runner import CommandResult, run_command


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def scan(target: str, ports: str, timeout: int, cancel_event: threading.Event) -> tuple[CommandResult, list[dict]]:
    args = [
        "nmap",
        "-p",
        ports,
        "-Pn",
        "--script",
        "vuln",
        "--host-timeout",
        f"{timeout}s",
        "-oX",
        "-",
        target,
    ]
    result = run_command(args, timeout, cancel_event)
    if result.status != "completed":
        return result, []
    return result, parse_xml(target, result.stdout)


def parse_xml(target: str, output: str) -> list[dict]:
    findings: list[dict] = []
    root = ET.fromstring(output)
    for host in root.findall(".//host"):
        address = host.find("address")
        host_value = address.get("addr") if address is not None else target
        for port_element in host.findall("./ports/port"):
            port = int(port_element.get("portid", "0"))
            protocol = port_element.get("protocol", "tcp")
            for script in port_element.findall("./script"):
                finding = _finding_from_script(host_value, port, protocol, script)
                if finding:
                    findings.append(finding)
        hostscript = host.find("./hostscript")
        if hostscript is not None:
            for script in hostscript.findall("./script"):
                finding = _finding_from_script(host_value, None, "tcp", script)
                if finding:
                    findings.append(finding)
    return findings


def _finding_from_script(host: str, port: int | None, protocol: str, script: ET.Element) -> dict | None:
    script_id = script.get("id", "nse-script")
    output = (script.get("output") or "").strip()
    if not output:
        return None
    cves = list(dict.fromkeys(CVE_RE.findall(output)))
    vulnerable = "VULNERABLE" in output.upper()
    severity = "high" if vulnerable else ("low" if cves else "info")
    title = script_id
    if cves:
        title = f"{script_id} ({', '.join(cves[:3])})"
    return {
        "host": host,
        "port": port,
        "protocol": protocol,
        "title": title,
        "severity": severity,
        "confidence": "high" if vulnerable else "medium",
        "cve_id": cves[0] if cves else None,
        "description": f"Nmap NSE script {script_id} reported results for this host.",
        "evidence": output[:4000],
        "remediation": "Review the NSE script output and apply vendor fixes for the affected service.",
        "source_tool": "nmap-nse",
        "rule_id": script_id,
        "fingerprint": f"nse:{script_id}:{host}:{port}",
    }
