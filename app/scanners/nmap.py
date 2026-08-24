"""Nmap service discovery adapter."""

from __future__ import annotations

import xml.etree.ElementTree as ET
import threading

from .runner import CommandResult, command_available, run_command


PORT_RANGES = {
    "quick": "1-1024",
    "standard": "1-10000",
    "deep": "1-65535",
}


def scan(target: str, profile: str, timeout: int, cancel_event: threading.Event) -> tuple[CommandResult, list[dict]]:
    args = [
        "nmap",
        "-p",
        PORT_RANGES[profile],
        "-sT",
        "-sV",
        "-Pn",
        "--open",
        "-T3",
        "--max-retries",
        "2",
        "--host-timeout",
        f"{timeout}s",
        "-oX",
        "-",
        target,
    ]
    if not command_available("nmap"):
        return run_command(["nmap"], timeout=1, cancel_event=cancel_event), []
    result = run_command(args, timeout, cancel_event)
    if result.status != "completed":
        return result, []
    return result, parse_xml(target, result.stdout)


def parse_xml(target: str, output: str) -> list[dict]:
    root = ET.fromstring(output)
    services: list[dict] = []
    for host in root.findall(".//host"):
        address = host.find("address")
        host_value = address.get("addr") if address is not None else target
        for port_element in host.findall("./ports/port"):
            state_element = port_element.find("state")
            if state_element is None or state_element.get("state") != "open":
                continue
            service_element = port_element.find("service")
            service_name = service_element.get("name", "") if service_element is not None else ""
            product = service_element.get("product", "") if service_element is not None else ""
            version = service_element.get("version", "") if service_element is not None else ""
            extra = service_element.get("extrainfo", "") if service_element is not None else ""
            if extra:
                version = f"{version} {extra}".strip()
            port = int(port_element.get("portid", "0"))
            url = None
            if service_name in {"http", "http-proxy", "https"} or port in {80, 443, 8080, 8443, 8000, 8888}:
                scheme = "https" if service_name == "https" or port in {443, 8443} else "http"
                url = f"{scheme}://{host_value}:{port}"
            services.append(
                {
                    "host": host_value,
                    "port": port,
                    "protocol": port_element.get("protocol", "tcp"),
                    "state": "open",
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "url": url,
                    "raw": {"service": service_name, "product": product, "version": version},
                }
            )
    return services
