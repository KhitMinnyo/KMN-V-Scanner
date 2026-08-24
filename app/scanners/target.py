"""Target validation and normalization."""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse

from ..config import settings


HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.:-]*[A-Za-z0-9]$")


class TargetError(ValueError):
    pass


def normalize_target(value: str) -> str:
    target = value.strip()
    if not target or target.startswith("-") or any(char in target for char in "\r\n\x00"):
        raise TargetError("Invalid target")

    parsed = urlparse(target if "://" in target else f"//{target}")
    host = parsed.hostname
    if not host:
        raise TargetError("Target must be a hostname, IP address, CIDR, or HTTP(S) URL")

    try:
        network = ipaddress.ip_network(host, strict=False)
        normalized = str(network) if network.prefixlen != network.max_prefixlen else host
        addresses = [network.network_address]
    except ValueError:
        if not HOSTNAME_RE.fullmatch(host) or len(host) > 253:
            raise TargetError("Invalid hostname")
        normalized = host
        try:
            addresses = [ipaddress.ip_address(info[4][0]) for info in socket.getaddrinfo(host, None)]
        except socket.gaierror as exc:
            raise TargetError("Target hostname could not be resolved") from exc

    if not settings.allow_external_targets:
        external = any(not address.is_private and not address.is_loopback and not address.is_link_local for address in addresses)
        if external:
            raise TargetError("External targets are disabled; set ALLOW_EXTERNAL_TARGETS=true for an authorized target")
    return normalized
