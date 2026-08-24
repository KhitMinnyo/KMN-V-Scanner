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


def normalize_target(value: str, authorization_confirmed: bool = False) -> str:
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

    external = any(not address.is_private and not address.is_loopback and not address.is_link_local for address in addresses)
    if not authorization_confirmed:
        raise TargetError("Confirm that you own or are authorized to scan this target")
    if external:
        if not settings.allow_external_targets:
            raise TargetError("External targets are disabled; set ALLOW_EXTERNAL_TARGETS=true for an authorized target")
        if settings.authorized_targets and not _matches_allowlist(host, addresses):
            raise TargetError("Target is not listed in AUTHORIZED_TARGETS")
    return normalized


def _matches_allowlist(host: str, addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address]) -> bool:
    normalized_host = host.lower().rstrip(".")
    for entry in settings.authorized_targets:
        if entry == normalized_host:
            return True
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if any(address in network for address in addresses):
            return True
    return False
