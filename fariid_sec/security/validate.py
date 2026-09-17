"""Target and scope validation.

We distinguish the *shape* of a target (IP, CIDR, hostname, URL) so the agent
can pick appropriate tools, and we provide scope checks so active testing is
limited to what the operator has authorized.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

TARGET_IP = "ip"
TARGET_CIDR = "cidr"
TARGET_HOSTNAME = "hostname"
TARGET_URL = "url"

_HOSTNAME_RE = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$"
)

# Private / loopback / link-local / reserved ranges that are only reachable
# from within the operator's own network or lab.
_SPECIAL_NETS = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]
_SPECIAL_NETWORKS = [ipaddress.ip_network(n) for n in _SPECIAL_NETS]


def _strip_port(host: str) -> str:
    """Remove a trailing ``:port`` from a bare hostname/IP if present."""
    if host.count(":") == 1 and not host.startswith("["):
        left, _, right = host.partition(":")
        if right.isdigit():
            return left
    return host


def classify_target(target: str) -> str | None:
    """Classify ``target`` as ip/cidr/hostname/url, or ``None`` if invalid."""
    if not target:
        return None
    t = target.strip()
    if "://" in t:
        try:
            parsed = urlparse(t)
            if parsed.scheme and parsed.netloc:
                return TARGET_URL
        except ValueError:
            return None
        return None

    t = t.rstrip("/")
    # CIDR (contains exactly one slash and is a valid network)
    if "/" in t and t.count("/") == 1:
        try:
            ipaddress.ip_network(t, strict=True)
            return TARGET_CIDR
        except ValueError:
            return None

    bare = _strip_port(t)
    try:
        ipaddress.ip_address(bare)
        return TARGET_IP
    except ValueError:
        pass

    if bare == "localhost" or _HOSTNAME_RE.match(bare):
        return TARGET_HOSTNAME

    return None


def validate_target(target: str) -> tuple[bool, str]:
    """Return ``(valid, kind_or_reason)`` for a target string."""
    kind = classify_target(target)
    if kind is None:
        return False, f"invalid target {target!r} (expected IP, CIDR, hostname, or URL)"
    return True, kind


def is_special_address(ip: str) -> bool:
    """True if ``ip`` is loopback, private, link-local, or reserved."""
    try:
        addr = ipaddress.ip_address(_strip_port(ip))
    except ValueError:
        return False
    return any(addr in net for net in _SPECIAL_NETWORKS)


def target_in_scope(target: str, scopes: list[str]) -> bool:
    """Return True if ``target`` falls within any of the authorized scopes."""
    if not scopes:
        return True  # no scope restrictions configured

    kind = classify_target(target)
    if kind in (TARGET_URL, TARGET_HOSTNAME):
        host = urlparse(target).hostname if kind == TARGET_URL else _strip_port(target)
        if host is None:
            return False
        return any(s.lstrip(".") in host.lower() for s in scopes if not _looks_like_ip(s))

    try:
        addr = ipaddress.ip_address(_strip_port(target))
    except ValueError:
        return False

    for scope in scopes:
        try:
            if "/" in scope:
                if addr in ipaddress.ip_network(scope, strict=False):
                    return True
            elif addr == ipaddress.ip_address(_strip_port(scope)):
                return True
        except ValueError:
            continue
    return False


def _looks_like_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(_strip_port(s))
        return True
    except ValueError:
        return False
