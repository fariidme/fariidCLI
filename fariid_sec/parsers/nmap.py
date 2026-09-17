"""Parse nmap output.

We prefer nmap's greppable format (``-oG -``) because it is stable and easy to
parse. The XML format is also supported as a fallback via :func:`parse_xml`.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

_HOST_RE = re.compile(r"Host:\s+(\S+)\s*(?:\(([^)]*)\))?")
_PORTS_RE = re.compile(r"Ports:\s+(.*?)(?:\t|$)")


def parse_greppable(text: str) -> list[dict]:
    """Parse ``nmap -oG -`` output into a list of host dicts."""
    hosts: list[dict] = []
    for line in text.splitlines():
        if not line.startswith("Host:"):
            continue
        host: dict = {}
        m = _HOST_RE.match(line)
        if m:
            host["ip"] = m.group(1)
            if m.group(2):
                host["hostname"] = m.group(2)

        ports: list[dict] = []
        pm = _PORTS_RE.search(line)
        if pm:
            for token in pm.group(1).split(","):
                token = token.strip()
                parts = token.split("/")
                if len(parts) >= 3 and parts[1] == "open":
                    ports.append(
                        {
                            "port": int(parts[0]),
                            "state": parts[1],
                            "protocol": parts[2],
                            "service": parts[4] if len(parts) > 4 else "",
                            "version": parts[6] if len(parts) > 6 else "",
                        }
                    )
        host["open_ports"] = ports
        host["port_count"] = len(ports)
        hosts.append(host)
    return hosts


def parse_xml(text: str) -> list[dict]:
    """Parse ``nmap -oX -`` XML output into host dicts."""
    hosts: list[dict] = []
    try:
        root = ET.fromstring(text)  # noqa: S314 (parsing trusted local nmap XML)
    except ET.ParseError:
        return hosts

    for h in root.iter("host"):
        addr = h.find("address")
        if addr is None:
            continue
        host: dict[str, Any] = {"ip": addr.get("addr", ""), "open_ports": []}
        hostnames = h.find("hostnames")
        if hostnames is not None and len(hostnames):
            host["hostname"] = hostnames[0].get("name")
        for p in h.iter("port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = p.find("service")
            host["open_ports"].append(
                {
                    "port": int(p.get("portid", 0)),
                    "state": "open",
                    "protocol": p.get("protocol", ""),
                    "service": service.get("name", "") if service is not None else "",
                    "version": service.get("product", "") if service is not None else "",
                }
            )
        host["port_count"] = len(host["open_ports"])
        hosts.append(host)
    return hosts


def summarize(hosts: list[dict]) -> dict:
    """Reduce parsed hosts to a compact summary."""
    total_ports = sum(h.get("port_count", 0) for h in hosts)
    services: dict[str, int] = {}
    for h in hosts:
        for p in h.get("open_ports", []):
            svc = p.get("service") or "unknown"
            services[svc] = services.get(svc, 0) + 1
    return {
        "hosts": len(hosts),
        "open_ports": total_ports,
        "services": services,
    }
