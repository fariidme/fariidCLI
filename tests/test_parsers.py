"""Tool output parser tests."""

from __future__ import annotations

import json

from fariid_sec.parsers.nmap import parse_greppable
from fariid_sec.parsers.nuclei import parse_jsonl


def test_parse_nmap_greppable() -> None:
    text = (
        "Host: 192.168.1.10 () Ports: 22/open/tcp//ssh//OpenSSH 7.9/,"
        "80/open/tcp//http//nginx/\tIgnored State: closed (998)"
    )
    hosts = parse_greppable(text)
    assert len(hosts) == 1
    assert hosts[0]["ip"] == "192.168.1.10"
    ports = {p["port"]: p for p in hosts[0]["open_ports"]}
    assert ports[22]["service"] == "ssh"
    assert ports[80]["service"] == "http"


def test_parse_nmap_ignores_closed() -> None:
    text = "Host: 10.0.0.1 () Ports: 22/open/tcp//ssh/,23/closed/tcp//telnet/\t"
    hosts = parse_greppable(text)
    assert len(hosts[0]["open_ports"]) == 1


def test_parse_nuclei_jsonl() -> None:
    obj = {
        "template-id": "http-cve-2021-44228",
        "info": {"name": "Log4Shell", "severity": "critical", "description": "rce", "tags": ["cve"]},
        "host": "http://example.com",
        "matched-at": "http://example.com/foo",
        "type": "http",
    }
    findings = parse_jsonl(json.dumps(obj) + "\nnot json\n")
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert findings[0]["name"] == "Log4Shell"
