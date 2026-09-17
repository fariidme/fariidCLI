"""Structured AI tools.

The AI agent never generates arbitrary shell commands. Instead it selects from
this fixed set of typed tools. Each tool carries a JSON schema for the model, a
risk level, an authorization requirement, and a handler that builds a safe
argument vector and runs it through :class:`CommandRunner`.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..ai.base import ToolDefinition
from ..parsers.output import OutputParser
from ..runners.command import CommandNotFound, CommandRunner
from ..runners.normalizer import ResultNormalizer
from ..security.validate import validate_target
from .registry import ToolRegistry

ToolResult = dict[str, Any]


@dataclass
class ExecutionContext:
    """Everything a tool handler needs to execute safely."""

    runner: CommandRunner
    registry: ToolRegistry
    normalize: ResultNormalizer
    mode: str = "passive"
    target: str | None = None
    confirm: Callable[[str], bool] = field(default_factory=lambda: lambda _msg: False)


@dataclass
class AgentTool:
    definition: ToolDefinition
    handler: Callable[[dict[str, Any], ExecutionContext], ToolResult]
    modes: tuple[str, ...] = ("passive", "active", "lab")


def _json_schema(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required}


def _target_from(args: dict, ctx: ExecutionContext) -> tuple[str, str | None]:
    """Return ``(target, error)`` for a tool that needs a target."""
    target = str(args.get("target") or ctx.target or "")
    if not target:
        return "", "no target provided"
    ok, reason = validate_target(target)
    if not ok:
        return target, reason
    return target, None


def _run_tool(
    ctx: ExecutionContext,
    tool_name: str,
    argv: list[str],
    parser: str | None = None,
    timeout: float | None = None,
    max_findings: int = 50,
) -> ToolResult:
    binary = argv[0]
    tool = ctx.registry.get(binary)
    if tool is None:
        return {"ok": False, "tool": tool_name, "error": f"unknown tool {binary!r}"}
    if not ctx.registry.is_installed(tool.name):
        return {
            "ok": False,
            "tool": tool_name,
            "error": f"{tool.binary} is not installed",
            "install_hint": tool.install_hint,
        }
    try:
        res = ctx.runner.run(argv, timeout=timeout)
    except CommandNotFound:
        return {
            "ok": False,
            "tool": tool_name,
            "error": f"{tool.binary} is not installed",
            "install_hint": tool.install_hint,
        }

    norm = ctx.normalize.normalize(res)
    findings: list[Any] = []
    if parser and res.returncode == 0 and res.stdout:
        findings = OutputParser.parse(parser, res.stdout).get("findings", [])[:max_findings]

    return {
        "ok": res.returncode == 0,
        "tool": tool_name,
        "command": " ".join(argv),
        "returncode": res.returncode,
        "timed_out": res.timed_out,
        "output": norm["stdout"]["text"],
        "error_output": norm["stderr"]["text"],
        "truncated": norm["stdout"]["truncated"],
        "findings": findings,
        "finding_count": len(findings),
        "duration": round(res.duration, 2),
    }


# --- handlers --------------------------------------------------------------
def run_nmap(args: dict, ctx: ExecutionContext) -> ToolResult:
    target, err = _target_from(args, ctx)
    if err:
        return {"ok": False, "tool": "nmap", "error": err}
    argv = ["nmap", "-oG", "-", "-sV"]
    ports = args.get("ports")
    if ports:
        argv += ["-p", str(ports)]
    else:
        argv += ["--top-ports", "1000"]
    options = str(args.get("options") or "").strip()
    if options:
        argv += options.split()
    argv.append(target)
    return _run_tool(ctx, "nmap", argv, parser="nmap")


def run_nuclei(args: dict, ctx: ExecutionContext) -> ToolResult:
    target, err = _target_from(args, ctx)
    if err:
        return {"ok": False, "tool": "nuclei", "error": err}
    argv = ["nuclei", "-u", target, "-jsonl", "-silent"]
    severity = args.get("severity")
    if severity:
        argv += ["-severity", str(severity)]
    tags = args.get("tags")
    if tags:
        argv += ["-tags", str(tags)]
    return _run_tool(ctx, "nuclei", argv, parser="nuclei")


def run_http_probe(args: dict, ctx: ExecutionContext) -> ToolResult:
    target, err = _target_from(args, ctx)
    if err:
        return {"ok": False, "tool": "httpx", "error": err}
    if "://" not in target:
        target = f"https://{target}"
    if ctx.registry.is_installed("httpx"):
        argv = ["httpx", "-u", target, "-status-code", "-title", "-tech-detect"]
        return _run_tool(ctx, "httpx", argv, parser=None)
    argv = ["curl", "-sS", "-I", "-L", "--max-time", "20", target]
    return _run_tool(ctx, "curl", argv, parser=None)


def run_gobuster(args: dict, ctx: ExecutionContext) -> ToolResult:
    target, err = _target_from(args, ctx)
    if err:
        return {"ok": False, "tool": "gobuster", "error": err}
    if "://" not in target:
        target = f"http://{target}"
    mode = str(args.get("mode", "dir"))
    wordlist = str(args.get("wordlist") or "/usr/share/wordlists/dirb/common.txt")
    if mode == "dns":
        argv = ["gobuster", "dns", "-d", target, "-w", wordlist]
    elif mode == "vhost":
        argv = ["gobuster", "vhost", "-u", target, "-w", wordlist]
    else:
        argv = ["gobuster", "dir", "-u", target, "-w", wordlist, "-q"]
    return _run_tool(ctx, "gobuster", argv, parser=None)


def run_ffuf(args: dict, ctx: ExecutionContext) -> ToolResult:
    url = args.get("url")
    if not url:
        return {"ok": False, "tool": "ffuf", "error": "no url provided"}
    wordlist = str(args.get("wordlist") or "/usr/share/wordlists/dirb/common.txt")
    argv = ["ffuf", "-u", f"{url}/FUZZ", "-w", wordlist, "-mc", "200,204,301,302,307,401,403"]
    return _run_tool(ctx, "ffuf", argv, parser=None)


def run_nikto(args: dict, ctx: ExecutionContext) -> ToolResult:
    target, err = _target_from(args, ctx)
    if err:
        return {"ok": False, "tool": "nikto", "error": err}
    if "://" not in target:
        target = f"http://{target}"
    argv = ["nikto", "-h", target]
    return _run_tool(ctx, "nikto", argv, parser=None)


def run_sqlmap(args: dict, ctx: ExecutionContext) -> ToolResult:
    url = args.get("url")
    if not url:
        return {"ok": False, "tool": "sqlmap", "error": "no url provided"}
    argv = ["sqlmap", "-u", url, "--batch", "--smart", "--level", "1", "--risk", "1"]
    return _run_tool(ctx, "sqlmap", argv, parser=None, timeout=600.0)


def run_dns_enum(args: dict, ctx: ExecutionContext) -> ToolResult:
    domain = args.get("domain") or args.get("target") or ctx.target
    if not domain:
        return {"ok": False, "tool": "dns", "error": "no domain provided"}
    if ctx.registry.is_installed("dnsrecon"):
        argv = ["dnsrecon", "-d", domain]
        return _run_tool(ctx, "dnsrecon", argv, parser=None)
    argv = ["dig", "+short", "A", domain]
    return _run_tool(ctx, "dig", argv, parser=None)


def run_searchsploit(args: dict, ctx: ExecutionContext) -> ToolResult:
    query = args.get("query")
    if not query:
        return {"ok": False, "tool": "searchsploit", "error": "no query provided"}
    argv = ["searchsploit", query, "--disable-colour"]
    return _run_tool(ctx, "searchsploit", argv, parser=None)


def run_whois(args: dict, ctx: ExecutionContext) -> ToolResult:
    target, err = _target_from(args, ctx)
    if err:
        return {"ok": False, "tool": "whois", "error": err}
    return _run_tool(ctx, "whois", ["whois", target], parser=None)


def read_file(args: dict, ctx: ExecutionContext) -> ToolResult:
    path = args.get("path")
    if not path:
        return {"ok": False, "tool": "read_file", "error": "no path provided"}
    p = Path(path).expanduser()
    if not _is_safe_path(p):
        return {"ok": False, "tool": "read_file", "error": f"refusing to read sensitive path: {p}"}
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError) as exc:
        return {"ok": False, "tool": "read_file", "error": str(exc)}
    norm = ctx.normalize.normalize_text(text)
    return {"ok": True, "tool": "read_file", "path": str(p), "content": norm["text"], "truncated": norm["truncated"]}


_SENSITIVE_PARTS = (
    "/etc/shadow",
    "/etc/passwd",
    ".ssh",
    ".aws",
    ".env",
    ".gnupg",
    "id_rsa",
    "id_ed25519",
    ".kube",
    ".config/gcloud",
    "authorized_keys",
)


def _is_safe_path(p: Path) -> bool:
    lower = str(p.resolve()).lower()
    for part in _SENSITIVE_PARTS:
        if part in lower:
            return False
    return True


# --- registry --------------------------------------------------------------
AGENT_TOOLS: dict[str, AgentTool] = {
    "run_nmap": AgentTool(
        ToolDefinition(
            "run_nmap",
            "Port-scan a target with nmap and report open ports/services.",
            _json_schema(
                {
                    "target": {"type": "string", "description": "IP, hostname, or CIDR"},
                    "ports": {"type": "string", "description": "optional port range, e.g. 80,443 or 1-1000"},
                    "options": {"type": "string", "description": "optional extra nmap flags"},
                },
                ["target"],
            ),
            risk="low",
        ),
        run_nmap,
    ),
    "run_http_probe": AgentTool(
        ToolDefinition(
            "run_http_probe",
            "Probe a web target for status, title, and technology (httpx/curl).",
            _json_schema({"target": {"type": "string"}}, ["target"]),
            risk="low",
        ),
        run_http_probe,
    ),
    "run_dns_enum": AgentTool(
        ToolDefinition(
            "run_dns_enum",
            "Enumerate DNS records for a domain (dnsrecon/dig).",
            _json_schema({"domain": {"type": "string"}}, ["domain"]),
            risk="low",
        ),
        run_dns_enum,
        modes=("passive", "active", "lab"),
    ),
    "run_whois": AgentTool(
        ToolDefinition(
            "run_whois", "Look up WHOIS registration for a domain/IP.",
            _json_schema({"target": {"type": "string"}}, ["target"]),
            risk="low",
        ),
        run_whois,
    ),
    "run_searchsploit": AgentTool(
        ToolDefinition(
            "run_searchsploit", "Search the local Exploit-DB for a software name/version.",
            _json_schema({"query": {"type": "string"}}, ["query"]),
            risk="low",
        ),
        run_searchsploit,
    ),
    "run_nuclei": AgentTool(
        ToolDefinition(
            "run_nuclei",
            "Run nuclei vulnerability templates against a target.",
            _json_schema(
                {
                    "target": {"type": "string"},
                    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                    "tags": {"type": "string"},
                },
                ["target"],
            ),
            risk="medium",
            requires_auth=True,
        ),
        run_nuclei,
        modes=("active", "lab"),
    ),
    "run_gobuster": AgentTool(
        ToolDefinition(
            "run_gobuster",
            "Brute-force directories, vhosts, or DNS names with gobuster.",
            _json_schema(
                {
                    "target": {"type": "string"},
                    "mode": {"type": "string", "enum": ["dir", "dns", "vhost"]},
                    "wordlist": {"type": "string"},
                },
                ["target"],
            ),
            risk="medium",
            requires_auth=True,
        ),
        run_gobuster,
        modes=("active", "lab"),
    ),
    "run_ffuf": AgentTool(
        ToolDefinition(
            "run_ffuf", "Fuzz a URL path with ffuf.",
            _json_schema({"url": {"type": "string"}, "wordlist": {"type": "string"}}, ["url"]),
            risk="medium",
            requires_auth=True,
        ),
        run_ffuf,
        modes=("active", "lab"),
    ),
    "run_nikto": AgentTool(
        ToolDefinition(
            "run_nikto", "Scan a web server for known vulnerabilities with nikto.",
            _json_schema({"target": {"type": "string"}}, ["target"]),
            risk="medium",
            requires_auth=True,
        ),
        run_nikto,
        modes=("active", "lab"),
    ),
    "run_sqlmap": AgentTool(
        ToolDefinition(
            "run_sqlmap", "Detect SQL injection in a URL with sqlmap (HIGH risk).",
            _json_schema({"url": {"type": "string"}}, ["url"]),
            risk="high",
            requires_auth=True,
        ),
        run_sqlmap,
        modes=("lab",),
    ),
    "read_file": AgentTool(
        ToolDefinition(
            "read_file",
            "Read a local text file (e.g. a saved report). Sensitive paths are refused.",
            _json_schema({"path": {"type": "string"}}, ["path"]),
            risk="low",
        ),
        read_file,
    ),
}


def tool_definitions_for_mode(mode: str) -> list[ToolDefinition]:
    """Return the AI tool definitions allowed in ``mode``."""
    return [t.definition for t in AGENT_TOOLS.values() if mode in t.modes]


def get_tool(name: str) -> AgentTool | None:
    return AGENT_TOOLS.get(name)
