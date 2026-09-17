"""The ``fariid-sec`` command-line interface."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import click

from .. import __version__
from ..agent import Planner, SecurityAgent
from ..ai import (
    AIError,
    AIProvider,
    AuthenticationError,
    Message,
    RateLimitError,
    Role,
    create_provider,
)
from ..config.manager import AppConfig, ConfigManager
from ..parsers.output import OutputParser
from ..reports import Finding, ReportData, ReportGenerator
from ..runners.command import CommandNotFound, CommandRunner
from ..runners.normalizer import ResultNormalizer
from ..security.redact import mask_secret, redact_text
from ..security.validate import classify_target, is_special_address, validate_target
from ..sessions import SessionManager
from ..targets import TargetManager
from ..tools import ToolRegistry
from ..utils.logging import setup_logging
from ..utils.platform import detect_platform, which
from . import ui

PASS = ui.console


class State:
    """Lazily-initialized CLI state shared across commands via ``ctx.obj``."""

    def __init__(
        self,
        provider: str | None,
        model: str | None,
        mode: str | None,
        yes: bool,
        json_out: bool,
        verbose: bool,
    ) -> None:
        self.provider_override = provider
        self.model_override = model
        self.mode_override = mode
        self.yes = yes
        self.json_out = json_out
        self.verbose = verbose
        self._manager: ConfigManager | None = None
        self._config: AppConfig | None = None
        self._registry: ToolRegistry | None = None
        self._provider: AIProvider | None = None

    @property
    def manager(self) -> ConfigManager:
        if self._manager is None:
            self._manager = ConfigManager()
        return self._manager

    @property
    def config(self) -> AppConfig:
        if self._config is None:
            self._config = self.manager.load()
        return self._config

    @property
    def mode(self) -> str:
        return self.mode_override or self.config.mode

    @property
    def registry(self) -> ToolRegistry:
        if self._registry is None:
            self._registry = ToolRegistry()
        return self._registry

    @property
    def runner(self) -> CommandRunner:
        return CommandRunner(timeout=300.0)

    @property
    def normalize(self) -> ResultNormalizer:
        return ResultNormalizer()

    @property
    def targets(self) -> TargetManager:
        return TargetManager(self.manager.targets_path)

    @property
    def sessions(self) -> SessionManager:
        return SessionManager(self.manager.sessions_dir)

    def provider_name(self) -> str:
        return self.provider_override or self.config.provider

    def provider_model(self) -> str:
        return self.model_override or self.config.effective_model

    def ai_provider(self) -> AIProvider:
        if self._provider is None:
            self._provider = create_provider(
                self.config, self.provider_override, self.model_override
            )
        return self._provider


# --- top-level group -------------------------------------------------------
@click.group(invoke_without_command=True)
@click.option("--provider", default=None, help="Override provider (deepseek|ollama|openai)")
@click.option("--model", default=None, help="Override model name")
@click.option(
    "--mode",
    default=None,
    type=click.Choice(["passive", "active", "lab"]),
    help="Override execution mode",
)
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation (authorized targets only)")
@click.option("--json", "json_out", is_flag=True, help="Emit machine-readable JSON")
@click.option("--verbose", "-v", is_flag=True, help="Verbose logging")
@click.pass_context
def cli(
    ctx: click.Context,
    provider: str | None,
    model: str | None,
    mode: str | None,
    yes: bool,
    json_out: bool,
    verbose: bool,
) -> None:
    ctx.obj = State(provider, model, mode, yes, json_out, verbose)
    if verbose:
        setup_logging(verbose=True)
    if ctx.invoked_subcommand is None:
        _show_banner(ctx.obj)


def _show_banner(state: State) -> None:
    platform = detect_platform()
    ui.banner(
        provider=state.provider_name(),
        model=state.provider_model(),
        mode=state.mode,
        platform="Kali Linux" if platform.is_kali else platform.system,
    )
    ui.info("Type 'fariid-sec --help' for commands.")
    ui.warn("Only test systems you own or are explicitly authorized to test.")


# --- version ---------------------------------------------------------------
@cli.command()
def version() -> None:
    """Show version."""
    PASS.print(f"Fariid Tech Security AI v{__version__}")


# --- mode ------------------------------------------------------------------
@cli.command()
@click.argument("mode", required=False, type=click.Choice(["passive", "active", "lab"]))
@click.pass_obj
def mode(state: State, mode: str | None) -> None:
    """Get or set the execution mode (passive/active/lab)."""
    if mode:
        state.manager.set("mode", mode)
        ui.success(f"Mode set to {mode}")
    else:
        PASS.print(f"Current mode: {state.config.mode}")


# --- config ----------------------------------------------------------------
@cli.group(invoke_without_command=True)
@click.pass_context
def config(ctx: click.Context) -> None:
    """View and edit configuration."""
    if ctx.invoked_subcommand is None:
        _show_config(ctx.obj)


def _show_config(state: State) -> None:
    cfg = state.config
    data = state.manager.public_view(cfg)
    rows = [(k, str(v)) for k, v in sorted(data.items())]
    ui.render_kv("Configuration", rows)
    ui.info("Secrets are masked. Set a key with: fariid-sec config set <key> <value>")


@config.command("show")
@click.pass_obj
def config_show(state: State) -> None:
    """Show current configuration (secrets masked)."""
    _show_config(state)


@config.command("get")
@click.argument("key")
@click.pass_obj
def config_get(state: State, key: str) -> None:
    """Get a single config value."""
    try:
        value = state.manager.get(key)
    except KeyError:
        ui.error(f"unknown config key: {key}")
        raise SystemExit(1) from None
    if "api_key" in key:
        value = mask_secret(value)
    PASS.print(value if value != "" else "(empty)")


@config.command("set")
@click.argument("key")
@click.argument("value", required=False)
@click.option("--provider", "provider_opt", default=None, help="Provider for api-key")
@click.pass_obj
def config_set(state: State, key: str, value: str | None, provider_opt: str | None) -> None:
    """Set a config value. 'api-key' prompts for hidden input."""
    if key in ("api-key", "api_key", "apikey"):
        provider = provider_opt or state.provider_name()
        if value is None:
            value = ui.prompt(f"API key for {provider}", password=True)
        state.manager.set_api_key(value or "", provider)
        ui.success(f"API key stored for '{provider}'")
        return

    if value is None:
        ui.error(f"missing value for {key}")
        raise SystemExit(1)

    try:
        state.manager.set(key, value)
    except (KeyError, ValueError) as exc:
        ui.error(str(exc))
        raise SystemExit(1) from None
    ui.success(f"{key} = {value}")


# --- tools -----------------------------------------------------------------
@cli.command()
@click.option("--category", default=None, help="Filter by category")
@click.option("--all", "show_all", is_flag=True, help="Show all tools incl. missing")
@click.option("--missing", is_flag=True, help="Show only missing tools")
@click.pass_obj
def tools(state: State, category: str | None, show_all: bool, missing: bool) -> None:
    """List installed (or missing) security tools."""
    rows = state.registry.status()
    if category:
        rows = [r for r in rows if r["category"] == category]
    if missing:
        rows = [r for r in rows if not r["installed"]]
    elif not show_all:
        rows = [r for r in rows if r["installed"]]

    if state.json_out:
        PASS.print(json.dumps(rows, indent=2))
        return

    table_rows = [
        [
            r["name"],
            r["category"],
            r["risk"],
            "installed" if r["installed"] else "missing",
            r["install_hint"] if not r["installed"] else (r["path"] or ""),
        ]
        for r in rows
    ]
    ui.render_table("Security Tools", ["Tool", "Category", "Risk", "Status", "Path/Hint"], table_rows)
    ui.info(f"{len([r for r in rows if r['installed']])} installed / {len(rows)} shown")


# --- doctor ----------------------------------------------------------------
@cli.command()
@click.pass_obj
def doctor(state: State) -> None:
    """Run a self-check of the environment and configuration."""
    checks: list[tuple[str, str, str]] = []
    platform = detect_platform()

    # Python
    checks.append(("Python", "ok" if platform.python else "fail", platform.python))
    # Git
    checks.append(("Git", "ok" if which("git") else "warn", which("git") or "not installed"))
    # Core tools
    for tool_name in ["nmap", "nuclei", "sqlmap", "nikto", "metasploit"]:
        tool = state.registry.get(tool_name)
        installed = tool is not None and state.registry.is_installed(tool.name)
        checks.append(
            (tool_name.title(), "ok" if installed else "warn", "installed" if installed else "missing")
        )
    # DeepSeek / provider
    provider = state.ai_provider()
    health = provider.check_health()
    status = health.get("status", "unknown")
    checks.append(
        (
            f"Provider ({state.provider_name()})",
            "ok" if status == "ok" else ("fail" if status == "unauthorized" else "warn"),
            f"{health.get('model', '')} — {status}",
        )
    )
    # Network
    checks.append(("Network", "ok" if _network_ok() else "warn", "basic connectivity"))
    # Permissions

    try:
        cfg_dir = state.manager.config_dir
        cfg_dir.mkdir(parents=True, exist_ok=True)
        mode = cfg_dir.stat().st_mode & 0o777
        checks.append(
            ("Permissions", "ok" if mode in (0o700, 0o600) else "warn", f"config dir mode {oct(mode)}")
        )
    except OSError as exc:
        checks.append(("Permissions", "fail", str(exc)))

    if state.json_out:
        PASS.print(json.dumps([{"check": c, "status": s, "detail": d} for c, s, d in checks], indent=2))
        return

    table_rows = [[c, s, d] for c, s, d in checks]
    ui.render_table("Doctor", ["Check", "Status", "Detail"], table_rows)
    ui.info("Install missing tools with sudo apt install <tool> (never auto-installed).")


def _network_ok() -> bool:
    import socket

    try:
        socket.create_connection(("1.1.1.1", 53), timeout=3)
        return True
    except OSError:
        return False


# --- target ----------------------------------------------------------------
@cli.group()
def target() -> None:
    """Manage authorized target profiles."""


@target.command("add")
@click.argument("name")
@click.argument("value")
@click.option("--desc", default="", help="Description")
@click.pass_obj
def target_add(state: State, name: str, value: str, desc: str) -> None:
    """Authorize a target (e.g. 'mylab 192.168.1.10')."""
    ok, reason = validate_target(value)
    if not ok:
        ui.error(reason)
        raise SystemExit(1)
    t = state.targets.add(name, value, desc)
    ui.success(f"Target '{t.name}' -> {t.value} ({t.kind})")


@target.command("list")
@click.pass_obj
def target_list(state: State) -> None:
    """List authorized targets."""
    targets = state.targets.list()
    if state.json_out:
        PASS.print(json.dumps([t.to_dict() for t in targets], indent=2))
        return
    if not targets:
        ui.info("No targets authorized yet.")
        return
    ui.render_table(
        "Authorized Targets",
        ["Name", "Value", "Kind", "Description"],
        [[t.name, t.value, t.kind, t.description] for t in targets],
    )


@target.command("remove")
@click.argument("name")
@click.pass_obj
def target_remove(state: State, name: str) -> None:
    """Remove an authorized target."""
    if state.targets.remove(name):
        ui.success(f"Removed target '{name}'")
    else:
        ui.error(f"no such target: {name}")
        raise SystemExit(1)


@target.command("show")
@click.argument("name")
@click.pass_obj
def target_show(state: State, name: str) -> None:
    """Show a single target."""
    t = state.targets.get(name)
    if not t:
        ui.error(f"no such target: {name}")
        raise SystemExit(1)
    ui.render_kv("Target", [("Name", t.name), ("Value", t.value), ("Kind", t.kind), ("Desc", t.description)])


# --- session ---------------------------------------------------------------
@cli.group()
def session() -> None:
    """Manage chat sessions."""


@session.command("list")
@click.pass_obj
def session_list(state: State) -> None:
    """List saved sessions."""
    sessions = state.sessions.list()
    if state.json_out:
        PASS.print(json.dumps([s.to_dict() for s in sessions], indent=2))
        return
    if not sessions:
        ui.info("No sessions yet. Start one with 'fariid-sec chat'.")
        return
    ui.render_table(
        "Sessions",
        ["ID", "Title", "Messages", "Updated"],
        [[s.id, s.title, str(s.message_count), s.updated_at] for s in sessions],
    )


@session.command("new")
@click.pass_obj
def session_new(state: State) -> None:
    """Create a new session."""
    s = state.sessions.create(provider=state.provider_name(), model=state.provider_model())
    ui.success(f"Created session {s.id}")


@session.command("resume")
@click.argument("session_id")
@click.pass_obj
def session_resume(state: State, session_id: str) -> None:
    """Resume a session in the chat REPL."""
    _chat(state, session_id=session_id)


@session.command("delete")
@click.argument("session_id")
@click.pass_obj
def session_delete(state: State, session_id: str) -> None:
    """Delete a session."""
    if state.sessions.delete(session_id):
        ui.success(f"Deleted session {session_id}")
    else:
        ui.error(f"no such session: {session_id}")
        raise SystemExit(1)


# --- chat ------------------------------------------------------------------
@cli.command()
@click.option("--message", "-m", default=None, help="One-shot message (no REPL)")
@click.option("--session", "session_id", default=None, help="Resume a session id")
@click.option("--new", "new_session", is_flag=True, help="Start a fresh session")
@click.option("--system", default=None, help="Custom system prompt")
@click.pass_obj
def chat(state: State, message: str | None, session_id: str | None, new_session: bool, system: str | None) -> None:
    """Start an interactive AI chat (streaming)."""
    _chat(state, message=message, session_id=session_id, new_session=new_session, system=system)


def _chat(
    state: State,
    message: str | None = None,
    session_id: str | None = None,
    new_session: bool = False,
    system: str | None = None,
) -> None:
    provider = state.ai_provider()
    sm = state.sessions
    session = None
    if not new_session and session_id:
        session = sm.get(session_id) or sm.create(
            provider=state.provider_name(), model=state.provider_model()
        )
    else:
        session = sm.create(provider=state.provider_name(), model=state.provider_model())

    default_system = (
        "You are the Fariid Tech Security AI, an expert security analyst helping with "
        "authorized security testing, CTFs, and defensive security."
    )
    messages: list[Message] = [Message(role=Role.SYSTEM, content=system or default_system)]
    for m in session.messages:
        if m.get("role") in ("user", "assistant"):
            messages.append(Message(role=m["role"], content=m.get("content", "")))

    def reply_stream(prompt: str) -> str:
        parts: list[str] = []
        try:
            for chunk in provider.chat_stream(messages):
                if chunk.content:
                    ui.emit(chunk.content)
                    parts.append(chunk.content)
        except AIError as exc:
            ui.error(_friendly_ai_error(exc))
            return ""
        ui.emit("\n")
        return "".join(parts)

    if message is not None:
        safe, _ = redact_text(message)
        messages.append(Message(role=Role.USER, content=safe))
        reply = reply_stream(message)
        sm.add_message(session.id, "user", safe)
        if reply:
            sm.add_message(session.id, "assistant", reply)
        return

    ui.success(f"Session {session.id} — type /help for commands, /exit to quit.")
    while True:
        try:
            user = ui.prompt("fariid-sec > ")
        except (KeyboardInterrupt, EOFError):
            ui.emit("\n")
            break
        user = user.strip()
        if not user:
            continue
        if user in ("/exit", "/quit", "exit", "quit"):
            break
        if user == "/help":
            ui.info("/exit quit  /clear reset  /session <id> switch  /help this help")
            continue
        if user == "/clear":
            messages = messages[:1]
            ui.info("Conversation cleared.")
            continue
        safe, _ = redact_text(user)
        messages.append(Message(role=Role.USER, content=safe))
        reply = reply_stream(user)
        sm.add_message(session.id, "user", safe)
        if reply:
            messages.append(Message(role=Role.ASSISTANT, content=reply))
            sm.add_message(session.id, "assistant", reply)
    ui.info(f"Session saved as {session.id}")


# --- agent -----------------------------------------------------------------
@cli.command()
@click.argument("request", required=False)
@click.option("--target", default=None, help="Authorized target for this request")
@click.pass_obj
def agent(state: State, request: str | None, target: str | None) -> None:
    """Run the AI security agent (tool-calling loop)."""
    provider = state.ai_provider()
    def make_agent() -> SecurityAgent:
        return SecurityAgent(
            provider,
            state.registry,
            state.runner,
            state.normalize,
            mode=state.mode,
            target=target,
            platform=detect_platform(),
            confirm=lambda m: ui.confirm(m),
        )

    if request:
        _run_agent_once(make_agent(), request)
        return

    ui.success("Security agent — describe your authorized task (/exit to quit).")
    while True:
        try:
            user = ui.prompt("agent > ")
        except (KeyboardInterrupt, EOFError):
            ui.emit("\n")
            break
        if not user or user in ("/exit", "/quit", "exit", "quit"):
            if not user:
                continue
            break
        _run_agent_once(make_agent(), user)


def _run_agent_once(agent: SecurityAgent, request: str) -> None:
    try:
        with ui.spinner("Thinking…"):
            result = agent.run(request)
    except AIError as exc:
        ui.error(_friendly_ai_error(exc))
        return

    if result.reasoning:
        PASS.print(f"[dim]{result.reasoning}[/dim]")
    ui.print_markdown(result.content or "")
    if result.tool_history:
        ui.heading("Actions performed")
        for entry in result.tool_history:
            ui.info(f"  - {entry.get('tool')} ({entry.get('risk', 'low')})")
    if result.usage:
        u = result.usage
        ui.info(f"tokens: {u.prompt_tokens} in / {u.completion_tokens} out")


# --- ask -------------------------------------------------------------------
@cli.command()
@click.argument("request")
@click.option("--target", default=None, help="Target to focus on")
@click.option("--execute", is_flag=True, help="Execute the plan via the agent")
@click.pass_obj
def ask(state: State, request: str, target: str | None, execute: bool) -> None:
    """Convert a natural-language request into a structured plan."""
    provider = state.ai_provider()
    try:
        plan = Planner(provider).plan(request, state.mode, target)
    except AIError as exc:
        ui.error(_friendly_ai_error(exc))
        raise SystemExit(1) from None

    if state.json_out:
        PASS.print(json.dumps(plan.to_dict(), indent=2))
    else:
        ui.render_kv(
            "Execution Plan",
            [
                ("Target", plan.target or "(not specified)"),
                ("Objective", plan.objective),
                ("Risk", plan.risk),
                ("Tools", ", ".join(plan.tools) or "none"),
            ],
        )
        for action in plan.actions:
            PASS.print(f"  • {action}")

    do_execute = execute or (not state.yes and ui.confirm("Execute this plan with the agent?"))
    if do_execute:
        agent = SecurityAgent(
            provider,
            state.registry,
            state.runner,
            state.normalize,
            mode=state.mode,
            target=plan.target or target,
            platform=detect_platform(),
            confirm=lambda m: ui.confirm(m),
        )
        _run_agent_once(agent, request)


# --- explain ---------------------------------------------------------------
@cli.command()
@click.argument("text")
@click.pass_obj
def explain(state: State, text: str) -> None:
    """Explain a security tool result or concept."""
    safe, _ = redact_text(text)
    provider = state.ai_provider()
    messages = [
        Message(
            role=Role.SYSTEM,
            content="You explain security tool output and concepts clearly and concisely.",
        ),
        Message(role=Role.USER, content=f"Explain the following security output/concept:\n\n{safe}"),
    ]
    try:
        _stream_messages(provider, messages)
    except AIError as exc:
        ui.error(_friendly_ai_error(exc))
        raise SystemExit(1) from None


# --- analyze ---------------------------------------------------------------
@cli.command()
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.pass_obj
def analyze(state: State, path: str) -> None:
    """Analyze a saved results JSON or raw tool output with the AI."""
    content = Path(path).read_text(encoding="utf-8", errors="replace")
    safe, _ = redact_text(content)
    provider = state.ai_provider()
    messages = [
        Message(
            role=Role.SYSTEM,
            content=(
                "You are a security analyst. Analyze the provided tool output or results and "
                "report findings with severity, evidence, affected service, impact, and remediation."
            ),
        ),
        Message(role=Role.USER, content=f"Analyze this security data:\n\n{safe}"),
    ]
    try:
        _stream_messages(provider, messages)
    except AIError as exc:
        ui.error(_friendly_ai_error(exc))
        raise SystemExit(1) from None


def _stream_messages(provider: AIProvider, messages: list[Message]) -> None:
    for chunk in provider.chat_stream(messages):
        if chunk.content:
            ui.emit(chunk.content)
    ui.emit("\n")


# --- scan / recon / web-audit / network / dns / ssl / vuln -----------------
@cli.command()
@click.argument("target")
@click.option("--ports", default=None, help="Ports to scan (e.g. 1-1000)")
@click.option("--nuclei", is_flag=True, help="Also run nuclei templates")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation (authorized targets only)")
@click.pass_obj
def scan(state: State, target: str, ports: str | None, nuclei: bool, yes: bool) -> None:
    """Actively scan a target (nmap + optional nuclei)."""
    if yes:
        state.yes = True
    tools = ["nmap"] + (["nuclei"] if nuclei else [])
    if not _authorize(state, target, tools, "AUTHORIZED SECURITY TEST"):
        return
    results = _run_nmap(state, target, ports)
    findings = _findings_from_nmap(results.get("findings", []), target)
    timeline = [{"time": _now(), "action": f"nmap scan of {target}"}]
    if nuclei:
        n = _run_nuclei(state, target)
        findings += _findings_from_nuclei(n.get("findings", []), target)
        timeline.append({"time": _now(), "action": f"nuclei scan of {target}"})
    _finish_scan(state, target, "active", tools, findings, timeline)


@cli.command()
@click.argument("target")
@click.pass_obj
def recon(state: State, target: str) -> None:
    """Passive reconnaissance (whois, DNS, HTTP headers)."""
    ok, reason = validate_target(target)
    if not ok:
        ui.error(reason)
        raise SystemExit(1)
    ui.heading(f"Reconnaissance: {target}")
    findings: list[Finding] = []
    timeline: list[dict] = []

    for _tool, argv in _recon_commands(target):
        res = _run(state, argv)
        timeline.append({"time": _now(), "action": f"{argv[0]} {target}"})
        if res.get("ok") and res.get("output"):
            ui.heading(argv[0])
            PASS.print(res["output"][:4000])
    _finish_scan(state, target, "passive", [a[0] for a in _recon_commands(target)], findings, timeline)


def _recon_commands(target: str) -> list[tuple[str, list[str]]]:
    cmds: list[tuple[str, list[str]]] = []
    if which("whois"):
        cmds.append(("whois", ["whois", target]))
    if which("dig"):
        cmds.append(("dig", ["dig", "+short", "A", target]))
    if which("curl"):
        scheme = target if "://" in target else f"https://{target}"
        cmds.append(("curl", ["curl", "-sS", "-I", "-L", "--max-time", "15", scheme]))
    return cmds


@cli.command()
@click.argument("target")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation (authorized targets only)")
@click.pass_obj
def web_audit(state: State, target: str, yes: bool) -> None:
    """Audit a web application (fingerprint + content discovery + vuln scan)."""
    if yes:
        state.yes = True
    if "://" not in target:
        target = f"https://{target}"
    tools = ["whatweb", "gobuster", "nuclei"]
    if not _authorize(state, target, tools, "AUTHORIZED WEB AUDIT"):
        return
    findings: list[Finding] = []
    timeline: list[dict] = []
    for tool, argv in [
        ("whatweb", ["whatweb", "-a", "1", target]),
        ("gobuster", ["gobuster", "dir", "-u", target, "-w", "/usr/share/wordlists/dirb/common.txt", "-q"]),
    ]:
        res = _run(state, argv, timeout=300)
        timeline.append({"time": _now(), "action": f"{tool} {target}"})
        if res.get("output"):
            ui.heading(tool)
            PASS.print(res["output"][:4000])
    n = _run_nuclei(state, target)
    findings += _findings_from_nuclei(n.get("findings", []), target)
    timeline.append({"time": _now(), "action": f"nuclei {target}"})
    _finish_scan(state, target, "active", tools, findings, timeline)


@cli.command()
@click.argument("target")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation (authorized targets only)")
@click.pass_obj
def network(state: State, target: str, yes: bool) -> None:
    """Scan a network range (nmap/masscan host discovery)."""
    if yes:
        state.yes = True
    if classify_target(target) != "cidr":
        ui.warn(f"{target} is not a CIDR range; treating as a single host.")
    tools = ["nmap"]
    if not _authorize(state, target, tools, "AUTHORIZED NETWORK SCAN"):
        return
    argv = ["nmap", "-sn", "-oG", "-", target] if which("nmap") else ["nmap", "-sP", target]
    res = _run(state, argv)
    ui.heading("Live hosts")
    if res.get("output"):
        PASS.print(res["output"][:6000])
    _finish_scan(state, target, "active", tools, [], [{"time": _now(), "action": f"network scan {target}"}])


@cli.command()
@click.argument("domain")
@click.pass_obj
def dns(state: State, domain: str) -> None:
    """Enumerate DNS records for a domain."""
    tools = ["dig"]
    if which("dnsrecon"):
        argv = ["dnsrecon", "-d", domain]
        tools = ["dnsrecon"]
    else:
        argv = ["dig", "+short", "ANY", domain]
    res = _run(state, argv)
    if res.get("output"):
        PASS.print(res["output"])
    _finish_scan(state, domain, "passive", tools, [], [{"time": _now(), "action": f"dns enum {domain}"}])


@cli.command()
@click.argument("host")
@click.pass_obj
def ssl(state: State, host: str) -> None:
    """Inspect TLS/SSL configuration and certificate."""
    tools = ["openssl"]
    argv = ["openssl", "s_client", "-connect", f"{host}:443", "-servername", host, "-brief"]
    res = _run(state, argv, input_data="\n")
    if res.get("output"):
        PASS.print(res["output"][:4000])
    _finish_scan(state, host, "passive", tools, [], [{"time": _now(), "action": f"ssl inspect {host}"}])


@cli.command()
@click.argument("target")
@click.option("--yes", "-y", is_flag=True, help="Skip confirmation (authorized targets only)")
@click.pass_obj
def vuln(state: State, target: str, yes: bool) -> None:
    """Run vulnerability scanners against a target."""
    if yes:
        state.yes = True
    tools = ["nuclei"]
    if not _authorize(state, target, tools, "AUTHORIZED VULNERABILITY SCAN"):
        return
    n = _run_nuclei(state, target)
    findings = _findings_from_nuclei(n.get("findings", []), target)
    _finish_scan(state, target, "active", tools, findings, [{"time": _now(), "action": f"vuln scan {target}"}])


# --- report ----------------------------------------------------------------
@cli.command()
@click.option("--input", "input_path", required=True, type=click.Path(exists=True, dir_okay=False))
@click.option("--format", "fmt", default="html", type=click.Choice(["html", "json", "md", "txt", "pdf"]))
@click.option("--output", "output", default=None, help="Output file path")
@click.pass_obj
def report(state: State, input_path: str, fmt: str, output: str | None) -> None:
    """Generate a report from a results JSON file."""
    data = json.loads(Path(input_path).read_text(encoding="utf-8"))
    report = _report_from_dict(data)
    gen = ReportGenerator(report)
    if output is None:
        output = str(state.manager.reports_dir / f"report-{_now().replace(':', '').replace('-', '')}.{fmt}")
    path = gen.write(Path(output), fmt)
    ui.success(f"Report written to {path}")


# --- update ----------------------------------------------------------------
@cli.command()
def update() -> None:
    """Update the CLI (git pull if a clone, else pip upgrade)."""
    import subprocess

    if Path(".git").exists():
        ui.info("Running 'git pull'…")
        subprocess.run(["git", "pull"], check=False)
        ui.success("Updated from git.")
    else:
        ui.info("Run: pip install --upgrade fariid-sec")
        ui.info("or clone the repo and run install.sh")


# --- helpers ---------------------------------------------------------------
def _now() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _friendly_ai_error(exc: AIError) -> str:
    if isinstance(exc, AuthenticationError):
        return "Invalid API key. Run: fariid-sec config set api-key"
    if isinstance(exc, RateLimitError):
        return "Rate limited by the AI provider. Try again shortly."
    return str(exc)


def _authorize(state: State, target: str, tools: list[str], mode_label: str) -> bool:
    ok, reason = validate_target(target)
    if not ok:
        ui.error(reason)
        raise SystemExit(1)
    authorized = state.targets.is_authorized(target)
    implicit = target.lower() in ("localhost", "127.0.0.1", "::1") or is_special_address(target)

    ui.heading("Authorization")
    ui.console_panel(
        f"Target:\n{target}\n\nMode:\n{mode_label}\n\nTools:\n{', '.join(tools)}"
    )
    if state.yes:
        if authorized or implicit:
            ui.success("Authorized — proceeding.")
            return True
        ui.error(
            "--yes requires the target in your authorized list "
            "(fariid-sec target add <name> <target>)"
        )
        return False
    return ui.confirm("Continue? [y/N]", default=False)


def _run(
    state: State,
    argv: list[str],
    timeout: float | None = None,
    input_data: str | None = None,
) -> dict[str, Any]:
    try:
        res = state.runner.run(argv, timeout=timeout, input=input_data)
    except CommandNotFound:
        return {"ok": False, "output": "", "findings": [], "error": f"{argv[0]} not installed"}
    norm = state.normalize.normalize(res)
    return {
        "ok": res.returncode == 0,
        "output": norm["stdout"]["text"],
        "findings": [],
        "returncode": res.returncode,
    }


def _run_nmap(state: State, target: str, ports: str | None) -> dict[str, Any]:
    if not state.registry.is_installed("nmap"):
        ui.error("nmap is not installed. Install with: sudo apt install nmap")
        return {"ok": False, "output": "", "findings": []}
    argv = ["nmap", "-oG", "-", "-sV", "--top-ports", "1000"]
    if ports:
        argv += ["-p", ports]
    argv.append(target)
    with ui.spinner("Running nmap…"):
        res = state.runner.run(argv, timeout=600)
    norm = state.normalize.normalize(res)
    findings = OutputParser.parse("nmap", res.stdout).get("findings", []) if res.returncode == 0 else []
    return {"ok": res.returncode == 0, "output": norm["stdout"]["text"], "findings": findings}


def _run_nuclei(state: State, target: str) -> dict[str, Any]:
    if not state.registry.is_installed("nuclei"):
        ui.warn("nuclei not installed — skipping (sudo apt install nuclei)")
        return {"ok": False, "output": "", "findings": []}
    argv = ["nuclei", "-u", target, "-jsonl", "-silent"]
    with ui.spinner("Running nuclei…"):
        res = state.runner.run(argv, timeout=600)
    norm = state.normalize.normalize(res)
    findings = OutputParser.parse("nuclei", res.stdout).get("findings", []) if res.returncode == 0 else []
    return {"ok": res.returncode == 0, "output": norm["stdout"]["text"], "findings": findings}


def _findings_from_nmap(hosts: list[dict], target: str) -> list[Finding]:
    out: list[Finding] = []
    for h in hosts:
        for p in h.get("open_ports", []):
            svc = p.get("service") or "unknown"
            out.append(
                Finding(
                    title=f"Open port {p['port']}/{p['protocol']} ({svc})",
                    severity="info",
                    target=h.get("ip", target),
                    service=svc,
                    evidence=f"{p['port']}/{p['protocol']} open — {p.get('version') or ''}".strip(),
                    description=f"Service {svc} is exposed on port {p['port']}.",
                    remediation="Restrict access via firewall if the service is not required.",
                )
            )
    return out


def _findings_from_nuclei(items: list[dict], target: str) -> list[Finding]:
    out: list[Finding] = []
    for f in items:
        out.append(
            Finding(
                title=f.get("name") or f.get("id") or "nuclei finding",
                severity=(f.get("severity") or "info").lower(),
                target=f.get("host") or target,
                service=f.get("type") or "",
                evidence=f.get("url") or f.get("matched-at") or "",
                description=f.get("description") or "",
                remediation="Apply vendor guidance and update the affected component.",
            )
        )
    return out


def _finish_scan(
    state: State,
    target: str,
    mode: str,
    tools: list[str],
    findings: list[Finding],
    timeline: list[dict],
) -> None:
    summary = (
        f"Assessment of {target} completed using {', '.join(tools) or 'no tools'}. "
        f"{len(findings)} finding(s) recorded."
    )
    data = ReportData(
        title=f"Security Assessment — {target}",
        target=target,
        scope=target,
        mode=mode,
        summary=summary,
        tools=tools,
        findings=findings,
        timeline=timeline,
    )
    ui.heading("Summary")
    ui.render_kv(
        "Findings",
        [("Total", str(len(findings)))] + [(k, str(v)) for k, v in data.severity_counts().items()],
    )
    for f in findings[:20]:
        PASS.print(f"  [bold]{f.severity.upper():7}[/bold] {f.title}")

    # Save JSON results for `fariid-sec report`.
    out_dir = state.manager.reports_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"scan-{_now().replace(':', '').replace('-', '').replace('+00:00', '')}.json"
    out_path.write_text(json.dumps(data.to_dict(), indent=2), encoding="utf-8")
    ui.success(f"Results saved to {out_path}")
    ui.info(f"Generate a report: fariid-sec report --input {out_path} --format html")


def _report_from_dict(d: dict) -> ReportData:
    findings = [
        Finding(
            title=f.get("title", ""),
            severity=f.get("severity", "info"),
            target=f.get("target", ""),
            service=f.get("service", ""),
            evidence=f.get("evidence", ""),
            description=f.get("description", ""),
            impact=f.get("impact", ""),
            remediation=f.get("remediation", ""),
            references=f.get("references", []),
        )
        for f in d.get("findings", [])
    ]
    return ReportData(
        title=d.get("title", "Security Assessment Report"),
        target=d.get("target", ""),
        scope=d.get("scope", ""),
        mode=d.get("mode", "passive"),
        summary=d.get("summary", ""),
        tools=d.get("tools", []),
        findings=findings,
        timeline=d.get("timeline", []),
        raw_results=d.get("raw_results", {}),
        generated_at=d.get("generated_at", _now()),
    )


if __name__ == "__main__":
    cli()
