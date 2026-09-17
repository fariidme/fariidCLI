"""Rich terminal UI helpers: banner, prompts, tables, spinners."""

from __future__ import annotations

import sys
from collections.abc import Iterator
from contextlib import contextmanager

from rich import box
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from .. import __version__

console = Console(highlight=False)

ACCENT = "bold magenta"
OK = "green"
WARN = "yellow"
ERR = "red"


def banner(provider: str = "", model: str = "", mode: str = "", platform: str = "") -> None:
    title = Text(" FARIID TECH SECURITY AI ", style="bold black on magenta")
    subtitle = Text(" AI-Powered Kali Security CLI ", style="bold magenta")
    console.print(Panel(Text("\n") + title + Text("\n") + subtitle + Text("\n"),
                        box=box.ROUNDED, border_style="magenta"))
    meta = Table.grid(padding=(0, 2))
    meta.add_column(style="dim", justify="right")
    meta.add_column(style="bold")
    meta.add_row("Provider", provider or "-")
    meta.add_row("Model", model or "-")
    meta.add_row("Platform", platform or "-")
    meta.add_row("Mode", (mode or "passive").title())
    meta.add_row("Version", __version__)
    console.print(meta)
    console.print()


def success(msg: str) -> None:
    console.print(f"[{OK}][+][/{OK}] {msg}")


def warn(msg: str) -> None:
    console.print(f"[{WARN}][!][/{WARN}] {msg}")


def error(msg: str) -> None:
    console.print(f"[{ERR}][-][/{ERR}] {msg}")


def info(msg: str) -> None:
    console.print(f"[dim]{msg}[/dim]")


def heading(msg: str) -> None:
    console.print(f"\n[bold underline]{msg}[/bold underline]")


def confirm(prompt: str, default: bool = False) -> bool:
    return bool(Confirm.ask(prompt, default=default))


def prompt(prompt: str, default: str = "", password: bool = False) -> str:
    return Prompt.ask(prompt, default=default, password=password)


def print_markdown(text: str) -> None:
    console.print(Markdown(text))


def render_table(title: str, columns: list[str], rows: list[list]) -> None:
    table = Table(title=title, title_style="bold", box=None, header_style="bold magenta")
    for col in columns:
        table.add_column(col, overflow="fold")
    for row in rows:
        table.add_row(*[str(c) for c in row])
    console.print(table)


def render_kv(title: str, items: list[tuple[str, str]]) -> None:
    table = Table(title=title, title_style="bold", box=None, show_header=False)
    table.add_column(style="dim", justify="right")
    table.add_column(style="bold")
    for key, value in items:
        table.add_row(str(key), str(value))
    console.print(table)


def console_panel(content: str, title: str = "") -> None:
    """Print a bordered panel (used for authorization prompts)."""
    console.print(Panel(content, title=title, border_style="magenta"))


@contextmanager
def spinner(text: str) -> Iterator[None]:
    status = console.status(text, spinner="dots")
    status.start()
    try:
        yield
    finally:
        status.stop()


def emit(text: str, end: str = "") -> None:
    """Write streaming output to the console without a newline.

    ``markup=False`` so model output containing ``[``/``]`` is never parsed as
    rich markup.
    """
    console.print(text, end=end, markup=False, highlight=False)
    sys.stdout.flush()
