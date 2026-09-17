"""Controlled subprocess execution.

All external security tools run through :class:`CommandRunner`, which never
uses a shell (no ``shell=True``), always passes an argument vector, enforces a
timeout, and captures output as text. This is the single choke point for
executing Kali binaries.
"""

from __future__ import annotations

import os
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field


class CommandError(Exception):
    """Base error for command execution."""


class CommandNotFound(CommandError):
    """The requested binary is not installed or not on PATH."""

    def __init__(self, binary: str, install_hint: str = "") -> None:
        self.binary = binary
        self.install_hint = install_hint
        super().__init__(f"{binary!r} not found")


@dataclass
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float = 0.0
    timed_out: bool = False
    meta: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    @property
    def output(self) -> str:
        return self.stdout if self.stdout.strip() else self.stderr

    def to_dict(self) -> dict:
        return {
            "command": " ".join(self.command),
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration": round(self.duration, 3),
            "timed_out": self.timed_out,
        }


class CommandRunner:
    """Run external binaries safely with timeout and output capture."""

    def __init__(
        self,
        timeout: float = 300.0,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
    ) -> None:
        self.timeout = timeout
        self.cwd = cwd
        self.env = env

    def _merged_env(self) -> dict[str, str] | None:
        if self.env is None:
            return None
        merged = os.environ.copy()
        merged.update(self.env)
        return merged

    def run(
        self, argv: list[str], timeout: float | None = None, input: str | None = None
    ) -> CommandResult:
        """Run ``argv`` (no shell) and return captured output.

        ``input`` is sent to the child's stdin and then closed (useful for tools
        like ``openssl s_client`` that exit on EOF).
        """
        effective_timeout = timeout if timeout is not None else self.timeout
        started = time.monotonic()
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                input=input,
                timeout=effective_timeout,
                cwd=self.cwd,
                env=self._merged_env(),
                check=False,
            )
        except FileNotFoundError as exc:
            raise CommandNotFound(argv[0]) from exc
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode(
                "utf-8", errors="replace"
            )
            stderr = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode(
                "utf-8", errors="replace"
            )
            return CommandResult(
                command=argv,
                returncode=-1,
                stdout=stdout,
                stderr=stderr,
                duration=time.monotonic() - started,
                timed_out=True,
            )
        return CommandResult(
            command=argv,
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            duration=time.monotonic() - started,
        )

    def stream(
        self,
        argv: list[str],
        timeout: float | None = None,
        on_line: Callable[[str], None] | None = None,
    ) -> CommandResult:
        """Run ``argv`` and stream each output line through ``on_line``."""
        effective_timeout = timeout if timeout is not None else self.timeout
        started = time.monotonic()
        stdout_chunks: list[str] = []
        stderr_chunks: list[str] = []

        try:
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=self.cwd,
                env=self._merged_env(),
            )
        except FileNotFoundError as exc:
            raise CommandNotFound(argv[0]) from exc

        assert proc.stdout is not None and proc.stderr is not None
        try:
            for line in proc.stdout:
                line = line.rstrip("\n")
                stdout_chunks.append(line)
                if on_line:
                    on_line(line)
            proc.wait(timeout=effective_timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return CommandResult(
                command=argv,
                returncode=-1,
                stdout="\n".join(stdout_chunks),
                stderr="\n".join(stderr_chunks),
                duration=time.monotonic() - started,
                timed_out=True,
            )

        stderr = proc.stderr.read()
        return CommandResult(
            command=argv,
            returncode=proc.returncode,
            stdout="\n".join(stdout_chunks),
            stderr=stderr,
            duration=time.monotonic() - started,
        )

    @staticmethod
    def which(binary: str) -> str | None:
        """Return the path to ``binary`` or ``None`` (thin wrapper for tests)."""
        import shutil

        return shutil.which(binary)
