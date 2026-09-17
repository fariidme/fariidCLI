"""Filesystem helpers: config/state directory resolution and safe writes."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def config_home() -> Path:
    """Resolve the Fariid config directory.

    Order of precedence: ``$FARIID_SEC_HOME`` -> ``$XDG_CONFIG_HOME`` ->
    ``~/.config/fariid-sec``.
    """
    if env := os.environ.get("FARIID_SEC_HOME"):
        return Path(env).expanduser()
    if xdg := os.environ.get("XDG_CONFIG_HOME"):
        return Path(xdg).expanduser() / "fariid-sec"
    return Path.home() / ".config" / "fariid-sec"


def state_home() -> Path:
    """Resolve the state directory (reports, caches, logs)."""
    if xdg := os.environ.get("XDG_STATE_HOME"):
        return Path(xdg).expanduser() / "fariid-sec"
    return Path.home() / ".local" / "share" / "fariid-sec"


def ensure_dir(path: Path, mode: int = 0o700) -> Path:
    """Create a directory (and parents) if missing. Returns ``path``."""
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(mode)
    except OSError:
        pass
    return path


def atomic_write_text(path: Path, text: str, mode: int = 0o600) -> None:
    """Write ``text`` to ``path`` atomically with restricted permissions."""
    ensure_dir(path.parent)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=".part")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")
