"""Platform and OS detection helpers.

We target Kali Linux first, but everything degrades gracefully on any
Linux/macOS/Windows box for development and CI.
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
from dataclasses import asdict, dataclass


@dataclass
class PlatformInfo:
    system: str
    release: str
    version: str
    machine: str
    python: str
    distro: str
    is_kali: bool
    is_linux: bool
    shell: str


def _read_os_release() -> dict[str, str]:
    """Parse /etc/os-release into a dict (empty on non-Linux)."""
    data: dict[str, str] = {}
    path = "/etc/os-release"
    if not os.path.exists(path):
        return data
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or "=" not in line or line.startswith("#"):
                    continue
                key, _, value = line.partition("=")
                data[key] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    return data


def detect_platform() -> PlatformInfo:
    """Return a snapshot of the current platform."""
    os_release = _read_os_release()
    distro_id = os_release.get("ID", "").lower()
    distro_like = os_release.get("ID_LIKE", "").lower()
    is_kali = distro_id == "kali" or "kali" in distro_like

    return PlatformInfo(
        system=platform.system(),
        release=platform.release(),
        version=platform.version(),
        machine=platform.machine(),
        python=f"{sys.implementation.name} {platform.python_version()}",
        distro=os_release.get("PRETTY_NAME", "") or os_release.get("NAME", "") or "unknown",
        is_kali=is_kali,
        is_linux=platform.system() == "Linux",
        shell=os.environ.get("SHELL", "unknown"),
    )


def is_kali() -> bool:
    return detect_platform().is_kali


def is_linux() -> bool:
    return platform.system() == "Linux"


def which(binary: str) -> str | None:
    """Return the full path to ``binary`` if it is on PATH, else ``None``."""
    return shutil.which(binary)


def platform_summary() -> dict:
    return asdict(detect_platform())
