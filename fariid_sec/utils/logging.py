"""Structured logging configuration for the CLI.

All loggers are namespaced under ``fariid_sec.*`` so we can control verbosity
globally without leaking third-party debug output into the terminal.
"""

from __future__ import annotations

import logging
import sys

_configured = False

DEFAULT_FORMAT = "%(asctime)s %(levelname)-7s %(name)s | %(message)s"


def setup_logging(level: int = logging.INFO, verbose: bool = False) -> None:
    """Configure the root ``fariid_sec`` logger once per process."""
    global _configured
    if _configured:
        return

    target_level = logging.DEBUG if verbose else level
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(DEFAULT_FORMAT, datefmt="%H:%M:%S"))

    root = logging.getLogger("fariid_sec")
    root.setLevel(target_level)
    root.addHandler(handler)
    root.propagate = False

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """Return a child logger namespaced under ``fariid_sec``."""
    return logging.getLogger(f"fariid_sec.{name}")
