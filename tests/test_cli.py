"""CLI tests via click's CliRunner."""

from __future__ import annotations

from click.testing import CliRunner
from fariid_sec.cli.main import cli


def test_version() -> None:
    result = CliRunner().invoke(cli, ["version"])
    assert result.exit_code == 0
    assert "Fariid Tech Security AI" in result.output


def test_help_lists_commands() -> None:
    result = CliRunner().invoke(cli, ["--help"])
    assert result.exit_code == 0
    for name in ["chat", "agent", "scan", "recon", "tools", "doctor", "report", "config"]:
        assert name in result.output


def test_config_set_and_get() -> None:
    runner = CliRunner()
    assert runner.invoke(cli, ["config", "set", "provider", "ollama"]).exit_code == 0
    result = runner.invoke(cli, ["config", "get", "provider"])
    assert "ollama" in result.output


def test_target_add_and_list() -> None:
    runner = CliRunner()
    assert runner.invoke(cli, ["target", "add", "lab", "127.0.0.1"]).exit_code == 0
    result = runner.invoke(cli, ["target", "list"])
    assert "127.0.0.1" in result.output


def test_scan_requires_authorization_with_yes() -> None:
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "8.8.8.8", "--yes"])
    assert "authorized list" in result.output
