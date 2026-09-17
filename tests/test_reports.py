"""Report generator tests."""

from __future__ import annotations

import json

from fariid_sec.reports import Finding, ReportData, ReportGenerator


def _sample() -> ReportData:
    return ReportData(
        title="Test Report",
        target="example.com",
        mode="active",
        tools=["nmap"],
        summary="One finding.",
        findings=[
            Finding(title="Open port 80", severity="low", service="http", evidence="80/open/tcp"),
            Finding(title="SQL injection", severity="high", evidence="vulnerable param"),
        ],
        timeline=[{"time": "now", "action": "scan"}],
    )


def test_render_html() -> None:
    html = ReportGenerator(_sample()).render("html")
    assert "<html" in html
    assert "Open port 80" in html
    assert "SQL injection" in html


def test_render_markdown() -> None:
    md = ReportGenerator(_sample()).render("md")
    assert "# Test Report" in md
    assert "SQL injection" in md


def test_render_json_roundtrip() -> None:
    data = json.loads(ReportGenerator(_sample()).render("json"))
    assert data["target"] == "example.com"
    assert data["finding_summary"]["high"] == 1
    assert data["findings"][0]["severity"] == "low"


def test_render_text() -> None:
    txt = ReportGenerator(_sample()).render("txt")
    assert "Test Report" in txt
    assert "SQL injection" in txt


def test_write_creates_file(tmp_path) -> None:
    out = ReportGenerator(_sample()).write(tmp_path / "report.html")
    assert out.exists()
    assert "Report" in out.read_text(encoding="utf-8")
