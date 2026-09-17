"""Report generation in HTML, JSON, Markdown, TXT and (optionally) PDF."""

from __future__ import annotations

import html
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Finding:
    title: str
    severity: str = "info"
    target: str = ""
    service: str = ""
    evidence: str = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReportData:
    title: str = "Security Assessment Report"
    target: str = ""
    scope: str = ""
    mode: str = "passive"
    summary: str = ""
    tools: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    raw_results: dict[str, Any] = field(default_factory=dict)
    generated_at: str = field(default_factory=_now)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["finding_summary"] = self.severity_counts()
        return data

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            sev = (f.severity or "unknown").lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity.lower(), 5))


class ReportGenerator:
    def __init__(self, data: ReportData) -> None:
        self.data = data

    # --- dispatch ----------------------------------------------------------
    def render(self, fmt: str) -> str:
        fmt = fmt.lower().lstrip(".")
        if fmt == "json":
            return self.render_json()
        if fmt == "md":
            return self.render_markdown()
        if fmt == "txt":
            return self.render_text()
        if fmt == "html":
            return self.render_html()
        if fmt == "pdf":
            return self.render_pdf()
        raise ValueError(f"unsupported report format: {fmt!r}")

    def write(self, path: Path, fmt: str | None = None) -> Path:
        fmt = fmt or path.suffix.lstrip(".")
        content = self.render(fmt)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    # --- formats -----------------------------------------------------------
    def render_json(self) -> str:
        return json.dumps(self.data.to_dict(), indent=2)

    def render_markdown(self) -> str:
        d = self.data
        lines: list[str] = [f"# {d.title}", ""]
        lines += ["## Executive Summary", "", d.summary or "*No summary provided.*", ""]
        lines += ["## Target", "", f"**Target:** {d.target or 'n/a'}", ""]
        lines += [f"**Scope:** {d.scope or 'n/a'}", ""]
        lines += [f"**Mode:** {d.mode}", ""]
        lines += ["## Tools Used", "", ", ".join(d.tools) if d.tools else "*None*", ""]
        lines += ["## Findings", ""]
        if not d.findings:
            lines += ["*No findings.*", ""]
        for f in _sort_findings(d.findings):
            lines += [f"### [{f.severity.upper()}] {f.title}", ""]
            if f.target:
                lines += [f"- **Target:** {f.target}"]
            if f.service:
                lines += [f"- **Service:** {f.service}"]
            if f.description:
                lines += [f"- **Description:** {f.description}"]
            if f.evidence:
                lines += [f"- **Evidence:** {f.evidence}"]
            if f.impact:
                lines += [f"- **Impact:** {f.impact}"]
            if f.remediation:
                lines += [f"- **Remediation:** {f.remediation}"]
            lines += [""]
        lines += ["## Timeline", ""]
        for step in d.timeline:
            lines += [f"- {step.get('time', '')} — {step.get('action', '')}"]
        lines += ["", f"*Generated {d.generated_at}*", ""]
        return "\n".join(lines)

    def render_text(self) -> str:
        d = self.data
        lines: list[str] = [f"{d.title}", "=" * len(d.title), ""]
        lines += ["EXECUTIVE SUMMARY", "-" * 17, d.summary or "No summary.", ""]
        lines += [f"TARGET:      {d.target or 'n/a'}"]
        lines += [f"SCOPE:       {d.scope or 'n/a'}"]
        lines += [f"MODE:        {d.mode}"]
        lines += [f"TOOLS:       {', '.join(d.tools) if d.tools else 'none'}", ""]
        lines += ["FINDINGS", "-" * 8, ""]
        for f in _sort_findings(d.findings):
            lines += [f"[{f.severity.upper()}] {f.title}"]
            if f.target:
                lines += [f"    Target:      {f.target}"]
            if f.service:
                lines += [f"    Service:     {f.service}"]
            if f.evidence:
                lines += [f"    Evidence:    {f.evidence}"]
            if f.remediation:
                lines += [f"    Remediation: {f.remediation}"]
            lines += [""]
        lines += [f"Generated: {d.generated_at}"]
        return "\n".join(lines)

    def render_html(self) -> str:
        d = self.data
        counts = d.severity_counts()
        esc = html.escape
        rows = []
        for f in _sort_findings(d.findings):
            sev = (f.severity or "info").lower()
            rows.append(
                f"""
        <tr>
          <td><span class="sev {sev}">{esc(sev)}</span></td>
          <td>{esc(f.title)}</td>
          <td>{esc(f.target or '')}</td>
          <td>{esc(f.service or '')}</td>
        </tr>"""
            )
        finding_rows = "\n".join(rows)

        detail_rows = []
        for f in _sort_findings(d.findings):
            sev = (f.severity or "info").lower()
            detail_rows.append(
                f"""
        <div class="finding">
          <h3><span class="sev {sev}">{esc(sev)}</span> {esc(f.title)}</h3>
          <p><strong>Target:</strong> {esc(f.target or 'n/a')} &nbsp;
             <strong>Service:</strong> {esc(f.service or 'n/a')}</p>
          <p><strong>Evidence:</strong> <code>{esc(f.evidence or '')}</code></p>
          <p>{esc(f.description or '')}</p>
          <p><strong>Impact:</strong> {esc(f.impact or '')}</p>
          <p><strong>Remediation:</strong> {esc(f.remediation or '')}</p>
        </div>"""
            )
        detail = "\n".join(detail_rows)

        timeline = "".join(
            f"<li>{esc(s.get('time', ''))} — {esc(s.get('action', ''))}</li>"
            for s in d.timeline
        )
        tools = ", ".join(esc(t) for t in d.tools) or "None"

        return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(d.title)}</title>
<style>
  :root {{ color-scheme: dark; --bg:#0f1216; --panel:#171c23; --text:#e6e8eb;
           --muted:#9aa4b2; --accent:#4f8cff; --border:#232a33; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--text);
          font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }}
  .wrap {{ max-width:920px; margin:0 auto; padding:40px 20px; }}
  h1 {{ font-size:26px; border-bottom:2px solid var(--border); padding-bottom:12px; }}
  h2 {{ font-size:19px; margin-top:34px; }}
  .meta {{ display:grid; grid-template-columns:auto 1fr; gap:6px 14px; color:var(--muted); }}
  .meta b {{ color:var(--text); }}
  table {{ width:100%; border-collapse:collapse; margin-top:12px; }}
  th, td {{ text-align:left; padding:9px 10px; border-bottom:1px solid var(--border); }}
  th {{ color:var(--muted); font-size:13px; text-transform:uppercase; letter-spacing:.04em; }}
  .sev {{ display:inline-block; padding:2px 9px; border-radius:999px; font-size:12px;
          font-weight:600; text-transform:uppercase; }}
  .sev.critical {{ background:#5b1113; color:#ffb3b5; }}
  .sev.high {{ background:#4d2410; color:#ffc59e; }}
  .sev.medium {{ background:#4d3a0e; color:#ffe08a; }}
  .sev.low {{ background:#0e3a2f; color:#9ee8c5; }}
  .sev.info {{ background:#1c2a3a; color:#b9d6f5; }}
  .finding {{ background:var(--panel); border:1px solid var(--border);
              border-radius:8px; padding:14px 16px; margin:12px 0; }}
  .finding h3 {{ margin:0 0 8px; }}
  code {{ background:#0c0f13; padding:1px 6px; border-radius:4px; }}
  ul {{ padding-left:20px; }}
  .badges span {{ margin-right:8px; color:var(--muted); }}
</style>
</head>
<body>
<div class="wrap">
  <h1>{esc(d.title)}</h1>
  <p class="badges">
    <span>Generated {esc(d.generated_at)}</span>
    <span>Mode: {esc(d.mode)}</span>
    <span>Critical: {counts.get('critical', 0)}</span>
    <span>High: {counts.get('high', 0)}</span>
    <span>Medium: {counts.get('medium', 0)}</span>
    <span>Low: {counts.get('low', 0)}</span>
  </p>

  <h2>Executive Summary</h2>
  <p>{esc(d.summary or 'No summary provided.')}</p>

  <h2>Target &amp; Scope</h2>
  <div class="meta">
    <b>Target</b><span>{esc(d.target or 'n/a')}</span>
    <b>Scope</b><span>{esc(d.scope or 'n/a')}</span>
    <b>Mode</b><span>{esc(d.mode)}</span>
    <b>Tools</b><span>{tools}</span>
  </div>

  <h2>Findings Overview</h2>
  <table>
    <thead><tr><th>Severity</th><th>Finding</th><th>Target</th><th>Service</th></tr></thead>
    <tbody>{finding_rows}
    </tbody>
  </table>

  <h2>Finding Details</h2>
  {detail or "<p>No findings.</p>"}

  <h2>Timeline</h2>
  <ul>{timeline or '<li>No timeline recorded.</li>'}</ul>

  <p style="color:var(--muted);margin-top:40px">Generated by Fariid Tech Security AI.
  Only test systems you own or are explicitly authorized to test.</p>
</div>
</body>
</html>
"""

    def render_pdf(self) -> str:
        try:
            from reportlab.lib.pagesizes import A4  # type: ignore
            from reportlab.pdfgen import canvas  # type: ignore
        except ImportError:
            # Fall back to text; the CLI prints a hint to install [pdf].
            return self.render_text()

        import io

        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=A4)
        width, height = A4
        y = height - 60
        c.setFont("Helvetica-Bold", 18)
        c.drawString(50, y, self.data.title)
        y -= 30
        c.setFont("Helvetica", 10)
        for line in self.render_text().splitlines():
            if y < 50:
                c.showPage()
                c.setFont("Helvetica", 10)
                y = height - 50
            c.drawString(50, y, line[:100])
            y -= 14
        c.save()
        return buf.getvalue().decode("latin-1", errors="replace")
