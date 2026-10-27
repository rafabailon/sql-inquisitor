"""Console, JSON, Markdown and HTML reporting."""

from __future__ import annotations

import html
import os
import re
from datetime import datetime
from pathlib import Path

from config import ScanConfig
from models import Finding, ScanResult, Severity, isoformat
from version import __version__

_ANSI = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[37m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_ONE_LINE = re.compile(r"\s+")


def _one_line(text: str, limit: int | None = None) -> str:
    collapsed = _ONE_LINE.sub(" ", text or "").strip()
    if limit is not None and len(collapsed) > limit:
        return collapsed[: max(0, limit - 3)] + "..."
    return collapsed


def _color(severity: Severity, text: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{_ANSI[severity]}{text}{_RESET}"


def render_console(result: ScanResult, *, color: bool = True) -> str:
    summary = result.summary()
    lines: list[str] = []
    lines.append(
        f"{_BOLD}SQL Inquisitor {__version__}{_RESET}" if color else f"SQL Inquisitor {__version__}"
    )
    lines.append(f"Target: {result.target}")
    lines.append(f"Started: {isoformat(result.started_at)}")
    lines.append(f"Duration: {result.duration_seconds:.2f} s")
    lines.append(
        "Requests: {requests} | Points: {tested}/{discovered} | Errors: {errors}".format(
            requests=summary["requests"],
            tested=summary["points_tested"],
            discovered=summary["points_discovered"],
            errors=summary["errors"],
        )
    )
    if result.stats.waf_observed:
        lines.append("WAF observed: " + ", ".join(result.stats.waf_observed))
    if result.aborted_reason:
        lines.append(f"Aborted: {result.aborted_reason}")
    lines.append("")
    if not result.findings:
        lines.append("No SQL injection was confirmed.")
    else:
        counts = ", ".join(
            f"{name}={count}"
            for name, count in sorted(
                summary["by_severity"].items(),
                key=lambda item: Severity(item[0]).rank,
                reverse=True,
            )
            if count
        )
        lines.append(f"Confirmed findings: {len(result.findings)} ({counts})")
        lines.append("")
        for index, finding in enumerate(result.sorted_findings(), start=1):
            label = f"[{finding.severity.value.upper()}]"
            if color:
                label = _color(finding.severity, label, True)
            lines.append(f"{index}. {label} {finding.title}")
            lines.append(
                f"   URL: {finding.method} {finding.url} | location: {finding.location} | "
                f"confidence: {finding.confidence.value}"
            )
            if finding.dbms:
                lines.append(f"   DBMS: {finding.dbms}")
            if finding.column_count:
                lines.append(f"   UNION columns: {finding.column_count}")
            lines.append(f"   Payload: {_one_line(finding.payload, 220)}")
            lines.append(f"   Evidence: {_one_line(finding.evidence, 260)}")
            lines.append("")
    if result.errors:
        lines.append("Scan notes and errors:")
        for error in result.errors[:10]:
            lines.append(f"- {_one_line(error, 300)}")
        if len(result.errors) > 10:
            lines.append(f"- ... {len(result.errors) - 10} more errors in the JSON report")
        lines.append("")
    if color:
        lines.append(
            _DIM
            + "Authorized testing only. Never use this tool on systems you do not own."
            + _RESET
        )
    else:
        lines.append("Authorized testing only. Never use this tool on systems you do not own.")
    return "\n".join(lines)


def render_markdown(result: ScanResult) -> str:
    summary = result.summary()
    lines = [
        "# SQL Inquisitor report",
        "",
        f"Target: `{result.target}`",
        "",
        f"Started: {isoformat(result.started_at)}",
        "",
        f"Duration: {result.duration_seconds:.2f} seconds",
        "",
        "This report was produced by SQL Inquisitor for authorized security testing. The scanner "
        "only executes read-only SQL, controlled delays and non-destructive error probes.",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Findings | {summary['findings']} |",
        f"| Critical | {summary['by_severity']['critical']} |",
        f"| High | {summary['by_severity']['high']} |",
        f"| Medium | {summary['by_severity']['medium']} |",
        f"| Low | {summary['by_severity']['low']} |",
        f"| Injection points discovered | {summary['points_discovered']} |",
        f"| Injection points tested | {summary['points_tested']} |",
        f"| HTTP requests | {summary['requests']} |",
        f"| Errors | {summary['errors']} |",
        "",
    ]
    if result.stats.waf_observed:
        lines.append("Observed filtering layers: " + ", ".join(result.stats.waf_observed))
        lines.append("")
    if result.aborted_reason:
        lines.append(f"Scan aborted: {result.aborted_reason}")
        lines.append("")
    if not result.findings:
        lines.extend(["## Findings", "", "No SQL injection was confirmed.", ""])
    else:
        lines.extend(["## Findings", ""])
        for index, finding in enumerate(result.sorted_findings(), start=1):
            lines.extend(_markdown_finding(index, finding))
    lines.extend(["## Errors and notes", ""])
    if result.errors:
        for error in result.errors:
            lines.append(f"- {_one_line(error, 500)}")
    else:
        lines.append("No errors were recorded.")
    lines.extend(
        [
            "",
            "## References",
            "",
            "- https://owasp.org/www-community/attacks/SQL_Injection",
            "- https://cwe.mitre.org/data/definitions/89.html",
            "- https://capec.mitre.org/data/definitions/66.html",
            "",
        ]
    )
    return "\n".join(lines)


def _markdown_finding(index: int, finding: Finding) -> list[str]:
    lines = [
        f"### {index}. {finding.title}",
        "",
        f"- Severity: {finding.severity.value}",
        f"- Confidence: {finding.confidence.value}",
        f"- Technique: {finding.technique.label}",
        f"- URL: `{finding.method} {finding.url}`",
        f"- Parameter: `{finding.parameter}` ({finding.location})",
    ]
    if finding.dbms:
        lines.append(f"- DBMS: {finding.dbms}")
    if finding.column_count:
        lines.append(f"- UNION columns: {finding.column_count}")
    lines.extend(
        [
            f"- Payload: `{_one_line(finding.payload, 400)}`",
            f"- Response: HTTP {finding.status_code}, {finding.response_length} bytes, "
            f"{finding.elapsed_ms} ms",
            "",
            f"**Description.** {finding.description}",
            "",
            f"**Evidence.** {_one_line(finding.evidence, 800)}",
            "",
            f"**Remediation.** {finding.remediation}",
            "",
            "**References.**",
            "",
        ]
    )
    for reference in finding.references:
        lines.append(f"- {reference}")
    lines.append("")
    return lines


def render_html(result: ScanResult) -> str:
    summary = result.summary()
    findings_html = _html_findings(result)
    errored = "".join(
        f"<li>{html.escape(_one_line(error, 600))}</li>" for error in result.errors[:100]
    )
    waf = (
        "<p><strong>Observed filtering layers:</strong> "
        + html.escape(", ".join(result.stats.waf_observed))
        + "</p>"
        if result.stats.waf_observed
        else ""
    )
    aborted = (
        f'<p class="warn"><strong>Scan aborted:</strong> {html.escape(result.aborted_reason)}</p>'
        if result.aborted_reason
        else ""
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SQL Inquisitor report - {html.escape(result.target)}</title>
<style>
:root {{ color-scheme: light dark; --bg:#f7f8fa; --card:#fff; --text:#1b1f24; --muted:#5b6570; --line:#d8dde3; --critical:#b00020; --high:#c2410c; --medium:#a16207; --low:#0369a1; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#101418; --card:#171d23; --text:#e7edf3; --muted:#9aa7b4; --line:#2a333d; }} }}
* {{ box-sizing: border-box; }}
body {{ margin: 0; padding: 2rem 1rem; background: var(--bg); color: var(--text); font: 16px/1.55 system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }}
main {{ max-width: 1040px; margin: 0 auto; }}
h1 {{ margin: 0 0 .25rem; font-size: 2rem; }}
h2 {{ margin-top: 2rem; border-bottom: 1px solid var(--line); padding-bottom: .35rem; }}
h3 {{ margin-bottom: .35rem; }}
p, li {{ color: var(--text); }}
.muted {{ color: var(--muted); }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: .75rem; margin: 1rem 0; }}
.card {{ background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: .9rem 1rem; }}
.card .value {{ font-size: 1.6rem; font-weight: 700; }}
.finding {{ background: var(--card); border: 1px solid var(--line); border-left: 6px solid var(--line); border-radius: 10px; padding: 1rem 1.2rem; margin: 1rem 0; }}
.finding.critical {{ border-left-color: var(--critical); }}
.finding.high {{ border-left-color: var(--high); }}
.finding.medium {{ border-left-color: var(--medium); }}
.finding.low {{ border-left-color: var(--low); }}
.badge {{ display: inline-block; border: 1px solid currentColor; border-radius: 999px; padding: .1rem .55rem; font-size: .8rem; font-weight: 700; text-transform: uppercase; }}
.critical .badge {{ color: var(--critical); }}
.high .badge {{ color: var(--high); }}
.medium .badge {{ color: var(--medium); }}
.low .badge {{ color: var(--low); }}
code, pre {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: .9em; }}
code {{ background: rgba(127,127,127,.14); padding: .1rem .3rem; border-radius: 4px; overflow-wrap: anywhere; }}
pre {{ background: rgba(127,127,127,.12); padding: .75rem; border-radius: 8px; overflow-x: auto; white-space: pre-wrap; overflow-wrap: anywhere; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ text-align: left; border-bottom: 1px solid var(--line); padding: .45rem .5rem; vertical-align: top; }}
.warn {{ color: var(--critical); }}
footer {{ margin-top: 3rem; color: var(--muted); font-size: .9rem; }}
</style>
</head>
<body>
<main>
<h1>SQL Inquisitor report</h1>
<p class="muted">Target: <code>{html.escape(result.target)}</code></p>
<p class="muted">Started {html.escape(isoformat(result.started_at))} | Duration {result.duration_seconds:.2f} seconds | Tool version {html.escape(__version__)}</p>
<p>This report was produced for authorized security testing. SQL Inquisitor only executes read-only SQL, controlled delays and non-destructive error probes.</p>
{waf}
{aborted}
<div class="grid">
<div class="card"><div class="muted">Findings</div><div class="value">{summary["findings"]}</div></div>
<div class="card"><div class="muted">Critical</div><div class="value">{summary["by_severity"]["critical"]}</div></div>
<div class="card"><div class="muted">High</div><div class="value">{summary["by_severity"]["high"]}</div></div>
<div class="card"><div class="muted">Points tested</div><div class="value">{summary["points_tested"]}</div></div>
<div class="card"><div class="muted">HTTP requests</div><div class="value">{summary["requests"]}</div></div>
</div>
<h2>Findings</h2>
{findings_html}
<h2>Errors and notes</h2>
<ul>{errored or "<li>No errors were recorded.</li>"}</ul>
<footer>Generated by SQL Inquisitor {html.escape(__version__)}. Use only on systems for which you have explicit written authorization.</footer>
</main>
</body>
</html>
"""


def _html_findings(result: ScanResult) -> str:
    if not result.findings:
        return "<p>No SQL injection was confirmed.</p>"
    blocks: list[str] = []
    for index, finding in enumerate(result.sorted_findings(), start=1):
        references = "".join(
            f'<li><a href="{html.escape(reference)}">{html.escape(reference)}</a></li>'
            for reference in finding.references
        )
        dbms = f"<tr><th>DBMS</th><td>{html.escape(finding.dbms)}</td></tr>" if finding.dbms else ""
        columns = (
            f"<tr><th>UNION columns</th><td>{finding.column_count}</td></tr>"
            if finding.column_count
            else ""
        )
        blocks.append(
            f"""<article class="finding {finding.severity.value}">
<div><span class="badge">{finding.severity.value}</span> <strong>{index}. {html.escape(finding.title)}</strong></div>
<p class="muted">Technique: {html.escape(finding.technique.label)} | Confidence: {html.escape(finding.confidence.value)}</p>
<table>
<tr><th>URL</th><td><code>{html.escape(finding.method)} {html.escape(finding.url)}</code></td></tr>
<tr><th>Parameter</th><td><code>{html.escape(finding.parameter)}</code> ({html.escape(finding.location)})</td></tr>
{dbms}
{columns}
<tr><th>Payload</th><td><code>{html.escape(finding.payload)}</code></td></tr>
<tr><th>Response</th><td>HTTP {finding.status_code}, {finding.response_length} bytes, {finding.elapsed_ms} ms</td></tr>
</table>
<p><strong>Description.</strong> {html.escape(finding.description)}</p>
<pre>{html.escape(finding.evidence)}</pre>
<p><strong>Remediation.</strong> {html.escape(finding.remediation)}</p>
<p><strong>References.</strong></p>
<ul>{references}</ul>
</article>"""
        )
    return "\n".join(blocks)


def write_reports(
    result: ScanResult,
    config: ScanConfig,
    formats: tuple[str, ...] | None = None,
) -> list[Path]:
    selected = formats if formats is not None else config.output_formats
    if not selected:
        return []
    if config.output_prefix is None:
        raise ValueError("an output prefix is required for file reports")
    paths: list[Path] = []
    for output_format in selected:
        if output_format not in {"json", "markdown", "md", "html"}:
            continue
        path = _report_path(config.output_prefix, output_format, result.started_at)
        if output_format == "json":
            content = result.to_json()
        elif output_format in {"markdown", "md"}:
            content = render_markdown(result)
        elif output_format == "html":
            content = render_html(result)
        else:
            continue
        _atomic_write(path, content)
        paths.append(path)
    return paths


def _report_path(prefix: Path, output_format: str, started_at: datetime) -> Path:
    extension = {"json": ".json", "markdown": ".md", "md": ".md", "html": ".html"}[output_format]
    if prefix.exists() and prefix.is_dir():
        stamp = started_at.strftime("%Y%m%d-%H%M%S")
        return prefix / f"sql-inquisitor-{stamp}{extension}"
    if prefix.suffix.lower() in {".json", ".md", ".markdown", ".html", ".htm"}:
        return prefix
    return Path(str(prefix) + extension)


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp-{os.getpid()}")
    temporary.write_text(content, encoding="utf-8")
    os.replace(temporary, path)
