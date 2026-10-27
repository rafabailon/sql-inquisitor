"""Report rendering and file output tests."""

from __future__ import annotations

import json

import pytest

from config import ScanConfig
from models import (
    Confidence,
    Finding,
    ScanResult,
    Severity,
    Technique,
)
from reporting import (
    render_console,
    render_html,
    render_markdown,
    write_reports,
)


def sample_result() -> ScanResult:
    result = ScanResult(target="https://example.test/item?id=1")
    result.findings = [
        Finding(
            technique=Technique.ERROR,
            url="https://example.test/item",
            method="GET",
            parameter="id",
            location="query",
            payload="1' AND <script>alert(1)</script>",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            evidence="Database error: unrecognized token <script>",
            dbms="SQLite",
            status_code=500,
            response_length=321,
            elapsed_ms=8.5,
            detail={"context": "numeric"},
        ),
        Finding(
            technique=Technique.BOOLEAN,
            url="https://example.test/item",
            method="GET",
            parameter="id",
            location="query",
            payload="1 AND 1=1",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            evidence="response split",
        ),
    ]
    result.stats.points_discovered = 2
    result.stats.points_tested = 2
    result.stats.requests = 25
    result.stats.waf_observed = ["Cloudflare"]
    result.errors = ["a recorded error"]
    return result


def test_console_report_contains_summary_and_findings():
    text = render_console(sample_result(), color=False)
    assert "SQL Inquisitor" in text
    assert "https://example.test/item?id=1" in text
    assert "Confirmed findings: 2" in text
    assert "critical=1" in text
    assert "high=1" in text
    assert "Error-based SQL injection" in text
    assert "UNION columns" not in text
    assert "WAF observed: Cloudflare" in text
    assert "Scan notes and errors" in text
    assert "Authorized testing only" in text
    assert "\033[" not in text


def test_console_report_color_uses_ansi():
    text = render_console(sample_result(), color=True)
    assert "\033[" in text


def test_console_report_for_clean_scan():
    result = ScanResult(target="https://example.test/")
    text = render_console(result, color=False)
    assert "No SQL injection was confirmed." in text
    assert "Confirmed findings" not in text


def test_console_report_shows_aborted_reason():
    result = sample_result()
    result.aborted_reason = "request budget exhausted"
    text = render_console(result, color=False)
    assert "Aborted: request budget exhausted" in text


def test_console_report_limits_error_lines():
    result = ScanResult(target="https://example.test/")
    result.errors = [f"error-{index}" for index in range(15)]
    text = render_console(result, color=False)
    assert "error-9" in text
    assert "5 more errors" in text


def test_markdown_report_contains_sections_and_escapes_nothing():
    text = render_markdown(sample_result())
    assert text.startswith("# SQL Inquisitor report")
    assert "| Findings | 2 |" in text
    assert "## Findings" in text
    assert "### 1." in text
    assert "**Evidence.**" in text
    assert "**Remediation.**" in text
    assert "## Errors and notes" in text
    assert "a recorded error" in text
    assert "Observed filtering layers: Cloudflare" in text
    assert "<script>" in text


def test_markdown_report_for_clean_scan():
    text = render_markdown(ScanResult(target="https://example.test/"))
    assert "No SQL injection was confirmed." in text
    assert "No errors were recorded." in text


def test_html_report_escapes_untrusted_values():
    text = render_html(sample_result())
    assert "<!DOCTYPE html>" in text
    assert "SQL Inquisitor report" in text
    assert "&lt;script&gt;" in text
    assert "<script>alert(1)</script>" not in text
    assert "Cloudflare" in text
    assert "critical" in text


def test_html_report_for_clean_scan():
    text = render_html(ScanResult(target="https://example.test/"))
    assert "No SQL injection was confirmed." in text
    assert "No errors were recorded." in text


def report_config(tmp_path, **overrides):
    values = {
        "target": "https://example.test/",
        "authorized": True,
        "output_prefix": tmp_path / "scan",
        "output_formats": ("json", "markdown", "html"),
    }
    values.update(overrides)
    return ScanConfig(**values)


def test_write_reports_creates_all_formats(tmp_path):
    config = report_config(tmp_path)
    paths = write_reports(sample_result(), config)
    assert [path.suffix for path in paths] == [".json", ".md", ".html"]
    assert all(path.exists() for path in paths)
    document = json.loads(paths[0].read_text(encoding="utf-8"))
    assert document["summary"]["findings"] == 2
    assert "SQL Inquisitor report" in paths[1].read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in paths[2].read_text(encoding="utf-8")
    assert not list(tmp_path.glob("*.tmp-*"))


def test_write_reports_to_directory_uses_timestamp(tmp_path):
    config = report_config(tmp_path, output_prefix=tmp_path, output_formats=("json",))
    paths = write_reports(sample_result(), config)
    assert len(paths) == 1
    assert paths[0].parent == tmp_path
    assert paths[0].name.startswith("sql-inquisitor-")
    assert paths[0].suffix == ".json"


def test_write_reports_honours_explicit_file_extension(tmp_path):
    config = report_config(
        tmp_path,
        output_prefix=tmp_path / "custom.md",
        output_formats=("markdown",),
    )
    paths = write_reports(sample_result(), config)
    assert paths == [tmp_path / "custom.md"]
    assert paths[0].exists()


def test_write_reports_can_override_formats(tmp_path):
    config = report_config(tmp_path, output_formats=("json",))
    paths = write_reports(sample_result(), config, formats=("html",))
    assert len(paths) == 1
    assert paths[0].suffix == ".html"


def test_write_reports_without_formats_returns_empty():
    config = ScanConfig(target="https://example.test/", authorized=True)
    assert write_reports(sample_result(), config) == []


def test_write_reports_requires_prefix_for_explicit_formats():
    config = ScanConfig(target="https://example.test/", authorized=True)
    with pytest.raises(ValueError):
        write_reports(sample_result(), config, formats=("json",))


def test_write_reports_ignores_unknown_explicit_format(tmp_path):
    config = report_config(tmp_path, output_formats=("json",))
    assert write_reports(sample_result(), config, formats=("xml",)) == []
