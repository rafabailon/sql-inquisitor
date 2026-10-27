"""Command line interface tests."""

from __future__ import annotations

import json
import runpy
import sys

import pytest

from cli import (
    EXIT_AUTHORIZATION,
    EXIT_ERROR,
    EXIT_FINDINGS,
    EXIT_NO_POINTS,
    EXIT_OK,
    _parse_cookies,
    _parse_formats,
    _parse_headers,
    _parse_techniques,
    build_parser,
    config_from_args,
    entrypoint,
    main,
)
from errors import ConfigError
from models import ALL_TECHNIQUES, Technique


class FakeStdin:
    def __init__(self, is_tty: bool) -> None:
        self._is_tty = is_tty

    def isatty(self) -> bool:
        return self._is_tty


def test_parse_techniques_accepts_all_and_subsets():
    assert _parse_techniques("all") == ALL_TECHNIQUES
    assert _parse_techniques("error,time") == (Technique.ERROR, Technique.TIME)
    assert _parse_techniques("error,error,union") == (Technique.ERROR, Technique.UNION)


def test_parse_techniques_rejects_unknown_names():
    with pytest.raises(ConfigError):
        _parse_techniques("error,nope")


def test_parse_formats_normalizes_and_deduplicates():
    assert _parse_formats("json,md,markdown,html") == ("json", "markdown", "html")
    with pytest.raises(ConfigError):
        _parse_formats("xml")


def test_parse_headers():
    assert _parse_headers(["X-Test: value", "Authorization: Bearer x"]) == {
        "X-Test": "value",
        "Authorization": "Bearer x",
    }
    with pytest.raises(ConfigError):
        _parse_headers(["invalid"])
    with pytest.raises(ConfigError):
        _parse_headers([": value"])


def test_parse_cookies():
    assert _parse_cookies(["a=1; b=2", "c=3"]) == {"a": "1", "b": "2", "c": "3"}
    with pytest.raises(ConfigError):
        _parse_cookies(["invalid"])


def test_build_parser_and_config_from_args():
    parser = build_parser()
    args = parser.parse_args(
        [
            "https://example.test/search?q=test",
            "--authorized",
            "--techniques",
            "error,union",
            "--scope",
            "example.test,api.example.test",
            "--exclude",
            "*/logout*",
            "--time-delay",
            "0.5",
            "--timeout",
            "4",
            "--connect-timeout",
            "9",
            "-H",
            "X-Test: value",
            "-b",
            "session=abc",
            "--tamper",
            "spaces,randomcase",
            "-o",
            "reports/scan",
            "--format",
            "json,html",
            "--thorough",
            "-v",
        ]
    )
    config = config_from_args(args)
    assert config.authorized is True
    assert config.techniques == (Technique.ERROR, Technique.UNION)
    assert config.scope == ("example.test", "api.example.test")
    assert config.exclude_patterns == ("*/logout*",)
    assert config.time_delay == 0.5
    assert config.connect_timeout == 4.0
    assert config.headers == {"X-Test": "value"}
    assert config.cookies == {"session": "abc"}
    assert config.tamper == ("spaces", "randomcase")
    assert config.output_formats == ("json", "html")
    assert config.thorough is True
    assert config.log_level == "INFO"


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["https://example.test/", "--techniques", "nope"],
        ["https://example.test/", "--format", "json"],
        ["https://example.test/", "-o", "report.json", "--format", "json,html"],
        ["https://example.test/", "-H", "invalid"],
        ["https://example.test/", "-b", "invalid"],
        ["https://example.test/", "--tamper", "unknown"],
        ["https://example.test/", "--output", "report", "--format", "xml"],
    ],
)
def test_invalid_cli_configuration_returns_error(arguments, capsys):
    assert main(arguments) == EXIT_ERROR
    captured = capsys.readouterr()
    assert "error:" in captured.err


def test_dry_run_prints_plan_and_sends_no_request(capsys):
    exit_code = main(
        [
            "https://example.test/search?q=test",
            "--dry-run",
            "--authorized",
            "--param",
            "q",
            "--scope",
            "example.test",
        ]
    )
    assert exit_code == EXIT_OK
    output = capsys.readouterr().out
    plan_text = output.split("\n\nDry run:")[0]
    plan = json.loads(plan_text)
    assert plan["target"] == "https://example.test/search?q=test"
    assert plan["authorization_confirmed"] is True
    assert plan["explicit_parameters"] == ["q"]
    assert "Dry run: no HTTP requests were sent." in output


def test_dry_run_does_not_require_authorization(capsys):
    assert main(["https://example.test/", "--dry-run"]) == EXIT_OK
    assert "authorization_confirmed" in capsys.readouterr().out


def test_non_interactive_without_authorization_is_refused(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", FakeStdin(False))
    assert main(["https://example.test/"]) == EXIT_AUTHORIZATION
    assert "authorization" in capsys.readouterr().err.lower()


def test_scope_mismatch_is_refused(monkeypatch, capsys):
    monkeypatch.setattr(sys, "stdin", FakeStdin(False))
    exit_code = main(["https://example.test/", "--authorized", "--scope", "other.test"])
    assert exit_code == EXIT_AUTHORIZATION
    assert "scope" in capsys.readouterr().err.lower()


def test_list_techniques_and_tampers(capsys):
    assert main(["--list-techniques"]) == EXIT_OK
    output = capsys.readouterr().out
    assert "error" in output
    assert "time-based blind" in output
    assert main(["--list-tampers"]) == EXIT_OK
    output = capsys.readouterr().out
    assert "randomcase" in output
    assert "versioned" in output


def test_version_exits_cleanly(capsys):
    with pytest.raises(SystemExit) as error:
        main(["--version"])
    assert error.value.code == 0
    assert "sql-inquisitor 1.0.0" in capsys.readouterr().out


def test_entrypoint_reads_sys_argv(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["sql-inquisitor", "--list-techniques"])
    assert entrypoint() == EXIT_OK
    assert "error-based" in capsys.readouterr().out


def test_module_entrypoint_runs(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["sql-inquisitor", "--version"])
    with pytest.raises(SystemExit) as error:
        runpy.run_module("cli", run_name="__main__")
    assert error.value.code == 0


def test_scan_with_finding_returns_findings_exit_code(lab, capsys):
    exit_code = main(
        [
            lab.base_url + "/search?q=test",
            "--authorized",
            "--no-crawl",
            "--techniques",
            "error",
            "--delay",
            "0",
            "--timeout",
            "5",
            "--no-color",
        ]
    )
    output = capsys.readouterr().out
    assert exit_code == EXIT_FINDINGS
    assert "Confirmed findings: 1" in output
    assert "Error-based SQL injection" in output


def test_fail_on_findings_can_be_disabled(lab):
    exit_code = main(
        [
            lab.base_url + "/search?q=test",
            "--authorized",
            "--no-crawl",
            "--techniques",
            "error",
            "--delay",
            "0",
            "--timeout",
            "5",
            "--no-fail-on-findings",
            "--quiet",
        ]
    )
    assert exit_code == EXIT_OK


def test_clean_scan_returns_ok(lab):
    exit_code = main(
        [
            lab.base_url + "/clean?q=test",
            "--authorized",
            "--no-crawl",
            "--techniques",
            "error",
            "--delay",
            "0",
            "--timeout",
            "5",
            "--quiet",
        ]
    )
    assert exit_code == EXIT_OK


def test_no_points_returns_dedicated_exit_code(lab):
    exit_code = main(
        [
            lab.base_url + "/",
            "--authorized",
            "--no-crawl",
            "--no-forms",
            "--techniques",
            "error",
            "--delay",
            "0",
            "--timeout",
            "5",
            "--quiet",
        ]
    )
    assert exit_code == EXIT_NO_POINTS


def test_quiet_suppresses_console_report(lab, capsys):
    exit_code = main(
        [
            lab.base_url + "/search?q=test",
            "--authorized",
            "--no-crawl",
            "--techniques",
            "error",
            "--delay",
            "0",
            "--timeout",
            "5",
            "--quiet",
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == EXIT_FINDINGS
    assert "SQL Inquisitor" not in captured.out


def test_reports_are_written_from_cli(lab, tmp_path):
    prefix = tmp_path / "cli-report"
    exit_code = main(
        [
            lab.base_url + "/search?q=test",
            "--authorized",
            "--no-crawl",
            "--techniques",
            "error",
            "--delay",
            "0",
            "--timeout",
            "5",
            "--quiet",
            "-o",
            str(prefix),
            "--format",
            "json,markdown",
        ]
    )
    assert exit_code == EXIT_FINDINGS
    assert prefix.with_suffix(".json").exists()
    assert prefix.with_suffix(".md").exists()


def test_cli_explicit_param_scan(lab, capsys):
    exit_code = main(
        [
            lab.base_url + "/search",
            "--authorized",
            "--no-crawl",
            "--param",
            "q",
            "--data",
            "q=test",
            "--method",
            "GET",
            "--techniques",
            "error",
            "--delay",
            "0",
            "--timeout",
            "5",
            "--no-color",
        ]
    )
    assert exit_code == EXIT_FINDINGS
    assert "parameter 'q'" in capsys.readouterr().out


def test_cli_log_file_is_written(lab, tmp_path):
    log_path = tmp_path / "logs" / "scan.log"
    exit_code = main(
        [
            lab.base_url + "/clean?q=test",
            "--authorized",
            "--no-crawl",
            "--techniques",
            "error",
            "--delay",
            "0",
            "--timeout",
            "5",
            "--quiet",
            "--debug",
            "--log-file",
            str(log_path),
        ]
    )
    assert exit_code == EXIT_OK
    assert log_path.exists()
    assert "sql_inquisitor" in log_path.read_text(encoding="utf-8").lower()
