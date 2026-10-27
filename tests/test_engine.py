"""Scanner orchestration tests."""

from __future__ import annotations

import logging

import pytest

from crawler import build_explicit_points
from engine import Scanner
from errors import ScopeError
from models import Technique


def test_explicit_point_scan(config_factory, lab):
    config = config_factory(
        path="/search?q=test",
        techniques=(Technique.ERROR,),
    )
    points = build_explicit_points(lab.base_url + "/search?q=test")
    result = Scanner(config, explicit_points=points).scan()
    assert result.stats.points_discovered == 1
    assert result.stats.points_tested == 1
    assert len(result.findings) == 1
    assert result.stats.findings == 1
    assert result.stats.finished_at is not None
    assert result.target == config.target
    assert result.config["target"] == config.target
    assert result.points[0]["parameter"] == "q"


def test_explicit_points_are_deduplicated(config_factory, lab):
    config = config_factory(path="/search?q=test", techniques=(Technique.ERROR,))
    points = build_explicit_points(lab.base_url + "/search?q=test")
    result = Scanner(config, explicit_points=points + points).scan()
    assert result.stats.points_discovered == 1


def test_max_points_limits_explicit_points(config_factory, lab):
    config = config_factory(
        path="/search?q=test&page=2",
        techniques=(Technique.ERROR,),
        max_points=1,
    )
    points = build_explicit_points(lab.base_url + "/search?q=test&page=2")
    result = Scanner(config, explicit_points=points).scan()
    assert result.stats.points_discovered == 1
    assert result.points[0]["parameter"] == "q"


def test_no_injection_points_is_reported(config_factory, lab):
    config = config_factory(path="/", crawl=False, scan_forms=False)
    result = Scanner(config).scan()
    assert result.stats.points_discovered == 0
    assert result.findings == []
    assert any("no query parameters or forms were discovered" in error for error in result.errors)
    assert result.aborted_reason is None


def test_scope_is_enforced_before_scanning(config_factory, lab):
    config = config_factory(path="/search?q=test", scope=("example.com",))
    with pytest.raises(ScopeError):
        Scanner(config).scan()


def test_request_budget_aborts_scan(config_factory, lab):
    config = config_factory(
        path="/union?q=test",
        techniques=(Technique.UNION,),
        max_requests=1,
    )
    points = build_explicit_points(lab.base_url + "/union?q=test")
    result = Scanner(config, explicit_points=points).scan()
    assert "budget" in result.aborted_reason
    assert result.stats.requests == 1
    assert result.stats.finished_at is not None
    assert result.findings == []


def test_baseline_transport_failure_is_recorded(config_factory, lab):
    config = config_factory(
        path="/search?q=test",
        techniques=(Technique.ERROR,),
        timeout=1.0,
        connect_timeout=0.5,
        time_delay=0.2,
    )
    point = build_explicit_points("http://127.0.0.1:1/search?q=test")[0]
    result = Scanner(config, explicit_points=[point]).scan()
    assert result.findings == []
    assert any("baseline request failed" in error for error in result.errors)
    assert result.stats.points_tested == 0


def test_detector_exception_is_isolated(config_factory, lab):
    class BrokenDetector:
        technique = Technique.ERROR

        def detect(self, point, baseline):
            raise RuntimeError("intentional detector failure")

    config = config_factory(path="/search?q=test", techniques=(Technique.ERROR,))
    points = build_explicit_points(lab.base_url + "/search?q=test")
    scanner = Scanner(config, explicit_points=points)
    scanner.detectors = [BrokenDetector()]
    result = scanner.scan()
    assert result.findings == []
    assert any(
        "intentional detector failure" in error and "detector failed" in error
        for error in result.errors
    )


def test_scanner_uses_canonical_detector_order(config_factory, lab):
    config = config_factory(
        path="/search?q=test",
        techniques=(Technique.TIME, Technique.UNION, Technique.ERROR, Technique.STACKED),
    )
    scanner = Scanner(config)
    assert [detector.technique for detector in scanner.detectors] == [
        Technique.ERROR,
        Technique.UNION,
        Technique.STACKED,
        Technique.TIME,
    ]
    scanner.client.close()


def test_scan_errors_are_capped(config_factory, lab):
    config = config_factory(path="/search?q=test", techniques=(Technique.ERROR,))
    scanner = Scanner(config)
    for index in range(150):
        scanner._record_error(f"error-{index}")
    assert len(scanner.result.errors) == 100
    assert scanner.result.errors[0] == "error-0"
    assert scanner.result.errors[-1] == "error-99"
    scanner.client.close()


def test_recorded_error_is_debug_logged(config_factory, lab, caplog):
    config = config_factory(path="/search?q=test", techniques=(Technique.ERROR,))
    scanner = Scanner(config, logger=logging.getLogger("test.engine"))
    with caplog.at_level(logging.DEBUG):
        scanner._record_error("a diagnostic error")
    assert "a diagnostic error" in caplog.text
    scanner.client.close()
