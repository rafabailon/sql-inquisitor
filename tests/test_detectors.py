"""End-to-end detector tests against the deliberately vulnerable lab server."""

from __future__ import annotations

from models import Confidence, Finding, ScanResult, Technique

CHEAP = (Technique.ERROR, Technique.BOOLEAN, Technique.UNION, Technique.STACKED)


def scan(config_factory, run_scan, path: str, techniques, **overrides) -> ScanResult:
    config = config_factory(path=path, techniques=tuple(techniques), **overrides)
    return run_scan(config)


def finding_for(result: ScanResult, technique: Technique) -> Finding:
    matches = [finding for finding in result.findings if finding.technique is technique]
    assert matches, f"no {technique.value} finding in {result.findings}"
    return matches[0]


def test_error_based_detection(config_factory, run_scan):
    result = scan(config_factory, run_scan, "/search?q=test", (Technique.ERROR,))
    finding = finding_for(result, Technique.ERROR)
    assert finding.url.endswith("/search")
    assert finding.parameter == "q"
    assert finding.method == "GET"
    assert finding.location == "query"
    assert finding.severity.value == "critical"
    assert finding.confidence is Confidence.HIGH
    assert finding.dbms == "SQLite"
    assert finding.payload
    assert "error" in finding.evidence.lower()
    assert finding.status_code == 500
    assert result.stats.points_discovered == 1
    assert result.stats.points_tested == 1


def test_boolean_based_detection(config_factory, run_scan):
    result = scan(config_factory, run_scan, "/blind?q=test", (Technique.BOOLEAN,))
    finding = finding_for(result, Technique.BOOLEAN)
    assert finding.severity.value == "high"
    assert finding.confidence is Confidence.HIGH
    assert "boolean" in finding.evidence.lower()
    assert finding.detail["confirmations"]


def test_boolean_based_detection_survives_dynamic_nonce(config_factory, run_scan):
    result = scan(config_factory, run_scan, "/dynamic?q=test", (Technique.BOOLEAN,))
    assert finding_for(result, Technique.BOOLEAN)


def test_boolean_based_detection_with_tamper(config_factory, run_scan):
    result = scan(
        config_factory,
        run_scan,
        "/blind?q=test",
        (Technique.BOOLEAN,),
        tamper=("spaces",),
    )
    finding = finding_for(result, Technique.BOOLEAN)
    assert "/**/" in finding.payload


def test_time_based_detection(config_factory, run_scan):
    result = scan(
        config_factory,
        run_scan,
        "/time?q=test",
        (Technique.TIME,),
        time_delay=0.6,
        time_samples=2,
    )
    finding = finding_for(result, Technique.TIME)
    assert finding.severity.value == "high"
    assert finding.dbms == "MySQL/MariaDB"
    assert "SLEEP" in finding.payload
    assert finding.detail["probe_seconds"] >= 0.4
    assert finding.detail["baseline_median_seconds"] < finding.detail["probe_seconds"]


def test_union_based_detection(config_factory, run_scan):
    result = scan(
        config_factory,
        run_scan,
        "/union?q=test",
        (Technique.UNION,),
        max_union_columns=5,
    )
    finding = finding_for(result, Technique.UNION)
    assert finding.severity.value == "critical"
    assert finding.column_count == 3
    assert "UNION SELECT" in finding.payload
    assert finding.detail["marker"] in finding.evidence


def test_numeric_union_detection(config_factory, run_scan):
    result = scan(
        config_factory,
        run_scan,
        "/numeric?id=1",
        (Technique.UNION,),
        max_union_columns=6,
    )
    finding = finding_for(result, Technique.UNION)
    assert finding.column_count == 4
    assert finding.parameter == "id"
    assert finding.payload.startswith("1 UNION SELECT")


def test_stacked_query_detection(config_factory, run_scan):
    result = scan(config_factory, run_scan, "/stacked?id=1", (Technique.STACKED,))
    finding = finding_for(result, Technique.STACKED)
    assert finding.severity.value == "critical"
    assert finding.confidence is Confidence.HIGH
    assert "no such table" in finding.evidence.lower()
    assert "inq" in finding.payload


def test_multiple_techniques_on_one_point(config_factory, run_scan):
    result = scan(
        config_factory,
        run_scan,
        "/union?q=test",
        (Technique.ERROR, Technique.BOOLEAN, Technique.UNION),
    )
    techniques = {finding.technique for finding in result.findings}
    assert techniques == {Technique.ERROR, Technique.BOOLEAN, Technique.UNION}
    assert len({finding.identifier for finding in result.findings}) == 3


def test_clean_endpoint_has_no_findings(config_factory, run_scan):
    result = scan(config_factory, run_scan, "/clean?q=test", CHEAP)
    assert result.findings == []
    assert result.stats.points_tested == 1


def test_clean_endpoint_has_no_time_findings(config_factory, run_scan):
    result = scan(
        config_factory,
        run_scan,
        "/clean?q=test",
        (Technique.TIME,),
        time_delay=0.4,
        time_samples=2,
    )
    assert result.findings == []


def test_fake_error_page_is_not_flagged(config_factory, run_scan):
    result = scan(config_factory, run_scan, "/fake-error?q=test", (Technique.ERROR,))
    assert result.findings == []


def test_waf_response_is_respected(config_factory, run_scan):
    result = scan(config_factory, run_scan, "/waf?q=test", (Technique.ERROR,))
    assert result.findings == []
    assert result.stats.blocked_requests >= 1
    assert "Cloudflare" in result.stats.waf_observed


def test_time_is_skipped_after_other_confirmation(config_factory, run_scan):
    result = scan(
        config_factory,
        run_scan,
        "/search?q=test",
        (Technique.ERROR, Technique.TIME),
        time_delay=0.3,
        time_samples=2,
        thorough=False,
    )
    assert {finding.technique for finding in result.findings} == {Technique.ERROR}
    assert result.stats.requests < 10


def test_thorough_runs_time_after_other_confirmation(config_factory, run_scan):
    result = scan(
        config_factory,
        run_scan,
        "/search?q=test",
        (Technique.ERROR, Technique.TIME),
        time_delay=0.3,
        time_samples=2,
        thorough=True,
    )
    assert {finding.technique for finding in result.findings} == {
        Technique.ERROR,
        Technique.TIME,
    }
    assert result.stats.requests >= 7


def test_stop_after_first_limits_findings(config_factory, run_scan):
    result = scan(
        config_factory,
        run_scan,
        "/union?q=test",
        (Technique.ERROR, Technique.BOOLEAN, Technique.UNION),
        stop_after_first=True,
    )
    assert len(result.findings) == 1
    assert result.findings[0].technique is Technique.ERROR
