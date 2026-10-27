"""Tests for the typed data model and report structures."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from models import (
    ALL_TECHNIQUES,
    REMEDIATION,
    Confidence,
    Detection,
    Finding,
    HttpResponse,
    InjectionPoint,
    RequestSpec,
    ScanResult,
    ScanStats,
    Severity,
    Technique,
    isoformat,
    severity_for_technique,
    strip_url_query,
    utc_now,
)


def make_point(**overrides) -> InjectionPoint:
    values = {
        "url": "https://example.test/search",
        "method": "GET",
        "location": "query",
        "name": "q",
        "value": "test",
        "params": (("q", "test"), ("page", "2")),
        "source": "unit-test",
    }
    values.update(overrides)
    return InjectionPoint(**values)


def make_finding(**overrides) -> Finding:
    values = {
        "technique": Technique.ERROR,
        "url": "https://example.test/search",
        "method": "GET",
        "parameter": "q",
        "location": "query",
        "payload": "test'",
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "evidence": "unrecognized token",
        "dbms": "SQLite",
        "status_code": 500,
        "response_length": 120,
        "elapsed_ms": 4.2,
    }
    values.update(overrides)
    return Finding(**values)


def test_severity_and_confidence_rank_order():
    ranks = [severity.rank for severity in Severity]
    assert ranks == sorted(ranks, reverse=True)
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank
    assert Confidence.HIGH.rank > Confidence.MEDIUM.rank > Confidence.LOW.rank


def test_technique_metadata_covers_every_technique():
    assert set(ALL_TECHNIQUES) == set(Technique)
    for technique in Technique:
        assert technique.label
        assert technique.description
        assert isinstance(severity_for_technique(technique), Severity)


def test_strip_url_query_removes_query_and_fragment():
    assert strip_url_query("https://example.test/a/b?c=1#frag") == "https://example.test/a/b"


def test_query_point_request_replaces_value_and_preserves_others():
    point = make_point()
    spec = point.request("payload")
    assert isinstance(spec, RequestSpec)
    assert spec.method == "GET"
    assert spec.params == (("q", "payload"), ("page", "2"))
    assert point.request().params == (("q", "test"), ("page", "2"))


def test_query_point_request_appends_unknown_parameter():
    point = make_point(name="extra", value="1")
    assert point.request("x").params == (("q", "test"), ("page", "2"), ("extra", "x"))


def test_urlencoded_form_point_replaces_body_field():
    point = make_point(
        method="POST",
        location="form",
        body_format="urlencoded",
        params=(("ref", "x"),),
        data=(("q", "test"), ("token", "abc")),
    )
    spec = point.request("' OR 1=1")
    assert spec.method == "POST"
    assert spec.params == (("ref", "x"),)
    assert spec.data == (("q", "' OR 1=1"), ("token", "abc"))
    assert spec.files == ()


def test_multipart_form_point_replaces_file_field():
    point = make_point(
        method="POST",
        location="form",
        body_format="multipart",
        data=(("q", "test"), ("token", "abc")),
    )
    spec = point.request("payload")
    assert spec.files == (("q", "payload"), ("token", "abc"))
    assert spec.data == ()


def test_request_spec_kwargs_and_cache_key():
    spec = RequestSpec(
        url="https://example.test/search",
        method="POST",
        params=(("ref", "x"),),
        data=(("q", "test"),),
        files=(("upload", "value"),),
    )
    kwargs = spec.as_kwargs()
    assert kwargs["method"] == "POST"
    assert kwargs["params"] == [("ref", "x")]
    assert kwargs["data"] == [("q", "test")]
    assert kwargs["files"] == [("upload", (None, "value"))]
    assert spec.cache_key() == (
        "POST",
        "https://example.test/search",
        (("ref", "x"),),
        (("q", "test"),),
        (("upload", "value"),),
    )


@pytest.mark.parametrize(
    "overrides",
    [
        {"location": "header"},
        {"method": "PUT"},
        {"body_format": "xml"},
    ],
)
def test_injection_point_validation(overrides):
    with pytest.raises(ValueError):
        make_point(**overrides)


def test_injection_point_identifier_is_stable_and_distinct():
    first = make_point()
    assert first.identifier == make_point().identifier
    assert first.identifier != make_point(name="page").identifier
    assert len(first.identifier) == 16


def test_injection_point_public_dict_hides_values():
    public = make_point().public_dict()
    assert public == {
        "url": "https://example.test/search",
        "method": "GET",
        "location": "query",
        "parameter": "q",
        "body_format": None,
        "source": "unit-test",
    }
    assert "value" not in public
    assert "payload" not in public


def test_http_response_properties():
    response = HttpResponse(
        url="https://example.test/",
        method="GET",
        status_code=200,
        body="hello",
        headers={"content-type": "text/html"},
        elapsed=0.25,
    )
    assert response.ok
    assert response.body_length == 5
    assert response.content_type == "text/html"
    metadata = response.metadata()
    assert metadata["elapsed_ms"] == 250.0
    assert metadata["blocked"] is False

    failed = HttpResponse("https://example.test/", "GET", 0, "", {}, 1.0, error="refused")
    assert not failed.ok
    assert failed.metadata()["transport_error"] == "refused"


def test_finding_serialization_and_identity():
    finding = make_finding()
    assert finding.identifier == make_finding().identifier
    assert finding.identifier != make_finding(parameter="page").identifier
    assert "q" in finding.title
    assert finding.description
    assert finding.remediation == REMEDIATION
    payload = finding.to_dict()
    assert payload["technique"] == "error"
    assert payload["severity"] == "critical"
    assert payload["confidence"] == "high"
    assert payload["references"]
    assert payload["response"]["status_code"] == 500
    assert json.loads(json.dumps(payload))["id"] == finding.identifier


def test_detection_is_plain_data():
    detection = Detection(
        technique=Technique.TIME,
        payload="x",
        evidence="delayed",
        confidence=Confidence.HIGH,
        detail={"probe": "sleep"},
    )
    assert detection.technique is Technique.TIME
    assert detection.detail["probe"] == "sleep"
    assert detection.column_count is None


def test_scan_stats_duration_and_dict():
    stats = ScanStats()
    stats.finished_at = stats.started_at
    assert stats.duration_seconds == 0.0
    stats.requests = 10
    stats.errors = 1
    stats.waf_observed = ["Cloudflare", "Cloudflare", "Sucuri"]
    payload = stats.to_dict()
    assert payload["requests"] == 10
    assert payload["waf_observed"] == ["Cloudflare", "Sucuri"]


def test_scan_result_summary_sorting_and_json():
    result = ScanResult(target="https://example.test/")
    low = make_finding(
        technique=Technique.BOOLEAN,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
    )
    critical = make_finding(severity=Severity.CRITICAL, confidence=Confidence.HIGH)
    info = make_finding(
        technique=Technique.STACKED,
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
    )
    result.findings = [low, info, critical]
    result.stats.points_discovered = 3
    result.stats.points_tested = 2
    result.stats.requests = 12
    result.errors = ["one error"]
    result.aborted_reason = "budget"

    summary = result.summary()
    assert summary["findings"] == 3
    assert summary["by_severity"]["critical"] == 1
    assert summary["by_severity"]["high"] == 1
    assert summary["by_severity"]["medium"] == 1
    assert summary["by_technique"]["error"] == 1
    assert summary["aborted"] == "budget"
    assert result.sorted_findings()[0] is critical

    document = json.loads(result.to_json())
    assert document["tool"]["name"] == "SQL Inquisitor"
    assert document["target"] == "https://example.test/"
    assert document["summary"]["findings"] == 3
    assert document["authorization"].startswith("The operator confirmed")
    assert document["findings"][0]["severity"] == "critical"


def test_isoformat_uses_utc_suffix():
    value = datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    assert isoformat(value) == "2024-01-02T03:04:05Z"
    assert utc_now().tzinfo is not None
