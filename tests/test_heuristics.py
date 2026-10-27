"""Heuristics used for response comparison and timing analysis."""

from __future__ import annotations

import pytest

from heuristics import (
    de_reflect,
    delay_threshold,
    entropy,
    is_delayed,
    median,
    median_absolute_deviation,
    normalize_text,
    similarity,
    timing_scales,
)


def test_normalize_text_lowercases_and_collapses_whitespace():
    assert normalize_text("  Hello\n\tWORLD   again ") == "hello world again"
    assert normalize_text("") == ""


def test_normalize_text_removes_volatile_tokens():
    body = (
        "nonce=0123456789abcdef0123456789abcdef "
        "uuid 12345678-1234-1234-1234-123456789abc "
        "time 2024-01-02T03:04:05Z "
        "epoch 1704164645000 "
        "token: abcdefghijklmnop12345"
    )
    normalized = normalize_text(body)
    assert "<token>" in normalized
    assert "<uuid>" in normalized
    assert "<time>" in normalized
    assert "<epoch>" in normalized
    assert "0123456789abcdef" not in normalized


def test_similarity_extremes_and_ordering():
    assert similarity("same body", "same body") == 1.0
    assert similarity("", "body") == 0.0
    close = similarity("the quick brown fox", "the quick brown cat")
    far = similarity("the quick brown fox", "completely different text")
    assert close > far
    assert 0.0 <= far <= close <= 1.0


def test_similarity_ignores_volatile_values():
    first = "nonce: 0123456789abcdef0123456789abcdef hello"
    second = "nonce: fedcba9876543210fedcba9876543210 hello"
    assert similarity(first, second) == 1.0


def test_de_reflect_removes_payload_variants():
    payload = "test' AND 1=1-- -"
    body = f"<p>value: {payload}</p><p>encoded: test%27%20AND%201%3D1--%20-</p>"
    reflected = de_reflect(body, payload, "test")
    assert payload not in reflected
    assert "test%27%20AND" not in reflected
    assert reflected.count("test") >= 2


def test_de_reflect_handles_empty_body():
    assert de_reflect("", "payload", "original") == ""


def test_median_helpers():
    assert median([]) == 0.0
    assert median([1.0, 3.0, 2.0]) == 2.0
    assert median_absolute_deviation([]) == 0.0
    assert median_absolute_deviation([1.0, 1.0, 1.0]) == 0.0
    assert median_absolute_deviation([1.0, 2.0, 3.0]) == 1.0


def test_is_delayed_uses_baseline_and_expected_delay():
    baseline = [0.010, 0.012, 0.011]
    assert is_delayed(0.60, baseline, 0.5)
    assert not is_delayed(0.10, baseline, 0.5)
    assert not is_delayed(0.60, baseline, 0)
    assert not is_delayed(0.60, [], 0.5)


def test_is_delayed_does_not_flag_slow_but_stable_endpoints():
    slow_baseline = [0.9, 0.92, 0.91]
    assert not is_delayed(1.1, slow_baseline, 0.5)


def test_delay_threshold_is_above_baseline():
    threshold = delay_threshold([0.01, 0.02], 0.5)
    assert 0.3 < threshold < 0.6


def test_timing_scales_requires_proportional_difference():
    baseline = [0.01, 0.01]
    assert timing_scales(0.6, 0.3, 0.6, 0.3, baseline)
    assert not timing_scales(0.6, 0.6, 0.6, 0.3, baseline)
    assert not timing_scales(0.1, 0.3, 0.6, 0.3, baseline)


def test_entropy():
    assert entropy("") == 0.0
    assert entropy("aaaaaaaa") == 0.0
    assert entropy("ab") == pytest.approx(1.0)
