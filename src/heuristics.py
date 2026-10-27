"""Heuristics for response comparison and timing analysis.

The scanner never trusts a single byte-for-byte comparison. Real applications include CSRF
tokens, timestamps, rotating nonces and advertisements in their pages, so boolean-based
detection uses normalized text similarity and a second confirmation pair.
"""

from __future__ import annotations

import html
import math
import re
import statistics
from collections.abc import Iterable
from difflib import SequenceMatcher
from urllib.parse import quote

TRUE_SIMILARITY = 0.97
FALSE_SIMILARITY = 0.90
SIMILARITY_DELTA = 0.06
NOISE_MARGIN = 0.02

_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_LONG_HEX = re.compile(r"\b(?:0x)?[0-9a-fA-F]{16,}\b")
_LONG_BASE64 = re.compile(r"\b[A-Za-z0-9+/]{32,}={0,2}\b")
_ISO_TIME = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
_EPOCH = re.compile(r"\b1[6-9]\d{8}(?:\d{3})?\b")
_CSRF_VALUE = re.compile(
    r"(?i)((?:csrf|xsrf|nonce|token)[\"']?\s*[:=]\s*[\"']?)[A-Za-z0-9_\-./+=]{12,}"
)
_SPACES = re.compile(r"\s+")
_TOKEN = re.compile(r"[A-Za-z0-9_]+|[^\sA-Za-z0-9_]")
_WORD = re.compile(r"\w+")


def normalize_text(text: str) -> str:
    """Remove common volatile tokens and collapse whitespace."""
    if not text:
        return ""
    normalized = _UUID.sub("<uuid>", text)
    normalized = _ISO_TIME.sub("<time>", normalized)
    normalized = _LONG_HEX.sub("<hex>", normalized)
    normalized = _LONG_BASE64.sub("<b64>", normalized)
    normalized = _EPOCH.sub("<epoch>", normalized)
    normalized = _CSRF_VALUE.sub(r"\1<token>", normalized)
    return _SPACES.sub(" ", normalized).strip().lower()


def _shingle_similarity(first: str, second: str, size: int = 4) -> float:
    first_tokens = _WORD.findall(first)
    second_tokens = _WORD.findall(second)
    if not first_tokens or not second_tokens:
        return 0.0
    first_shingles = {
        " ".join(first_tokens[index : index + size])
        for index in range(max(1, len(first_tokens) - size + 1))
    }
    second_shingles = {
        " ".join(second_tokens[index : index + size])
        for index in range(max(1, len(second_tokens) - size + 1))
    }
    if not first_shingles or not second_shingles:
        return 0.0
    intersection = len(first_shingles & second_shingles)
    union = len(first_shingles | second_shingles)
    return intersection / union if union else 0.0


def similarity(first: str, second: str) -> float:
    """Return a stable similarity score between 0.0 and 1.0.

    Small bodies use ``difflib`` after volatile-token normalization. Large bodies use word
    four-gram Jaccard similarity and a length ratio to keep the cost bounded.
    """
    first_normalized = normalize_text(first)
    second_normalized = normalize_text(second)
    if first_normalized == second_normalized:
        return 1.0
    if not first_normalized or not second_normalized:
        return 0.0
    length_ratio = min(len(first_normalized), len(second_normalized)) / max(
        len(first_normalized), len(second_normalized)
    )
    if max(len(first_normalized), len(second_normalized)) <= 20_000:
        matcher = SequenceMatcher(None, first_normalized, second_normalized, autojunk=False)
        if matcher.quick_ratio() < 0.5:
            return min(matcher.quick_ratio(), length_ratio)
        return matcher.ratio()
    shingles = _shingle_similarity(first_normalized, second_normalized)
    return 0.5 * length_ratio + 0.5 * shingles


def de_reflect(body: str, payload: str, original: str) -> str:
    """Replace an injected payload with the original value to neutralize reflection noise."""
    if not body:
        return body
    variants = {
        payload,
        quote(payload, safe=""),
        html.escape(payload, quote=True),
        html.escape(payload, quote=False),
    }
    result = body
    for variant in sorted(variants, key=len, reverse=True):
        if variant:
            result = result.replace(variant, original)
    return result


def median(values: Iterable[float]) -> float:
    sequence = list(values)
    return statistics.median(sequence) if sequence else 0.0


def median_absolute_deviation(values: Iterable[float]) -> float:
    sequence = list(values)
    if not sequence:
        return 0.0
    center = statistics.median(sequence)
    return statistics.median(abs(value - center) for value in sequence)


def is_delayed(
    elapsed: float,
    baseline_samples: Iterable[float],
    expected_delay: float,
    tolerance: float = 0.7,
) -> bool:
    """Decide whether a response was delayed by roughly ``expected_delay`` seconds.

    The rule compares against a baseline median and the absolute delay, which prevents a
    naturally slow endpoint from being reported as time-based SQL injection.
    """
    samples = list(baseline_samples)
    if not samples or expected_delay <= 0:
        return False
    baseline = statistics.median(samples)
    deviation = median_absolute_deviation(samples)
    jitter_margin = min(max(0.03, deviation * 4.0), expected_delay * 0.2)
    required = max(baseline + expected_delay * tolerance, expected_delay * 0.75)
    return elapsed >= required + jitter_margin


def delay_threshold(baseline_samples: Iterable[float], expected_delay: float) -> float:
    samples = list(baseline_samples)
    baseline = statistics.median(samples) if samples else 0.0
    deviation = median_absolute_deviation(samples)
    jitter_margin = min(max(0.03, deviation * 4.0), expected_delay * 0.2)
    return max(baseline + expected_delay * 0.7, expected_delay * 0.75) + jitter_margin


def timing_scales(
    first_elapsed: float,
    second_elapsed: float,
    first_delay: float,
    second_delay: float,
    baseline_samples: Iterable[float],
) -> bool:
    """Check that a shorter delayed payload is faster than a longer one."""
    samples = list(baseline_samples)
    if not is_delayed(first_elapsed, samples, first_delay):
        return False
    if not is_delayed(second_elapsed, samples, second_delay):
        return False
    difference = first_elapsed - second_elapsed
    expected_difference = first_delay - second_delay
    return difference >= expected_difference * 0.5


def entropy(text: str) -> float:
    """Small helper used by tests and diagnostics, not by detection decisions."""
    if not text:
        return 0.0
    frequencies: dict[str, int] = {}
    for character in text:
        frequencies[character] = frequencies.get(character, 0) + 1
    total = len(text)
    return -sum((count / total) * math.log2(count / total) for count in frequencies.values())
