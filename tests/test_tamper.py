"""Payload tamper strategy tests."""

from __future__ import annotations

from tamper import TAMPER_STRATEGIES, apply_tampers


def test_strategy_registry_has_descriptions():
    assert set(TAMPER_STRATEGIES) == {"randomcase", "spaces", "versioned"}
    assert all(description for description in TAMPER_STRATEGIES.values())


def test_randomcase_preserves_meaning_and_changes_keyword_case():
    payload = "1' AND SLEEP(2)-- -"
    transformed = apply_tampers(payload, ["randomcase"])
    assert transformed.lower() == payload.lower()
    assert "and" in transformed.lower()
    assert "sleep" in transformed.lower()


def test_spaces_replaces_spaces_outside_trailing_comment():
    transformed = apply_tampers("1' AND 1=1-- -", ["spaces"])
    assert transformed == "1'/**/AND/**/1=1 -- -"
    assert "/**/" in transformed
    assert "-- -" in transformed


def test_versioned_comments_wrap_keywords():
    transformed = apply_tampers("1' AND 1=1-- -", ["versioned"])
    assert transformed == "1' /*!50000AND*/ 1=1 -- -"
    assert "/*!50000AND*/" in transformed


def test_strategies_chain_in_order():
    payload = "1' AND 1=1-- -"
    first = apply_tampers(payload, ["spaces", "versioned"])
    second = apply_tampers(apply_tampers(payload, ["spaces"]), ["versioned"])
    assert first == second
    assert "/**/" in first


def test_unknown_strategies_are_ignored():
    assert apply_tampers("payload", ["does-not-exist"]) == "payload"
    assert apply_tampers("payload", []) == "payload"


def test_comment_without_trailing_dashes_is_handled():
    assert "/**/" in apply_tampers("1 AND 1=1", ["spaces"])
    assert "/*!50000AND*/" in apply_tampers("1 AND 1=1", ["versioned"])
