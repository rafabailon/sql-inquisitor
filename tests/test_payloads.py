"""Payload generation tests, including the read-only safety invariant."""

from __future__ import annotations

import re

import pytest

from models import Technique
from payloads import (
    apply_tamper,
    boolean_pairs,
    error_payloads,
    looks_numeric,
    numeric_marker_expression,
    stacked_payloads,
    time_payloads,
    union_contexts,
    union_payload,
)

DESTRUCTIVE = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|TRUNCATE|CREATE|REPLACE|MERGE|GRANT|REVOKE)\b",
    re.IGNORECASE,
)


def all_payload_values() -> list[str]:
    values = [payload.value for payload in error_payloads("test")]
    for pair in boolean_pairs("test"):
        values.extend([pair.true_value, pair.false_value])
    values.extend(payload.value for payload in time_payloads("test", 0.5))
    for context in union_contexts("test"):
        values.append(union_payload("test", context, ["1", "NULL"]))
    values.extend(payload.value for payload in stacked_payloads("test", "inqtoken"))
    return values


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("1", True),
        ("-1", True),
        ("1.5", True),
        (" 42 ", True),
        ("1 OR 1", False),
        ("test", False),
        ("", False),
        ("1e3", False),
    ],
)
def test_looks_numeric(value, expected):
    assert looks_numeric(value) is expected


def test_error_payloads_are_unique_and_typed():
    payloads = error_payloads("test")
    values = [payload.value for payload in payloads]
    assert len(values) == len(set(values))
    assert "test'" in values
    assert 'test"' in values
    assert "test\\" in values
    assert all(payload.technique is Technique.ERROR for payload in payloads)
    assert all(payload.description for payload in payloads)
    assert {payload.context for payload in payloads} == {"string"}


def test_error_payloads_detect_numeric_context():
    payloads = error_payloads("1")
    by_value = {payload.value: payload for payload in payloads}
    assert by_value["1'"].context == "numeric"
    assert by_value["'"].context == "string"


def test_boolean_pairs_are_ordered_paired_and_unique():
    pairs = boolean_pairs("test")
    assert len(pairs) >= 10
    assert pairs[0].true_value == "test%' AND '1'='1'-- -"
    assert pairs[0].false_value == "test%' AND '1'='2'-- -"
    keys = {(pair.true_value, pair.false_value) for pair in pairs}
    assert len(keys) == len(pairs)
    assert all(pair.true_value != pair.false_value for pair in pairs)
    assert all(pair.baseline_side in {"true", "false"} for pair in pairs)
    assert all(pair.context for pair in pairs)


def test_boolean_pairs_include_numeric_and_quote_contexts():
    pairs = boolean_pairs("1")
    contexts = {pair.context for pair in pairs}
    assert {"single-quote", "double-quote", "parenthesis", "numeric"} <= contexts
    numeric = [pair for pair in pairs if pair.context == "numeric"]
    assert numeric[0].true_value == "1 AND 1=1-- -"


def test_boolean_pair_rejects_invalid_baseline_side():
    with pytest.raises(ValueError):
        type(boolean_pairs("test")[0])(
            true_value="a",
            false_value="b",
            context="x",
            dbms=None,
            baseline_side="maybe",
        )


def test_time_payloads_cover_major_dbms_families():
    payloads = time_payloads("test", 0.5)
    families = {payload.dbms for payload in payloads}
    assert "MySQL/MariaDB" in families
    assert "PostgreSQL" in families
    assert "Microsoft SQL Server" in families
    assert "Oracle" in families
    assert all(payload.technique is Technique.TIME for payload in payloads)
    assert all("0.5" in payload.value or "0:0:1" in payload.value for payload in payloads)
    assert len({payload.value for payload in payloads}) == len(payloads)


def test_time_payloads_format_ms_sql_seconds_as_whole_seconds():
    payloads = time_payloads("1", 2.4)
    mssql = [payload for payload in payloads if payload.dbms == "Microsoft SQL Server"]
    assert mssql
    assert all("0:0:2" in payload.value for payload in mssql)


@pytest.mark.parametrize("delay", [0, -1])
def test_time_payloads_reject_non_positive_delay(delay):
    with pytest.raises(ValueError):
        time_payloads("test", delay)


def test_union_contexts_put_numeric_first_for_numeric_input():
    contexts = union_contexts("1")
    assert contexts[0].context == "numeric"
    assert contexts[0].closing == ""
    string_contexts = union_contexts("test")
    assert string_contexts[0].context == "single-quote"
    assert all(context.context != "numeric" for context in string_contexts)
    assert any(context.use_from_dual for context in contexts)


def test_union_payload_construction():
    context = union_contexts("test")[0]
    payload = union_payload("test", context, ["1", "NULL", "NULL"])
    assert payload == "test' UNION SELECT 1, NULL, NULL-- -"
    alternative = union_payload("test", context, ["1"], comment="#", union_all=True)
    assert alternative == "test' UNION ALL SELECT 1#"
    dual_context = next(context for context in union_contexts("test") if context.use_from_dual)
    assert union_payload("test", dual_context, ["1"]).endswith(" FROM dual-- -")


def test_numeric_marker_expression_never_contains_marker():
    marker = 12345678
    expression = numeric_marker_expression(marker)
    assert expression == "(12345677)+1"
    assert str(marker) not in expression
    with pytest.raises(ValueError):
        numeric_marker_expression(1)


def test_stacked_payloads_are_tokenized_and_non_destructive():
    payloads = stacked_payloads("1", "inqabc123")
    token_payloads = [payload for payload in payloads if payload.token]
    division_payloads = [payload for payload in payloads if payload.token is None]
    assert token_payloads
    assert division_payloads
    assert all(payload.token == "inqabc123" for payload in token_payloads)
    assert all("SELECT * FROM inqabc123" in payload.value for payload in token_payloads)
    assert any("1/0" in payload.value for payload in division_payloads)


def test_no_payload_is_destructive():
    for value in all_payload_values():
        assert not DESTRUCTIVE.search(value), value


def test_apply_tamper_without_strategies_is_identity():
    assert apply_tamper("test' AND 1=1-- -", ()) == "test' AND 1=1-- -"
