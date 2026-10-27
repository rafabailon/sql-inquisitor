"""Typed data models shared by the scanner, detectors and reporters."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from urllib.parse import urlsplit, urlunsplit


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return _CONFIDENCE_RANK[self]


_CONFIDENCE_RANK: dict[Confidence, int] = {
    Confidence.HIGH: 3,
    Confidence.MEDIUM: 2,
    Confidence.LOW: 1,
}


class Technique(str, Enum):
    ERROR = "error"
    BOOLEAN = "boolean"
    TIME = "time"
    UNION = "union"
    STACKED = "stacked"

    @property
    def label(self) -> str:
        return _TECHNIQUE_LABEL[self]

    @property
    def description(self) -> str:
        return _TECHNIQUE_DESCRIPTION[self]


_TECHNIQUE_LABEL: dict[Technique, str] = {
    Technique.ERROR: "error-based",
    Technique.BOOLEAN: "boolean-based blind",
    Technique.TIME: "time-based blind",
    Technique.UNION: "union-based",
    Technique.STACKED: "stacked queries",
}

_TECHNIQUE_DESCRIPTION: dict[Technique, str] = {
    Technique.ERROR: (
        "Crafted input makes the application disclose a database error. The input reaches a SQL "
        "statement without safe parameter binding, which is a direct SQL injection."
    ),
    Technique.BOOLEAN: (
        "Crafted true and false conditions produce consistently different responses while no "
        "database error is disclosed. This is boolean-based blind SQL injection."
    ),
    Technique.TIME: (
        "Crafted database delay expressions increase the response time reproducibly and in "
        "proportion to the requested delay. This is time-based blind SQL injection."
    ),
    Technique.UNION: (
        "A UNION query with a controlled marker is reflected in the response, proving that an "
        "attacker can append result sets to the original query."
    ),
    Technique.STACKED: (
        "A second, non-destructive statement is executed by the database, as shown by an error "
        "that references a table generated only by that second statement."
    ),
}

ALL_TECHNIQUES: tuple[Technique, ...] = (
    Technique.ERROR,
    Technique.BOOLEAN,
    Technique.UNION,
    Technique.STACKED,
    Technique.TIME,
)

_TECHNIQUE_SEVERITY: dict[Technique, Severity] = {
    Technique.ERROR: Severity.CRITICAL,
    Technique.BOOLEAN: Severity.HIGH,
    Technique.TIME: Severity.HIGH,
    Technique.UNION: Severity.CRITICAL,
    Technique.STACKED: Severity.CRITICAL,
}

REMEDIATION = (
    "Replace string concatenation with parameterized queries or prepared statements for every "
    "database call. Validate and allow-list input types at the trust boundary. Apply the "
    "principle of least privilege to the database account used by the application. Disable "
    "verbose database errors in production responses and keep a web application firewall as a "
    "defence-in-depth control, never as the primary fix."
)

REFERENCES: tuple[str, ...] = (
    "https://owasp.org/www-community/attacks/SQL_Injection",
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection",
    "https://cwe.mitre.org/data/definitions/89.html",
    "https://capec.mitre.org/data/definitions/66.html",
)


def severity_for_technique(technique: Technique) -> Severity:
    return _TECHNIQUE_SEVERITY[technique]


def strip_url_query(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


@dataclass(frozen=True)
class RequestSpec:
    """An HTTP request derived from an injection point.

    Query parameters, body fields and multipart fields are stored as ordered tuples so that
    repeated parameter names survive the round trip.
    """

    url: str
    method: str = "GET"
    params: tuple[tuple[str, str], ...] = ()
    data: tuple[tuple[str, str], ...] = ()
    files: tuple[tuple[str, str], ...] = ()

    def as_kwargs(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"method": self.method, "url": self.url}
        if self.params:
            kwargs["params"] = list(self.params)
        if self.data:
            kwargs["data"] = list(self.data)
        if self.files:
            kwargs["files"] = [(name, (None, value)) for name, value in self.files]
        return kwargs

    def cache_key(self) -> tuple[Any, ...]:
        return (
            self.method.upper(),
            self.url,
            self.params,
            self.data,
            self.files,
        )


@dataclass(frozen=True)
class InjectionPoint:
    """One parameter value that can be replaced with a test payload."""

    url: str
    method: str
    location: str
    name: str
    value: str
    params: tuple[tuple[str, str], ...] = ()
    data: tuple[tuple[str, str], ...] = ()
    body_format: str | None = None
    source: str = ""

    def __post_init__(self) -> None:
        if self.location not in {"query", "form"}:
            raise ValueError(f"unsupported injection location: {self.location}")
        if self.method not in {"GET", "POST"}:
            raise ValueError(f"unsupported HTTP method: {self.method}")
        if self.body_format not in {None, "urlencoded", "multipart"}:
            raise ValueError(f"unsupported body format: {self.body_format}")

    @property
    def identifier(self) -> str:
        payload = f"{self.method}|{self.url}|{self.location}|{self.name}|{self.params}|{self.data}"
        return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()[:16]

    def _replace(
        self, pairs: tuple[tuple[str, str], ...], value: str
    ) -> tuple[tuple[str, str], ...]:
        replaced = tuple((key, value if key == self.name else current) for key, current in pairs)
        if any(key == self.name for key, _ in pairs):
            return replaced
        return pairs + ((self.name, value),)

    def request(self, value: str | None = None) -> RequestSpec:
        """Build a request with this parameter replaced by ``value``."""
        new_value = self.value if value is None else value
        if self.location == "query":
            return RequestSpec(
                url=self.url,
                method=self.method,
                params=self._replace(self.params, new_value),
            )
        if self.body_format == "multipart":
            return RequestSpec(
                url=self.url,
                method=self.method,
                params=self.params,
                files=self._replace(self.data, new_value),
            )
        return RequestSpec(
            url=self.url,
            method=self.method,
            params=self.params,
            data=self._replace(self.data, new_value),
        )

    def public_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "location": self.location,
            "parameter": self.name,
            "body_format": self.body_format,
            "source": self.source,
        }


@dataclass
class HttpResponse:
    """A normalized HTTP response, including transport failures."""

    url: str
    method: str
    status_code: int
    body: str
    headers: dict[str, str]
    elapsed: float
    error: str | None = None
    blocked: bool = False
    waf: str | None = None
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status_code < 400

    @property
    def body_length(self) -> int:
        return len(self.body)

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")

    def metadata(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "status_code": self.status_code,
            "response_length": self.body_length,
            "elapsed_ms": round(self.elapsed * 1000.0, 2),
            "blocked": self.blocked,
            "waf": self.waf,
            "transport_error": self.error,
        }


@dataclass
class Detection:
    """A raw confirmation produced by a detector."""

    technique: Technique
    payload: str
    evidence: str
    confidence: Confidence
    dbms: str | None = None
    status_code: int | None = None
    response_length: int | None = None
    elapsed_ms: float | None = None
    column_count: int | None = None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class Finding:
    """A confirmed vulnerability, ready for reporting."""

    technique: Technique
    url: str
    method: str
    parameter: str
    location: str
    payload: str
    severity: Severity
    confidence: Confidence
    evidence: str
    dbms: str | None = None
    status_code: int | None = None
    response_length: int | None = None
    elapsed_ms: float | None = None
    column_count: int | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    remediation: str = REMEDIATION
    references: tuple[str, ...] = REFERENCES
    detected_at: datetime = field(default_factory=utc_now)

    @property
    def title(self) -> str:
        return f"{self.technique.label.capitalize()} SQL injection in parameter '{self.parameter}'"

    @property
    def identifier(self) -> str:
        material = f"{self.technique.value}|{self.method}|{self.url}|{self.parameter}"
        return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:16]

    @property
    def description(self) -> str:
        return self.technique.description

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.identifier,
            "title": self.title,
            "technique": self.technique.value,
            "technique_label": self.technique.label,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "url": self.url,
            "method": self.method,
            "location": self.location,
            "parameter": self.parameter,
            "payload": self.payload,
            "dbms": self.dbms,
            "column_count": self.column_count,
            "evidence": self.evidence,
            "description": self.description,
            "remediation": self.remediation,
            "references": list(self.references),
            "detected_at": isoformat(self.detected_at),
            "response": {
                "status_code": self.status_code,
                "response_length": self.response_length,
                "elapsed_ms": self.elapsed_ms,
            },
            "detail": self.detail,
        }


@dataclass
class ScanStats:
    started_at: datetime = field(default_factory=utc_now)
    finished_at: datetime | None = None
    requests: int = 0
    errors: int = 0
    blocked_requests: int = 0
    points_discovered: int = 0
    points_tested: int = 0
    findings: int = 0
    waf_observed: list[str] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        end = self.finished_at or utc_now()
        return max(0.0, (end - self.started_at).total_seconds())

    def to_dict(self) -> dict[str, Any]:
        return {
            "requests": self.requests,
            "errors": self.errors,
            "blocked_requests": self.blocked_requests,
            "points_discovered": self.points_discovered,
            "points_tested": self.points_tested,
            "findings": self.findings,
            "duration_seconds": round(self.duration_seconds, 3),
            "waf_observed": sorted(set(self.waf_observed)),
        }


@dataclass
class ScanResult:
    target: str
    config: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    points: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    aborted_reason: str | None = None

    @property
    def started_at(self) -> datetime:
        return self.stats.started_at

    @property
    def finished_at(self) -> datetime | None:
        return self.stats.finished_at

    @property
    def duration_seconds(self) -> float:
        return self.stats.duration_seconds

    def summary(self) -> dict[str, Any]:
        by_severity = {severity.value: 0 for severity in Severity}
        by_technique = {technique.value: 0 for technique in Technique}
        for finding in self.findings:
            by_severity[finding.severity.value] += 1
            by_technique[finding.technique.value] += 1
        return {
            "findings": len(self.findings),
            "by_severity": by_severity,
            "by_technique": by_technique,
            "points_discovered": self.stats.points_discovered,
            "points_tested": self.stats.points_tested,
            "requests": self.stats.requests,
            "errors": len(self.errors),
            "aborted": self.aborted_reason,
        }

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda finding: (
                -finding.severity.rank,
                -finding.confidence.rank,
                finding.url,
                finding.parameter,
                finding.technique.value,
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": {
                "name": "SQL Inquisitor",
                "version": _version(),
                "description": "Ethical SQL injection detection for authorized security testing",
            },
            "target": self.target,
            "started_at": isoformat(self.started_at),
            "finished_at": isoformat(self.finished_at) if self.finished_at else None,
            "duration_seconds": round(self.duration_seconds, 3),
            "authorization": "The operator confirmed authorization to test the target.",
            "config": self.config,
            "summary": self.summary(),
            "stats": self.stats.to_dict(),
            "findings": [finding.to_dict() for finding in self.sorted_findings()],
            "points": self.points,
            "errors": self.errors,
            "aborted_reason": self.aborted_reason,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


def _version() -> str:
    try:
        from version import __version__

        return __version__
    except Exception:  # pragma: no cover - defensive fallback
        return "unknown"
