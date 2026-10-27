"""Configuration objects and validation for SQL Inquisitor."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from errors import ConfigError
from models import ALL_TECHNIQUES, Technique
from tamper import TAMPER_STRATEGIES

DEFAULT_USER_AGENT = "SQLInquisitor/1.0 (authorized security testing)"
VALID_OUTPUT_FORMATS = ("json", "markdown", "html")
VALID_LOG_LEVELS = ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG")


def normalize_target_url(url: str) -> str:
    """Validate and canonicalize an HTTP or HTTPS target URL."""
    candidate = (url or "").strip()
    if not candidate:
        raise ConfigError("the target URL is empty")
    if len(candidate) > 4096:
        raise ConfigError("the target URL is longer than 4096 characters")
    if any(character.isspace() for character in candidate):
        raise ConfigError("the target URL contains whitespace")
    if any(ord(character) < 32 for character in candidate):
        raise ConfigError("the target URL contains control characters")
    parts = urlsplit(candidate)
    if parts.scheme not in {"http", "https"}:
        raise ConfigError("the target URL must use the http or https scheme")
    if not parts.hostname:
        raise ConfigError("the target URL must include a host")
    if parts.username or parts.password:
        raise ConfigError(
            "credentials in the target URL are not accepted; use request headers or cookies"
        )
    try:
        port = parts.port
    except ValueError as exc:
        raise ConfigError("the target URL contains an invalid port") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ConfigError("the target URL contains an invalid port")
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, parts.query, ""))


def normalize_scope(values: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for raw in values:
        value = (raw or "").strip().lower()
        if not value:
            continue
        if "://" in value:
            parsed = urlsplit(value)
            value = parsed.netloc.lower()
        value = value.split("/", 1)[0]
        if value.startswith("*."):
            suffix = value[2:]
            if not suffix or "." not in suffix:
                raise ConfigError(f"invalid scope pattern: {raw}")
        elif not value:
            raise ConfigError(f"invalid scope pattern: {raw}")
        if value not in normalized:
            normalized.append(value)
    return tuple(normalized)


def _validate_header_map(values: dict[str, str], label: str) -> dict[str, str]:
    cleaned: dict[str, str] = {}
    for name, value in values.items():
        key = str(name).strip()
        text = str(value)
        if not key:
            raise ConfigError(f"{label} contains an empty name")
        if any(character in key for character in "\r\n:"):
            raise ConfigError(f"{label} contains an invalid name: {key!r}")
        if any(character in text for character in "\r\n"):
            raise ConfigError(f"{label} contains a newline in the value for {key!r}")
        cleaned[key] = text
    return cleaned


@dataclass
class ScanConfig:
    """Every tunable used during a scan.

    The dataclass is intentionally plain: it is easy to build from the command line, from a
    test, or from another Python program. Values are validated once in ``__post_init__`` so the
    rest of the code can rely on them.
    """

    target: str
    authorized: bool = False
    techniques: tuple[Technique, ...] = ALL_TECHNIQUES
    timeout: float = 10.0
    connect_timeout: float = 5.0
    max_retries: int = 1
    delay: float = 0.1
    max_pages: int = 20
    max_depth: int = 2
    max_points: int = 100
    max_requests: int = 3000
    max_body_bytes: int = 2_000_000
    max_union_columns: int = 5
    time_delay: float = 3.0
    time_samples: int = 3
    verify_tls: bool = True
    follow_redirects: bool = True
    crawl: bool = True
    scan_query: bool = True
    scan_forms: bool = True
    respect_robots: bool = True
    same_origin_only: bool = True
    user_agent: str = DEFAULT_USER_AGENT
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    proxy: str | None = None
    trust_env: bool = False
    tamper: tuple[str, ...] = ()
    scope: tuple[str, ...] = ()
    exclude_patterns: tuple[str, ...] = ()
    output_prefix: Path | None = None
    output_formats: tuple[str, ...] = ()
    fail_on_findings: bool = True
    quiet: bool = False
    log_level: str = "WARNING"
    log_file: Path | None = None
    stop_after_first: bool = False
    thorough: bool = False

    def __post_init__(self) -> None:
        self.target = normalize_target_url(self.target)
        if not isinstance(self.techniques, tuple) or not self.techniques:
            raise ConfigError("at least one detection technique must be enabled")
        for technique in self.techniques:
            if not isinstance(technique, Technique):
                raise ConfigError(f"invalid detection technique: {technique!r}")
        if len(set(self.techniques)) != len(self.techniques):
            raise ConfigError("duplicate detection techniques are not allowed")
        if self.delay < 0:
            raise ConfigError("the request delay cannot be negative")
        if self.delay > 60:
            raise ConfigError("the request delay cannot exceed 60 seconds")
        if self.timeout <= 0 or self.timeout > 600:
            raise ConfigError("the timeout must be between 0 and 600 seconds")
        if self.connect_timeout <= 0 or self.connect_timeout > self.timeout:
            raise ConfigError("the connect timeout must be positive and no larger than the timeout")
        if not 0 <= self.max_retries <= 10:
            raise ConfigError("max_retries must be between 0 and 10")
        if not 1 <= self.max_pages <= 10_000:
            raise ConfigError("max_pages must be between 1 and 10000")
        if not 0 <= self.max_depth <= 20:
            raise ConfigError("max_depth must be between 0 and 20")
        if not 1 <= self.max_points <= 100_000:
            raise ConfigError("max_points must be between 1 and 100000")
        if not 1 <= self.max_requests <= 1_000_000:
            raise ConfigError("max_requests must be between 1 and 1000000")
        if not 1024 <= self.max_body_bytes <= 50_000_000:
            raise ConfigError("max_body_bytes must be between 1024 and 50000000")
        if not 1 <= self.max_union_columns <= 20:
            raise ConfigError("max_union_columns must be between 1 and 20")
        if not 0.1 <= self.time_delay <= 60:
            raise ConfigError("time_delay must be between 0.1 and 60 seconds")
        if self.time_delay >= self.timeout:
            raise ConfigError("time_delay must be smaller than the request timeout")
        if not 2 <= self.time_samples <= 10:
            raise ConfigError("time_samples must be between 2 and 10")
        if not self.user_agent or len(self.user_agent) > 512:
            raise ConfigError("the user agent must be non-empty and no longer than 512 characters")
        self.headers = _validate_header_map(dict(self.headers), "headers")
        self.cookies = _validate_header_map(dict(self.cookies), "cookies")
        if self.proxy:
            proxy_parts = urlsplit(self.proxy)
            if proxy_parts.scheme not in {"http", "https"} or not proxy_parts.hostname:
                raise ConfigError("the proxy must be an http or https URL with a host")
        for strategy in self.tamper:
            if strategy not in TAMPER_STRATEGIES:
                raise ConfigError(
                    f"unknown tamper strategy: {strategy}; "
                    f"choose from {', '.join(sorted(TAMPER_STRATEGIES))}"
                )
        self.tamper = tuple(dict.fromkeys(self.tamper))
        self.scope = normalize_scope(self.scope)
        self.exclude_patterns = tuple(pattern for pattern in self.exclude_patterns if pattern)
        self.output_formats = tuple(dict.fromkeys(self.output_formats))
        for output_format in self.output_formats:
            if output_format not in VALID_OUTPUT_FORMATS:
                raise ConfigError(
                    f"unknown output format: {output_format}; "
                    f"choose from {', '.join(VALID_OUTPUT_FORMATS)}"
                )
        if self.output_formats and self.output_prefix is None:
            raise ConfigError("file output formats require an output path")
        if self.output_prefix is not None:
            self.output_prefix = Path(self.output_prefix).expanduser()
        if self.log_level.upper() not in VALID_LOG_LEVELS:
            raise ConfigError(f"invalid log level: {self.log_level}")
        self.log_level = self.log_level.upper()
        if self.log_file is not None:
            self.log_file = Path(self.log_file).expanduser()

    @property
    def technique_names(self) -> tuple[str, ...]:
        return tuple(technique.value for technique in self.techniques)

    def has(self, technique: Technique) -> bool:
        return technique in self.techniques

    def logging_level(self) -> int:
        return getattr(logging, self.log_level)

    def public_dict(self) -> dict[str, Any]:
        """Return a report-safe summary without headers, cookies or proxy credentials."""
        proxy = None
        if self.proxy:
            parts = urlsplit(self.proxy)
            proxy = urlunsplit((parts.scheme, parts.hostname or "", "", "", ""))
        return {
            "target": self.target,
            "techniques": list(self.technique_names),
            "time_delay_seconds": self.time_delay,
            "request_delay_seconds": self.delay,
            "timeout_seconds": self.timeout,
            "max_retries": self.max_retries,
            "crawl": self.crawl,
            "scan_forms": self.scan_forms,
            "respect_robots": self.respect_robots,
            "same_origin_only": self.same_origin_only,
            "max_pages": self.max_pages,
            "max_depth": self.max_depth,
            "max_points": self.max_points,
            "max_requests": self.max_requests,
            "max_union_columns": self.max_union_columns,
            "time_samples": self.time_samples,
            "verify_tls": self.verify_tls,
            "follow_redirects": self.follow_redirects,
            "tamper": list(self.tamper),
            "scope": list(self.scope),
            "exclude_patterns": list(self.exclude_patterns),
            "output_formats": list(self.output_formats),
            "header_names": sorted(self.headers),
            "cookie_names": sorted(self.cookies),
            "proxy": proxy,
            "user_agent": self.user_agent,
            "fail_on_findings": self.fail_on_findings,
            "stop_after_first": self.stop_after_first,
            "thorough": self.thorough,
        }
