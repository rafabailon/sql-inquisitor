"""Authorization and scope guardrails for ethical use."""

from __future__ import annotations

import ipaddress
import sys
from collections.abc import Callable
from urllib.parse import urlsplit

from config import ScanConfig
from errors import AuthorizationError, ScopeError

AUTHORIZATION_PHRASE = "I HAVE AUTHORIZATION"
METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata",
    "instance-data",
    "metadata.azure.internal",
}


def _host_matches(hostname: str, netloc: str, pattern: str) -> bool:
    pattern = pattern.lower().rstrip(".")
    hostname = hostname.lower().rstrip(".")
    netloc = netloc.lower()
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return hostname == suffix or hostname.endswith("." + suffix)
    if ":" in pattern:
        return netloc == pattern
    return hostname == pattern or netloc == pattern


def is_denied_target(url: str) -> bool:
    """Block cloud metadata endpoints, which must never be scanned."""
    parts = urlsplit(url)
    hostname = (parts.hostname or "").lower().rstrip(".")
    if not hostname:
        return True
    if hostname in METADATA_HOSTS:
        return True
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return address.is_link_local or address.is_multicast or address.is_unspecified


class ScopeGuard:
    """Enforce that every request target belongs to the authorized host set."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        target = urlsplit(config.target)
        self.target_host = (target.hostname or "").lower()
        self.target_netloc = target.netloc.lower()
        patterns = config.scope or (self.target_host,)
        self.patterns = tuple(pattern.lower() for pattern in patterns)

    def allows(self, url: str) -> bool:
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"}:
            return False
        hostname = (parts.hostname or "").lower()
        if not hostname or is_denied_target(url):
            return False
        netloc = parts.netloc.lower()
        return any(_host_matches(hostname, netloc, pattern) for pattern in self.patterns)

    def check(self, url: str) -> None:
        if not self.allows(url):
            raise ScopeError(f"URL is outside the authorized scope: {url}")

    def check_target(self) -> None:
        self.check(self.config.target)


def ensure_authorization(
    config: ScanConfig,
    *,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
    is_tty: bool | None = None,
) -> None:
    """Require an explicit, informed confirmation before any network request.

    A non-interactive invocation must pass the ``--authorized`` flag. An interactive terminal
    receives a short warning and must type the exact confirmation phrase.
    """
    if config.authorized:
        return
    interactive = sys.stdin.isatty() if is_tty is None else is_tty
    if not interactive:
        raise AuthorizationError(
            "authorization was not confirmed; pass --authorized only after obtaining written "
            "permission to test the target"
        )
    output_fn("")
    output_fn("SQL Inquisitor performs active SQL injection tests and can cause database load.")
    output_fn("Use it only on systems for which you have explicit written authorization.")
    output_fn("The tool never executes INSERT, UPDATE, DELETE or DDL statements.")
    output_fn("")
    answer = input_fn(f"Type {AUTHORIZATION_PHRASE!r} to continue: ")
    if answer.strip() != AUTHORIZATION_PHRASE:
        raise AuthorizationError("authorization phrase was not entered; scan aborted")
