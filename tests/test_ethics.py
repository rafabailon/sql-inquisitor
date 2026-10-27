"""Authorization and scope guardrail tests."""

from __future__ import annotations

import pytest

from errors import AuthorizationError, ScopeError
from ethics import (
    AUTHORIZATION_PHRASE,
    ScopeGuard,
    ensure_authorization,
    is_denied_target,
)


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata/",
        "http://instance-data/",
        "http://metadata.azure.internal/",
        "http://224.0.0.1/",
        "http://0.0.0.0/",
        "http://[::]/",
        "http:///no-host",
    ],
)
def test_denied_targets(url):
    assert is_denied_target(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8080/",
        "https://example.test/",
        "http://10.0.0.5/",
        "http://192.168.1.1/",
    ],
)
def test_allowed_targets_are_not_denied(url):
    assert is_denied_target(url) is False


def test_scope_allows_target_and_exact_host_only(config_factory):
    config = config_factory()
    guard = ScopeGuard(config)
    assert guard.allows(config.target)
    assert guard.allows("http://127.0.0.1:1234/other")
    assert not guard.allows("http://example.test/")
    guard.check_target()


def test_scope_wildcard_matches_apex_and_subdomains(config_factory):
    config = config_factory(scope=("*.example.test",))
    guard = ScopeGuard(config)
    assert guard.allows("https://example.test/")
    assert guard.allows("https://api.example.test/path")
    assert guard.allows("https://deep.api.example.test/path")
    assert not guard.allows("https://example.test.evil.example/")


def test_scope_with_port_matches_netloc(config_factory):
    config = config_factory(scope=("example.test:8443",))
    guard = ScopeGuard(config)
    assert guard.allows("https://example.test:8443/")
    assert not guard.allows("https://example.test:9443/")


def test_scope_rejects_bad_scheme_and_denied_hosts(config_factory):
    config = config_factory(scope=("example.test", "169.254.169.254"))
    guard = ScopeGuard(config)
    assert not guard.allows("ftp://example.test/")
    assert not guard.allows("http://169.254.169.254/")
    assert not guard.allows("http:///no-host")


def test_scope_check_raises_for_outside_url(config_factory):
    config = config_factory()
    guard = ScopeGuard(config)
    with pytest.raises(ScopeError):
        guard.check("https://outside.example/")
    with pytest.raises(ScopeError):
        guard.check("http://127.0.0.2/")


def test_authorization_short_circuits_with_flag(config_factory):
    config = config_factory(authorized=True)

    def fail(_: str) -> str:
        raise AssertionError("input must not be requested when --authorized is supplied")

    ensure_authorization(config, input_fn=fail, is_tty=True)


def test_authorization_requires_flag_in_non_interactive_mode(config_factory):
    config = config_factory(authorized=False)
    with pytest.raises(AuthorizationError):
        ensure_authorization(config, is_tty=False)


def test_authorization_accepts_exact_phrase(config_factory):
    config = config_factory(authorized=False)
    messages: list[str] = []
    ensure_authorization(
        config,
        input_fn=lambda prompt: AUTHORIZATION_PHRASE,
        output_fn=messages.append,
        is_tty=True,
    )
    assert any("authorization" in message.lower() for message in messages)
    assert any("INSERT" in message for message in messages)


def test_authorization_rejects_wrong_phrase(config_factory):
    config = config_factory(authorized=False)
    with pytest.raises(AuthorizationError):
        ensure_authorization(
            config,
            input_fn=lambda prompt: "yes",
            output_fn=lambda message: None,
            is_tty=True,
        )
