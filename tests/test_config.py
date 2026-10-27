"""Configuration validation and normalization tests."""

from __future__ import annotations

import pytest

from config import (
    DEFAULT_USER_AGENT,
    normalize_scope,
    normalize_target_url,
)
from errors import ConfigError
from models import ALL_TECHNIQUES, Technique


def test_normalize_target_url_adds_root_path_and_lowercases_host():
    assert normalize_target_url("HTTP://Example.COM") == "http://example.com/"
    assert normalize_target_url("https://Example.com/path?b=1#fragment") == (
        "https://example.com/path?b=1"
    )


def test_normalize_target_url_trims_surrounding_whitespace():
    assert normalize_target_url("  https://example.com/a  ") == "https://example.com/a"


@pytest.mark.parametrize(
    "url",
    [
        "",
        "   ",
        "example.com",
        "ftp://example.com/",
        "http://",
        "http://user:password@example.com/",
        "http://example.com:0/",
        "http://example.com:70000/",
        "http://exa mple.com/",
        "http://example.com/\x00",
        "https://example.com/" + "a" * 5000,
    ],
)
def test_invalid_target_urls_are_rejected(url):
    with pytest.raises(ConfigError):
        normalize_target_url(url)


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        ((), ()),
        (("Example.com",), ("example.com",)),
        (("https://example.com/path",), ("example.com",)),
        (("example.com", "example.com"), ("example.com",)),
        (("*.example.org",), ("*.example.org",)),
        ((" example.com:8443 ",), ("example.com:8443",)),
    ],
)
def test_normalize_scope(values, expected):
    assert normalize_scope(values) == expected


@pytest.mark.parametrize("value", ["*.localhost"])
def test_invalid_scope_patterns(value):
    with pytest.raises(ConfigError):
        normalize_scope((value,))


def test_blank_scope_entries_are_ignored():
    assert normalize_scope(("  ", "example.com", "")) == ("example.com",)


def test_defaults_are_valid_and_typed(config_factory):
    config = config_factory()
    assert config.target.startswith("http://127.0.0.1:")
    assert config.techniques == ALL_TECHNIQUES
    assert config.technique_names == tuple(technique.value for technique in ALL_TECHNIQUES)
    assert config.user_agent == DEFAULT_USER_AGENT
    assert config.log_level == "WARNING"
    assert config.has(Technique.ERROR)
    assert config.has(Technique.TIME)
    assert config.logging_level() > 0


def test_technique_names_and_has_with_subset(config_factory):
    config = config_factory(techniques=(Technique.ERROR, Technique.UNION))
    assert config.technique_names == ("error", "union")
    assert config.has(Technique.UNION)
    assert not config.has(Technique.TIME)


@pytest.mark.parametrize(
    "overrides",
    [
        {"techniques": ()},
        {"techniques": ["error"]},
        {"techniques": (Technique.ERROR, Technique.ERROR)},
        {"delay": -0.1},
        {"delay": 61.0},
        {"timeout": 0.0},
        {"timeout": 601.0},
        {"timeout": 2.0, "connect_timeout": 3.0},
        {"max_retries": -1},
        {"max_retries": 11},
        {"max_pages": 0},
        {"max_pages": 10001},
        {"max_depth": -1},
        {"max_depth": 21},
        {"max_points": 0},
        {"max_points": 100_001},
        {"max_requests": 0},
        {"max_requests": 1_000_001},
        {"max_body_bytes": 1023},
        {"max_body_bytes": 50_000_001},
        {"max_union_columns": 0},
        {"max_union_columns": 21},
        {"time_delay": 0.05},
        {"time_delay": 60.0, "timeout": 30.0},
        {"time_samples": 1},
        {"time_samples": 11},
        {"user_agent": ""},
        {"user_agent": "a" * 513},
        {"headers": {"": "value"}},
        {"headers": {"X-Bad\nName": "value"}},
        {"headers": {"X-Test": "line\nbreak"}},
        {"cookies": {"name": "line\rbreak"}},
        {"proxy": "socks5://proxy.example:1080"},
        {"proxy": "http://"},
        {"tamper": ("unknown",)},
        {"output_formats": ("json",)},
        {"output_prefix": "report", "output_formats": ("xml",)},
        {"log_level": "TRACE"},
    ],
)
def test_invalid_configuration_values(config_factory, overrides):
    with pytest.raises(ConfigError):
        config_factory(**overrides)


def test_tamper_duplicates_are_removed(config_factory):
    config = config_factory(tamper=("spaces", "spaces", "randomcase"))
    assert config.tamper == ("spaces", "randomcase")


def test_output_formats_are_deduplicated_and_prefix_is_expanded(config_factory, tmp_path):
    prefix = tmp_path / "report"
    config = config_factory(output_prefix=prefix, output_formats=("json", "json", "html"))
    assert config.output_formats == ("json", "html")
    assert config.output_prefix == prefix


def test_public_dict_redacts_sensitive_values(config_factory):
    config = config_factory(
        headers={"Authorization": "Bearer super-secret"},
        cookies={"session": "cookie-secret"},
        proxy="http://user:password@proxy.example:8080",
        scope=("example.com",),
        tamper=("spaces",),
        output_prefix="report",
        output_formats=("json", "markdown"),
    )
    public = config.public_dict()
    serialized = repr(public)
    assert "super-secret" not in serialized
    assert "cookie-secret" not in serialized
    assert "password" not in serialized
    assert public["header_names"] == ["Authorization"]
    assert public["cookie_names"] == ["session"]
    assert public["proxy"] == "http://proxy.example"
    assert public["scope"] == ["example.com"]
    assert public["tamper"] == ["spaces"]
    assert public["output_formats"] == ["json", "markdown"]
    assert "headers" not in public
    assert "cookies" not in public


def test_log_level_is_normalized(config_factory):
    assert config_factory(log_level="debug").log_level == "DEBUG"


def test_boolean_flags_defaults(config_factory):
    config = config_factory()
    assert config.verify_tls is True
    assert config.follow_redirects is True
    assert config.fail_on_findings is True
    assert config.thorough is False
