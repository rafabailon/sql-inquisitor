"""HTML parsing, explicit point construction and crawler tests."""

from __future__ import annotations

import pytest

from config import ScanConfig
from crawler import (
    Crawler,
    build_explicit_points,
    parse_html,
)
from errors import ConfigError
from ethics import ScopeGuard
from http_client import HttpClient


def test_parse_html_extracts_links_forms_and_fields():
    body = """
    <html><body>
    <a href="/one?a=1#frag">one</a>
    <a href="https://other.example/two">two</a>
    <area href="mailto:test@example.test">
    <form action="submit" method="post" enctype="multipart/form-data">
    <input name="q" value="hello">
    <input name="disabled" value="x" disabled>
    <input name="go" type="submit" value="Go">
    <input name="check" type="checkbox" value="1">
    <input name="empty">
    <select name="kind">
    <option value="a">A</option>
    <option value="b" selected>B</option>
    </select>
    <select name="untouched"><option>C</option></select>
    <textarea name="notes"> some text </textarea>
    </form>
    <form action="/get"><input name="g" value="1"></form>
    </body></html>
    """
    page = parse_html(body, "https://example.test/base/")
    assert page.links == [
        "https://example.test/one?a=1#frag",
        "https://other.example/two",
        "mailto:test@example.test",
    ]
    assert len(page.forms) == 2
    first = page.forms[0]
    assert first.action == "https://example.test/base/submit"
    assert first.method == "POST"
    assert first.enctype == "multipart/form-data"
    assert first.fields == [
        ("q", "hello"),
        ("empty", ""),
        ("kind", "b"),
        ("untouched", "C"),
        ("notes", "some text"),
    ]
    second = page.forms[1]
    assert second.method == "GET"
    assert second.enctype == "application/x-www-form-urlencoded"
    assert second.fields == [("g", "1")]


def test_parse_html_tolerates_malformed_markup():
    page = parse_html("<form action=/x><input name=q", "https://example.test/")
    assert page.links == []
    assert page.forms == []


def test_build_explicit_points_from_query_string():
    points = build_explicit_points("https://example.test/search?q=test&page=2")
    assert [point.name for point in points] == ["q", "page"]
    assert points[0].request("payload").params == (("q", "payload"), ("page", "2"))
    assert all(point.method == "GET" for point in points)


def test_build_explicit_points_with_names_on_bare_url():
    points = build_explicit_points("https://example.test/search", ["q", "page"])
    assert [point.name for point in points] == ["q", "page"]
    assert points[0].value == "1"


def test_build_explicit_points_deduplicates_names():
    points = build_explicit_points("https://example.test/search", ["q", "q"])
    assert [point.name for point in points] == ["q"]


def test_build_explicit_points_for_post_body():
    points = build_explicit_points(
        "https://example.test/login?ref=home",
        data="user=alice&password=secret",
    )
    assert [point.name for point in points] == ["user", "password"]
    assert all(point.method == "POST" for point in points)
    assert points[0].body_format == "urlencoded"
    assert points[0].params == (("ref", "home"),)
    spec = points[0].request("payload")
    assert spec.data == (("user", "payload"), ("password", "secret"))


def test_build_explicit_points_post_method_with_names():
    points = build_explicit_points(
        "https://example.test/login", ["user", "password"], method="POST"
    )
    assert [point.name for point in points] == ["user", "password"]
    assert points[0].request("x").data == (("user", "x"), ("password", "1"))


@pytest.mark.parametrize(
    ("target", "params", "data", "method"),
    [
        ("https://example.test/", [], None, None),
        ("https://example.test/", [], "not-a-pair", None),
        ("https://example.test/", ["q"], None, "PUT"),
    ],
)
def test_invalid_explicit_point_builds(target, params, data, method):
    with pytest.raises(ConfigError):
        build_explicit_points(target, params, data, method)


def test_crawler_discovers_query_point(config_factory, lab):
    config = config_factory(path="/search?q=test", crawl=False)
    client = HttpClient(config)
    try:
        result = Crawler(config, client, ScopeGuard(config)).discover()
    finally:
        client.close()
    assert result.pages_fetched == 1
    assert len(result.points) == 1
    point = result.points[0]
    assert point.name == "q"
    assert point.value == "test"
    assert point.location == "query"


def test_crawler_discovers_post_form_points(config_factory, lab):
    config = config_factory(path="/form", crawl=False)
    client = HttpClient(config)
    try:
        result = Crawler(config, client, ScopeGuard(config)).discover()
    finally:
        client.close()
    names = sorted(point.name for point in result.points)
    assert names == ["q", "token"]
    assert all(point.method == "POST" for point in result.points)
    assert all(point.body_format == "urlencoded" for point in result.points)
    assert all(point.url == lab.base_url + "/search" for point in result.points)


def test_crawler_discovers_multipart_form_points(config_factory, lab):
    config = config_factory(path="/multipart-form", crawl=False)
    client = HttpClient(config)
    try:
        result = Crawler(config, client, ScopeGuard(config)).discover()
    finally:
        client.close()
    assert result.points
    assert all(point.body_format == "multipart" for point in result.points)
    assert all(point.url == lab.base_url + "/multipart-search" for point in result.points)


def test_crawler_obeys_robots_txt(config_factory, lab):
    config = config_factory(path="/", max_pages=1, max_depth=1, crawl=True)
    client = HttpClient(config)
    try:
        result = Crawler(config, client, ScopeGuard(config)).discover()
    finally:
        client.close()
    assert result.robots_blocked >= 1
    assert all("/hidden" not in point.source for point in result.points)


def test_crawler_can_ignore_robots_txt(config_factory, lab):
    config = config_factory(path="/", max_pages=1, max_depth=1, crawl=True, respect_robots=False)
    client = HttpClient(config)
    try:
        result = Crawler(config, client, ScopeGuard(config)).discover()
    finally:
        client.close()
    assert result.robots_blocked == 0


def test_crawler_applies_exclude_patterns(config_factory, lab):
    config = config_factory(path="/form", crawl=False, exclude_patterns=("*/search*",))
    client = HttpClient(config)
    try:
        result = Crawler(config, client, ScopeGuard(config)).discover()
    finally:
        client.close()
    assert result.points == []


def test_crawler_respects_max_pages(config_factory, lab):
    config = config_factory(path="/page2", crawl=True, max_depth=2, max_pages=1)
    client = HttpClient(config)
    try:
        result = Crawler(config, client, ScopeGuard(config)).discover()
    finally:
        client.close()
    assert result.pages_fetched == 1


def test_crawler_skips_static_assets_and_external_hosts(config_factory, lab):
    config = config_factory(path="/page2", crawl=True, max_depth=2, max_pages=2)
    client = HttpClient(config)
    try:
        result = Crawler(config, client, ScopeGuard(config)).discover()
    finally:
        client.close()
    assert result.pages_fetched == 2
    assert all(point.url.startswith(lab.base_url) for point in result.points)


def test_crawler_without_html_only_scans_query(config_factory, lab):
    config = config_factory(path="/clean?q=test", crawl=False)
    client = HttpClient(config)
    try:
        result = Crawler(config, client, ScopeGuard(config)).discover()
    finally:
        client.close()
    assert len(result.points) == 1


def test_crawler_reports_transport_errors(lab):
    config = ScanConfig(
        target="http://127.0.0.1:1/missing",
        authorized=True,
        crawl=False,
        delay=0.0,
        timeout=1.0,
        connect_timeout=0.5,
        time_delay=0.2,
        max_retries=0,
    )
    client = HttpClient(config)
    try:
        result = Crawler(config, client, ScopeGuard(config)).discover()
    finally:
        client.close()
    assert result.pages_fetched == 0
    assert result.errors
