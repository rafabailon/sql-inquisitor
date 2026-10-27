"""Sanity tests for the deliberately vulnerable lab server itself."""

from __future__ import annotations

import time

import requests
from target_server import _connection, _query_value, _sleep, create_server


def get(lab, path, **kwargs):
    return requests.get(lab.base_url + path, timeout=5, **kwargs)


def test_lab_state_and_server_factory():
    server = create_server("127.0.0.1", 0)
    try:
        assert server.state.requests == 0
        assert server.state.gateway_calls == 0
        assert server.server_address[0] == "127.0.0.1"
    finally:
        server.server_close()


def test_connection_seeds_items_table():
    connection = _connection()
    try:
        rows = connection.execute("SELECT id, name FROM items ORDER BY id").fetchall()
    finally:
        connection.close()
    assert rows == [(1, "apple"), (2, "banana"), (3, "test")]


def test_query_value_and_sleep_helpers():
    assert _query_value("a=1&b=2", "a") == "1"
    assert _query_value("a=1", "missing", "default") == "default"
    assert _sleep(0) == 0
    assert _sleep("bad") == 0


def test_index_lists_endpoints(lab):
    response = get(lab, "/")
    assert response.status_code == 200
    assert "SQL Inquisitor Lab" in response.text
    assert "/search?q=test" in response.text
    assert response.headers["X-Lab"] == "sql-inquisitor"


def test_robots_txt(lab):
    response = get(lab, "/robots.txt")
    assert response.status_code == 200
    assert "Disallow: /hidden" in response.text


def test_search_endpoint_returns_rows(lab):
    response = get(lab, "/search", params={"q": "test"})
    assert response.status_code == 200
    assert "Results for: test" in response.text
    assert "<td>test</td>" in response.text


def test_search_endpoint_renders_null_union_rows(lab):
    payload = "test' UNION SELECT 1, NULL, NULL, NULL-- -"
    response = get(lab, "/search", params={"q": payload})
    assert response.status_code == 200
    assert "None" in response.text


def test_dynamic_endpoint_renders_null_union_rows(lab):
    payload = "test' UNION SELECT 1, NULL-- -"
    response = get(lab, "/dynamic", params={"q": payload})
    assert response.status_code == 200
    assert "nonce:" in response.text
    assert "None" in response.text


def test_dynamic_endpoint_changes_nonce(lab):
    first = get(lab, "/dynamic", params={"q": "test"}).text
    second = get(lab, "/dynamic", params={"q": "test"}).text
    assert first != second
    first_nonce = first.split("nonce:")[1].split("</p>")[0].strip()
    second_nonce = second.split("nonce:")[1].split("</p>")[0].strip()
    assert first_nonce != second_nonce


def test_clean_endpoint_uses_parameter_binding(lab):
    response = get(lab, "/clean", params={"q": "test"})
    assert response.status_code == 200
    assert "Clean search" in response.text


def test_blind_endpoint_boolean_split(lab):
    true_response = get(lab, "/blind", params={"q": "test' AND '1'='1'-- -"})
    false_response = get(lab, "/blind", params={"q": "test' AND '1'='2'-- -"})
    assert true_response.text == "ITEM FOUND"
    assert false_response.text == "NO RESULTS"


def test_time_endpoint_actually_sleeps(lab):
    started = time.monotonic()
    response = get(lab, "/time", params={"q": "test' AND SLEEP(0.2)-- -"})
    elapsed = time.monotonic() - started
    assert response.status_code == 200
    assert elapsed >= 0.18


def test_union_endpoint(lab):
    response = get(lab, "/union", params={"q": "test"})
    assert response.status_code == 200
    assert "Union endpoint" in response.text


def test_stacked_endpoint_reports_missing_table(lab):
    response = get(lab, "/stacked", params={"id": "1; SELECT * FROM inqmissing-- -"})
    assert response.status_code == 500
    assert "no such table: inqmissing" in response.text


def test_numeric_endpoint(lab):
    response = get(lab, "/numeric", params={"id": "1"})
    assert response.status_code == 200
    assert "id=1" in response.text
    assert "apple" in response.text


def test_forms_point_to_internal_actions(lab):
    form = get(lab, "/form")
    multipart = get(lab, "/multipart-form")
    assert 'action="/search"' in form.text
    assert 'action="/multipart-search"' in multipart.text
    assert 'name="q"' in form.text
    assert 'name="token"' in form.text


def test_urlencoded_post_to_search(lab):
    response = requests.post(
        lab.base_url + "/search",
        data={"q": "test", "token": "fixed-token"},
        timeout=5,
    )
    assert response.status_code == 200
    assert "Results for: test" in response.text


def test_multipart_post_to_multipart_search(lab):
    response = requests.post(
        lab.base_url + "/multipart-search",
        files={"q": (None, "test"), "token": (None, "fixed-token")},
        timeout=5,
    )
    assert response.status_code == 200
    assert "Results for: test" in response.text


def test_fake_error_endpoint_looks_scary_but_is_safe(lab):
    response = get(lab, "/fake-error", params={"q": "test"})
    assert response.status_code == 200
    assert "mysql_query() failed" in response.text
    assert "SQLSTATE[HY000]" in response.text


def test_waf_endpoint_blocks_injection_markers(lab):
    blocked = get(lab, "/waf", params={"q": "test'"})
    allowed = get(lab, "/waf", params={"q": "test"})
    assert blocked.status_code == 403
    assert "Cloudflare" in blocked.text
    assert "cf-ray" in {name.lower() for name in blocked.headers}
    assert allowed.status_code == 200


def test_redirect_endpoint(lab):
    response = get(lab, "/redirect", allow_redirects=False)
    assert response.status_code == 302
    assert response.headers["Location"] == "/search?q=apple"


def test_gateway_endpoint_fails_once_then_succeeds(lab):
    lab.state.gateway_calls = 0
    first = get(lab, "/gateway", params={"q": "test"})
    second = get(lab, "/gateway", params={"q": "test"})
    assert first.status_code == 502
    assert second.status_code == 200
    assert "gateway ok" in second.text


def test_large_endpoint_is_bounded(lab):
    response = get(lab, "/large", params={"size": "99999"})
    assert response.status_code == 200
    assert len(response.text) == 20_000


def test_unknown_route_and_error_route(lab):
    assert get(lab, "/does-not-exist").status_code == 404
    assert get(lab, "/error").status_code == 500


def test_hidden_route_responds_even_though_robots_disallows_it(lab):
    response = get(lab, "/hidden", params={"q": "test"})
    assert response.status_code == 200
    assert "Hidden search" in response.text


def test_request_counter_increments(lab):
    before = lab.state.requests
    get(lab, "/clean", params={"q": "test"})
    assert lab.state.requests == before + 1
