"""A deliberately vulnerable local lab used by the test suite and for manual demos.

This module contains no production code. It is a small SQLite-backed HTTP server with string
concatenated SQL, plus a few safe endpoints used to test false-positive resistance, robots.txt
handling, redirects, retries and multipart forms.

Run it manually with ``python tests/target_server.py --port 8080`` and scan it with
``sql-inquisitor http://127.0.0.1:8080/ --authorized``.
"""

from __future__ import annotations

import argparse
import html
import sqlite3
import threading
import time
import uuid
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

ITEMS = (
    (1, "apple", "fruit", 1.5),
    (2, "banana", "fruit", 0.5),
    (3, "test", "tool", 9.0),
)


def _sleep(seconds) -> int:
    try:
        time.sleep(max(0.0, float(seconds)))
    except (TypeError, ValueError):
        return 0
    return 0


def _connection() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.create_function("sleep", 1, _sleep)
    connection.create_function("pg_sleep", 1, _sleep)
    connection.execute(
        "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, category TEXT, price REAL)"
    )
    connection.executemany("INSERT INTO items VALUES (?, ?, ?, ?)", ITEMS)
    return connection


def _query_value(query: str, name: str, default: str = "") -> str:
    values = parse_qs(query, keep_blank_values=True).get(name)
    return values[0] if values else default


class LabState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.gateway_calls = 0
        self.requests = 0


def create_server(host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), LabHandler)
    server.daemon_threads = True
    server.state = LabState()  # type: ignore[attr-defined]
    return server


class LabHandler(BaseHTTPRequestHandler):
    server_version = "SQLInquisitorLab/1.0"
    protocol_version = "HTTP/1.0"

    @property
    def state(self) -> LabState:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - stdlib signature
        return

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        with self.state.lock:
            self.state.requests += 1
        parts = urlsplit(self.path)
        path = parts.path.rstrip("/") or "/"
        try:
            if path == "/":
                self._send(200, self._index())
            elif path == "/robots.txt":
                self._send(200, "User-agent: *\nDisallow: /hidden\n", "text/plain")
            elif path == "/search":
                self._search(parts, method)
            elif path == "/multipart-search":
                self._multipart_search(method)
            elif path == "/clean":
                self._clean(parts, method)
            elif path == "/numeric":
                self._numeric(parts)
            elif path == "/blind":
                self._blind(parts)
            elif path == "/time":
                self._time(parts)
            elif path == "/union":
                self._union(parts)
            elif path == "/stacked":
                self._stacked(parts)
            elif path == "/form":
                self._send(
                    200,
                    self._form("/search", "application/x-www-form-urlencoded"),
                )
            elif path == "/multipart-form":
                self._send(
                    200,
                    self._form("/multipart-search", "multipart/form-data"),
                )
            elif path == "/dynamic":
                self._dynamic(parts)
            elif path == "/fake-error":
                self._fake_error(parts)
            elif path == "/hidden":
                self._search(parts, method, title="Hidden search")
            elif path == "/page2":
                self._page2()
            elif path == "/page3":
                self._page3()
            elif path == "/waf":
                self._waf(parts)
            elif path == "/slow":
                self._slow(parts)
            elif path == "/large":
                self._large(parts)
            elif path == "/gateway":
                self._gateway(parts)
            elif path == "/redirect":
                self._redirect()
            elif path == "/error":
                self._send(500, "Internal server error", "text/plain")
            else:
                self._send(404, "Not found", "text/plain")
        except BrokenPipeError:
            return

    def _index(self) -> str:
        links = [
            "/search?q=test",
            "/clean?q=test",
            "/numeric?id=1",
            "/blind?q=test",
            "/union?q=test",
            "/stacked?id=1",
            "/form",
            "/multipart-form",
            "/dynamic?q=test",
            "/fake-error?q=test",
            "/hidden?q=test",
            "/page2",
            "/waf?q=test",
            "/slow?q=test",
            "/large?size=100",
            "/gateway?q=test",
            "/redirect",
        ]
        items = "".join(f'<li><a href="{link}">{link}</a></li>' for link in links)
        return f"""<!DOCTYPE html>
<html><head><title>SQL Inquisitor Lab</title></head>
<body><h1>SQL Inquisitor Lab</h1><ul>{items}</ul></body></html>"""

    def _search(self, parts, method: str, title: str = "Search") -> None:
        params = self._params(parts, method)
        value = params.get("q", "")
        connection = _connection()
        try:
            rows = connection.execute(
                f"SELECT id, name, category, price FROM items WHERE name LIKE '%{value}%'"
            ).fetchall()
        except sqlite3.Error as exc:
            self._send(500, f"Database error: {exc}", "text/plain")
            return
        finally:
            connection.close()
        table = "".join(
            f"<tr><td>{html.escape(str(row[0]))}</td><td>{html.escape(str(row[1]))}</td>"
            f"<td>{html.escape(str(row[2]))}</td><td>{html.escape(str(row[3]))}</td></tr>"
            for row in rows
        )
        self._send(
            200,
            f"""<!DOCTYPE html>
<html><head><title>{html.escape(title)}</title></head>
<body><h1>{html.escape(title)}</h1>
<p>Results for: {html.escape(value)}</p>
<table><thead><tr><th>id</th><th>name</th><th>category</th><th>price</th></tr></thead>
<tbody>{table}</tbody></table></body></html>""",
        )

    def _clean(self, parts, method: str) -> None:
        params = self._params(parts, method)
        value = params.get("q", "")
        connection = _connection()
        try:
            rows = connection.execute(
                "SELECT id, name, category, price FROM items WHERE name LIKE ?",
                (f"%{value}%",),
            ).fetchall()
        except sqlite3.Error as exc:
            self._send(500, f"Database error: {exc}", "text/plain")
            return
        finally:
            connection.close()
        body = "".join(
            f"<li>{html.escape(str(row[0]))} {html.escape(str(row[1]))}</li>" for row in rows
        )
        self._send(
            200,
            f"<html><body><h1>Clean search</h1><p>Results for: {html.escape(value)}</p>"
            f"<ul>{body}</ul></body></html>",
        )

    def _numeric(self, parts) -> None:
        value = _query_value(parts.query, "id", "1")
        connection = _connection()
        try:
            rows = connection.execute(
                f"SELECT id, name, category, price FROM items WHERE id = {value}"
            ).fetchall()
        except sqlite3.Error as exc:
            self._send(500, f"Database error: {exc}", "text/plain")
            return
        finally:
            connection.close()
        body = "".join(
            f"<li>{html.escape(str(row[0]))} {html.escape(str(row[1]))}</li>" for row in rows
        )
        self._send(
            200,
            f"<html><body><h1>Numeric item</h1><p>id={html.escape(value)}</p>"
            f"<ul>{body}</ul></body></html>",
        )

    def _blind(self, parts) -> None:
        value = _query_value(parts.query, "q", "")
        connection = _connection()
        try:
            rows = connection.execute(
                f"SELECT id FROM items WHERE name LIKE '%{value}%'"
            ).fetchall()
        except sqlite3.Error as exc:
            self._send(500, f"Database error: {exc}", "text/plain")
            return
        finally:
            connection.close()
        self._send(200, "ITEM FOUND" if rows else "NO RESULTS", "text/plain")

    def _time(self, parts) -> None:
        value = _query_value(parts.query, "q", "")
        connection = _connection()
        try:
            connection.execute(f"SELECT id FROM items WHERE name LIKE '%{value}%'").fetchall()
        except sqlite3.Error as exc:
            self._send(500, f"Database error: {exc}", "text/plain")
            return
        finally:
            connection.close()
        self._send(200, "timing endpoint ok", "text/plain")

    def _union(self, parts) -> None:
        value = _query_value(parts.query, "q", "")
        connection = _connection()
        try:
            rows = connection.execute(
                f"SELECT id, name, category FROM items WHERE name LIKE '%{value}%'"
            ).fetchall()
        except sqlite3.Error as exc:
            self._send(500, f"Database error: {exc}", "text/plain")
            return
        finally:
            connection.close()
        body = "".join(
            f"<tr><td>{row[0]}</td><td>{html.escape(str(row[1]))}</td>"
            f"<td>{html.escape(str(row[2]))}</td></tr>"
            for row in rows
        )
        self._send(
            200,
            f"<html><body><h1>Union endpoint</h1><p>Results for: {html.escape(value)}</p>"
            f"<table>{body}</table></body></html>",
        )

    def _stacked(self, parts) -> None:
        value = _query_value(parts.query, "id", "1")
        connection = _connection()
        try:
            connection.executescript(f"SELECT id, name FROM items WHERE id = {value};")
        except sqlite3.Error as exc:
            self._send(500, f"Database error: {exc}", "text/plain")
            return
        finally:
            connection.close()
        self._send(200, "stacked endpoint ok", "text/plain")

    def _dynamic(self, parts) -> None:
        value = _query_value(parts.query, "q", "")
        nonce = str(uuid.uuid4())
        connection = _connection()
        try:
            rows = connection.execute(
                f"SELECT id, name FROM items WHERE name LIKE '%{value}%'"
            ).fetchall()
        except sqlite3.Error as exc:
            self._send(500, f"Database error: {exc}", "text/plain")
            return
        finally:
            connection.close()
        body = "".join(
            f"<li>{html.escape(str(row[0]))} {html.escape(str(row[1]))}</li>" for row in rows
        )
        self._send(
            200,
            f"<html><body><p>nonce: {nonce}</p><p>Results for: {html.escape(value)}</p>"
            f"<ul>{body}</ul></body></html>",
        )

    def _fake_error(self, parts) -> None:
        value = _query_value(parts.query, "q", "")
        connection = _connection()
        try:
            rows = connection.execute(
                "SELECT id, name FROM items WHERE name LIKE ?", (f"%{value}%",)
            ).fetchall()
        except sqlite3.Error as exc:
            self._send(500, f"Database error: {exc}", "text/plain")
            return
        finally:
            connection.close()
        body = "".join(
            f"<li>{html.escape(str(row[0]))} {html.escape(str(row[1]))}</li>" for row in rows
        )
        self._send(
            200,
            "<html><body><h1>Debug handbook</h1>"
            "<p>Warning: mysql_query() failed is an example of a message we document.</p>"
            "<p>SQLSTATE[HY000] is another documentation example.</p>"
            f"<p>Results for: {html.escape(value)}</p><ul>{body}</ul></body></html>",
        )

    def _page2(self) -> None:
        self._send(
            200,
            '<html><body><h1>Page two</h1><a href="/page3">page three</a>'
            '<a href="/search?q=apple">apple search</a></body></html>',
        )

    def _page3(self) -> None:
        self._send(
            200, '<html><body><h1>Page three</h1><a href="/clean?q=apple">clean</a></body></html>'
        )

    def _form(self, action: str, enctype: str) -> str:
        return f"""<!DOCTYPE html>
<html><body><h1>Form</h1>
<form action="{action}" method="post" enctype="{enctype}">
<label>Query <input type="text" name="q" value="test"></label>
<input type="hidden" name="token" value="fixed-token">
<button type="submit" name="go" value="1">Search</button>
</form></body></html>"""

    def _multipart_search(self, method: str) -> None:
        params = self._params(urlsplit(self.path), method)
        value = params.get("q", "")
        connection = _connection()
        try:
            rows = connection.execute(
                f"SELECT id, name FROM items WHERE name LIKE '%{value}%'"
            ).fetchall()
        except sqlite3.Error as exc:
            self._send(500, f"Database error: {exc}", "text/plain")
            return
        finally:
            connection.close()
        body = "".join(
            f"<li>{html.escape(str(row[0]))} {html.escape(str(row[1]))}</li>" for row in rows
        )
        self._send(
            200,
            f"<html><body><h1>Multipart search</h1><p>Results for: {html.escape(value)}</p>"
            f"<ul>{body}</ul></body></html>",
        )

    def _waf(self, parts) -> None:
        value = _query_value(parts.query, "q", "")
        lowered = value.lower()
        if "'" in value or '"' in value or "union" in lowered or "sleep" in lowered:
            self._send(
                403,
                "<html><body><h1>Attention Required! | Cloudflare</h1>"
                "<p>Request blocked.</p></body></html>",
                headers={"cf-ray": "lab"},
            )
            return
        self._send(200, f"<html><body>WAF endpoint for {html.escape(value)}</body></html>")

    def _slow(self, parts) -> None:
        value = _query_value(parts.query, "q", "")
        time.sleep(0.2)
        self._send(200, f"<html><body>slow endpoint for {html.escape(value)}</body></html>")

    def _large(self, parts) -> None:
        size = _query_value(parts.query, "size", "100")
        try:
            count = max(1, min(int(size), 20_000))
        except ValueError:
            count = 100
        self._send(200, "A" * count, "text/plain")

    def _gateway(self, parts) -> None:
        with self.state.lock:
            calls = self.state.gateway_calls
            self.state.gateway_calls += 1
        if calls == 0:
            self._send(502, "temporary gateway failure", "text/plain")
            return
        value = _query_value(parts.query, "q", "")
        self._send(200, f"<html><body>gateway ok for {html.escape(value)}</body></html>")

    def _redirect(self) -> None:
        self._send(302, "", headers={"Location": "/search?q=apple"})

    def _params(self, parts, method: str) -> dict[str, str]:
        params = {
            name: values[0]
            for name, values in parse_qs(parts.query, keep_blank_values=True).items()
        }
        if method != "POST":
            return params
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(min(length, 2_000_000))
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" in content_type:
            message = BytesParser(policy=policy.default).parsebytes(
                b"Content-Type: " + content_type.encode("latin-1") + b"\r\n"
                b"MIME-Version: 1.0\r\n\r\n" + body
            )
            for part in message.iter_parts():
                name = part.get_param("name", header="content-disposition")
                if name:
                    payload = part.get_payload(decode=True) or b""
                    params[name] = payload.decode("utf-8", errors="replace")
        else:
            params.update(
                {
                    name: values[0]
                    for name, values in parse_qs(
                        body.decode("utf-8", errors="replace"), keep_blank_values=True
                    ).items()
                }
            )
        return params

    def _send(
        self,
        status: int,
        body: str,
        content_type: str = "text/html; charset=utf-8",
        headers: dict[str, str] | None = None,
    ) -> None:
        encoded = body.encode("utf-8", errors="replace")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("X-Lab", "sql-inquisitor")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if encoded:
            self.wfile.write(encoded)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the deliberately vulnerable SQL Inquisitor lab"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    server = create_server(args.host, args.port)
    host, port = server.server_address[:2]
    print(f"SQL Inquisitor lab listening on http://{host}:{port}/")
    print("This server is intentionally vulnerable. Keep it bound to localhost.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
