# Testing

SQL Inquisitor ships with an automated pytest suite that exercises every layer of the application and the deliberately vulnerable lab server that the integration tests use as a target. The suite is designed to be deterministic, offline and fast. It does not contact the public internet, does not require a database server and does not need Docker or any external penetration testing tool. The lab server binds to an ephemeral port on the loopback interface for the duration of the test session and is shut down when the session ends.

## Preparing the environment

Install the package in editable mode together with the development extras. The runtime dependency is `requests`; the development extras add `pytest`, `pytest-cov` and `ruff`. The commands below assume that you are in the repository root and that you have created and activated a virtual environment.

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]"
```

The editable installation is not strictly required because `pyproject.toml` sets `pythonpath = ["src"]` and `testpaths = ["tests"]` for pytest. It is nevertheless the closest reproduction of a user installation and it makes the `sql-inquisitor` command available to the CLI tests. If you prefer not to install the project, run the suite from the repository root with `PYTHONPATH=src python3 -m pytest -q`.

## Running the suite

The default invocation runs every test and prints a short summary. The `-ra` option in the project configuration lists skipped and failed tests with their reasons.

```bash
python3 -m pytest -q
```

Coverage is measured with branch coverage over the source tree in `src/`. The configuration in `pyproject.toml` already restricts the source, enables branch coverage and shows missing lines.

```bash
python3 -m pytest -q --cov=src --cov-report=term-missing
```

An HTML coverage report is useful when you are adding a detector or a parser.

```bash
python3 -m pytest -q --cov=src --cov-report=html
```

You can select a single module, a single test or a keyword expression with the standard pytest options. The examples below are the most common during development.

```bash
python3 -m pytest tests/test_detectors.py -q
python3 -m pytest tests/test_cli.py::test_scan_with_finding_returns_findings_exit_code -q
python3 -m pytest -q -k "union or stacked"
python3 -m pytest -q -x --pdb
```

The suite is intentionally sequential. Do not add `-n` parallel workers unless you have checked that the shared lab server and its gateway call counter remain isolated, because the gateway endpoint fails exactly once and the counter is process-wide.

## Markers

The project configuration declares two markers. The `integration` marker identifies end-to-end tests that use the local HTTP lab server. The `slow` marker identifies tests that include deliberate response delays, which are primarily the time-based detector tests. Both markers are registered so that `--strict-markers` accepts them and so that future tests can be tagged without changing the configuration.

```bash
python3 -m pytest -q -m integration
python3 -m pytest -q -m "not slow"
```

All current tests run by default. The full suite completes in a few seconds on a normal development machine because the integration tests use zero request delays, no retries and short time-based delays between two and six tenths of a second.

## Session fixtures

The shared fixtures live in `tests/conftest.py`. The `lab` fixture is session-scoped. It calls `create_server` from `tests/target_server.py` with port zero, starts `serve_forever` in a daemon thread, and yields a namespace with the base URL, the server object and the mutable lab state. The fixture shuts the server down and joins the thread in a `finally` block, so a failing test cannot leak a listening socket.

The `config_factory` fixture returns a function that builds a valid `ScanConfig` for the lab. Its defaults are deliberately conservative for test speed: authorization is enabled, all techniques are selected, crawling is disabled, the request delay is zero, the timeout is five seconds and retries are disabled. Individual tests override only the fields they need, which keeps each test focused.

The `run_scan` fixture returns a function that constructs a `Scanner` with an optional list of explicit injection points and runs it to completion. Tests therefore assert on the returned `ScanResult` instead of scraping console output, except in the CLI tests where console and exit-code behaviour is the subject under test.

## The lab server

`tests/target_server.py` is a small `ThreadingHTTPServer` that embeds SQLite through the Python standard library. Every request opens a fresh in-memory database, creates the `items` table and registers `sleep` and `pg_sleep` functions that call `time.sleep`. The data set contains three rows, including a row named `test`, which makes boolean and UNION results easy to predict. The server is intentionally vulnerable and must stay bound to localhost.

The endpoint map is the quickest way to understand which behaviour each integration test covers.

| Endpoint | Behaviour and purpose |
| --- | --- |
| `/` | Index page that links to every other endpoint. |
| `/robots.txt` | Disallows `/hidden`, which tests robots.txt compliance. |
| `/search` | Concatenates `q` into a `LIKE` clause on GET and POST. Vulnerable to error, boolean, UNION, stacked and time techniques. |
| `/multipart-search` | Same concatenation as `/search`, reachable through a multipart form. |
| `/clean` | Uses a bound parameter for `q`. The main false-positive control. |
| `/numeric` | Concatenates a numeric `id` without quotes. Exercises numeric contexts. |
| `/blind` | Returns `ITEM FOUND` or `NO RESULTS` for a concatenated `q`. |
| `/time` | Concatenates `q` and executes the database delay function. |
| `/union` | Selects three columns through a concatenated `q`. Exercises column counting. |
| `/stacked` | Uses `executescript` with a concatenated numeric `id`. Exercises stacked queries. |
| `/form` | URL-encoded POST form that submits to `/search`. |
| `/multipart-form` | Multipart POST form that submits to `/multipart-search`. |
| `/dynamic` | Vulnerable endpoint that adds a fresh UUID nonce on every response. Exercises normalization. |
| `/fake-error` | Safe endpoint whose page contains realistic database error strings as documentation examples. |
| `/hidden` | Vulnerable endpoint that robots.txt disallows. It still responds when requested directly. |
| `/page2`, `/page3` | Linked pages used to test crawl depth, same-origin rules and link discovery. |
| `/waf` | Returns HTTP 403 with Cloudflare-like markers when a request contains quotes, `union` or `sleep`. |
| `/slow` | Sleeps 200 milliseconds on every request. Exercises slow-but-stable timing rejection. |
| `/large` | Returns a configurable body of up to 20,000 bytes. Exercises body truncation. |
| `/gateway` | Returns HTTP 502 on the first call and HTTP 200 afterwards. Exercises retry behaviour. |
| `/redirect` | Returns HTTP 302 to `/search?q=apple`. Exercises redirect handling. |
| `/error` | Returns HTTP 500. Exercises error-response handling. |
| Unknown paths | Return HTTP 404. |

Start the lab manually when you want to demonstrate the scanner or debug a detector by hand.

```bash
python3 tests/target_server.py --port 8080
sql-inquisitor "http://127.0.0.1:8080/search?q=test" --authorized --no-crawl
```

The manual server uses the same code as the fixture, so behaviour observed by hand matches behaviour observed in the suite. Keep it on `127.0.0.1`; the default binding is loopback only.

## Test modules

Each module has a narrow responsibility so that a failure points to one layer. The suite is organised as follows.

| Module | Coverage |
| --- | --- |
| `tests/conftest.py` | Session lab fixture, configuration factory and scan runner. |
| `tests/test_config.py` | URL and scope normalization, valid ranges, deduplication, public redaction and log levels. |
| `tests/test_models.py` | Frozen request models, parameter replacement, multipart fields, identifiers, serialization and statistics. |
| `tests/test_payloads.py` | Uniqueness, context selection, boolean pairing, DBMS families, delay validation and marker construction. |
| `tests/test_tamper.py` | Case, whitespace, comment and versioned transformations. |
| `tests/test_signatures.py` | Signature matching, snippet extraction and differential comparison. |
| `tests/test_heuristics.py` | Normalization, volatile tokens, similarity, reflection removal, timing scale and entropy. |
| `tests/test_ethics.py` | Denied hosts, metadata addresses, scope matching, wildcard rules and authorization phrases. |
| `tests/test_crawler.py` | HTML parsing, explicit points, forms, multipart, robots.txt, exclusions, depth and static assets. |
| `tests/test_http_client.py` | Headers, form posts, redirects, retries, WAF detection, truncation, budgets, throttling and transport errors. |
| `tests/test_detectors.py` | End-to-end detection for all five techniques plus false-positive, WAF, thorough and stop-after-first behaviour. |
| `tests/test_engine.py` | Explicit points, deduplication, limits, scope enforcement, budgets, baselines, detector isolation and ordering. |
| `tests/test_reporting.py` | Console, JSON, Markdown, HTML, escaping, atomic writes and unknown formats. |
| `tests/test_cli.py` | Parser helpers, configuration errors, dry run, authorization, exit codes, reports and logging. |
| `tests/test_lab_server.py` | Sanity tests for every lab endpoint, including nullable rows, forms and counters. |
| `tests/test_docs.py` | Presence, prose formatting, required content and dependency claims for all documentation. |

The documentation tests are deliberately strict. They assert that every required document exists, that no line begins with a space or a tab, that the detection and ethics documents mention their required concepts, that `pyproject.toml` declares only `requests` as a runtime dependency, and that the license text is the MIT License. Removing a document or reformatting a code block with indentation will therefore fail the suite rather than silently degrading the documentation.

## What the integration tests prove

The detector tests are end-to-end. They start from a URL, let the real crawler or an explicit point build a request, send real HTTP requests to the lab, run the real detector, and assert on the `Finding` that the engine produced. This catches integration mistakes that unit tests on payload strings cannot catch, such as a mismatched form action, a lost content type, an incorrectly replaced repeated parameter or a baseline that is not reused.

The false-positive tests are as important as the positive tests. `/clean` uses parameter binding and must not produce a finding. `/fake-error` contains text that looks like MySQL and PDO errors but never changes after injection and must not be flagged. `/slow` is slow but stable and must not satisfy the time-based confirmation rule. `/waf` returns a blocking response and must be respected instead of retried or evaded. `/dynamic` changes a nonce on every response and must still allow boolean detection after normalization.

The engine tests cover the operational contract. They verify that explicit points are deduplicated, that `max_points` is enforced, that a missing injection point yields the dedicated exit code, that a target outside scope is rejected before any request, that the request budget aborts a scan cleanly, that a transport failure on a baseline is recorded rather than raised, that a detector exception is isolated, that detectors run in canonical order, and that scan errors are capped.

The CLI tests invoke `main` with patched `sys.argv` and capture output. They check every documented exit code, the dry run, the interactive and non-interactive authorization paths, scope refusal, report file creation, `--fail-on-findings` behaviour, quiet mode and log-file creation. The lab-server tests are a separate safety net for the fixtures themselves, because a broken lab can make a detector test pass or fail for the wrong reason.

## Assertions on requests and timing

Integration tests keep the request count bounded. A clean scan with four cheap techniques still sends a substantial number of probes, which is expected for a differential scanner, so tests either isolate techniques or use `--no-crawl` and a zero delay. Timing tests use a requested delay of two to six tenths of a second, a timeout larger than the delay and two timing samples. The rule that the delay must be smaller than the timeout is enforced by `ScanConfig`, so an invalid test configuration fails immediately instead of producing a misleading timing result.

The time-based tests assert only what the detector promises: a vulnerable endpoint is detected, a slow but stable endpoint is rejected, and time-based checks are skipped after another technique confirms the same point unless thorough mode is enabled. Do not assert exact elapsed times in new tests. Use lower bounds and the detector's own confirmation semantics so the suite remains reliable on loaded machines.

## Adding a test

Place unit tests next to the layer they exercise and use the existing helpers rather than duplicating setup. Prefer the `config_factory` and `run_scan` fixtures for anything that needs a live target. When a new endpoint is required, add it to `tests/target_server.py`, add a sanity test in `tests/test_lab_server.py`, and keep the endpoint loopback-only and in-memory.

Name tests descriptively, use `@pytest.mark.parametrize` for input matrices, and keep assertions specific. A test that only asserts that a list is non-empty is usually too weak; assert the technique, the parameter, the payload class or the exact exit code that proves the behaviour. If a test needs to inspect logs, use `caplog`. If it needs files, use `tmp_path`. If it needs to patch terminal state or `sys.argv`, use `monkeypatch`.

Tests must never contact a real external host. Use the `lab` fixture, a local socket that you close in a fixture, or a mock. Tests must never write outside `tmp_path`. Tests must not depend on execution order, wall-clock dates, hostnames or open ports other than the ephemeral lab port.

## Make targets and linting

A small `Makefile` wraps the common commands. The targets are conveniences only; every one expands to a command documented in this file.

```bash
make install
make test
make coverage
make lint
make lab
```

`make lint` runs `ruff check src tests`. Ruff is part of the development extras and its rule selection and line length are configured in `pyproject.toml`. The linter is not a runtime dependency and the scanner does not import it. Run the linter before opening a pull request, because the CI workflow runs both the linter and the test suite.

## Continuous integration

A minimal CI job installs the package and runs the suite with coverage. The suite needs no services and no secrets, which keeps the pipeline fast and reproducible.

```bash
python3 -m pip install -e ".[dev]"
python3 -m pytest -q --cov=src --cov-report=term-missing
```

If the pipeline runs the CLI against the lab, start `tests/target_server.py` on loopback, wait until the port accepts connections, run the command with `--authorized`, and always terminate the server in a cleanup step. Do not pass real credentials to CI, and do not point CI at production systems.

## Troubleshooting

If the suite cannot bind a socket, check whether a firewall or container policy blocks loopback listeners. The lab asks the operating system for port zero, so it does not collide with a fixed port, but it still needs permission to listen on `127.0.0.1`.

If timing tests fail intermittently, the machine is probably overloaded or the requested delay is too close to the timeout. Increase the delay only within the allowed range, keep the timeout comfortably larger, and avoid running other heavy jobs at the same time.

If imports fail, run from the repository root so that pytest reads `pyproject.toml`, or install the package in editable mode. If `requests` is missing, install the runtime dependency with `python3 -m pip install -e .`. If `pytest` is missing, install the development extras with `python3 -m pip install -e ".[dev]"`.

If the documentation tests fail after an edit, inspect the reported line number. The most common cause is indentation inside a Markdown code block, which the documentation gate rejects on purpose. Use unindented fenced blocks and blank lines without trailing spaces.
