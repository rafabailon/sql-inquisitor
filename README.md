# SQL Inquisitor

SQL Inquisitor is a self-contained, ethical SQL injection scanner written in pure Python. It tests one authorized web target for the five practical SQL injection classes: error-based injection, boolean-based blind injection, time-based blind injection, UNION-based injection and stacked queries. The scanner discovers query parameters and HTML forms, sends a small number of controlled probes, confirms every candidate with a second and independent observation, and produces console, JSON, Markdown and HTML reports.

SQL Inquisitor is designed for penetration testers, application security engineers, developers and students who need a readable reference implementation as much as a working scanner. The code is typed, modular and covered by an automated test suite that runs against a deliberately vulnerable local lab server. The lab server is part of the test suite and uses only the Python standard library, so the project needs no Docker container, no external database engine and no third-party penetration testing tool.

## The most important warning

Use SQL Inquisitor only on systems for which you have explicit written authorization. The scanner sends active requests that can raise database errors, consume database CPU and trigger web application firewall rules. The ethical guardrails are not decorative: a scan refuses to start unless the operator passes the `--authorized` flag or types the exact phrase `I HAVE AUTHORIZATION` at an interactive terminal. The scope guard blocks cloud metadata endpoints and hosts outside the configured scope. The payload catalogue contains no INSERT, UPDATE, DELETE, DROP, ALTER, TRUNCATE or CREATE statement. Read `docs/ETHICS.md` before your first scan.

## Features

- Detection of error-based, boolean-based blind, time-based blind, UNION-based and stacked-query SQL injection.
- Crawling of same-origin links and discovery of GET query parameters, URL-encoded forms and multipart forms.
- Differential error signatures for MySQL and MariaDB, PostgreSQL, Microsoft SQL Server, Oracle, SQLite, Microsoft Access, IBM DB2, Firebird and generic PDO or JDBC errors.
- Two-step confirmation for every technique, with volatile-token normalization for pages that contain nonces, timestamps or rotating identifiers.
- Time-based confirmation that checks both an absolute delay and a scaled shorter delay, which rejects slow but stable endpoints.
- UNION detection that searches for a controlled numeric marker evaluated by the database rather than reflected in the HTML, and that determines the column count.
- Stacked-query detection that references a random table name and requires the database error to mention that name.
- Strict authorization, scope and rate controls, automatic request budgeting and WAF observation without evasion.
- Console output, machine-readable JSON, Markdown reports and a self-contained HTML report.
- A standard-library lab server with vulnerable and safe endpoints for demonstrations and automated tests.
- A pytest suite that covers the configuration, payloads, tampering, signatures, heuristics, crawler, HTTP client, ethics, detectors, engine, reporting, CLI, documentation and lab server.

## Requirements

- Python 3.10 or newer.
- The `requests` library, which is the only runtime dependency.
- `pytest` and optionally `pytest-cov` for running the test suite.
- `ruff` for linting the source tree.

No SQL database server is required to use or test the project. The lab server embeds SQLite through the Python standard library. No external scanner such as sqlmap is used, imported or invoked.

## Installation

Create and activate a virtual environment, then install the package in editable mode.

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev]"
```

The editable installation provides the `sql-inquisitor` command. You can also run the scanner directly from the source tree with `python3 src/cli.py`. The complete dependency and installation discussion is in `docs/EXTERNAL_SOFTWARE.md`.

## Quick start

Start the local lab in one terminal.

```bash
python3 tests/target_server.py --port 8080
```

Run an authorized scan against an intentionally vulnerable endpoint in another terminal.

```bash
sql-inquisitor "http://127.0.0.1:8080/search?q=test" --authorized --no-crawl
```

The scanner prints a console report and exits with status 1 because it confirmed a vulnerability. To write reports, add an output prefix and one or more formats.

```bash
sql-inquisitor "http://127.0.0.1:8080/union?q=test" \
--authorized --no-crawl --techniques error,boolean,union \
-o reports/union-scan --format json,markdown,html
```

To validate the command line without sending a request, use a dry run.

```bash
sql-inquisitor "https://example.test/item?id=1" --authorized --dry-run
```

To scan a parameter that is not present in the URL, use an explicit parameter or a form body.

```bash
sql-inquisitor "https://example.test/search" --authorized --param q
sql-inquisitor "https://example.test/login" --authorized --data "user=alice&password=secret"
```

## How it works

The scanner first builds a scope guard and fetches the seed page. The crawler extracts links, query strings and forms while respecting `robots.txt`, the same-origin policy and exclusion globs. Each discovered parameter becomes an injection point that can generate a request with the parameter replaced by a payload. The engine requests a baseline response for each point, then runs the enabled detectors in a fixed order: error-based, boolean-based, UNION-based, stacked-query and finally time-based. A detector returns a finding only after a second observation confirms the first. The engine deduplicates findings, records statistics, respects the request budget and stops cleanly when a target blocks too many requests.

## Detection techniques

Error-based detection injects syntax-breaking characters and comments, then compares the set of database error signatures in the probe response with the signatures already present in the baseline. A signature that appears only after injection and reproduces on a second request confirms the finding.

Boolean-based blind detection sends true and false condition pairs, normalizes volatile tokens, removes reflected payloads and compares text similarity against the baseline and against the opposite response. Two independent pairs must produce the expected response split.

Time-based blind detection measures several baseline samples, sends database-specific delay expressions and requires a response delay close to the requested delay plus a second, shorter delay that scales in the expected direction. Stable but slow endpoints are rejected.

UNION-based detection appends a `UNION SELECT` with a numeric expression that the database evaluates. Because the marker value is absent from the payload, HTML reflection cannot create a false positive. The detector probes the column count and confirms the marker on a second request.

Stacked-query detection appends a read-only second statement that references a random table name. The database must report an error that mentions that exact name, which proves the second statement executed rather than merely being reflected. A division-by-zero probe is available as a lower-confidence fallback.

Read `docs/DETECTION.md` for the full decision rules, payload families and limitations.

## Reports and exit codes

The console report summarizes the target, duration, request count, discovered points, findings by severity, evidence, payloads and remediation. JSON reports are intended for automation and include a tool block, target, timestamps, public configuration, summary, statistics, findings, discovered points and errors. Markdown reports are intended for tickets and pull requests. HTML reports are self-contained and escape all untrusted values.

The process exit codes are stable and suitable for CI.

| Code | Meaning |
| --- | --- |
| 0 | Scan completed and no finding was reported, or findings were disabled with `--no-fail-on-findings`. |
| 1 | Scan completed and at least one finding was confirmed. |
| 2 | Invalid configuration, scan failure or an aborted scan. |
| 3 | Authorization was not confirmed or the target is outside the scope. |
| 4 | No injection points were discovered. |
| 130 | The scan was interrupted by the user. |

## Configuration highlights

`--techniques` selects a comma-separated subset of `error`, `boolean`, `union`, `stacked` and `time`, or `all`. `--time-delay` controls the requested delay in seconds and must be smaller than `--timeout`. `--time-samples` controls baseline timing samples. `--delay` sets the minimum interval between requests and should be increased on production systems. `--max-requests` is a hard budget. `--scope` adds allowed hosts or wildcard suffixes. `--exclude` skips URL globs. `--tamper` applies safe keyword transformations such as `randomcase`, `spaces` and `versioned`. `--thorough` also runs time-based checks on points that are already confirmed by another technique.

Authentication is supported through repeated `-H "Name: value"` headers and `-b "name=value"` cookies. TLS verification is enabled by default; `--insecure` disables it only for controlled lab environments. `--proxy` routes traffic through an HTTP or HTTPS proxy. `--trust-env` makes `requests` honour proxy environment variables.

The complete reference is in `docs/USAGE.md`.

## Testing

Run the automated suite from the repository root.

```bash
python3 -m pytest -q
python3 -m pytest -q --cov=src --cov-report=term-missing
```

The suite starts the vulnerable lab server on an ephemeral localhost port for the duration of the test session. It uses no external network access. Integration tests deliberately use short delays, small request budgets and isolated techniques so that the full suite remains fast and deterministic. Read `docs/TESTING.md` for the fixtures, markers, endpoint map and guidance on adding tests.

## Documentation

- `docs/ARCHITECTURE.md` explains the source layout, data flow and design decisions.
- `docs/USAGE.md` is the complete command-line reference with examples.
- `docs/DETECTION.md` describes every detection technique, decision rule and limitation.
- `docs/TESTING.md` describes the test suite and the local lab server.
- `docs/ETHICS.md` describes the authorization, scope and read-only guardrails.
- `docs/EXTERNAL_SOFTWARE.md` documents every external software dependency and its installation.

## Limitations

SQL Inquisitor is a focused detector, not an exploitation framework. It does not extract data, enumerate schemas, bypass authentication, upload files, execute commands or persist access. It cannot prove the absence of SQL injection, because coverage depends on the discovered entry points, the WAF behaviour and the database engine. It does not attempt to defeat web application firewalls and stops after a bounded number of blocked requests. Non-relational injection, second-order injection and injection in JSON or XML bodies are outside the current scope, although URL-encoded and multipart forms are supported.

## License

SQL Inquisitor is released under the MIT License. See `LICENSE`.
