# Architecture

SQL Inquisitor is organised as a small Python application with a single orchestration layer and focused modules around it. The design goal is to make every security decision explicit and testable, while keeping the dependency surface at one runtime library. All source files live directly in `src/`; only the five detectors are grouped in the `src/detectors/` subpackage. Importing the modules from a source checkout requires either an editable installation or `PYTHONPATH=src`, and pytest configures that path automatically.

## Source layout

| Path | Responsibility |
| --- | --- |
| `src/version.py` | Version, author and license metadata. |
| `src/cli.py` | Argument parsing, configuration construction, authorization, exit codes and report dispatch. |
| `src/config.py` | The validated `ScanConfig` dataclass, URL normalization, scope normalization and a report-safe public configuration. |
| `src/errors.py` | A small exception hierarchy for configuration, authorization, scope and request-budget failures. |
| `src/ethics.py` | Authorization confirmation, scope matching and cloud metadata blocking. |
| `src/models.py` | Frozen request and injection-point models, HTTP responses, detections, findings, scan statistics and scan results. |
| `src/http_client.py` | The `requests` wrapper with throttling, retries, body limits, WAF observation and request budgeting. |
| `src/crawler.py` | HTML parsing, link and form discovery, robots handling, scope checks and explicit point construction. |
| `src/payloads.py` | Payload dataclasses and generators for all five techniques. |
| `src/tamper.py` | Safe keyword-level payload transformations. |
| `src/signatures.py` | Database error signatures, snippet extraction and differential error comparison. |
| `src/heuristics.py` | Normalization, similarity, reflection removal and timing analysis. |
| `src/engine.py` | The `Scanner`, which discovers points, fetches baselines, runs detectors and assembles results. |
| `src/detectors/` | One module per technique plus shared detector helpers. |
| `src/reporting.py` | Console, JSON, Markdown and HTML rendering and atomic file writes. |
| `src/logging_utils.py` | Console and file logging configuration. |
| `tests/target_server.py` | The deliberately vulnerable and safe HTTP lab used by tests and demos. |
| `tests/` | The pytest suite and its fixtures. |

## Data flow

A scan begins in `cli.main`. The command line parser produces a namespace, and `config_from_args` converts it into a `ScanConfig`. The dataclass validates every field in `__post_init__`, normalizes the target URL and scope patterns, deduplicates options, and converts strings into enums where appropriate. Validation raises `ConfigError` before any network activity occurs.

The CLI then enforces authorization. If `--authorized` is present, the check succeeds immediately. Otherwise, an interactive terminal is asked to type `I HAVE AUTHORIZATION`; a non-interactive invocation fails with exit code 3. The scope guard checks the target URL next, which blocks targets outside the configured host patterns and cloud metadata addresses.

The engine constructs an `HttpClient` and a `ScopeGuard`. If explicit `--param` or `--data` points were supplied, `build_explicit_points` creates them directly; otherwise the `Crawler` discovers points. Discovery records every query parameter and every non-disabled form field, preserving repeated parameter names in an ordered tuple. The engine deduplicates points by a stable SHA-256 identifier and truncates the list at `max_points`.

For each point, the engine obtains a baseline response and caches it by a request key. The detectors run in canonical order: error-based, boolean-based, UNION-based, stacked-query and time-based. This order is deliberate. Cheap and highly reliable checks run first, and time-based checks run last because they are the slowest and are skipped by default when another technique has already confirmed the point. The engine converts each raw detection into a `Finding`, assigns severity by technique, deduplicates findings by technique, method, URL and parameter, and records statistics.

After the scan, the engine marks the finish time, closes the HTTP session and returns a `ScanResult`. The CLI renders the console report and writes any requested files. Exit status is derived from findings, discovery count and abort state.

## Core models

`RequestSpec` is a frozen, transport-neutral description of a request. Query parameters, URL-encoded data and multipart fields are stored as ordered tuples rather than dictionaries so repeated names survive a round trip, which matters for frameworks that bind the first or last occurrence. `InjectionPoint` adds the location, parameter name, original value and source URL. Calling `request(value)` replaces only the target parameter and leaves every other parameter intact. A multipart point places the replacement in `files`, while a URL-encoded point places it in `data`.

`HttpResponse` normalizes successful and failed requests into one type. A transport failure has status code zero and a non-empty `error`; the rest of the scanner does not need to catch exceptions from `requests`. The response records status, decoded body, lower-case headers, elapsed time, truncation state and WAF information.

`Detection` is what a detector returns: the technique, the payload that was actually sent, human-readable evidence, confidence and optional DBMS, column count and timing details. `Finding` is the report-facing form with severity, remediation, references and a timestamp. `ScanResult` aggregates findings, points, errors and statistics and knows how to serialize itself to JSON.

## Detection contract

Every detector implements `Detector.detect(point, baseline)`, which returns a `Detection` or `None`. The shared `_send` helper applies configured tamper strategies before building the request. Detectors never mutate the configuration, never write to the target and never continue after a blocked response. Each detector is responsible for its own confirmation step, which keeps the technique-specific evidence close to the decision.

The error detector sends syntax-breaking probes and compares the error signature key set of the probe against the baseline. The boolean detector uses normalized text similarity and two independent condition pairs. The UNION detector generates an unpredictable numeric marker, searches for the evaluated value, and then probes column counts in two phases. The stacked detector generates a random table token and requires the token to appear in a database table error. The time detector uses baseline timing samples and checks both absolute and scaled delays.

## Safety architecture

The tool is read-only by construction. Payload generators contain only SELECT statements, boolean expressions, error expressions and controlled delay functions. A test asserts that no destructive keyword appears in any generated payload. The scope guard is checked before the seed request and again for every crawled URL and form action. Automatic HTTP redirects are followed by the HTTP layer and the final URL is not revalidated against the scope, so a cross-origin redirect is a known residual risk and should be treated as a potential SSRF finding. Cloud metadata hostnames and link-local, multicast or unspecified IP addresses are always denied, even if a scope pattern would otherwise match them.

`HttpClient` enforces the request budget before every attempt, including retries. It throttles requests with a monotonic clock and applies a penalty after HTTP 429 or 503 responses using `Retry-After` when present. It records WAF signatures from headers and bodies but never attempts to evade or disable a WAF. If 25 requests are blocked, the engine stops the scan to avoid abusive traffic.

Configuration values are bounded. Timeouts, retry counts, page and point limits, request counts, body sizes, union column limits, time delays and timing samples all have explicit ranges. Header names and values are rejected if they contain newlines or separators that could enable header injection. The public configuration used in reports lists header and cookie names but never their values, and strips proxy credentials.

## Reporting architecture

Reporting is pure rendering over `ScanResult`. The console renderer collapses untrusted evidence to one line and optionally applies ANSI colors only when standard output is a terminal and `NO_COLOR` is absent. JSON uses the result's `to_dict` method. Markdown renders findings as headings and bullet lists. HTML escapes every field with `html.escape`, including payloads, evidence and references, and embeds its CSS so the file works offline.

File output is atomic: the renderer writes a temporary file in the destination directory and replaces the final path with `os.replace`. A directory prefix produces timestamped file names, while a prefix with a known extension is used verbatim. If more than one format is requested, the CLI rejects a file-extension prefix because it could only hold one report.

## Performance and robustness

The scanner is sequential by design. Sequential requests make rate limiting predictable, keep evidence attributable and avoid overwhelming a target. Redundant baselines are cached per request key, so multiple detectors share one original-value response. Boolean confirmation stops after two pairs, error detection stops after the first reproducible signature, and UNION detection stops at the first confirmed column count. Response bodies are streamed and capped at `max_body_bytes`, which bounds memory use on large or malicious pages. Similarity uses `difflib` for bodies up to 20,000 characters and switches to bounded word four-gram Jaccard similarity above that threshold.

Detector exceptions are caught per detector and recorded as scan errors, so one malformed response cannot abort an entire scan. Request-budget exhaustion and keyboard interrupts are handled at the engine level and produce partial results with an abort reason. Logging is quiet by default, verbose with `-v`, and fully diagnostic with `--debug` or `--log-file`.
