# Usage

SQL Inquisitor is a command-line scanner. This document describes every option, the expected behaviour, the output files and the exit codes. It also explains the recommended workflow for a first authorized test and for continuous integration.

## Invocation

The installed command is `sql-inquisitor`. In a source checkout, the same entry point is available by running `src/cli.py`, because Python puts the script directory on the import path.

```bash
sql-inquisitor --help
python3 src/cli.py --help
```

The only positional argument is the target URL. It must use HTTP or HTTPS and must contain a host. Credentials in the URL are rejected; supply authentication through headers or cookies instead. A URL fragment is discarded. The host is lower-cased and the path defaults to `/`.

```bash
sql-inquisitor "https://example.test/search?q=test" --authorized
```

## Authorization

Active scanning requires explicit authorization. The `--authorized` flag is the non-interactive acknowledgement that the operator has written permission. Without it, the process prints a warning and requires the exact phrase `I HAVE AUTHORIZATION` when standard input is a terminal. Without the flag and without a terminal, the process exits with status 3 before sending any request.

```bash
sql-inquisitor "https://example.test/" --authorized
printf 'I HAVE AUTHORIZATION\n' | sql-inquisitor "https://example.test/"
```

The second command is not recommended for unattended use because authorization should be a deliberate human decision. The flag exists so that CI pipelines run only after an approval step outside the tool.

## Dry run

`--dry-run` validates the configuration and prints a JSON plan without sending a single request. The plan includes the normalized target, selected techniques, timing values, request limits, public output settings, authorization state and explicit parameter names. It is the safest way to check an invocation before a real scan.

```bash
sql-inquisitor "https://example.test/item?id=1" --authorized --dry-run
```

## Technique selection

`--techniques` accepts a comma-separated list of `error`, `boolean`, `union`, `stacked` and `time`, or the word `all`. The default is `all`. Selecting fewer techniques reduces requests and noise, which is useful for a first pass or for a target with strict rate limits.

```bash
sql-inquisitor "https://example.test/search?q=test" --authorized --techniques error,boolean
sql-inquisitor "https://example.test/search?q=test" --authorized --techniques time
```

The engine runs techniques in a fixed order regardless of the order on the command line. Time-based checks are skipped for a point that another technique already confirmed unless `--thorough` is present. This default keeps scans fast and avoids unnecessary delays on points whose vulnerability is already proven. Use `--thorough` when the report must document every applicable technique.

## Discovery and crawling

By default the crawler fetches the seed page, discovers query parameters and forms, and follows same-origin links up to `--max-depth` pages and `--max-pages` fetches. It respects `robots.txt`, skips static assets and honours exclusion globs. Use `--no-crawl` to test only the seed URL, `--no-forms` to skip form submission, and `--no-robots` only when you have a specific reason to ignore the site's published crawling rules.

```bash
sql-inquisitor "https://example.test/" --authorized --no-crawl
sql-inquisitor "https://example.test/" --authorized --max-pages 50 --max-depth 4
sql-inquisitor "https://example.test/" --authorized --exclude "*/logout*" --exclude "*/delete*"
sql-inquisitor "https://example.test/" --authorized --cross-origin --scope example.test,api.example.test
```

`--cross-origin` relaxes the same-origin rule but still requires every host to match `--scope`. Without an explicit scope, only the target host is allowed.

## Explicit parameters and bodies

Use `--param` to test a named parameter that is absent from the URL. Use `--data` to define a URL-encoded body. `--method` selects GET or POST and defaults to POST when `--data` is present and GET otherwise. Repeated `--param` options are allowed.

```bash
sql-inquisitor "https://example.test/search" --authorized --param q
sql-inquisitor "https://example.test/search" --authorized --param q --param page
sql-inquisitor "https://example.test/login" --authorized --data "username=alice&password=secret"
sql-inquisitor "https://example.test/login?ref=home" --authorized --data "username=alice" --method POST
```

The data value must use `application/x-www-form-urlencoded` syntax and must contain at least one `=` character. Multipart forms are discovered automatically from HTML and submitted with the correct content type. File inputs, checkboxes, radio buttons, submit buttons, image buttons and disabled inputs are deliberately excluded because replacing them is either meaningless or unsafe.

## Scope and exclusions

`--scope` accepts a host, `host:port` or a wildcard suffix such as `*.example.test`. It can be repeated or comma-separated. The wildcard matches the apex domain and any subdomain but not a look-alike suffix such as `example.test.evil.example`. Every request, every discovered link and every form action must pass the scope guard.

```bash
sql-inquisitor "https://app.example.test/" --authorized --scope "*.example.test"
sql-inquisitor "https://app.example.test/" --authorized --scope app.example.test:8443
```

Cloud metadata hosts, link-local addresses, multicast addresses and the unspecified address are always denied. The guard blocks `169.254.169.254`, `metadata.google.internal`, `metadata`, `instance-data`, `metadata.azure.internal`, IPv6 link-local addresses and similar endpoints even if a scope pattern would otherwise match them.

`--exclude` accepts a URL glob and can be repeated. It applies to crawling and to discovered forms, not to an explicitly supplied target.

## Rate, timing and limits

The scanner is sequential and throttled. `--delay` sets the minimum number of seconds between request starts and defaults to 0.1. Increase it on shared or production systems. `--max-requests` is a hard budget across the whole scan, including retries. When the budget is exhausted, the engine returns partial results and the CLI exits with status 2.

```bash
sql-inquisitor "https://example.test/" --authorized --delay 0.5 --max-requests 500
```

`--timeout` is the response read timeout and `--connect-timeout` is the connection timeout. The connect timeout is silently capped at the read timeout. `--max-retries` applies only to safe GET and HEAD requests and only to transport failures or HTTP 502 and 504; blocked responses are not retried.

`--time-delay` is the requested database delay for time-based detection and must be smaller than `--timeout`. `--time-samples` controls how many baseline timing samples are collected. A larger delay makes detection more reliable on noisy networks but slows the scan. A value of 0.5 to 1.0 second is usually sufficient on local networks; use 2 to 5 seconds for remote targets with jitter.

```bash
sql-inquisitor "https://example.test/" --authorized --techniques time --time-delay 1.5 --time-samples 4
```

`--max-pages`, `--max-depth`, `--max-points` and `--max-union-columns` bound crawling and UNION probing. `--max-body-bytes` bounds response reading and defaults to two million bytes. `--stop-after-first` stops testing a point after the first confirmed technique, which is useful when breadth matters more than a complete technique inventory.

## Requests, authentication and transport

Repeated `-H` or `--header` options add request headers. The value must contain a colon after the header name. Repeated `-b` or `--cookie` options accept `name=value` pairs separated by semicolons.

```bash
sql-inquisitor "https://example.test/" --authorized \
-H "Authorization: Bearer token" \
-H "X-Requested-With: XMLHttpRequest" \
-b "session=abc; theme=dark"
```

`--user-agent` overrides the default user agent. `--insecure` disables TLS certificate verification and should be used only against controlled lab systems. `--proxy` sends requests through an HTTP or HTTPS proxy. `--trust-env` makes `requests` honour the standard proxy environment variables. Proxy credentials in reports are removed and header or cookie values are never written to reports.

## Tamper strategies

`--tamper` applies safe transformations to generated payloads. `randomcase` randomizes the case of SQL keywords outside the intended semantics. `spaces` replaces keyword-separating spaces with inline comments while preserving the trailing SQL comment. `versioned` wraps common MySQL keywords in versioned comments. Strategies can be chained.

```bash
sql-inquisitor "https://example.test/" --authorized --tamper spaces,randomcase
```

Tampering is never used to attack a WAF, disable a control or conceal the scan. It exists to test whether a target's SQL parsing remains vulnerable under trivial keyword obfuscation and to reduce accidental false negatives from naive filters. If a target blocks the scanner, the correct action is to stop and coordinate with its owner.

## Reports

`-o` or `--output` sets a prefix or directory. `--format` accepts `json`, `markdown`, `html` or `md`, and can be repeated in a comma-separated list. If `--output` is present without `--format`, JSON is written. If `--format` is present without `--output`, the configuration is rejected.

```bash
sql-inquisitor "https://example.test/" --authorized -o reports/scan --format json,markdown,html
sql-inquisitor "https://example.test/" --authorized -o reports/scan.json --format json
```

A prefix without a known extension produces `prefix.json`, `prefix.md` and `prefix.html`. A directory produces timestamped names such as `sql-inquisitor-20261025-120000.json`. A prefix with a known extension is used verbatim and therefore supports only one format. Files are written atomically.

The console report goes to standard output unless `--quiet` is used. Colors are enabled only when standard output is a terminal and the `NO_COLOR` environment variable is absent. `--no-color` forces plain text. `-v` enables informational progress messages, `--debug` enables debug messages and tracebacks, and `--log-file` writes debug-level logs to a file regardless of the console level.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No finding was reported, or `--fail-on-findings` was disabled. |
| 1 | At least one finding was confirmed and `--fail-on-findings` is active. |
| 2 | Configuration error, scan failure or aborted scan. |
| 3 | Authorization missing or target outside scope. |
| 4 | No injection points were discovered. |
| 130 | Scan interrupted by the user. |

The `--no-fail-on-findings` form disables the finding exit code, which is useful when the report itself is the deliverable. The flag is implemented with `argparse.BooleanOptionalAction` and defaults to true.

## Recommended workflow

Begin with a dry run and a naked, non-invasive request through a browser or `curl` to confirm that the target is reachable. Confirm that you have written authorization and that the target host is in scope. Start with `--no-crawl` against one known parameter, a small request budget and a conservative delay. Add techniques only as needed. Review the evidence and the response details before reporting a finding. Never run the scanner against a target whose owner has not approved active testing.

```bash
sql-inquisitor "https://example.test/item?id=1" --authorized --dry-run
sql-inquisitor "https://example.test/item?id=1" --authorized --no-crawl --techniques error,boolean --delay 0.3 --max-requests 200
sql-inquisitor "https://example.test/item?id=1" --authorized --no-crawl --techniques time --time-delay 2 --time-samples 4 -o reports/item --format json,html
```

## Library use

The modules can be used as a library. Build a `ScanConfig`, create a `Scanner` and call `scan`. The result is a typed `ScanResult` that can be serialized with `to_json`.

```bash
PYTHONPATH=src python3 -c "from config import ScanConfig; from engine import Scanner; r=Scanner(ScanConfig(target='https://example.test/item?id=1', authorized=True, crawl=False)).scan(); print(r.to_json())"
```

The same authorization and scope rules apply because `Scanner.scan` invokes the scope guard. The `authorized` field should be set to true only after the same human approval that the CLI requires.

## Troubleshooting

If the scanner exits with status 4, the URL has no query parameters and no forms were discovered. Supply `--param`, include a query string, or allow crawling. If the scanner exits with status 3, check `--scope` and confirm authorization. If no findings appear on a known vulnerable lab, check `--techniques` and the technique-specific delay. A time-based scan with a delay close to the timeout can fail because the request times out before the delay completes. If a target returns 403 or 429, stop and reduce the request rate rather than attempting to bypass the block.
