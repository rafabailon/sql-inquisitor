"""Command line interface for SQL Inquisitor."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from config import ScanConfig
from crawler import build_explicit_points
from engine import Scanner
from errors import AuthorizationError, ConfigError, ScopeError
from ethics import ScopeGuard, ensure_authorization
from logging_utils import configure_logging
from models import ALL_TECHNIQUES, Technique
from reporting import render_console, write_reports
from tamper import TAMPER_STRATEGIES
from version import __version__

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2
EXIT_AUTHORIZATION = 3
EXIT_NO_POINTS = 4
EXIT_INTERRUPTED = 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sql-inquisitor",
        description=(
            "Ethical SQL injection scanner for authorized security testing. It discovers query "
            "parameters and forms, then tests error-based, boolean-based, time-based, UNION-based "
            "and stacked-query injection."
        ),
        epilog=(
            "Examples: sql-inquisitor https://example.test/item?id=1 --authorized | "
            "sql-inquisitor https://example.test/search --param q --authorized -o report --format json,html"
        ),
    )
    parser.add_argument("target", nargs="?", help="HTTP or HTTPS URL to test")
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="confirm that you have explicit written authorization to test the target",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate the configuration and print the plan without sending any request",
    )
    parser.add_argument(
        "--scope",
        action="append",
        default=[],
        metavar="HOST",
        help="allowed host or *.suffix pattern; repeat or use commas",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="GLOB",
        help="URL glob to exclude from crawling; repeatable",
    )
    parser.add_argument(
        "--techniques",
        default="all",
        metavar="LIST",
        help="comma-separated techniques: error, boolean, union, stacked, time, or all",
    )
    parser.add_argument("--time-delay", type=float, default=3.0, metavar="SECONDS")
    parser.add_argument("--time-samples", type=int, default=3, metavar="N")
    parser.add_argument("--delay", type=float, default=0.1, metavar="SECONDS")
    parser.add_argument("--timeout", type=float, default=10.0, metavar="SECONDS")
    parser.add_argument("--connect-timeout", type=float, default=5.0, metavar="SECONDS")
    parser.add_argument("--max-retries", type=int, default=1, metavar="N")
    parser.add_argument("--max-pages", type=int, default=20, metavar="N")
    parser.add_argument("--max-depth", type=int, default=2, metavar="N")
    parser.add_argument("--max-points", type=int, default=100, metavar="N")
    parser.add_argument("--max-requests", type=int, default=3000, metavar="N")
    parser.add_argument("--max-union-columns", type=int, default=5, metavar="N")
    parser.add_argument("--max-body-bytes", type=int, default=2_000_000, metavar="N")
    parser.add_argument("--no-crawl", action="store_true", help="only test the seed URL")
    parser.add_argument("--no-forms", action="store_true", help="do not submit discovered forms")
    parser.add_argument("--no-robots", action="store_true", help="ignore robots.txt restrictions")
    parser.add_argument(
        "--cross-origin",
        action="store_true",
        help="allow crawling other hosts permitted by --scope",
    )
    parser.add_argument("--param", action="append", default=[], metavar="NAME")
    parser.add_argument("--data", metavar="QUERY", help="urlencoded body for explicit POST testing")
    parser.add_argument("--method", choices=("GET", "POST"), help="method for explicit testing")
    parser.add_argument("-H", "--header", action="append", default=[], metavar="NAME: VALUE")
    parser.add_argument("-b", "--cookie", action="append", default=[], metavar="NAME=VALUE")
    parser.add_argument("--proxy", metavar="URL")
    parser.add_argument("--insecure", action="store_true", help="disable TLS certificate checks")
    parser.add_argument("--trust-env", action="store_true", help="honour HTTP proxy environment")
    parser.add_argument("--user-agent", default="SQLInquisitor/1.0 (authorized security testing)")
    parser.add_argument(
        "--tamper",
        default="",
        metavar="LIST",
        help="payload transforms: randomcase, spaces, versioned",
    )
    parser.add_argument("-o", "--output", metavar="PREFIX", help="report path prefix or directory")
    parser.add_argument(
        "--format",
        default="",
        metavar="LIST",
        help="file formats: json, markdown, html; requires --output",
    )
    parser.add_argument(
        "--fail-on-findings",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="exit with status 1 when a vulnerability is found (default: true)",
    )
    parser.add_argument(
        "--stop-after-first",
        action="store_true",
        help="stop testing a point after the first confirmed technique",
    )
    parser.add_argument(
        "--thorough",
        action="store_true",
        help="also run time-based checks on points already confirmed by another technique",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress the console report")
    parser.add_argument("-v", "--verbose", action="store_true", help="show progress messages")
    parser.add_argument("--debug", action="store_true", help="show debug messages and tracebacks")
    parser.add_argument("--log-file", metavar="PATH", help="write debug logs to a file")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    parser.add_argument("--list-techniques", action="store_true", help="show detection techniques")
    parser.add_argument("--list-tampers", action="store_true", help="show payload transforms")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _split_csv(values: list[str] | str) -> list[str]:
    if isinstance(values, str):
        values = [values]
    items: list[str] = []
    for value in values:
        for part in value.split(","):
            part = part.strip()
            if part:
                items.append(part)
    return items


def _parse_techniques(raw: str) -> tuple[Technique, ...]:
    requested = _split_csv(raw)
    if not requested or "all" in {item.lower() for item in requested}:
        return ALL_TECHNIQUES
    mapping = {technique.value: technique for technique in Technique}
    selected: list[Technique] = []
    for name in requested:
        technique = mapping.get(name.lower())
        if technique is None:
            raise ConfigError(f"unknown technique: {name}; choose from {', '.join(mapping)} or all")
        if technique not in selected:
            selected.append(technique)
    if not selected:
        raise ConfigError("at least one technique must be selected")
    return tuple(selected)


def _parse_formats(raw: str) -> tuple[str, ...]:
    formats: list[str] = []
    for name in _split_csv(raw):
        normalized = name.lower()
        if normalized == "md":
            normalized = "markdown"
        if normalized not in {"json", "markdown", "html"}:
            raise ConfigError(f"unknown output format: {name}; choose from json, markdown, html")
        if normalized not in formats:
            formats.append(normalized)
    return tuple(formats)


def _parse_headers(raw_headers: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for raw in raw_headers:
        name, separator, value = raw.partition(":")
        if not separator or not name.strip():
            raise ConfigError(f"invalid header {raw!r}; use 'Name: value'")
        headers[name.strip()] = value.strip()
    return headers


def _parse_cookies(raw_cookies: list[str]) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for raw in raw_cookies:
        for part in raw.split(";"):
            part = part.strip()
            if not part:
                continue
            name, separator, value = part.partition("=")
            if not separator or not name.strip():
                raise ConfigError(f"invalid cookie {part!r}; use 'name=value'")
            cookies[name.strip()] = value.strip()
    return cookies


def config_from_args(args: argparse.Namespace) -> ScanConfig:
    if not args.target:
        raise ConfigError("a target URL is required")
    techniques = _parse_techniques(args.techniques)
    formats = _parse_formats(args.format)
    output_prefix = Path(args.output).expanduser() if args.output else None
    if formats and output_prefix is None:
        raise ConfigError("--format requires --output")
    if output_prefix is not None and not formats:
        formats = ("json",)
    if (
        output_prefix is not None
        and len(formats) > 1
        and output_prefix.suffix.lower()
        in {
            ".json",
            ".md",
            ".markdown",
            ".html",
            ".htm",
        }
    ):
        raise ConfigError(
            "an output prefix with a file extension supports only one format; use a prefix "
            "such as reports/scan for multiple formats"
        )
    scope = _split_csv(args.scope)
    tamper = tuple(_split_csv(args.tamper))
    for strategy in tamper:
        if strategy not in TAMPER_STRATEGIES:
            raise ConfigError(
                f"unknown tamper strategy: {strategy}; "
                f"choose from {', '.join(sorted(TAMPER_STRATEGIES))}"
            )
    log_level = "WARNING"
    if args.verbose:
        log_level = "INFO"
    if args.quiet:
        log_level = "ERROR"
    if args.debug:
        log_level = "DEBUG"
    return ScanConfig(
        target=args.target,
        authorized=args.authorized,
        techniques=techniques,
        timeout=args.timeout,
        connect_timeout=min(args.connect_timeout, args.timeout),
        max_retries=args.max_retries,
        delay=args.delay,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        max_points=args.max_points,
        max_requests=args.max_requests,
        max_body_bytes=args.max_body_bytes,
        max_union_columns=args.max_union_columns,
        time_delay=args.time_delay,
        time_samples=args.time_samples,
        verify_tls=not args.insecure,
        follow_redirects=True,
        crawl=not args.no_crawl,
        scan_forms=not args.no_forms,
        respect_robots=not args.no_robots,
        same_origin_only=not args.cross_origin,
        user_agent=args.user_agent,
        headers=_parse_headers(args.header),
        cookies=_parse_cookies(args.cookie),
        proxy=args.proxy,
        trust_env=args.trust_env,
        tamper=tamper,
        scope=tuple(scope),
        exclude_patterns=tuple(args.exclude),
        output_prefix=output_prefix,
        output_formats=formats,
        fail_on_findings=args.fail_on_findings,
        quiet=args.quiet,
        log_level=log_level,
        log_file=Path(args.log_file).expanduser() if args.log_file else None,
        stop_after_first=args.stop_after_first,
        thorough=args.thorough,
    )


def _print_techniques() -> None:
    for technique in ALL_TECHNIQUES:
        print(f"{technique.value:8} {technique.label:24} {technique.description}")


def _print_tampers() -> None:
    for name, description in sorted(TAMPER_STRATEGIES.items()):
        print(f"{name:12} {description}")


def _use_color(args: argparse.Namespace) -> bool:
    if args.no_color or os.environ.get("NO_COLOR") is not None:
        return False
    return sys.stdout.isatty()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.list_techniques:
        _print_techniques()
        return EXIT_OK
    if args.list_tampers:
        _print_tampers()
        return EXIT_OK
    try:
        config = config_from_args(args)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    if args.dry_run:
        plan = dict(config.public_dict())
        plan["authorization_confirmed"] = config.authorized
        plan["explicit_parameters"] = list(dict.fromkeys(args.param))
        print(json.dumps(plan, indent=2, ensure_ascii=False))
        print("\nDry run: no HTTP requests were sent.")
        return EXIT_OK
    try:
        ensure_authorization(config)
    except AuthorizationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_AUTHORIZATION
    try:
        ScopeGuard(config).check_target()
    except ScopeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_AUTHORIZATION
    explicit_points = []
    if args.param or args.data:
        try:
            explicit_points = build_explicit_points(
                config.target, args.param, args.data, args.method
            )
        except ConfigError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_ERROR
    configure_logging(config)
    result = None
    try:
        scanner = Scanner(config, explicit_points=explicit_points)
        result = scanner.scan()
        paths = write_reports(result, config)
    except Exception as exc:  # pragma: no cover - last-resort CLI guard
        print(f"error: scan failed: {exc}", file=sys.stderr)
        if args.debug:
            raise
        return EXIT_ERROR
    if not config.quiet:
        print(render_console(result, color=_use_color(args)))
    if paths:
        print("Reports written:")
        for path in paths:
            print(f"- {path}")
    if result.aborted_reason and result.aborted_reason.startswith("interrupted"):
        return EXIT_INTERRUPTED
    if result.aborted_reason:
        return EXIT_ERROR
    if result.stats.points_discovered == 0:
        return EXIT_NO_POINTS
    if result.findings and config.fail_on_findings:
        return EXIT_FINDINGS
    return EXIT_OK


def entrypoint() -> int:
    return main()


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
