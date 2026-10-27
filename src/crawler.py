"""Same-origin crawler that discovers query and form injection points."""

from __future__ import annotations

import fnmatch
import logging
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import (
    parse_qsl,
    urljoin,
    urlsplit,
    urlunsplit,
)
from urllib.robotparser import RobotFileParser

from config import ScanConfig
from errors import ConfigError
from ethics import ScopeGuard
from http_client import HttpClient
from models import InjectionPoint

_STATIC_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".bmp",
    ".css",
    ".js",
    ".mjs",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
    ".rar",
    ".7z",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".mp3",
    ".mp4",
    ".avi",
    ".mov",
    ".wav",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
}
_SKIP_SCHEMES = {"mailto", "tel", "javascript", "data", "blob", "about", "ftp"}
_SKIP_INPUT_TYPES = {
    "submit",
    "button",
    "image",
    "reset",
    "file",
    "checkbox",
    "radio",
}
_FORM_HTML_TYPES = {"text/html", "application/xhtml+xml"}


@dataclass
class ParsedForm:
    action: str
    method: str
    enctype: str
    fields: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class ParsedPage:
    forms: list[ParsedForm] = field(default_factory=list)
    links: list[str] = field(default_factory=list)


class _PageParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.page = ParsedPage()
        self._form: ParsedForm | None = None
        self._select_name: str | None = None
        self._select_options: list[tuple[str, bool]] = []
        self._option_value: str | None = None
        self._option_started = False
        self._option_selected = False
        self._option_text: list[str] = []
        self._textarea_name: str | None = None
        self._textarea_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.lower(): (value or "") for name, value in attrs}
        tag = tag.lower()
        if tag == "form":
            self._finish_form()
            self._form = ParsedForm(
                action=urljoin(self.base_url, attributes.get("action", "") or ""),
                method=(attributes.get("method", "GET") or "GET").upper(),
                enctype=(
                    attributes.get("enctype", "") or "application/x-www-form-urlencoded"
                ).lower(),
            )
            if self._form.method not in {"GET", "POST"}:
                self._form.method = "GET"
            return
        if tag in {"a", "area"}:
            href = attributes.get("href", "").strip()
            if href:
                self.page.links.append(urljoin(self.base_url, href))
            return
        if tag == "input" and self._form is not None:
            if "disabled" in attributes:
                return
            input_type = (attributes.get("type", "text") or "text").lower()
            name = attributes.get("name", "")
            if not name or input_type in _SKIP_INPUT_TYPES:
                return
            self._form.fields.append((name, attributes.get("value", "")))
            return
        if tag == "select" and self._form is not None:
            self._select_name = attributes.get("name", "")
            self._select_options = []
            self._option_started = False
            return
        if tag == "option" and self._select_name is not None:
            self._option_value = attributes.get("value")
            self._option_started = True
            self._option_selected = "selected" in attributes
            self._option_text = []
            return
        if tag == "textarea" and self._form is not None:
            self._textarea_name = attributes.get("name", "")
            self._textarea_text = []
            return

    def handle_data(self, data: str) -> None:
        if self._option_started:
            self._option_text.append(data)
        if self._textarea_name is not None:
            self._textarea_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "option" and self._select_name is not None:
            value = (
                self._option_value
                if self._option_value is not None
                else "".join(self._option_text).strip()
            )
            self._select_options.append((value, self._option_selected))
            self._option_value = None
            self._option_started = False
            self._option_selected = False
            self._option_text = []
        elif tag == "select" and self._select_name is not None:
            if self._form is not None and self._select_name:
                selected = next(
                    (value for value, is_selected in self._select_options if is_selected),
                    self._select_options[0][0] if self._select_options else "",
                )
                self._form.fields.append((self._select_name, selected))
            self._select_name = None
            self._select_options = []
            self._option_started = False
            self._option_value = None
            self._option_selected = False
            self._option_text = []
        elif tag == "textarea" and self._textarea_name is not None:
            if self._form is not None and self._textarea_name:
                self._form.fields.append(
                    (self._textarea_name, "".join(self._textarea_text).strip())
                )
            self._textarea_name = None
            self._textarea_text = []
        elif tag == "form":
            self._finish_form()

    def _finish_form(self) -> None:
        if self._form is not None and self._form.fields:
            self.page.forms.append(self._form)
        self._form = None

    def close(self) -> None:
        super().close()
        self._finish_form()


def parse_html(body: str, base_url: str) -> ParsedPage:
    parser = _PageParser(base_url)
    try:
        parser.feed(body)
        parser.close()
    except Exception:  # HTMLParser is tolerant; keep whatever was parsed
        pass
    return parser.page


@dataclass
class CrawlResult:
    points: list[InjectionPoint] = field(default_factory=list)
    pages_fetched: int = 0
    errors: list[str] = field(default_factory=list)
    robots_blocked: int = 0


class Crawler:
    def __init__(
        self,
        config: ScanConfig,
        client: HttpClient,
        scope: ScopeGuard,
        logger: logging.Logger | None = None,
    ) -> None:
        self.config = config
        self.client = client
        self.scope = scope
        self.logger = logger or logging.getLogger("sql_inquisitor.crawler")
        self._robots: dict[str, RobotFileParser | None] = {}
        self._points: list[InjectionPoint] = []
        self._point_ids: set[str] = set()
        self._visited: set[str] = set()
        self._errors: list[str] = []
        self._robots_blocked = 0
        self._pages_fetched = 0

    def discover(self) -> CrawlResult:
        queue: deque[tuple[str, int]] = deque([(self.config.target, 0)])
        while queue and self._pages_fetched < self.config.max_pages:
            if len(self._points) >= self.config.max_points:
                self.logger.info("injection point limit reached; crawl stopped")
                break
            url, depth = queue.popleft()
            key = _url_key(url)
            if key in self._visited:
                continue
            if depth > 0 and not self._robots_allows(url):
                self._robots_blocked += 1
                self.logger.debug("robots.txt disallows %s", url)
                continue
            self._visited.add(key)
            response = self.client.request("GET", url)
            if response.error:
                self._errors.append(f"{url}: {response.error}")
                continue
            self._pages_fetched += 1
            if self.config.scan_query:
                self._add_query_points(url)
            if not _is_html(response.content_type, response.body):
                continue
            page = parse_html(response.body, response.url)
            if self.config.scan_forms:
                self._add_form_points(page.forms)
            if not self.config.crawl or depth >= self.config.max_depth:
                continue
            for link in page.links:
                if not self._should_follow(link):
                    continue
                queue.append((_strip_fragment(link), depth + 1))
        self.logger.info(
            "crawl finished: %s pages, %s injection points, %s errors",
            self._pages_fetched,
            len(self._points),
            len(self._errors),
        )
        return CrawlResult(
            points=self._points,
            pages_fetched=self._pages_fetched,
            errors=self._errors,
            robots_blocked=self._robots_blocked,
        )

    def _add_query_points(self, url: str) -> None:
        parts = urlsplit(url)
        pairs = tuple(parse_qsl(parts.query, keep_blank_values=True))
        if not pairs:
            return
        base = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))
        for name, value in pairs:
            point = InjectionPoint(
                url=base,
                method="GET",
                location="query",
                name=name,
                value=value,
                params=pairs,
                source=url,
            )
            self._add_point(point)

    def _add_form_points(self, forms: list[ParsedForm]) -> None:
        for form in forms:
            action_parts = urlsplit(form.action)
            if not self.scope.allows(form.action):
                self.logger.debug("form action outside scope: %s", form.action)
                continue
            action_pairs = tuple(parse_qsl(action_parts.query, keep_blank_values=True))
            base = urlunsplit(
                (action_parts.scheme, action_parts.netloc, action_parts.path or "/", "", "")
            )
            if self.config.scan_query and action_pairs:
                for name, value in action_pairs:
                    self._add_point(
                        InjectionPoint(
                            url=base,
                            method="GET",
                            location="query",
                            name=name,
                            value=value,
                            params=action_pairs,
                            source=form.action,
                        )
                    )
            fields = tuple(form.fields)
            if form.method == "GET":
                params = action_pairs + fields
                for name, value in fields:
                    self._add_point(
                        InjectionPoint(
                            url=base,
                            method="GET",
                            location="query",
                            name=name,
                            value=value,
                            params=params,
                            source=form.action,
                        )
                    )
            else:
                body_format = "multipart" if "multipart/form-data" in form.enctype else "urlencoded"
                for name, value in fields:
                    self._add_point(
                        InjectionPoint(
                            url=base,
                            method="POST",
                            location="form",
                            name=name,
                            value=value,
                            params=action_pairs,
                            data=fields,
                            body_format=body_format,
                            source=form.action,
                        )
                    )

    def _add_point(self, point: InjectionPoint) -> None:
        if len(self._points) >= self.config.max_points:
            return
        if point.identifier in self._point_ids:
            return
        if any(fnmatch.fnmatch(point.url, pattern) for pattern in self.config.exclude_patterns):
            return
        self._point_ids.add(point.identifier)
        self._points.append(point)

    def _should_follow(self, url: str) -> bool:
        parts = urlsplit(url)
        if parts.scheme.lower() not in {"http", "https"}:
            return False
        if parts.scheme.lower() in _SKIP_SCHEMES:
            return False
        if not self.scope.allows(url):
            return False
        if (
            self.config.same_origin_only
            and parts.netloc.lower() != urlsplit(self.config.target).netloc.lower()
        ):
            return False
        path = parts.path.lower()
        if any(path.endswith(extension) for extension in _STATIC_EXTENSIONS):
            return False
        if any(fnmatch.fnmatch(url, pattern) for pattern in self.config.exclude_patterns):
            return False
        if not self._robots_allows(url):
            self._robots_blocked += 1
            return False
        return True

    def _robots_allows(self, url: str) -> bool:
        if not self.config.respect_robots:
            return True
        parts = urlsplit(url)
        origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
        if origin not in self._robots:
            robots_url = origin + "/robots.txt"
            response = self.client.request("GET", robots_url)
            if response.error or response.status_code >= 400:
                self._robots[origin] = None
            else:
                parser = RobotFileParser()
                parser.set_url(robots_url)
                parser.parse(response.body.splitlines())
                self._robots[origin] = parser
        parser = self._robots[origin]
        if parser is None:
            return True
        try:
            return parser.can_fetch(self.config.user_agent, url)
        except Exception:
            return True


def _strip_fragment(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


def _url_key(url: str) -> str:
    parts = urlsplit(_strip_fragment(url))
    pairs = sorted(parse_qsl(parts.query, keep_blank_values=True))
    query = "&".join(f"{name}={value}" for name, value in pairs)
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, query, ""))


def _is_html(content_type: str, body: str) -> bool:
    lowered = content_type.lower()
    if any(html_type in lowered for html_type in _FORM_HTML_TYPES):
        return True
    if lowered:
        return False
    sample = body[:1024].lower()
    return "<html" in sample or "<form" in sample


def build_explicit_points(
    target: str,
    params: list[str] | None = None,
    data: str | None = None,
    method: str | None = None,
) -> list[InjectionPoint]:
    """Build injection points for ``--param`` and ``--data`` command line usage."""
    parts = urlsplit(target)
    query_pairs = tuple(parse_qsl(parts.query, keep_blank_values=True))
    body_pairs: tuple[tuple[str, str], ...] = ()
    if data:
        if "=" not in data:
            raise ConfigError("--data must use application/x-www-form-urlencoded syntax")
        body_pairs = tuple(parse_qsl(data, keep_blank_values=True))
        if not body_pairs:
            raise ConfigError("--data must use application/x-www-form-urlencoded syntax")
    selected_method = (method or ("POST" if data else "GET")).upper()
    if selected_method not in {"GET", "POST"}:
        raise ConfigError("--method must be GET or POST")
    base = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))
    if selected_method == "GET":
        all_params = query_pairs + body_pairs
        names = params or [name for name, _ in all_params]
        if not all_params:
            all_params = tuple((name, "1") for name in names)
        points = [
            InjectionPoint(
                url=base,
                method="GET",
                location="query",
                name=name,
                value=dict(all_params).get(name, "1"),
                params=all_params,
                source=target,
            )
            for name in dict.fromkeys(names)
        ]
    else:
        names = params or [name for name, _ in body_pairs] or [name for name, _ in query_pairs]
        body = body_pairs or tuple((name, "1") for name in names)
        points = [
            InjectionPoint(
                url=base,
                method="POST",
                location="form",
                name=name,
                value=dict(body).get(name, "1"),
                params=query_pairs,
                data=body,
                body_format="urlencoded",
                source=target,
            )
            for name in dict.fromkeys(names)
        ]
    if not points:
        raise ConfigError(
            "no parameter names were supplied; use --param or include them in the URL"
        )
    return points
