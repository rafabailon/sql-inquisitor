"""Scan orchestration: discovery, baselines, detectors and result assembly."""

from __future__ import annotations

import logging
from collections import OrderedDict
from datetime import timezone

from config import ScanConfig
from crawler import Crawler
from detectors.base import Baseline, Detector
from detectors.boolean_based import BooleanBasedDetector
from detectors.error_based import ErrorBasedDetector
from detectors.stacked import StackedBasedDetector
from detectors.time_based import TimeBasedDetector
from detectors.union_based import UnionBasedDetector
from errors import RequestBudgetExceeded
from ethics import ScopeGuard
from http_client import HttpClient
from models import (
    Detection,
    Finding,
    InjectionPoint,
    ScanResult,
    ScanStats,
    Technique,
    severity_for_technique,
    utc_now,
)

MAX_BLOCKED_REQUESTS = 25
MAX_RECORDED_ERRORS = 100

_CANONICAL_ORDER: tuple[Technique, ...] = (
    Technique.ERROR,
    Technique.BOOLEAN,
    Technique.UNION,
    Technique.STACKED,
    Technique.TIME,
)

_DETECTOR_CLASSES: dict[Technique, type[Detector]] = {
    Technique.ERROR: ErrorBasedDetector,
    Technique.BOOLEAN: BooleanBasedDetector,
    Technique.UNION: UnionBasedDetector,
    Technique.STACKED: StackedBasedDetector,
    Technique.TIME: TimeBasedDetector,
}


class Scanner:
    """Run one authorized scan and return a :class:`ScanResult`."""

    def __init__(
        self,
        config: ScanConfig,
        explicit_points: list[InjectionPoint] | None = None,
        logger: logging.Logger | None = None,
        client: HttpClient | None = None,
    ) -> None:
        self.config = config
        self.logger = logger or logging.getLogger("sql_inquisitor.engine")
        self.stats = ScanStats()
        self.client = client or HttpClient(config, stats=self.stats, logger=self.logger)
        self.scope = ScopeGuard(config)
        self.explicit_points = explicit_points or []
        self.result = ScanResult(
            target=config.target,
            config=config.public_dict(),
            stats=self.stats,
        )
        self._baseline_cache: OrderedDict[tuple[object, ...], Baseline] = OrderedDict()
        self._finding_ids: set[str] = set()
        self._points: list[InjectionPoint] = []
        self.detectors = [
            _DETECTOR_CLASSES[technique](config, self.client, self.logger)
            for technique in _CANONICAL_ORDER
            if config.has(technique)
        ]

    def scan(self) -> ScanResult:
        self.scope.check_target()
        try:
            self._points = self._discover()
            self.stats.points_discovered = len(self._points)
            self.result.points = [point.public_dict() for point in self._points]
            self._scan_points()
        except RequestBudgetExceeded as exc:
            self.result.aborted_reason = str(exc)
            self.logger.warning("scan stopped: %s", exc)
        except KeyboardInterrupt:
            self.result.aborted_reason = "interrupted by user"
            self.logger.warning("scan interrupted by user; partial results retained")
        except Exception as exc:  # pragma: no cover - defensive top-level guard
            self.result.aborted_reason = f"unexpected error: {exc}"
            self._record_error(f"unexpected scan error: {exc}")
            self.logger.exception("unexpected scan error")
        finally:
            self.stats.finished_at = utc_now().astimezone(timezone.utc)
            self.stats.findings = len(self.result.findings)
            self.stats.points_tested = max(self.stats.points_tested, 0)
            self.client.close()
        return self.result

    def _discover(self) -> list[InjectionPoint]:
        if self.explicit_points:
            self.logger.info("using %s explicit injection points", len(self.explicit_points))
            return self._deduplicate(self.explicit_points)[: self.config.max_points]
        crawler = Crawler(self.config, self.client, self.scope, self.logger)
        crawl = crawler.discover()
        for error in crawl.errors:
            self._record_error(error)
        if crawl.robots_blocked:
            self.logger.info(
                "%s URLs were not followed because robots.txt disallowed them",
                crawl.robots_blocked,
            )
        return self._deduplicate(crawl.points)[: self.config.max_points]

    def _scan_points(self) -> None:
        if not self._points:
            self.logger.warning("no injection points were discovered")
            self._record_error(
                "no query parameters or forms were discovered; provide --param or a URL "
                "with query parameters"
            )
            return
        self.logger.info("testing %s injection points", len(self._points))
        for index, point in enumerate(self._points, start=1):
            if self.stats.blocked_requests >= MAX_BLOCKED_REQUESTS:
                self.result.aborted_reason = (
                    "target blocked or rate-limited too many requests; stopping to avoid abuse"
                )
                self.logger.warning(self.result.aborted_reason)
                break
            self.logger.info(
                "[%s/%s] %s %s parameter %s",
                index,
                len(self._points),
                point.method,
                point.url,
                point.name,
            )
            baseline = self._baseline(point)
            if baseline is None:
                continue
            point_findings: list[Finding] = []
            for detector in self.detectors:
                if (
                    detector.technique is Technique.TIME
                    and point_findings
                    and not self.config.thorough
                ):
                    self.logger.debug(
                        "skipping time-based checks for %s because the point is already "
                        "confirmed; use --thorough to run them anyway",
                        point.name,
                    )
                    continue
                try:
                    detection = detector.detect(point, baseline)
                except RequestBudgetExceeded:
                    raise
                except Exception as exc:
                    self._record_error(
                        f"{detector.technique.value} detector failed for {point.url} "
                        f"parameter {point.name}: {exc}"
                    )
                    self.logger.debug(
                        "detector failure on %s parameter %s",
                        point.url,
                        point.name,
                        exc_info=True,
                    )
                    continue
                if detection is None:
                    continue
                finding = self._to_finding(point, detection)
                if finding.identifier in self._finding_ids:
                    continue
                self._finding_ids.add(finding.identifier)
                self.result.findings.append(finding)
                point_findings.append(finding)
                self.logger.info(
                    "confirmed %s SQL injection on %s parameter %s",
                    finding.technique.value,
                    point.url,
                    point.name,
                )
                if self.config.stop_after_first:
                    break
            self.stats.points_tested += 1

    def _baseline(self, point: InjectionPoint) -> Baseline | None:
        request_spec = point.request()
        key = request_spec.cache_key()
        if key in self._baseline_cache:
            return self._baseline_cache[key]
        response = self.client.request_spec(request_spec)
        if response.error:
            self._record_error(
                f"baseline request failed for {point.url} parameter {point.name}: {response.error}"
            )
            return None
        if response.status_code == 0:
            self._record_error(
                f"baseline request returned no status for {point.url} parameter {point.name}"
            )
            return None
        baseline = Baseline(point=point, response=response)
        self._baseline_cache[key] = baseline
        return baseline

    def _to_finding(self, point: InjectionPoint, detection: Detection) -> Finding:
        detail = dict(detection.detail)
        detail.setdefault("source", point.source)
        detail.setdefault("location", point.location)
        detail.setdefault("body_format", point.body_format)
        return Finding(
            technique=detection.technique,
            url=point.url,
            method=point.method,
            parameter=point.name,
            location=point.location,
            payload=detection.payload,
            severity=severity_for_technique(detection.technique),
            confidence=detection.confidence,
            evidence=detection.evidence,
            dbms=detection.dbms,
            status_code=detection.status_code,
            response_length=detection.response_length,
            elapsed_ms=detection.elapsed_ms,
            column_count=detection.column_count,
            detail=detail,
        )

    def _record_error(self, message: str) -> None:
        if len(self.result.errors) < MAX_RECORDED_ERRORS:
            self.result.errors.append(message)
        self.logger.debug("scan error recorded: %s", message)

    @staticmethod
    def _deduplicate(points: list[InjectionPoint]) -> list[InjectionPoint]:
        seen: set[str] = set()
        unique: list[InjectionPoint] = []
        for point in points:
            if point.identifier in seen:
                continue
            seen.add(point.identifier)
            unique.append(point)
        return unique
