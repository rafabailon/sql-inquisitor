"""Base classes and shared helpers for detection modules."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from config import ScanConfig
from http_client import HttpClient
from models import Detection, HttpResponse, InjectionPoint, Technique
from payloads import apply_tamper
from signatures import DetectedError


@dataclass
class Baseline:
    """The original-value response for one injection point."""

    point: InjectionPoint
    response: HttpResponse
    timing_samples: list[float] = field(default_factory=list)


class Detector(ABC):
    technique: Technique

    def __init__(
        self,
        config: ScanConfig,
        client: HttpClient,
        logger: logging.Logger | None = None,
    ) -> None:
        self.config = config
        self.client = client
        self.logger = logger or logging.getLogger(
            f"sql_inquisitor.detectors.{self.technique.value}"
        )

    def _send(
        self, point: InjectionPoint, value: str, *, apply_tampering: bool = True
    ) -> tuple[HttpResponse, str]:
        tampered = apply_tamper(value, self.config.tamper) if apply_tampering else value
        response = self.client.request_spec(point.request(tampered))
        return response, tampered

    @staticmethod
    def _choose_dbms(errors: list[DetectedError]) -> str | None:
        for error in errors:
            if error.dbms != "Generic SQL":
                return error.dbms
        return errors[0].dbms if errors else None

    @abstractmethod
    def detect(self, point: InjectionPoint, baseline: Baseline) -> Detection | None:
        """Return a confirmed detection or ``None``."""
