"""Stacked-query SQL injection detection using non-destructive statements."""

from __future__ import annotations

import re
import secrets

from detectors.base import Baseline, Detector
from models import Confidence, Detection, InjectionPoint, Technique
from payloads import stacked_payloads
from signatures import DetectedError, new_sql_errors

_DIVISION = re.compile(
    r"division by zero|divide by zero|divisor is equal to zero|cannot divide by zero|"
    r"division by 0|arithmetic overflow|data exception",
    re.IGNORECASE,
)


class StackedBasedDetector(Detector):
    technique = Technique.STACKED

    def detect(self, point: InjectionPoint, baseline: Baseline) -> Detection | None:
        token = "inq" + secrets.token_hex(6)
        for payload in stacked_payloads(point.value, token):
            response, sent_value = self._send(point, payload.value)
            if response.blocked:
                self.logger.debug("stacked probe blocked; stopping stacked checks for this point")
                return None
            if response.error:
                continue
            errors = new_sql_errors(baseline.response.body, response.body)
            if not errors:
                continue
            if payload.token:
                token_errors = [
                    error for error in errors if self._is_table_error(error, payload.token)
                ]
                if not token_errors:
                    continue
                confirmation, confirmation_value = self._send(
                    point, sent_value, apply_tampering=False
                )
                if confirmation.error or confirmation.blocked:
                    continue
                confirmed_errors = new_sql_errors(baseline.response.body, confirmation.body)
                confirmed_token_errors = [
                    error
                    for error in confirmed_errors
                    if self._is_table_error(error, payload.token)
                ]
                if not confirmed_token_errors:
                    continue
                self.logger.info(
                    "stacked-query injection confirmed on %s parameter %s",
                    point.url,
                    point.name,
                )
                return self._detection(
                    point,
                    confirmation_value,
                    confirmation,
                    confirmed_token_errors,
                    payload.context,
                    Confidence.HIGH,
                    f"Second statement referenced table {payload.token!r} and the database "
                    f"reported: {confirmed_token_errors[0].snippet}",
                )
            if self._is_division_error(errors):
                confirmation, confirmation_value = self._send(
                    point, sent_value, apply_tampering=False
                )
                if confirmation.error or confirmation.blocked:
                    continue
                confirmed_errors = new_sql_errors(baseline.response.body, confirmation.body)
                if not self._is_division_error(confirmed_errors):
                    continue
                self.logger.info(
                    "stacked-query arithmetic probe confirmed on %s parameter %s",
                    point.url,
                    point.name,
                )
                return self._detection(
                    point,
                    confirmation_value,
                    confirmation,
                    confirmed_errors,
                    payload.context,
                    Confidence.MEDIUM,
                    f"Second statement produced a reproducible division error: "
                    f"{confirmed_errors[0].snippet}",
                )
        return None

    def _detection(
        self,
        point: InjectionPoint,
        payload: str,
        response,
        errors: list[DetectedError],
        context: str,
        confidence: Confidence,
        evidence: str,
    ) -> Detection:
        return Detection(
            technique=self.technique,
            payload=payload,
            evidence=evidence,
            confidence=confidence,
            dbms=self._choose_dbms(errors),
            status_code=response.status_code,
            response_length=response.body_length,
            elapsed_ms=round(response.elapsed * 1000.0, 2),
            detail={"context": context, "payload": payload},
        )

    @staticmethod
    def _is_table_error(error: DetectedError, token: str) -> bool:
        if token not in error.snippet:
            return False
        material = f"{error.pattern} {error.snippet}".lower()
        markers = (
            "no such table",
            "no such column",
            "doesn't exist",
            "does not exist",
            "unknown table",
            "invalid object name",
            "invalid column name",
            "table or view does not exist",
            "base table or view not found",
            "object not found",
            "unknown column",
        )
        return any(marker in material for marker in markers)

    @staticmethod
    def _is_division_error(errors: list[DetectedError]) -> bool:
        return any(_DIVISION.search(error.snippet) for error in errors)
