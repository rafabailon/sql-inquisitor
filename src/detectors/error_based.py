"""Error-based SQL injection detection."""

from __future__ import annotations

from detectors.base import Baseline, Detector
from models import Confidence, Detection, InjectionPoint, Technique
from payloads import error_payloads
from signatures import new_sql_errors


class ErrorBasedDetector(Detector):
    technique = Technique.ERROR

    def detect(self, point: InjectionPoint, baseline: Baseline) -> Detection | None:
        for payload in error_payloads(point.value):
            response, sent_value = self._send(point, payload.value)
            if response.blocked:
                self.logger.debug("error probe blocked; stopping error checks for this point")
                return None
            if response.error:
                continue
            errors = new_sql_errors(baseline.response.body, response.body)
            if not errors:
                continue
            confirmation, confirmation_value = self._send(point, payload.value)
            if confirmation.error or confirmation.blocked:
                continue
            confirmed_errors = new_sql_errors(baseline.response.body, confirmation.body)
            if not confirmed_errors:
                self.logger.debug("error signature for parameter %s did not reproduce", point.name)
                continue
            dbms = self._choose_dbms(confirmed_errors)
            self.logger.info(
                "error-based injection confirmed on %s parameter %s (%s)",
                point.url,
                point.name,
                dbms or "unknown DBMS",
            )
            return Detection(
                technique=self.technique,
                payload=sent_value if sent_value == confirmation_value else confirmation_value,
                evidence=confirmed_errors[0].snippet,
                confidence=Confidence.HIGH,
                dbms=dbms,
                status_code=confirmation.status_code,
                response_length=confirmation.body_length,
                elapsed_ms=round(confirmation.elapsed * 1000.0, 2),
                detail={
                    "context": payload.context,
                    "signature": confirmed_errors[0].pattern,
                    "probe": payload.description,
                },
            )
        return None
