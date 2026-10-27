"""Time-based blind SQL injection detection."""

from __future__ import annotations

from statistics import median

from detectors.base import Baseline, Detector
from heuristics import is_delayed, median_absolute_deviation, timing_scales
from models import Confidence, Detection, InjectionPoint, Technique
from payloads import time_payloads


class TimeBasedDetector(Detector):
    technique = Technique.TIME

    def detect(self, point: InjectionPoint, baseline: Baseline) -> Detection | None:
        samples = self._baseline_samples(point, baseline)
        if samples is None:
            return None
        delay = self.config.time_delay
        confirm_delay = max(0.15, delay * 0.6)
        payloads = time_payloads(point.value, delay)
        confirmation_payloads = time_payloads(point.value, confirm_delay)
        for index, payload in enumerate(payloads):
            if index >= len(confirmation_payloads):
                break
            response, sent_value = self._send(point, payload.value)
            if response.blocked:
                self.logger.debug("time probe blocked; stopping time-based checks for this point")
                return None
            if response.error:
                continue
            if not is_delayed(response.elapsed, samples, delay):
                continue
            confirmation, confirmation_value = self._send(point, confirmation_payloads[index].value)
            if confirmation.error or confirmation.blocked:
                continue
            if not timing_scales(
                response.elapsed,
                confirmation.elapsed,
                delay,
                confirm_delay,
                samples,
            ):
                self.logger.debug(
                    "time response did not scale for parameter %s; possible jitter", point.name
                )
                continue
            self.logger.info(
                "time-based injection confirmed on %s parameter %s (%s)",
                point.url,
                point.name,
                payload.dbms,
            )
            evidence = (
                f"Baseline median {median(samples) * 1000:.0f} ms; delayed probe "
                f"{response.elapsed * 1000:.0f} ms for a requested {delay:.2f} s delay; "
                f"confirmation {confirmation.elapsed * 1000:.0f} ms for "
                f"{confirm_delay:.2f} s. Payload: {sent_value!r}."
            )
            return Detection(
                technique=self.technique,
                payload=sent_value,
                evidence=evidence,
                confidence=Confidence.HIGH,
                dbms=payload.dbms,
                status_code=confirmation.status_code,
                response_length=confirmation.body_length,
                elapsed_ms=round(confirmation.elapsed * 1000.0, 2),
                detail={
                    "context": payload.context,
                    "probe": payload.description,
                    "requested_delay_seconds": delay,
                    "confirmation_delay_seconds": confirm_delay,
                    "baseline_samples_seconds": [round(value, 4) for value in samples],
                    "baseline_median_seconds": round(median(samples), 4),
                    "baseline_mad_seconds": round(median_absolute_deviation(samples), 4),
                    "probe_seconds": round(response.elapsed, 4),
                    "confirmation_seconds": round(confirmation.elapsed, 4),
                    "confirmation_payload": confirmation_value,
                },
            )
        return None

    def _baseline_samples(self, point: InjectionPoint, baseline: Baseline) -> list[float] | None:
        samples = list(baseline.timing_samples)
        if not samples:
            samples.append(baseline.response.elapsed)
        while len(samples) < self.config.time_samples:
            response, _ = self._send(point, point.value)
            if response.error or response.blocked:
                return None
            samples.append(response.elapsed)
        baseline.timing_samples = samples
        return samples
