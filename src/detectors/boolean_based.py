"""Boolean-based blind SQL injection detection."""

from __future__ import annotations

from detectors.base import Baseline, Detector
from heuristics import (
    FALSE_SIMILARITY,
    SIMILARITY_DELTA,
    TRUE_SIMILARITY,
    de_reflect,
    normalize_text,
    similarity,
)
from models import Confidence, Detection, InjectionPoint, Technique
from payloads import BooleanPair, boolean_pairs
from signatures import has_new_sql_error

REQUIRED_CONFIRMATIONS = 2


class BooleanBasedDetector(Detector):
    technique = Technique.BOOLEAN

    def detect(self, point: InjectionPoint, baseline: Baseline) -> Detection | None:
        normalized_baseline = normalize_text(baseline.response.body)
        confirmations: list[dict[str, object]] = []
        self._blocked = False
        for pair in boolean_pairs(point.value):
            confirmation = self._test_pair(point, baseline, normalized_baseline, pair)
            if self._blocked:
                self.logger.debug("boolean probe blocked; stopping boolean checks for this point")
                return None
            if confirmation is None:
                continue
            confirmations.append(confirmation)
            self.logger.debug(
                "boolean confirmation %s/%s on parameter %s (%s)",
                len(confirmations),
                REQUIRED_CONFIRMATIONS,
                point.name,
                pair.description,
            )
            if len(confirmations) >= REQUIRED_CONFIRMATIONS:
                latest = confirmations[-1]
                evidence = (
                    f"Two independent boolean pairs produced the expected response split. "
                    f"True/false similarity delta: {latest['baseline_like']:.4f} vs "
                    f"{latest['other']:.4f}; payloads: {latest['true_payload']!r} and "
                    f"{latest['false_payload']!r}."
                )
                self.logger.info(
                    "boolean-based injection confirmed on %s parameter %s",
                    point.url,
                    point.name,
                )
                return Detection(
                    technique=self.technique,
                    payload=str(latest["true_payload"]),
                    evidence=evidence,
                    confidence=Confidence.HIGH,
                    status_code=int(latest["status_code"]),
                    response_length=int(latest["response_length"]),
                    elapsed_ms=float(latest["elapsed_ms"]),
                    detail={
                        "context": pair.context,
                        "confirmations": confirmations,
                        "true_payload": latest["true_payload"],
                        "false_payload": latest["false_payload"],
                    },
                )
        return None

    def _test_pair(
        self,
        point: InjectionPoint,
        baseline: Baseline,
        normalized_baseline: str,
        pair: BooleanPair,
    ) -> dict[str, object] | None:
        true_response, true_value = self._send(point, pair.true_value)
        false_response, false_value = self._send(point, pair.false_value)
        if true_response.blocked or false_response.blocked:
            self._blocked = True
            return None
        if true_response.error or false_response.error:
            return None
        if true_response.status_code != baseline.response.status_code:
            return None
        if false_response.status_code != baseline.response.status_code:
            return None
        if has_new_sql_error(baseline.response.body, true_response.body):
            return None
        if has_new_sql_error(baseline.response.body, false_response.body):
            return None

        true_body = de_reflect(true_response.body, true_value, point.value)
        false_body = de_reflect(false_response.body, false_value, point.value)
        normalized_true = normalize_text(true_body)
        normalized_false = normalize_text(false_body)

        true_similarity = similarity(normalized_baseline, normalized_true)
        false_similarity = similarity(normalized_baseline, normalized_false)
        pair_similarity = similarity(normalized_true, normalized_false)

        if pair.baseline_side == "true":
            baseline_like = true_similarity
            other = false_similarity
            exact_baseline = normalized_true == normalized_baseline
        else:
            baseline_like = false_similarity
            other = true_similarity
            exact_baseline = normalized_false == normalized_baseline
        exact_pair_difference = normalized_true != normalized_false

        confirmed = False
        if exact_baseline and exact_pair_difference:
            confirmed = True
        elif (
            baseline_like >= 0.995
            and other <= 0.97
            and baseline_like - other >= 0.01
            and pair_similarity <= 0.98
        ):
            confirmed = True
        elif (
            baseline_like >= TRUE_SIMILARITY
            and other <= FALSE_SIMILARITY
            and baseline_like - other >= SIMILARITY_DELTA
            and pair_similarity <= FALSE_SIMILARITY
        ):
            confirmed = True
        if not confirmed:
            return None

        return {
            "context": pair.context,
            "description": pair.description,
            "true_payload": true_value,
            "false_payload": false_value,
            "baseline_like": round(baseline_like, 6),
            "other": round(other, 6),
            "pair_similarity": round(pair_similarity, 6),
            "exact_baseline": exact_baseline,
            "status_code": true_response.status_code,
            "response_length": true_response.body_length,
            "elapsed_ms": round(true_response.elapsed * 1000.0, 2),
        }
