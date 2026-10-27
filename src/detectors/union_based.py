"""UNION-based SQL injection detection."""

from __future__ import annotations

import secrets

from detectors.base import Baseline, Detector
from models import Confidence, Detection, InjectionPoint, Technique
from payloads import (
    UnionContext,
    numeric_marker_expression,
    union_contexts,
    union_payload,
)
from signatures import new_sql_errors


class UnionBasedDetector(Detector):
    technique = Technique.UNION

    def detect(self, point: InjectionPoint, baseline: Baseline) -> Detection | None:
        marker = self._new_marker(baseline.response.body)
        if marker is None:
            return None
        expression = numeric_marker_expression(marker)
        marker_text = str(marker)
        contexts = union_contexts(point.value)
        saw_sql_error = False

        for context in contexts:
            for column_count in range(1, self.config.max_union_columns + 1):
                columns = [expression] + ["NULL"] * (column_count - 1)
                payload = union_payload(point.value, context, columns)
                response, sent_value = self._send(point, payload)
                if response.blocked:
                    return None
                if response.error:
                    continue
                errors = new_sql_errors(baseline.response.body, response.body)
                if errors:
                    saw_sql_error = True
                if marker_text in response.body and marker_text not in baseline.response.body:
                    detection = self._confirm(
                        point,
                        baseline,
                        context,
                        column_count,
                        marker_text,
                        sent_value,
                    )
                    if detection is not None:
                        return detection
                    continue
                if errors:
                    continue

        if not saw_sql_error:
            return None

        for context in contexts:
            for column_count in range(1, self.config.max_union_columns + 1):
                null_payload = union_payload(point.value, context, ["NULL"] * column_count)
                response, _ = self._send(point, null_payload)
                if response.blocked:
                    return None
                if response.error:
                    continue
                if response.status_code >= 500:
                    continue
                if new_sql_errors(baseline.response.body, response.body):
                    continue
                for position in range(column_count):
                    columns = ["NULL"] * column_count
                    columns[position] = expression
                    payload = union_payload(point.value, context, columns)
                    candidate, sent_value = self._send(point, payload)
                    if candidate.blocked:
                        return None
                    if candidate.error:
                        continue
                    if marker_text in candidate.body and marker_text not in baseline.response.body:
                        detection = self._confirm(
                            point,
                            baseline,
                            context,
                            column_count,
                            marker_text,
                            sent_value,
                        )
                        if detection is not None:
                            return detection
        return None

    def _confirm(
        self,
        point: InjectionPoint,
        baseline: Baseline,
        context: UnionContext,
        column_count: int,
        marker_text: str,
        sent_value: str,
    ) -> Detection | None:
        confirmation, confirmation_value = self._send(point, sent_value, apply_tampering=False)
        if confirmation.error or confirmation.blocked:
            return None
        if marker_text not in confirmation.body:
            return None
        self.logger.info(
            "union-based injection confirmed on %s parameter %s with %s columns",
            point.url,
            point.name,
            column_count,
        )
        evidence = (
            f"UNION SELECT with {column_count} columns returned the controlled marker "
            f"{marker_text}. Context: {context.context}. Payload: {confirmation_value!r}."
        )
        return Detection(
            technique=self.technique,
            payload=confirmation_value,
            evidence=evidence,
            confidence=Confidence.HIGH,
            status_code=confirmation.status_code,
            response_length=confirmation.body_length,
            elapsed_ms=round(confirmation.elapsed * 1000.0, 2),
            column_count=column_count,
            detail={
                "context": context.context,
                "column_count": column_count,
                "marker": marker_text,
                "from_dual": context.use_from_dual,
                "payload": confirmation_value,
            },
        )

    @staticmethod
    def _new_marker(baseline_body: str) -> int | None:
        for _ in range(5):
            marker = secrets.randbelow(90_000_000) + 10_000_000
            if str(marker) not in baseline_body:
                return marker
        return None
