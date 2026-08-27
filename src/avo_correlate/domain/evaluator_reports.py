"""Fail-closed parsing for untrusted evaluator JSON output."""

import json
import math
from decimal import Decimal
from typing import Any, cast

from pydantic import ValidationError

from avo_correlate.contracts.evaluation import EvaluationRecord


class InvalidEvaluatorReport(ValueError):
    pass


def parse_evaluation_report(
    payload: bytes,
    *,
    max_bytes: int,
    declared_metrics: frozenset[str],
) -> EvaluationRecord:
    if len(payload) > max_bytes:
        raise InvalidEvaluatorReport("evaluator report exceeds byte limit")
    try:
        document = json.loads(
            payload,
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=Decimal,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, InvalidEvaluatorReport) as exc:
        raise InvalidEvaluatorReport(f"invalid evaluator JSON: {exc}") from exc
    _reject_non_finite(document)
    try:
        record = EvaluationRecord.model_validate(document)
    except ValidationError as exc:
        raise InvalidEvaluatorReport(f"report schema validation failed: {exc}") from exc
    actual = set(record.aggregate_metrics)
    expected = set(declared_metrics)
    if actual != expected:
        raise InvalidEvaluatorReport(
            "metric declaration mismatch: "
            f"expected {sorted(declared_metrics)}, got {sorted(actual)}"
        )
    for trial in record.trial_records:
        if set(trial.metrics) != expected:
            raise InvalidEvaluatorReport("trial metrics do not match declared metrics")
    if set(record.uncertainty) != expected:
        raise InvalidEvaluatorReport("uncertainty metrics do not match declared metrics")
    return record


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidEvaluatorReport(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise InvalidEvaluatorReport(f"non-finite JSON number: {value}")


def _reject_non_finite(value: object) -> None:
    if isinstance(value, Decimal) and not value.is_finite():
        raise InvalidEvaluatorReport("non-finite decimal")
    if isinstance(value, float) and not math.isfinite(value):
        raise InvalidEvaluatorReport("non-finite float")
    if isinstance(value, dict):
        mapping = cast(dict[object, object], value)
        for nested in mapping.values():
            _reject_non_finite(nested)
    elif isinstance(value, list):
        sequence = cast(list[object], value)
        for nested in sequence:
            _reject_non_finite(nested)
