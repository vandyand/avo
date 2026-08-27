"""Deterministic statistical comparison rules for admission."""

from decimal import Decimal
from typing import Literal

from avo_correlate.contracts.evaluation import ComparisonRecord, EvaluationRecord


class ComparisonInputError(ValueError):
    pass


def compare_evaluations(
    incumbent: EvaluationRecord,
    candidate: EvaluationRecord,
    *,
    metric: str,
    direction: Literal["maximize", "minimize"],
    minimum_effect: Decimal,
) -> ComparisonRecord:
    """Compare non-overlapping confidence bounds using the packet's default rule."""
    if minimum_effect < 0:
        raise ComparisonInputError("minimum_effect cannot be negative")
    if incumbent.hardware_class != candidate.hardware_class:
        raise ComparisonInputError("paired evaluations require the same hardware class")
    incumbent_trials = [(item.trial_index, item.seed) for item in incumbent.trial_records]
    candidate_trials = [(item.trial_index, item.seed) for item in candidate.trial_records]
    if not incumbent_trials or incumbent_trials != candidate_trials:
        raise ComparisonInputError("paired evaluations require identical trial indices and seeds")
    try:
        incumbent_value = incumbent.aggregate_metrics[metric]
        candidate_value = candidate.aggregate_metrics[metric]
        incumbent_interval = incumbent.uncertainty[metric]
        candidate_interval = candidate.uncertainty[metric]
    except KeyError as exc:
        raise ComparisonInputError(f"metric lacks aggregate or uncertainty: {metric}") from exc
    if direction == "maximize":
        separated = candidate_interval.lower >= incumbent_interval.upper + minimum_effect
        point_improved = candidate_value >= incumbent_value + minimum_effect
    else:
        separated = candidate_interval.upper <= incumbent_interval.lower - minimum_effect
        point_improved = candidate_value <= incumbent_value - minimum_effect
    conclusion: Literal["improved", "not_improved", "within_noise"]
    if separated:
        conclusion = "improved"
    elif point_improved:
        conclusion = "within_noise"
    else:
        conclusion = "not_improved"
    return ComparisonRecord(
        metric=metric,
        direction=direction,
        incumbent_value=incumbent_value,
        candidate_value=candidate_value,
        minimum_effect=minimum_effect,
        conclusion=conclusion,
    )


def evaluation_is_admissible(record: EvaluationRecord) -> bool:
    hard_constraints = [item for item in record.constraints if item.severity == "hard"]
    return (
        record.evaluator_tier == "admission"
        and record.outcome == "passed"
        and bool(record.trial_records)
        and bool(hard_constraints)
        and all(item.passed for item in hard_constraints)
    )
