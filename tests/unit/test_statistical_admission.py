from datetime import UTC, datetime
from decimal import Decimal

import pytest

from avo_correlate.contracts.evaluation import (
    ConstraintResult,
    EvaluationRecord,
    TrialRecord,
    UncertaintyRecord,
)
from avo_correlate.domain.admission import (
    ComparisonInputError,
    compare_evaluations,
    evaluation_is_admissible,
)
from tests.conftest import DIGEST_A, DIGEST_B, component


def evaluation(
    candidate_id: str, value: str, lower: str, upper: str, *, tier: str = "admission"
) -> EvaluationRecord:
    now = datetime.now(UTC)
    return EvaluationRecord(
        evaluation_id=f"eval-{candidate_id}",
        candidate_id=candidate_id,
        evaluator_ref=component("evaluator"),
        evaluator_tier=tier,  # type: ignore[arg-type]
        evaluator_profile_digest=DIGEST_A,
        execution_image_digest=DIGEST_B,
        hardware_class="test-x86-64",
        input_artifact_digests=[DIGEST_A],
        trial_records=[
            TrialRecord(
                trial_index=0,
                seed=1,
                metrics={"score": Decimal(value)},
                workload_time_ms=Decimal("1"),
                sandbox_setup_time_ms=Decimal("0"),
                queue_time_ms=Decimal("0"),
                host_overhead_time_ms=Decimal("0"),
            )
        ],
        aggregate_metrics={"score": Decimal(value)},
        uncertainty={
            "score": UncertaintyRecord(
                method="paired-bootstrap",
                lower=Decimal(lower),
                upper=Decimal(upper),
                confidence_level=Decimal("0.95"),
            )
        },
        constraints=[ConstraintResult(name="correctness", passed=True)],
        outcome="passed",
        evidence_artifacts=[],
        started_at=now,
        completed_at=now,
    )


def test_default_comparison_requires_separated_confidence_bounds() -> None:
    incumbent = evaluation("seed", "10", "9", "11")
    improved = evaluation("candidate", "14", "13", "15")
    noisy = evaluation("noisy", "12", "10", "14")
    assert (
        compare_evaluations(
            incumbent, improved, metric="score", direction="maximize", minimum_effect=Decimal("2")
        ).conclusion
        == "improved"
    )
    assert (
        compare_evaluations(
            incumbent, noisy, metric="score", direction="maximize", minimum_effect=Decimal("2")
        ).conclusion
        == "within_noise"
    )
    assert evaluation_is_admissible(improved)


def test_minimization_uses_inverse_bound_rule() -> None:
    incumbent = evaluation("seed", "10", "9", "11")
    candidate = evaluation("candidate", "6", "5", "7")
    comparison = compare_evaluations(
        incumbent, candidate, metric="score", direction="minimize", minimum_effect=Decimal("2")
    )
    assert comparison.conclusion == "improved"


def test_unpaired_hardware_is_rejected() -> None:
    incumbent = evaluation("seed", "10", "9", "11")
    candidate = evaluation("candidate", "14", "13", "15").model_copy(
        update={"hardware_class": "another-worker-class"}
    )
    with pytest.raises(ComparisonInputError, match="hardware"):
        compare_evaluations(
            incumbent,
            candidate,
            metric="score",
            direction="maximize",
            minimum_effect=Decimal("1"),
        )


def test_negative_minimum_effect_is_rejected() -> None:
    with pytest.raises(ComparisonInputError, match="cannot be negative"):
        compare_evaluations(
            evaluation("seed", "10", "9", "11"),
            evaluation("candidate", "14", "13", "15"),
            metric="score",
            direction="maximize",
            minimum_effect=Decimal("-1"),
        )


def test_unpaired_trials_are_rejected() -> None:
    candidate = evaluation("candidate", "14", "13", "15")
    mismatched_trial = candidate.trial_records[0].model_copy(update={"seed": 2})

    with pytest.raises(ComparisonInputError, match="trial indices and seeds"):
        compare_evaluations(
            evaluation("seed", "10", "9", "11"),
            candidate.model_copy(update={"trial_records": [mismatched_trial]}),
            metric="score",
            direction="maximize",
            minimum_effect=Decimal("1"),
        )


def test_missing_comparison_metric_is_rejected() -> None:
    candidate = evaluation("candidate", "14", "13", "15").model_copy(
        update={"aggregate_metrics": {}}
    )

    with pytest.raises(ComparisonInputError, match="metric lacks aggregate or uncertainty"):
        compare_evaluations(
            evaluation("seed", "10", "9", "11"),
            candidate,
            metric="score",
            direction="maximize",
            minimum_effect=Decimal("1"),
        )


def test_worse_candidate_is_not_improved() -> None:
    comparison = compare_evaluations(
        evaluation("seed", "10", "9", "11"),
        evaluation("candidate", "8", "7", "9"),
        metric="score",
        direction="maximize",
        minimum_effect=Decimal("1"),
    )

    assert comparison.conclusion == "not_improved"
