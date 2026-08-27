"""Offline structured-advisory evaluation contracts and scorer tests."""

import json
from typing import Any

import pytest
from pydantic import ValidationError

from avo_correlate.contracts.advisory import (
    AdvisoryEvidenceItem,
    AdvisoryFinding,
    AdvisoryFindingCategory,
    AdvisoryFindingSeverity,
    AdvisoryPatchReview,
    AdvisoryPatchReviewInput,
    AdvisoryRecommendation,
)
from avo_correlate.contracts.advisory_evaluation import (
    AdvisoryEvaluationCase,
    AdvisoryEvaluationCaseDigest,
    AdvisoryEvaluationResultManifest,
    AdvisoryEvaluationStage,
    ForbiddenClaim,
    RecordedObservation,
    RecordedObservationKind,
    SeverityExpectation,
    ThemeExpectation,
)
from avo_correlate.domain.advisory_evaluation import (
    evaluate_advisory_case,
    evaluate_advisory_cases,
    forbidden_claim_matches,
    theme_matches,
)

DIGEST = "sha256:" + "a" * 64


def _input(*, evidence: bool = False) -> AdvisoryPatchReviewInput:
    catalog = (
        [AdvisoryEvidenceItem(evidence_id="patch", content_digest=DIGEST, label="patch")]
        if evidence
        else []
    )
    return AdvisoryPatchReviewInput(
        candidate_id="candidate-1",
        objective="check the patch",
        patch="diff --git a/app.py b/app.py",
        changed_paths=["app.py"],
        evidence_catalog=catalog,
    )


def _review(
    *, candidate_id: str = "candidate-1", findings: list[AdvisoryFinding] | None = None
) -> AdvisoryPatchReview:
    return AdvisoryPatchReview(
        candidate_id=candidate_id,
        recommendation=(
            AdvisoryRecommendation.ACCEPT if findings else AdvisoryRecommendation.NO_CONCLUSION
        ),
        summary="The review is bounded and complete.",
        rationale="The supplied input and evidence are sufficient for this conclusion.",
        findings=findings or [],
        missing_tests=[],
        limitations=[],
        confidence_micros=700_000,
    )


def _case(
    observation: RecordedObservation,
    *,
    expected_stage: AdvisoryEvaluationStage = AdvisoryEvaluationStage.ACCEPTED,
    review_input: AdvisoryPatchReviewInput | None = None,
    **rubric: Any,
) -> AdvisoryEvaluationCase:
    return AdvisoryEvaluationCase(
        case_id="case-1",
        review_input=review_input or _input(),
        observation=observation,
        expected_stage=expected_stage,
        **rubric,
    )


def test_duplicate_key_and_malformed_json_are_parse_rejected() -> None:
    duplicate = _case(
        RecordedObservation(
            kind=RecordedObservationKind.MALFORMED_JSON, payload='{"a": 1, "a": 2}'
        ),
        expected_stage=AdvisoryEvaluationStage.PARSE_REJECTED,
    )
    score = evaluate_advisory_case(duplicate)
    assert score.actual_stage == "parse_rejected"
    assert score.expected_stage_correct is True
    assert score.error_code == "invalid_json"
    assert "duplicate" in (score.error_message or "")

    long_key = "k" * 10_000
    long_duplicate = _case(
        RecordedObservation(
            kind=RecordedObservationKind.MALFORMED_JSON,
            payload=json.dumps({long_key: 1})[:-1] + f',"{long_key}":2}}',
        ),
        expected_stage=AdvisoryEvaluationStage.PARSE_REJECTED,
    )
    assert len(evaluate_advisory_case(long_duplicate).error_message or "") == 2_000


@pytest.mark.parametrize("payload", ["[]", '{"x": NaN}', '{"x": Infinity}'])
def test_non_object_or_non_finite_json_is_parse_rejected(payload: str) -> None:
    case = _case(
        RecordedObservation(kind=RecordedObservationKind.REVIEW_JSON, payload=payload),
        expected_stage=AdvisoryEvaluationStage.ACCEPTED,
    )
    score = evaluate_advisory_case(case)
    assert score.actual_stage == AdvisoryEvaluationStage.PARSE_REJECTED
    assert score.expected_stage_correct is False


def test_malformed_label_does_not_make_valid_payload_parse_rejected() -> None:
    case = _case(
        RecordedObservation(
            kind=RecordedObservationKind.MALFORMED_JSON, payload=_review().model_dump_json()
        ),
        expected_stage=AdvisoryEvaluationStage.PARSE_REJECTED,
    )
    score = evaluate_advisory_case(case)
    assert score.actual_stage == "accepted"
    assert score.expected_stage_correct is False


def test_omitted_strict_wire_field_is_rejected_before_defaults() -> None:
    payload = _review().model_dump(mode="json")
    del payload["confidence_micros"]
    case = _case(
        RecordedObservation(kind=RecordedObservationKind.REVIEW_JSON, payload=json.dumps(payload)),
        expected_stage=AdvisoryEvaluationStage.WIRE_REJECTED,
    )
    score = evaluate_advisory_case(case)
    assert score.actual_stage == "wire_rejected"
    assert score.strict_schema_valid is False
    assert score.error_code == "wire_schema"


def test_fabricated_evidence_is_semantically_rejected() -> None:
    finding = AdvisoryFinding(
        category=AdvisoryFindingCategory.SECURITY,
        severity=AdvisoryFindingSeverity.HIGH,
        summary="A security concern is present.",
        rationale="The finding cites fabricated evidence.",
        evidence_refs=["not-in-catalog"],
        affected_paths=[],
    )
    # The wire schema itself accepts the reference; semantic binding rejects it.
    payload = _review(findings=[finding]).model_dump_json()
    case = _case(
        RecordedObservation(kind=RecordedObservationKind.REVIEW_JSON, payload=payload),
        expected_stage=AdvisoryEvaluationStage.SEMANTIC_REJECTED,
    )
    score = evaluate_advisory_case(case)
    assert score.actual_stage == "semantic_rejected"
    assert score.strict_schema_valid is True
    assert score.semantic_valid is False
    assert score.error_code == "semantic_binding"


def test_accepted_no_conclusion_review_is_valid() -> None:
    case = _case(
        RecordedObservation(
            kind=RecordedObservationKind.REVIEW_JSON, payload=_review().model_dump_json()
        ),
        expected_stage=AdvisoryEvaluationStage.ACCEPTED,
    )
    score = evaluate_advisory_case(case)
    assert score.actual_stage == "accepted"
    assert score.semantic_valid is True


def test_provider_refusal_and_truncation_short_circuit() -> None:
    for kind in (RecordedObservationKind.REFUSAL, RecordedObservationKind.TRUNCATED):
        case = _case(
            RecordedObservation(kind=kind, payload="provider evidence"),
            expected_stage=AdvisoryEvaluationStage.PROVIDER_REJECTED,
        )
        score = evaluate_advisory_case(case)
        assert score.actual_stage == "provider_rejected"
        assert score.strict_schema_valid is False
        assert score.semantic_valid is False
    huge = _case(
        RecordedObservation(kind=RecordedObservationKind.REFUSAL, payload="x" * 2_000_000),
        expected_stage=AdvisoryEvaluationStage.PROVIDER_REJECTED,
    )
    assert len(evaluate_advisory_case(huge).error_message or "") == 2_000
    empty = _case(
        RecordedObservation(kind=RecordedObservationKind.TRUNCATED, payload=""),
        expected_stage=AdvisoryEvaluationStage.PROVIDER_REJECTED,
    )
    assert evaluate_advisory_case(empty).error_message


def test_marker_groups_are_and_of_or_and_bind_category_and_evidence() -> None:
    finding = AdvisoryFinding(
        category=AdvisoryFindingCategory.SECURITY,
        severity=AdvisoryFindingSeverity.LOW,
        summary="Path traversal guard is present.",
        rationale="The guard checks the requested path.",
        evidence_refs=["patch"],
        affected_paths=["app.py"],
    )
    review = _review(findings=[finding])
    theme = ThemeExpectation(
        theme_id="security-guard",
        marker_groups=[["missing", "path"], ["traversal", "other"]],
        required_finding_category=AdvisoryFindingCategory.SECURITY,
        required_evidence_refs=["patch"],
    )
    assert theme_matches(theme, review) is True
    missing_alternative = theme.model_copy(update={"marker_groups": [["path"], ["absent"]]})
    assert theme_matches(missing_alternative, review) is False
    wrong_binding = theme.model_copy(update={"required_evidence_refs": ["other"]})
    assert theme_matches(wrong_binding, review) is False


def test_forbidden_claims_use_complete_marker_expression() -> None:
    review = _review()
    claim = ForbiddenClaim(
        claim_id="invented", marker_groups=[["evidence"], ["proves", "guarantees"]]
    )
    assert forbidden_claim_matches(claim, review) is False
    claim = claim.model_copy(update={"marker_groups": [["review"], ["bounded"]]})
    assert forbidden_claim_matches(claim, review) is True


def test_severity_uses_later_in_range_finding() -> None:
    findings = [
        AdvisoryFinding(
            category=AdvisoryFindingCategory.COMPATIBILITY,
            severity=AdvisoryFindingSeverity.CRITICAL,
            summary="first",
            rationale="first",
            affected_paths=[],
        ),
        AdvisoryFinding(
            category=AdvisoryFindingCategory.COMPATIBILITY,
            severity=AdvisoryFindingSeverity.LOW,
            summary="second",
            rationale="second",
            affected_paths=[],
        ),
    ]
    expectation = SeverityExpectation(
        category=AdvisoryFindingCategory.COMPATIBILITY,
        min_severity=AdvisoryFindingSeverity.LOW,
        max_severity=AdvisoryFindingSeverity.MEDIUM,
    )
    case = _case(
        RecordedObservation(
            kind=RecordedObservationKind.REVIEW_JSON,
            payload=_review(findings=findings).model_dump_json(),
        ),
        severity_expectations=[expectation],
    )
    score = evaluate_advisory_case(case)
    assert score.severity_matches[0].matched is True
    assert score.severity_matches[0].finding_severity == "low"


def test_aggregate_ordering_integer_micros_and_zero_denominators() -> None:
    cases = [
        _case(
            RecordedObservation(kind=RecordedObservationKind.REFUSAL, payload="no"),
            expected_stage=AdvisoryEvaluationStage.PROVIDER_REJECTED,
        ).model_copy(update={"case_id": "b"}),
        _case(
            RecordedObservation(kind=RecordedObservationKind.TRUNCATED, payload="cut"),
            expected_stage=AdvisoryEvaluationStage.PROVIDER_REJECTED,
        ).model_copy(update={"case_id": "a"}),
    ]
    report = evaluate_advisory_cases(cases)
    assert [item.case_id for item in report.case_scores] == ["a", "b"]
    assert report.aggregate.expected_stage_accuracy.value_micros == 1_000_000
    assert report.aggregate.theme_recall.denominator == 0
    assert report.aggregate.theme_recall.value_micros == 0
    assert report.aggregate.unsupported_claim_rate.denominator == 0
    assert report.aggregate.severity_calibration_accuracy.denominator == 0
    assert evaluate_advisory_cases(cases).model_dump() == report.model_dump()


def test_unsupported_claim_denominator_uses_all_frozen_expressions() -> None:
    observation = RecordedObservation(
        kind=RecordedObservationKind.REVIEW_JSON, payload=_review().model_dump_json()
    )
    cases = [
        _case(
            observation,
            forbidden_claims=[
                ForbiddenClaim(claim_id="matched", marker_groups=[["review"], ["bounded"]])
            ],
        ).model_copy(update={"case_id": "a"}),
        _case(
            observation,
            forbidden_claims=[
                ForbiddenClaim(claim_id="absent", marker_groups=[["impossible-marker"]])
            ],
        ).model_copy(update={"case_id": "b"}),
    ]
    metric = evaluate_advisory_cases(cases).aggregate.unsupported_claim_rate
    assert (metric.numerator, metric.denominator, metric.value_micros) == (1, 2, 500_000)


def test_contract_bounds_uniqueness_and_frozen_no_mutation() -> None:
    with pytest.raises(ValidationError):
        ThemeExpectation(theme_id="empty", marker_groups=[[]])
    with pytest.raises(ValidationError):
        SeverityExpectation(
            category=AdvisoryFindingCategory.TESTING,
            min_severity=AdvisoryFindingSeverity.HIGH,
            max_severity=AdvisoryFindingSeverity.LOW,
        )
    theme = ThemeExpectation(theme_id="duplicate", marker_groups=[["x"]])
    with pytest.raises(ValidationError):
        _case(
            RecordedObservation(kind=RecordedObservationKind.REFUSAL, payload="no"),
            expected_stage=AdvisoryEvaluationStage.PROVIDER_REJECTED,
            themes=[theme, theme],
        )
    case = _case(
        RecordedObservation(kind=RecordedObservationKind.REFUSAL, payload="no"),
        expected_stage=AdvisoryEvaluationStage.PROVIDER_REJECTED,
    )
    before = case.model_dump()
    evaluate_advisory_case(case)
    assert case.model_dump() == before
    with pytest.raises(ValidationError):
        case.model_validate({**before, "unexpected": True})


def test_result_manifest_is_strict_and_stably_ordered() -> None:
    entries = [
        AdvisoryEvaluationCaseDigest(case_id="a", case_digest=DIGEST, result_digest=DIGEST),
        AdvisoryEvaluationCaseDigest(case_id="b", case_digest=DIGEST, result_digest=DIGEST),
    ]
    manifest = AdvisoryEvaluationResultManifest(
        corpus_digest=DIGEST,
        report_digest=DIGEST,
        report_size_bytes=123,
        case_digests=entries,
    )
    assert manifest.model_dump()["manifest_type"] == "advisory_evaluation_result"
    with pytest.raises(ValidationError):
        AdvisoryEvaluationResultManifest(
            corpus_digest=DIGEST,
            report_digest=DIGEST,
            report_size_bytes=123,
            case_digests=list(reversed(entries)),
        )
