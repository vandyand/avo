"""Deterministic, provider-free scoring for the structured-advisory corpus."""

import json
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, cast

from jsonschema import Draft202012Validator, ValidationError
from pydantic import ValidationError as PydanticValidationError

from avo_correlate.contracts.advisory import AdvisoryFinding, AdvisoryPatchReview
from avo_correlate.contracts.advisory_evaluation import (
    AdvisoryAggregateScore,
    AdvisoryCaseScore,
    AdvisoryEvaluationCase,
    AdvisoryEvaluationReport,
    AdvisoryEvaluationStage,
    ForbiddenClaim,
    IntegerMicrosMetric,
    RecordedObservationKind,
    SeverityExpectation,
    SeverityMatch,
    ThemeExpectation,
)
from avo_correlate.domain.advisory import (
    AdvisoryReviewValidationError,
    validate_advisory_review,
)
from avo_correlate.domain.structured_schema import compile_strict_output_schema

EVALUATOR_ID = "avo-advisory-evaluation"
EVALUATOR_VERSION = 1


def evaluate_advisory_case(
    case: AdvisoryEvaluationCase | Mapping[str, Any],
) -> AdvisoryCaseScore:
    """Evaluate one recorded case without contacting a provider.

    Invalid case definitions raise validation errors.  Invalid *observations*
    are expected corpus data and become a detailed score instead of raising.
    """

    typed_case = (
        case
        if isinstance(case, AdvisoryEvaluationCase)
        else AdvisoryEvaluationCase.model_validate(case)
    )
    observation = typed_case.observation
    actual_stage: AdvisoryEvaluationStage
    strict_valid = False
    semantic_valid = False
    review: AdvisoryPatchReview | None = None
    error_code: str | None = None
    error_message: str | None = None
    evidence: list[str] = []

    if observation.kind in {RecordedObservationKind.REFUSAL, RecordedObservationKind.TRUNCATED}:
        actual_stage = AdvisoryEvaluationStage.PROVIDER_REJECTED
        error_code = observation.kind.value
        error_message = (
            observation.payload.strip() or f"provider {observation.kind.value} observation recorded"
        )[:2_000]
        evidence.append(f"observation_kind={observation.kind.value}")
    else:
        try:
            document = _parse_json(observation.payload)
        except ValueError as exc:
            actual_stage = AdvisoryEvaluationStage.PARSE_REJECTED
            error_code = "invalid_json"
            error_message = _short_error(str(exc))
            evidence.append("duplicate-key-safe JSON parsing failed")
        else:
            compiled = compile_strict_output_schema(AdvisoryPatchReview)
            validator = Draft202012Validator(compiled.wire_schema)
            wire_errors = sorted(
                cast(Any, validator).iter_errors(cast(Any, document)),
                key=lambda item: list(item.path),
            )
            if wire_errors:
                actual_stage = AdvisoryEvaluationStage.WIRE_REJECTED
                error_code = "wire_schema"
                error_message = _wire_error(wire_errors[0])
                evidence.append(f"wire_schema_digest={compiled.wire_digest}")
            else:
                strict_valid = True
                try:
                    review = AdvisoryPatchReview.model_validate(document)
                except PydanticValidationError as exc:
                    actual_stage = AdvisoryEvaluationStage.WIRE_REJECTED
                    error_code = "pydantic_schema"
                    error_message = _short_error(str(exc))
                    evidence.append("Pydantic AdvisoryPatchReview validation failed")
                else:
                    try:
                        validate_advisory_review(review, typed_case.review_input)
                    except AdvisoryReviewValidationError as exc:
                        actual_stage = AdvisoryEvaluationStage.SEMANTIC_REJECTED
                        error_code = "semantic_binding"
                        error_message = _short_error(str(exc))
                        evidence.append("validate_advisory_review rejected input binding")
                    else:
                        semantic_valid = True
                        actual_stage = AdvisoryEvaluationStage.ACCEPTED
                        evidence.append("wire schema, Pydantic, and semantic validation passed")

    matched_themes: list[str] = []
    missing_themes: list[str] = []
    matched_claims: list[str] = []
    severity_matches: list[SeverityMatch] = []
    if review is not None:
        review_text = _review_text(review)
        for theme in typed_case.themes:
            if _theme_matches(theme, review, review_text):
                matched_themes.append(theme.theme_id)
            else:
                missing_themes.append(theme.theme_id)
        for claim in typed_case.forbidden_claims:
            if _marker_groups_match(claim.marker_groups, review_text):
                matched_claims.append(claim.claim_id)
        for index, expectation in enumerate(typed_case.severity_expectations):
            severity_matches.append(_severity_match(index, expectation, review.findings))
    else:
        missing_themes = [theme.theme_id for theme in typed_case.themes]

    return AdvisoryCaseScore(
        case_id=typed_case.case_id,
        expected_stage=typed_case.expected_stage,
        actual_stage=actual_stage,
        expected_stage_correct=actual_stage is typed_case.expected_stage,
        strict_schema_valid=strict_valid,
        semantic_valid=semantic_valid,
        matched_theme_ids=matched_themes,
        missing_theme_ids=missing_themes,
        matched_forbidden_claim_ids=matched_claims,
        severity_matches=severity_matches,
        error_code=error_code,
        error_message=error_message,
        evidence=evidence,
    )


def evaluate_advisory_cases(
    cases: Iterable[AdvisoryEvaluationCase | Mapping[str, Any]],
    *,
    report_id: str = "offline-advisory-evaluation-v2",
    corpus_digest: str | None = None,
    source_digests: Mapping[str, str] | None = None,
) -> AdvisoryEvaluationReport:
    """Evaluate cases in stable ID order and produce a reproducible report."""

    typed_cases = [
        item
        if isinstance(item, AdvisoryEvaluationCase)
        else AdvisoryEvaluationCase.model_validate(item)
        for item in cases
    ]
    if len({item.case_id for item in typed_cases}) != len(typed_cases):
        raise ValueError("case IDs must be unique")
    scores = sorted(
        (evaluate_advisory_case(item) for item in typed_cases), key=lambda item: item.case_id
    )
    aggregate = aggregate_advisory_scores(scores, cases=typed_cases)
    wire_schema_digest = compile_strict_output_schema(AdvisoryPatchReview).wire_digest
    return AdvisoryEvaluationReport(
        evaluator_id=EVALUATOR_ID,
        evaluator_version=EVALUATOR_VERSION,
        wire_schema_digest=wire_schema_digest,
        report_id=report_id,
        case_scores=scores,
        aggregate=aggregate,
        corpus_digest=corpus_digest,
        source_digests=dict(source_digests or {}),
    )


def aggregate_advisory_scores(
    scores: Sequence[AdvisoryCaseScore],
    *,
    cases: Sequence[AdvisoryEvaluationCase],
) -> AdvisoryAggregateScore:
    """Aggregate case evidence with integer micros and explicit zero ratios."""

    score_ids = [score.case_id for score in scores]
    case_ids = [case.case_id for case in cases]
    if len(score_ids) != len(set(score_ids)) or len(case_ids) != len(set(case_ids)):
        raise ValueError("aggregate case IDs must be unique")
    if set(score_ids) != set(case_ids):
        raise ValueError("aggregate scores and rubrics must have the same case IDs")
    case_by_id = {case.case_id: case for case in cases}
    stage_numerator = sum(score.expected_stage_correct for score in scores)
    strict_numerator = sum(score.strict_schema_valid for score in scores)
    semantic_numerator = sum(score.semantic_valid for score in scores)
    theme_denominator = sum(len(case.themes) for case in case_by_id.values())
    theme_numerator = sum(len(score.matched_theme_ids) for score in scores)
    claim_denominator = sum(len(case.forbidden_claims) for case in case_by_id.values())
    claim_numerator = sum(len(score.matched_forbidden_claim_ids) for score in scores)
    severity_denominator = sum(len(case.severity_expectations) for case in case_by_id.values())
    severity_numerator = sum(
        sum(match.matched for match in score.severity_matches) for score in scores
    )
    return AdvisoryAggregateScore(
        expected_stage_accuracy=_metric(stage_numerator, len(scores)),
        strict_schema_validity=_metric(strict_numerator, len(scores)),
        semantic_validity=_metric(semantic_numerator, len(scores)),
        theme_recall=_metric(theme_numerator, theme_denominator),
        unsupported_claim_rate=_metric(claim_numerator, claim_denominator),
        severity_calibration_accuracy=_metric(severity_numerator, severity_denominator),
    )


def _parse_json(payload: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        document: Any = json.loads(
            payload,
            object_pairs_hook=reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, UnicodeEncodeError, ValueError) as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError("invalid JSON: top-level document must be an object")
    return cast(dict[str, Any], document)


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant: {value}")


def _wire_error(error: ValidationError) -> str:
    path = ".".join(str(item) for item in error.path) or "$"
    return f"wire schema rejected at {path}: {_short_error(error.message)}"


def _short_error(value: str) -> str:
    return value[:2_000]


def _review_text(review: AdvisoryPatchReview) -> str:
    value: Any = review.model_dump(mode="json")
    rendered = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return unicodedata.normalize("NFC", rendered).casefold()


def _marker_groups_match(groups: Sequence[Sequence[str]], text: str) -> bool:
    return all(
        any(unicodedata.normalize("NFC", marker).casefold() in text for marker in group)
        for group in groups
    )


def theme_matches(theme: ThemeExpectation, review: AdvisoryPatchReview) -> bool:
    """Return whether a theme's complete marker and binding expression matches."""

    return _theme_matches(theme, review, _review_text(review))


def forbidden_claim_matches(claim: ForbiddenClaim, review: AdvisoryPatchReview) -> bool:
    """Return whether every marker group of a forbidden claim is present."""

    return _marker_groups_match(claim.marker_groups, _review_text(review))


def _theme_matches(theme: ThemeExpectation, review: AdvisoryPatchReview, text: str) -> bool:
    if not _marker_groups_match(theme.marker_groups, text):
        return False
    for finding in review.findings:
        if (
            theme.required_finding_category is not None
            and finding.category != theme.required_finding_category
        ):
            continue
        if not set(theme.required_evidence_refs).issubset(finding.evidence_refs):
            continue
        return True
    return theme.required_finding_category is None and not theme.required_evidence_refs


def _severity_match(
    index: int,
    expectation: SeverityExpectation,
    findings: Sequence[AdvisoryFinding],
) -> SeverityMatch:
    expectation_id = f"severity-{index + 1}"
    first_out_of_range: AdvisoryFinding | None = None
    for finding in findings:
        if finding.category != expectation.category:
            continue
        if not set(expectation.evidence_refs).issubset(finding.evidence_refs):
            continue
        rank = _severity_rank(finding.severity)
        low = _severity_rank(expectation.min_severity)
        high = _severity_rank(expectation.max_severity)
        if low <= rank <= high:
            return SeverityMatch(
                expectation_id=expectation_id,
                matched=True,
                finding_severity=finding.severity,
            )
        if first_out_of_range is None:
            first_out_of_range = finding
    if first_out_of_range is not None:
        return SeverityMatch(
            expectation_id=expectation_id,
            matched=False,
            finding_severity=first_out_of_range.severity,
            error="matched finding severity is outside the expected range",
        )
    return SeverityMatch(
        expectation_id=expectation_id,
        matched=False,
        error="no finding matched the expected category and evidence references",
    )


def _severity_rank(value: Any) -> int:
    from avo_correlate.contracts.advisory import AdvisoryFindingSeverity

    return list(AdvisoryFindingSeverity).index(value)


def _metric(numerator: int, denominator: int) -> IntegerMicrosMetric:
    value = 0 if denominator == 0 else numerator * 1_000_000 // denominator
    return IntegerMicrosMetric(
        numerator=numerator,
        denominator=denominator,
        value_micros=value,
    )


# Operation-oriented aliases used by corpus/CLI callers.
score_advisory_case = evaluate_advisory_case
score_case = evaluate_advisory_case
aggregate_scores = aggregate_advisory_scores

__all__ = [
    "EVALUATOR_ID",
    "EVALUATOR_VERSION",
    "aggregate_advisory_scores",
    "aggregate_scores",
    "evaluate_advisory_case",
    "evaluate_advisory_cases",
    "forbidden_claim_matches",
    "score_advisory_case",
    "score_case",
    "theme_matches",
]
