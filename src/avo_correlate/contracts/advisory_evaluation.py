"""Immutable contracts for the offline structured-advisory evaluation corpus.

These records describe observations and measurements only.  In particular, no
record in this module can authorize a patch, admission, mutation, or lifecycle
transition.
"""

import unicodedata
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import AliasChoices, Field, StringConstraints, field_validator, model_validator

from avo_correlate.contracts.advisory import (
    AdvisoryFindingCategory,
    AdvisoryFindingSeverity,
    AdvisoryPatchReviewInput,
)
from avo_correlate.contracts.base import NonEmptyString, Sha256Digest, StrictModel

MAX_EVALUATION_CASES = 10_000
MAX_RUBRIC_ITEMS = 128
MAX_MARKER_GROUPS = 64
MAX_MARKERS_PER_GROUP = 32
MAX_MARKER_CHARS = 512
MAX_ERROR_CHARS = 2_000
MAX_EVIDENCE_LINES = 64

Marker = Annotated[str, StringConstraints(min_length=1, max_length=MAX_MARKER_CHARS)]
BoundedError = Annotated[str, StringConstraints(min_length=1, max_length=MAX_ERROR_CHARS)]


class RecordedObservationKind(StrEnum):
    REVIEW_JSON = "review_json"
    MALFORMED_JSON = "malformed_json"
    REFUSAL = "refusal"
    TRUNCATED = "truncated"


class AdvisoryEvaluationStage(StrEnum):
    ACCEPTED = "accepted"
    PARSE_REJECTED = "parse_rejected"
    WIRE_REJECTED = "wire_rejected"
    SEMANTIC_REJECTED = "semantic_rejected"
    PROVIDER_REJECTED = "provider_rejected"


class SeverityExpectation(StrictModel):
    """A bounded severity range for a category/evidence-bound finding."""

    schema_version: Literal[1] = 1
    category: AdvisoryFindingCategory
    evidence_refs: list[NonEmptyString] = Field(default_factory=list, max_length=32)
    min_severity: AdvisoryFindingSeverity
    max_severity: AdvisoryFindingSeverity

    @model_validator(mode="after")
    def validate_range(self) -> "SeverityExpectation":
        if _severity_rank(self.min_severity) > _severity_rank(self.max_severity):
            raise ValueError("minimum severity must not exceed maximum severity")
        if len(self.evidence_refs) != len(set(self.evidence_refs)):
            raise ValueError("severity evidence references must be unique")
        return self


class ThemeExpectation(StrictModel):
    """Conjunctive literal marker groups, optionally bound to finding evidence."""

    schema_version: Literal[1] = 1
    theme_id: NonEmptyString
    marker_groups: list[list[Marker]] = Field(min_length=1, max_length=MAX_MARKER_GROUPS)
    required_finding_category: AdvisoryFindingCategory | None = Field(
        default=None,
        validation_alias=AliasChoices("required_finding_category", "required_category"),
    )
    required_evidence_refs: list[NonEmptyString] = Field(
        default_factory=list,
        max_length=32,
        validation_alias=AliasChoices("required_evidence_refs", "evidence_refs"),
    )

    @field_validator("marker_groups")
    @classmethod
    def validate_markers(cls, groups: list[list[str]]) -> list[list[str]]:
        if any(not group for group in groups):
            raise ValueError("every marker group must contain at least one alternative")
        if any(len(group) > MAX_MARKERS_PER_GROUP for group in groups):
            raise ValueError("marker group contains too many alternatives")
        normalized: list[list[str]] = []
        for group in groups:
            values: list[str] = []
            for marker in group:
                value = unicodedata.normalize("NFC", marker).strip()
                if not value:
                    raise ValueError("markers must not be empty")
                folded = value.casefold()
                if folded not in {item.casefold() for item in values}:
                    values.append(value)
            normalized.append(values)
        return normalized

    @model_validator(mode="after")
    def validate_binding(self) -> "ThemeExpectation":
        if len(self.required_evidence_refs) != len(set(self.required_evidence_refs)):
            raise ValueError("required evidence references must be unique")
        return self


class ForbiddenClaim(StrictModel):
    """A claim pattern whose complete marker expression is disallowed by the rubric."""

    schema_version: Literal[1] = 1
    claim_id: NonEmptyString
    marker_groups: list[list[Marker]] = Field(min_length=1, max_length=MAX_MARKER_GROUPS)

    @field_validator("marker_groups")
    @classmethod
    def validate_markers(cls, groups: list[list[str]]) -> list[list[str]]:
        return ThemeExpectation.validate_markers(groups)


class RecordedObservation(StrictModel):
    """A captured provider result; ``payload`` is never interpreted as authority."""

    schema_version: Literal[1] = 1
    kind: RecordedObservationKind
    payload: Annotated[str, StringConstraints(max_length=2_000_000)] = Field(
        validation_alias=AliasChoices("payload", "content", "raw_text")
    )

    @property
    def content(self) -> str:
        return self.payload

    @property
    def raw_text(self) -> str:
        return self.payload


class AdvisoryEvaluationCase(StrictModel):
    """One input, recorded observation, and private deterministic rubric."""

    schema_version: Literal[1] = 1
    case_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    review_input: AdvisoryPatchReviewInput
    observation: RecordedObservation
    expected_stage: AdvisoryEvaluationStage
    themes: list[ThemeExpectation] = Field(
        default_factory=lambda: list[ThemeExpectation](), max_length=MAX_RUBRIC_ITEMS
    )
    forbidden_claims: list[ForbiddenClaim] = Field(
        default_factory=lambda: list[ForbiddenClaim](), max_length=MAX_RUBRIC_ITEMS
    )
    severity_expectations: list[SeverityExpectation] = Field(
        default_factory=lambda: list[SeverityExpectation](), max_length=MAX_RUBRIC_ITEMS
    )

    @model_validator(mode="after")
    def validate_definition(self) -> "AdvisoryEvaluationCase":
        allowed = {
            RecordedObservationKind.REVIEW_JSON: {
                AdvisoryEvaluationStage.ACCEPTED,
                AdvisoryEvaluationStage.WIRE_REJECTED,
                AdvisoryEvaluationStage.SEMANTIC_REJECTED,
            },
            RecordedObservationKind.MALFORMED_JSON: {AdvisoryEvaluationStage.PARSE_REJECTED},
            RecordedObservationKind.REFUSAL: {AdvisoryEvaluationStage.PROVIDER_REJECTED},
            RecordedObservationKind.TRUNCATED: {AdvisoryEvaluationStage.PROVIDER_REJECTED},
        }
        if self.expected_stage not in allowed[self.observation.kind]:
            raise ValueError("expected stage is incompatible with observation kind")
        _unique_ids("theme IDs", [item.theme_id for item in self.themes])
        _unique_ids("forbidden claim IDs", [item.claim_id for item in self.forbidden_claims])
        return self


class SeverityMatch(StrictModel):
    schema_version: Literal[1] = 1
    expectation_id: NonEmptyString
    matched: bool
    finding_severity: AdvisoryFindingSeverity | None = None
    error: BoundedError | None = None


class AdvisoryCaseScore(StrictModel):
    """Detailed, deterministic result for a single corpus case."""

    schema_version: Literal[1] = 1
    case_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    expected_stage: AdvisoryEvaluationStage
    actual_stage: AdvisoryEvaluationStage
    expected_stage_correct: bool
    strict_schema_valid: bool
    semantic_valid: bool
    matched_theme_ids: list[NonEmptyString] = Field(
        default_factory=list, max_length=MAX_RUBRIC_ITEMS
    )
    missing_theme_ids: list[NonEmptyString] = Field(
        default_factory=list, max_length=MAX_RUBRIC_ITEMS
    )
    matched_forbidden_claim_ids: list[NonEmptyString] = Field(
        default_factory=list, max_length=MAX_RUBRIC_ITEMS
    )
    severity_matches: list[SeverityMatch] = Field(
        default_factory=lambda: list[SeverityMatch](), max_length=MAX_RUBRIC_ITEMS
    )
    error_code: NonEmptyString | None = None
    error_message: BoundedError | None = None
    evidence: list[BoundedError] = Field(default_factory=list, max_length=MAX_EVIDENCE_LINES)

    @model_validator(mode="after")
    def validate_ids(self) -> "AdvisoryCaseScore":
        _unique_ids("matched theme IDs", self.matched_theme_ids)
        _unique_ids("missing theme IDs", self.missing_theme_ids)
        _unique_ids("matched forbidden claim IDs", self.matched_forbidden_claim_ids)
        return self


class IntegerMicrosMetric(StrictModel):
    """A ratio represented without floating-point arithmetic."""

    schema_version: Literal[1] = 1
    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    value_micros: int = Field(ge=0, le=1_000_000)

    @model_validator(mode="after")
    def validate_value(self) -> "IntegerMicrosMetric":
        if self.numerator > self.denominator:
            raise ValueError("metric numerator cannot exceed denominator")
        expected = 0 if self.denominator == 0 else (self.numerator * 1_000_000) // self.denominator
        if self.value_micros != expected:
            raise ValueError("metric value_micros does not match integer ratio")
        return self


class AdvisoryAggregateScore(StrictModel):
    schema_version: Literal[1] = 1
    expected_stage_accuracy: IntegerMicrosMetric
    strict_schema_validity: IntegerMicrosMetric
    semantic_validity: IntegerMicrosMetric
    theme_recall: IntegerMicrosMetric
    unsupported_claim_rate: IntegerMicrosMetric
    severity_calibration_accuracy: IntegerMicrosMetric

    @property
    def expected_stage_accuracy_micros(self) -> int:
        return self.expected_stage_accuracy.value_micros

    @property
    def strict_schema_validity_micros(self) -> int:
        return self.strict_schema_validity.value_micros

    @property
    def semantic_validity_micros(self) -> int:
        return self.semantic_validity.value_micros

    @property
    def theme_recall_micros(self) -> int:
        return self.theme_recall.value_micros

    @property
    def unsupported_claim_rate_micros(self) -> int:
        return self.unsupported_claim_rate.value_micros

    @property
    def severity_calibration_accuracy_micros(self) -> int:
        return self.severity_calibration_accuracy.value_micros


class AdvisoryEvaluationReport(StrictModel):
    schema_version: Literal[1] = 1
    evaluator_id: Literal["avo-advisory-evaluation"]
    evaluator_version: Literal[1]
    wire_schema_digest: Sha256Digest
    report_id: NonEmptyString
    case_scores: list[AdvisoryCaseScore] = Field(max_length=MAX_EVALUATION_CASES)
    aggregate: AdvisoryAggregateScore
    corpus_digest: Sha256Digest | None = None
    source_digests: dict[NonEmptyString, Sha256Digest] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_case_order(self) -> "AdvisoryEvaluationReport":
        ids = [score.case_id for score in self.case_scores]
        if ids != sorted(ids):
            raise ValueError("case scores must be in stable case ID order")
        if len(ids) != len(set(ids)):
            raise ValueError("case IDs must be unique")
        return self


class AdvisoryEvaluationCaseDigest(StrictModel):
    """Content-addressed references for one case and its scored result."""

    schema_version: Literal[1] = 1
    case_id: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    case_digest: Sha256Digest
    result_digest: Sha256Digest


class AdvisoryEvaluationResultManifest(StrictModel):
    """Schema-exportable linkage among corpus, report, and case result evidence."""

    schema_version: Literal[1] = 1
    manifest_type: Literal["advisory_evaluation_result"] = "advisory_evaluation_result"
    corpus_digest: Sha256Digest
    report_digest: Sha256Digest
    report_size_bytes: int = Field(ge=0, le=10_000_000)
    case_digests: list[AdvisoryEvaluationCaseDigest] = Field(
        default_factory=lambda: list[AdvisoryEvaluationCaseDigest](),
        max_length=MAX_EVALUATION_CASES,
    )
    result_manifest_digest: Sha256Digest | None = None

    @model_validator(mode="after")
    def validate_case_order(self) -> "AdvisoryEvaluationResultManifest":
        ids = [item.case_id for item in self.case_digests]
        if ids != sorted(ids):
            raise ValueError("manifest case digests must be in stable case ID order")
        if len(ids) != len(set(ids)):
            raise ValueError("manifest case IDs must be unique")
        return self


def _severity_rank(value: AdvisoryFindingSeverity) -> int:
    return list(AdvisoryFindingSeverity).index(value)


def _unique_ids(label: str, values: list[str]) -> None:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must be unique")


# Short names are useful to corpus authors while retaining explicit names for
# generated schemas and callers that prefer them.
ObservationKind = RecordedObservationKind
ExpectedStage = AdvisoryEvaluationStage
EvaluationCase = AdvisoryEvaluationCase
CaseScore = AdvisoryCaseScore
AggregateScore = AdvisoryAggregateScore
EvaluationReport = AdvisoryEvaluationReport
AdvisoryObservation = RecordedObservation
AdvisoryRecordedObservation = RecordedObservation
AdvisoryThemeExpectation = ThemeExpectation
AdvisoryForbiddenClaim = ForbiddenClaim
AdvisorySeverityExpectation = SeverityExpectation
AdvisoryExpectedStage = AdvisoryEvaluationStage
AdvisoryAggregate = AdvisoryAggregateScore
AdvisoryPerCaseScore = AdvisoryCaseScore
ResultManifest = AdvisoryEvaluationResultManifest

__all__ = [
    "AdvisoryAggregate",
    "AdvisoryAggregateScore",
    "AdvisoryCaseScore",
    "AdvisoryEvaluationCase",
    "AdvisoryEvaluationCaseDigest",
    "AdvisoryEvaluationReport",
    "AdvisoryEvaluationResultManifest",
    "AdvisoryEvaluationStage",
    "AdvisoryExpectedStage",
    "AdvisoryForbiddenClaim",
    "AdvisoryObservation",
    "AdvisoryPerCaseScore",
    "AdvisoryRecordedObservation",
    "AdvisorySeverityExpectation",
    "AdvisoryThemeExpectation",
    "AggregateScore",
    "CaseScore",
    "EvaluationCase",
    "EvaluationReport",
    "ExpectedStage",
    "ForbiddenClaim",
    "IntegerMicrosMetric",
    "ObservationKind",
    "RecordedObservation",
    "RecordedObservationKind",
    "ResultManifest",
    "SeverityExpectation",
    "SeverityMatch",
    "ThemeExpectation",
]
