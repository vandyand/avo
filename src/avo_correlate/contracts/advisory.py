"""Versioned contracts for bounded, advisory patch review inference.

These contracts deliberately contain no policy, admission, or lifecycle authority.
An advisory review can describe a candidate and its evidence, but it cannot make a
state transition or authorize a mutation.
"""

import re
import unicodedata
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, StringConstraints, field_validator, model_validator

from avo_correlate.contracts.base import Sha256Digest, StrictModel

# Keep these limits named: callers should use them when constructing prompts and
# providers should use the same values when applying transport limits.
MAX_CANDIDATE_ID_CHARS = 128
MAX_OBJECTIVE_CHARS = 12_000
MAX_PATCH_BYTES = 200_000
MAX_CHANGED_PATHS = 256
MAX_CHANGED_PATH_CHARS = 512
MAX_EVALUATION_SUMMARIES = 64
MAX_EVALUATION_ID_CHARS = 128
MAX_EVALUATION_SUMMARY_CHARS = 4_000
MAX_EVIDENCE_ITEMS = 256
MAX_EVIDENCE_ID_CHARS = 128
MAX_EVIDENCE_LABEL_CHARS = 512
MAX_EVIDENCE_REFS = 32
MAX_FINDINGS = 32
MAX_MISSING_TESTS = 32
MAX_LIMITATIONS = 32
MAX_FINDING_SUMMARY_CHARS = 2_000
MAX_FINDING_RATIONALE_CHARS = 4_000
MAX_SUGGESTED_FIX_CHARS = 2_000
MAX_REVIEW_SUMMARY_CHARS = 4_000
MAX_REVIEW_RATIONALE_CHARS = 8_000
MAX_LIST_ITEM_CHARS = 1_000
MAX_INPUT_BYTES = 500_000

CandidateId = Annotated[
    str,
    StringConstraints(min_length=1, max_length=MAX_CANDIDATE_ID_CHARS, strip_whitespace=True),
]
Objective = Annotated[
    str, StringConstraints(min_length=1, max_length=MAX_OBJECTIVE_CHARS, strip_whitespace=True)
]
PatchText = Annotated[str, StringConstraints(max_length=MAX_PATCH_BYTES)]
ChangedPath = Annotated[
    str,
    StringConstraints(min_length=1, max_length=MAX_CHANGED_PATH_CHARS, strip_whitespace=True),
]
EvidenceId = Annotated[
    str,
    StringConstraints(min_length=1, max_length=MAX_EVIDENCE_ID_CHARS, strip_whitespace=True),
]
BoundedEvaluationId = Annotated[
    str,
    StringConstraints(min_length=1, max_length=MAX_EVALUATION_ID_CHARS, strip_whitespace=True),
]
BoundedSummary = Annotated[
    str,
    StringConstraints(min_length=1, max_length=MAX_EVALUATION_SUMMARY_CHARS, strip_whitespace=True),
]
BoundedListItem = Annotated[
    str, StringConstraints(min_length=1, max_length=MAX_LIST_ITEM_CHARS, strip_whitespace=True)
]

_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")


def validate_advisory_path(value: str) -> str:
    """Validate a changed path as a normalized, relative POSIX path."""

    normalized = unicodedata.normalize("NFC", value)
    if normalized != value:
        raise ValueError("changed paths must already be NFC-normalized")
    if "\x00" in value or "\\" in value or value.startswith("/"):
        raise ValueError("changed paths must be relative POSIX paths")
    if _DRIVE_PREFIX.match(value):
        raise ValueError("changed paths cannot contain a drive prefix")
    if any(segment in {"", ".", ".."} for segment in value.split("/")):
        raise ValueError("changed paths contain an unsafe segment")
    return value


class AdvisoryRecommendation(StrEnum):
    """Non-authoritative recommendation made by an advisory reviewer."""

    ACCEPT = "accept"
    ACCEPT_WITH_FOLLOW_UP = "accept_with_follow_up"
    REVISE = "revise"
    REJECT = "reject"
    NO_CONCLUSION = "no_conclusion"


class AdvisoryFindingSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AdvisoryFindingCategory(StrEnum):
    CORRECTNESS = "correctness"
    COMPATIBILITY = "compatibility"
    SECURITY = "security"
    TESTING = "testing"
    MAINTAINABILITY = "maintainability"
    EFFICIENCY = "efficiency"
    DOCUMENTATION = "documentation"


class AdvisoryEvidenceItem(StrictModel):
    """An immutable catalog entry that a review may cite."""

    schema_version: Literal[1] = 1
    evidence_id: EvidenceId
    content_digest: Sha256Digest
    label: Annotated[
        str,
        StringConstraints(max_length=MAX_EVIDENCE_LABEL_CHARS, strip_whitespace=True),
    ] = ""


class AdvisoryEvaluationSummary(StrictModel):
    """A bounded, already-produced evaluator summary supplied as context."""

    schema_version: Literal[1] = 1
    evaluation_id: BoundedEvaluationId
    outcome: Literal[
        "passed",
        "failed",
        "errored",
        "timed_out",
        "policy_blocked",
        "invalid_report",
    ]
    summary: BoundedSummary
    evidence_refs: list[EvidenceId] = Field(default_factory=list, max_length=MAX_EVIDENCE_REFS)


class AdvisoryPatchReviewInput(StrictModel):
    """The complete, bounded input presented to an advisory review model."""

    schema_version: Literal[1] = 1
    candidate_id: CandidateId
    objective: Objective
    patch: PatchText
    changed_paths: list[ChangedPath] = Field(
        min_length=1, max_length=MAX_CHANGED_PATHS
    )
    evaluation_summaries: list[AdvisoryEvaluationSummary] = Field(
        default_factory=lambda: list[AdvisoryEvaluationSummary](),
        max_length=MAX_EVALUATION_SUMMARIES,
    )
    evidence_catalog: list[AdvisoryEvidenceItem] = Field(
        default_factory=lambda: list[AdvisoryEvidenceItem](), max_length=MAX_EVIDENCE_ITEMS
    )

    @field_validator("changed_paths")
    @classmethod
    def validate_changed_paths(cls, values: list[str]) -> list[str]:
        return [validate_advisory_path(value) for value in values]

    @field_validator("patch")
    @classmethod
    def validate_patch_bytes(cls, value: str) -> str:
        if len(value.encode("utf-8")) > MAX_PATCH_BYTES:
            raise ValueError("advisory patch exceeds byte limit")
        return value

    @model_validator(mode="after")
    def validate_unique_references_and_size(self) -> "AdvisoryPatchReviewInput":
        path_keys = [path.casefold() for path in self.changed_paths]
        if len(path_keys) != len(set(path_keys)):
            raise ValueError("changed paths must be unique, ignoring case")

        evidence_keys = [item.evidence_id.casefold() for item in self.evidence_catalog]
        if len(evidence_keys) != len(set(evidence_keys)):
            raise ValueError("evidence IDs must be unique, ignoring case")

        catalog_ids = {item.evidence_id for item in self.evidence_catalog}
        for summary in self.evaluation_summaries:
            if not set(summary.evidence_refs).issubset(catalog_ids):
                raise ValueError(
                    f"evaluation {summary.evaluation_id} cites evidence outside the catalog"
                )

        if len(self.model_dump_json().encode("utf-8")) > MAX_INPUT_BYTES:
            raise ValueError("advisory review input exceeds byte limit")
        return self


class AdvisoryFinding(StrictModel):
    """A bounded observation; it is not an instruction or an authority decision."""

    schema_version: Literal[1] = 1
    category: AdvisoryFindingCategory
    severity: AdvisoryFindingSeverity
    summary: Annotated[
        str,
        StringConstraints(
            min_length=1, max_length=MAX_FINDING_SUMMARY_CHARS, strip_whitespace=True
        ),
    ]
    rationale: Annotated[
        str,
        StringConstraints(
            min_length=1, max_length=MAX_FINDING_RATIONALE_CHARS, strip_whitespace=True
        ),
    ]
    evidence_refs: list[EvidenceId] = Field(default_factory=list, max_length=MAX_EVIDENCE_REFS)
    affected_paths: list[ChangedPath] = Field(default_factory=list, max_length=MAX_CHANGED_PATHS)
    suggested_fix: Annotated[
        str,
        StringConstraints(max_length=MAX_SUGGESTED_FIX_CHARS, strip_whitespace=True),
    ] | None = None

    @field_validator("affected_paths")
    @classmethod
    def validate_affected_paths(cls, values: list[str]) -> list[str]:
        return [validate_advisory_path(value) for value in values]


def _empty_findings() -> list[AdvisoryFinding]:
    return []


class AdvisoryPatchReview(StrictModel):
    """Validated advisory output, intentionally disconnected from campaign authority."""

    schema_version: Literal[1] = 1
    candidate_id: CandidateId
    recommendation: AdvisoryRecommendation
    summary: Annotated[
        str,
        StringConstraints(min_length=1, max_length=MAX_REVIEW_SUMMARY_CHARS, strip_whitespace=True),
    ]
    rationale: Annotated[
        str,
        StringConstraints(
            min_length=1, max_length=MAX_REVIEW_RATIONALE_CHARS, strip_whitespace=True
        ),
    ]
    findings: list[AdvisoryFinding] = Field(
        default_factory=_empty_findings, max_length=MAX_FINDINGS
    )
    missing_tests: list[BoundedListItem] = Field(
        default_factory=list, max_length=MAX_MISSING_TESTS
    )
    limitations: list[BoundedListItem] = Field(default_factory=list, max_length=MAX_LIMITATIONS)
    confidence_micros: int = Field(ge=0, le=1_000_000)


# Short aliases make the enum names convenient at call sites while preserving the
# explicit Advisory* names in generated schemas and documentation.
Recommendation = AdvisoryRecommendation
FindingSeverity = AdvisoryFindingSeverity
FindingCategory = AdvisoryFindingCategory


__all__ = [
    "AdvisoryEvaluationSummary",
    "AdvisoryEvidenceItem",
    "AdvisoryFinding",
    "AdvisoryFindingCategory",
    "AdvisoryFindingSeverity",
    "AdvisoryPatchReview",
    "AdvisoryPatchReviewInput",
    "AdvisoryRecommendation",
    "FindingCategory",
    "FindingSeverity",
    "Recommendation",
    "validate_advisory_path",
]
