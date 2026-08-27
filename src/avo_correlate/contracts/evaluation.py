"""Authoritative evaluation and admission records."""

from datetime import datetime
from decimal import Decimal
from typing import Literal

from pydantic import Field, field_validator

from avo_correlate.contracts.base import (
    ActorRef,
    ArtifactRef,
    NonEmptyString,
    Sha256Digest,
    StrictModel,
    VersionedComponentRef,
    require_aware_datetime,
)


class TrialRecord(StrictModel):
    schema_version: Literal[1] = 1
    trial_index: int = Field(ge=0)
    seed: int
    metrics: dict[str, Decimal]
    workload_time_ms: Decimal = Field(ge=0)
    sandbox_setup_time_ms: Decimal = Field(ge=0)
    queue_time_ms: Decimal = Field(ge=0)
    host_overhead_time_ms: Decimal = Field(ge=0)


class UncertaintyRecord(StrictModel):
    schema_version: Literal[1] = 1
    method: NonEmptyString
    lower: Decimal
    upper: Decimal
    confidence_level: Decimal = Field(gt=0, lt=1)


class ConstraintResult(StrictModel):
    schema_version: Literal[1] = 1
    name: NonEmptyString
    passed: bool
    severity: Literal["hard", "soft"] = "hard"
    evidence_digest: Sha256Digest | None = None


class EvaluationRecord(StrictModel):
    schema_version: Literal[1] = 1
    evaluation_id: NonEmptyString
    candidate_id: NonEmptyString
    evaluator_ref: VersionedComponentRef
    evaluator_tier: Literal["development", "admission", "audit"]
    evaluator_profile_digest: Sha256Digest
    execution_image_digest: Sha256Digest
    hardware_class: NonEmptyString
    input_artifact_digests: list[Sha256Digest]
    trial_records: list[TrialRecord]
    aggregate_metrics: dict[str, Decimal]
    uncertainty: dict[str, UncertaintyRecord]
    constraints: list[ConstraintResult]
    outcome: Literal[
        "passed", "failed", "errored", "timed_out", "policy_blocked", "invalid_report"
    ]
    evidence_artifacts: list[ArtifactRef]
    started_at: datetime
    completed_at: datetime

    _aware_started = field_validator("started_at")(require_aware_datetime)
    _aware_completed = field_validator("completed_at")(require_aware_datetime)


class ComparisonRecord(StrictModel):
    schema_version: Literal[1] = 1
    metric: NonEmptyString
    direction: Literal["maximize", "minimize"]
    incumbent_value: Decimal
    candidate_value: Decimal
    minimum_effect: Decimal
    conclusion: Literal["improved", "not_improved", "within_noise"]


class AdmissionDecision(StrictModel):
    schema_version: Literal[1] = 1
    admission_id: NonEmptyString
    candidate_id: NonEmptyString
    expected_champion_id: NonEmptyString
    evaluation_ids: list[NonEmptyString] = Field(min_length=1)
    policy_decision_ids: list[NonEmptyString] = Field(min_length=1)
    outcome: Literal["admit", "reject", "quarantine", "review_required"]
    reason_codes: list[NonEmptyString] = Field(min_length=1)
    comparison: ComparisonRecord
    decided_by: ActorRef
    decided_at: datetime

    _aware_decided = field_validator("decided_at")(require_aware_datetime)
