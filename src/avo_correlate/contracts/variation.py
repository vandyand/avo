"""Variation session, attempt, and candidate records."""

from datetime import datetime
from typing import Literal

from pydantic import Field, field_validator, model_validator

from avo_correlate.contracts.base import (
    ArtifactRef,
    NonEmptyString,
    Sha256Digest,
    StrictModel,
    VersionedComponentRef,
    require_aware_datetime,
)
from avo_correlate.contracts.budgets import UsageRecord


class CandidateRef(StrictModel):
    schema_version: Literal[1] = 1
    candidate_id: NonEmptyString
    source_tree_digest: Sha256Digest
    lineage_sequence: int = Field(ge=0)


class VariationSessionRequest(StrictModel):
    schema_version: Literal[1] = 1
    session_id: NonEmptyString
    run_id: NonEmptyString
    champion: CandidateRef
    lineage_index_digest: Sha256Digest
    initial_context_digest: Sha256Digest
    tool_capability_token: NonEmptyString
    development_evaluator_refs: list[VersionedComponentRef] = Field(min_length=1)
    budget_reservation_id: NonEmptyString
    random_seed: int


class VariationSessionResult(StrictModel):
    schema_version: Literal[1] = 1
    session_id: NonEmptyString
    outcome: Literal["proposal_ready", "exhausted", "policy_blocked", "cancelled", "failed"]
    proposed_workspace_digest: Sha256Digest | None = None
    proposed_patch_digest: Sha256Digest | None = None
    rationale_artifact: ArtifactRef | None = None
    attempt_index_digest: Sha256Digest
    usage: UsageRecord

    @model_validator(mode="after")
    def proposal_requires_workspace(self) -> "VariationSessionResult":
        if self.outcome == "proposal_ready" and self.proposed_workspace_digest is None:
            raise ValueError("proposal_ready requires proposed_workspace_digest")
        return self


class VariationAttemptRecord(StrictModel):
    schema_version: Literal[1] = 1
    attempt_id: NonEmptyString
    session_id: NonEmptyString
    parent_workspace_digest: Sha256Digest
    result_workspace_digest: Sha256Digest | None = None
    patch_digest: Sha256Digest | None = None
    development_evaluation_ids: list[NonEmptyString]
    tool_trace_digest: Sha256Digest
    outcome: Literal[
        "improved", "no_improvement", "invalid", "errored", "abandoned", "policy_blocked"
    ]
    started_at: datetime
    completed_at: datetime

    _aware_started = field_validator("started_at")(require_aware_datetime)
    _aware_completed = field_validator("completed_at")(require_aware_datetime)


class CandidateManifest(StrictModel):
    schema_version: Literal[1] = 1
    candidate_id: NonEmptyString
    run_id: NonEmptyString
    session_id: NonEmptyString
    parent_candidate_ids: list[NonEmptyString]
    base_workspace_digest: Sha256Digest
    source_tree_digest: Sha256Digest
    patch_artifact: ArtifactRef | None = None
    result_artifacts: list[ArtifactRef]
    harness_ref: VersionedComponentRef
    model_config_digest: Sha256Digest
    context_digest: Sha256Digest
    attempt_index_digest: Sha256Digest
    execution_profile_digest: Sha256Digest
    policy_bundle_digest: Sha256Digest
    created_at: datetime

    _aware_created = field_validator("created_at")(require_aware_datetime)
