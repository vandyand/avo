"""Immutable, signed human-review records."""

from datetime import datetime
from typing import Literal

from pydantic import Field, field_validator

from avo_correlate.contracts.base import (
    ActorRef,
    NonEmptyString,
    Sha256Digest,
    StrictModel,
    require_aware_datetime,
)


class ReviewRequest(StrictModel):
    schema_version: Literal[1] = 1
    review_id: NonEmptyString
    run_id: NonEmptyString
    candidate_id: NonEmptyString
    action: NonEmptyString
    proposer_id: NonEmptyString
    eligible_roles: list[NonEmptyString] = Field(min_length=1)
    approvals_required: int = Field(ge=1, le=2)
    proposer_may_review: bool = False
    required_evidence_digests: list[Sha256Digest] = Field(default_factory=list)
    expires_at: datetime
    created_at: datetime

    _aware_expires = field_validator("expires_at")(require_aware_datetime)
    _aware_created = field_validator("created_at")(require_aware_datetime)


class ReviewDecision(StrictModel):
    schema_version: Literal[1] = 1
    decision_id: NonEmptyString
    review_id: NonEmptyString
    reviewer: ActorRef
    reviewer_role: NonEmptyString
    outcome: Literal["approve", "reject"]
    evidence_digests: list[Sha256Digest] = Field(default_factory=list)
    rationale: NonEmptyString
    signature_digest: Sha256Digest
    decided_at: datetime

    _aware_decided = field_validator("decided_at")(require_aware_datetime)


class ReviewStatus(StrictModel):
    schema_version: Literal[1] = 1
    review_id: NonEmptyString
    state: Literal["pending", "approved", "rejected", "expired"]
    approvals: int = Field(ge=0)
    approvals_required: int = Field(ge=1, le=2)
