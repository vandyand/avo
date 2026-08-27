"""Policy requests, obligations, and decisions."""

from datetime import datetime
from typing import Any, Literal

from pydantic import Field, field_validator

from avo_correlate.contracts.base import (
    NonEmptyString,
    Sha256Digest,
    StrictModel,
    require_aware_datetime,
)


class PolicyObligation(StrictModel):
    schema_version: Literal[1] = 1
    obligation_type: NonEmptyString
    parameters: dict[str, Any] = Field(default_factory=dict)


class PolicyRequest(StrictModel):
    schema_version: Literal[1] = 1
    action: NonEmptyString
    resource: NonEmptyString
    actor_id: NonEmptyString
    attributes: dict[str, Any] = Field(default_factory=dict)


class PolicyDecision(StrictModel):
    schema_version: Literal[1] = 1
    decision_id: NonEmptyString
    policy_engine_id: NonEmptyString
    policy_bundle_digest: Sha256Digest
    action: NonEmptyString
    resource: NonEmptyString
    input_digest: Sha256Digest
    outcome: Literal["allow", "deny", "review"]
    reason_codes: list[NonEmptyString] = Field(min_length=1)
    obligations: list[PolicyObligation] = Field(default_factory=list[PolicyObligation])
    decided_at: datetime

    _aware_decided = field_validator("decided_at")(require_aware_datetime)
