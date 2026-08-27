"""Session capability and tool invocation records."""

from datetime import datetime
from typing import Any, Literal

from pydantic import Field, field_validator

from avo_correlate.contracts.base import (
    NonEmptyString,
    NonNegativeInt,
    Sha256Digest,
    StrictModel,
    require_aware_datetime,
)
from avo_correlate.contracts.budgets import UsageRecord


class CapabilityClaims(StrictModel):
    schema_version: Literal[1] = 1
    token_id: NonEmptyString
    session_id: NonEmptyString
    actor_id: NonEmptyString
    workspace_digest: Sha256Digest
    tools: list[NonEmptyString] = Field(min_length=1)
    policy_decision_id: NonEmptyString
    expires_at: datetime

    _aware_expires = field_validator("expires_at")(require_aware_datetime)


class ToolInvocationRecord(StrictModel):
    schema_version: Literal[1] = 1
    invocation_id: NonEmptyString
    activity_id: NonEmptyString
    session_id: NonEmptyString
    actor_id: NonEmptyString
    tool_id: NonEmptyString
    tool_version: NonEmptyString
    arguments_digest: Sha256Digest
    policy_decision_id: NonEmptyString
    outcome: Literal["succeeded", "failed", "policy_blocked", "timed_out"]
    output_artifact_digests: list[Sha256Digest]
    input_bytes: NonNegativeInt
    output_bytes: NonNegativeInt
    usage: UsageRecord
    redaction_profile: NonEmptyString
    started_at: datetime
    completed_at: datetime
    error: dict[str, Any] | None = None

    _aware_started = field_validator("started_at")(require_aware_datetime)
    _aware_completed = field_validator("completed_at")(require_aware_datetime)
