"""Model gateway request, response, and immutable invocation provenance."""

from datetime import datetime
from typing import Any, Literal

from pydantic import Field, field_validator

from avo_correlate.contracts.base import (
    NonEmptyString,
    Sha256Digest,
    StrictModel,
    require_aware_datetime,
)
from avo_correlate.contracts.budgets import UsageRecord


class ModelRequest(StrictModel):
    schema_version: Literal[1] = 1
    invocation_id: NonEmptyString
    model: NonEmptyString
    system_artifact_digest: Sha256Digest
    developer_artifact_digest: Sha256Digest
    user_artifact_digest: Sha256Digest
    tool_schema_digest: Sha256Digest
    parameters: dict[str, Any] = Field(default_factory=dict)


class ModelResponse(StrictModel):
    schema_version: Literal[1] = 1
    invocation_id: NonEmptyString
    provider_request_id: str | None = None
    provider_model_revision: str | None = None
    output_artifact_digest: Sha256Digest
    finish_reason: NonEmptyString
    usage: UsageRecord


class ModelInvocationRecord(StrictModel):
    schema_version: Literal[1] = 1
    invocation_id: NonEmptyString
    activity_id: NonEmptyString
    session_id: NonEmptyString
    provider: NonEmptyString
    endpoint_class: NonEmptyString
    requested_model: NonEmptyString
    provider_model_revision: str | None = None
    system_artifact_digest: Sha256Digest
    developer_artifact_digest: Sha256Digest
    user_artifact_digest: Sha256Digest
    tool_schema_digest: Sha256Digest
    parameters: dict[str, Any] = Field(default_factory=dict)
    provider_request_id: str | None = None
    usage: UsageRecord
    provider_usage: dict[str, int] = Field(default_factory=dict)
    retry_parent_invocation_id: str | None = None
    finish_reason: str | None = None
    error_class: str | None = None
    request_artifact_digest: Sha256Digest
    response_artifact_digest: Sha256Digest | None = None
    cost_source: Literal["provider", "price_table", "estimate"]
    started_at: datetime
    completed_at: datetime

    _aware_started = field_validator("started_at")(require_aware_datetime)
    _aware_completed = field_validator("completed_at")(require_aware_datetime)
