"""Coding-agent runtime, event, economics, and reconciliation contracts."""

from datetime import datetime
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from avo_correlate.contracts.base import (
    NonEmptyString,
    NonNegativeInt,
    PositiveInt,
    Sha256Digest,
    StrictModel,
    require_aware_datetime,
)
from avo_correlate.contracts.operations import DoctorCheck
from avo_correlate.contracts.plugins import SignedPluginManifest


def _require_aware_optional(value: datetime | None) -> datetime | None:
    return None if value is None else require_aware_datetime(value)


class HarnessRuntimeProfile(StrictModel):
    schema_version: Literal[1] = 1
    profile_id: NonEmptyString
    plugin: SignedPluginManifest
    transport: Literal["sdk", "subprocess", "http"]
    requested_model: NonEmptyString
    authentication_class: Literal["subscription", "api_key", "none"]
    credential_profile_ref: NonEmptyString | None = None
    permission_profile_digest: Sha256Digest
    development_evaluator_id: NonEmptyString
    max_wall_time_seconds: PositiveInt
    max_turns: PositiveInt
    completion_schema_digest: Sha256Digest
    price_table_digest: Sha256Digest | None = None
    configuration: dict[str, Any] = Field(default_factory=dict)


class RuntimeCapabilityReport(StrictModel):
    schema_version: Literal[1] = 1
    profile_digest: Sha256Digest
    compatible: bool
    checks: list[DoctorCheck] = Field(min_length=1)


class RuntimeSessionRef(StrictModel):
    schema_version: Literal[1] = 1
    adapter_id: NonEmptyString
    native_session_id: NonEmptyString
    native_operation_id: NonEmptyString | None = None
    invocation_id: NonEmptyString | None = None
    storage_class: Literal["memory", "local", "provider"]
    checkpoint: NonNegativeInt | NonEmptyString | None = None


class RuntimeEvent(StrictModel):
    schema_version: Literal[1] = 1
    invocation_id: NonEmptyString
    sequence: PositiveInt
    event_type: Literal[
        "session_started",
        "message",
        "tool_started",
        "tool_completed",
        "usage",
        "checkpoint",
        "completion",
        "error",
    ]
    provider_event_type: NonEmptyString | None = None
    payload_digest: Sha256Digest
    usage_delta: dict[str, NonNegativeInt] = Field(default_factory=dict)
    occurred_at: datetime

    _aware_occurred = field_validator("occurred_at")(require_aware_datetime)


class AgentCompletion(StrictModel):
    schema_version: Literal[1] = 1
    outcome: Literal["proposal", "stop"]
    rationale: NonEmptyString
    claimed_tests: list[NonEmptyString] = Field(default_factory=list)


class RuntimeInspection(StrictModel):
    """Provider observation used to make retry versus reconciliation explicit."""

    schema_version: Literal[1] = 1
    state: Literal[
        "not_started",
        "running",
        "completed",
        "interrupted",
        "missing",
        "unknown",
    ]
    session: RuntimeSessionRef
    completion: AgentCompletion | None = None
    evidence_digests: list[Sha256Digest] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_completion(self) -> "RuntimeInspection":
        if self.completion is not None and self.state != "completed":
            raise ValueError("only completed runtime inspection carries a completion")
        return self


class EconomicUsageRecord(StrictModel):
    schema_version: Literal[1] = 1
    billing_mode: Literal["metered", "subscription", "local", "unknown"]
    charged_cost_microusd: NonNegativeInt | None = None
    provider_equivalent_cost_microusd: NonNegativeInt | None = None
    counterfactual_cost_microusd: NonNegativeInt | None = None
    cost_source: Literal["provider", "price_table", "estimate", "none"]
    price_table_digest: Sha256Digest | None = None
    token_details: dict[str, NonNegativeInt] = Field(default_factory=dict)
    quota_details: dict[str, NonNegativeInt] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_price_source(self) -> "EconomicUsageRecord":
        if self.cost_source == "price_table" and self.price_table_digest is None:
            raise ValueError("price_table cost source requires price_table_digest")
        if self.billing_mode == "metered" and self.charged_cost_microusd is None:
            raise ValueError("metered billing requires charged cost")
        return self


class HarnessInvocationRecord(StrictModel):
    schema_version: Literal[1] = 1
    invocation_id: NonEmptyString
    activity_id: NonEmptyString
    run_id: NonEmptyString
    session_id: NonEmptyString | None = None
    profile_digest: Sha256Digest
    runtime_id: NonEmptyString
    state: Literal["started", "running", "completed", "failed", "reconciliation_required"]
    adapter_version: NonEmptyString
    runtime_version: NonEmptyString
    requested_model: NonEmptyString
    resolved_model: NonEmptyString | None = None
    runtime_session: RuntimeSessionRef | None = None
    workspace_before_digest: Sha256Digest
    workspace_after_digest: Sha256Digest | None = None
    event_stream_artifact_digest: Sha256Digest | None = None
    completion: AgentCompletion | None = None
    usage: dict[str, NonNegativeInt] = Field(default_factory=dict)
    economics: EconomicUsageRecord
    error_class: NonEmptyString | None = None
    started_at: datetime
    completed_at: datetime | None = None

    _aware_started = field_validator("started_at")(require_aware_datetime)
    _aware_completed = field_validator("completed_at")(_require_aware_optional)


class ReconciliationCaseRecord(StrictModel):
    schema_version: Literal[1] = 1
    reconciliation_id: NonEmptyString
    run_id: NonEmptyString
    activity_id: NonEmptyString
    session_id: NonEmptyString | None = None
    reason: NonEmptyString
    evidence_digests: list[Sha256Digest] = Field(default_factory=list)
    budget_reservation_id: NonEmptyString | None = None
    state: Literal["open", "resolved"]
    resolution: Literal["retry", "accept_result", "cancel", "fail"] | None = None
    resolution_note: NonEmptyString | None = None
    opened_at: datetime
    resolved_at: datetime | None = None

    _aware_opened = field_validator("opened_at")(require_aware_datetime)
    _aware_resolved = field_validator("resolved_at")(_require_aware_optional)

    @model_validator(mode="after")
    def validate_resolution(self) -> "ReconciliationCaseRecord":
        if self.state == "open" and any(
            value is not None for value in (self.resolution, self.resolution_note, self.resolved_at)
        ):
            raise ValueError("open reconciliation cannot have resolution fields")
        if self.state == "resolved" and (self.resolution is None or self.resolved_at is None):
            raise ValueError("resolved reconciliation requires resolution and timestamp")
        return self
