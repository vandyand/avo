"""Structured native-agent turn contracts."""

from typing import Any, Literal

from pydantic import Field, model_validator

from avo_correlate.contracts.base import NonEmptyString, Sha256Digest, StrictModel
from avo_correlate.contracts.budgets import UsageRecord


class AgentObservation(StrictModel):
    schema_version: Literal[1] = 1
    tool_id: NonEmptyString
    outcome: Literal["succeeded", "failed", "policy_blocked"]
    result_digest: Sha256Digest
    summary: NonEmptyString


class AgentTurn(StrictModel):
    schema_version: Literal[1] = 1
    action: Literal["tool", "propose", "stop"]
    rationale: NonEmptyString
    tool_id: str | None = None
    arguments: dict[str, Any] | None = None
    proposed_workspace_digest: Sha256Digest | None = None
    proposed_patch_digest: Sha256Digest | None = None
    stop_reason: Literal["exhausted", "policy_blocked", "cancelled", "failed"] | None = None
    usage: UsageRecord = Field(default_factory=UsageRecord.zero)

    @model_validator(mode="after")
    def validate_action_fields(self) -> "AgentTurn":
        if self.action == "tool" and (not self.tool_id or self.arguments is None):
            raise ValueError("tool action requires tool_id and arguments")
        if self.action == "propose" and self.proposed_workspace_digest is None:
            raise ValueError("proposal requires a workspace digest")
        if self.action == "stop" and self.stop_reason is None:
            raise ValueError("stop action requires a reason")
        return self


class AgentContext(StrictModel):
    schema_version: Literal[1] = 1
    run_id: NonEmptyString
    session_id: NonEmptyString
    champion_workspace_digest: Sha256Digest
    initial_context_digest: Sha256Digest
    observations: list[AgentObservation]
    turn_number: int = Field(ge=1)
    turns_remaining: int = Field(ge=0)
