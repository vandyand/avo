"""Deterministic supervisor observations and directives."""

from typing import Any, Literal

from pydantic import Field

from avo_correlate.contracts.base import NonEmptyString, StrictModel

DirectiveName = Literal[
    "continue",
    "reduce_scope",
    "request_more_evidence",
    "revisit_lineage",
    "change_hypothesis",
    "pause",
    "request_review",
    "terminate",
]


class SupervisorObservation(StrictModel):
    schema_version: Literal[1] = 1
    run_id: NonEmptyString
    run_state: NonEmptyString
    sessions_without_admission: int = Field(ge=0)
    repeated_failure_count: int = Field(ge=0)
    quarantine_count: int = Field(ge=0)
    duplicate_patch_count: int = Field(ge=0)
    policy_denial_count: int = Field(ge=0)
    budget_fraction_micros: int = Field(ge=0, le=1_000_000)
    diversity_fraction_micros: int = Field(ge=0, le=1_000_000)


class SupervisorDirective(StrictModel):
    schema_version: Literal[1] = 1
    directive: DirectiveName
    reason_codes: list[NonEmptyString] = Field(min_length=1)
    payload: dict[str, Any] = Field(default_factory=dict)
