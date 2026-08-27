"""Immutable experiment configuration."""

import re
import unicodedata
from typing import Literal

from pydantic import Field, field_validator, model_validator

from avo_correlate.contracts.base import (
    ActorRef,
    NonEmptyString,
    PositiveInt,
    Sha256Digest,
    StrictModel,
    VersionedComponentRef,
)
from avo_correlate.contracts.budgets import BudgetSpec

_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:")


def validate_manifest_path(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value)
    if normalized != value:
        raise ValueError("manifest paths must already be NFC-normalized")
    if not value or "\x00" in value:
        raise ValueError("manifest paths must be non-empty and contain no NUL")
    if "\\" in value or value.startswith("/") or _DRIVE_PREFIX.match(value):
        raise ValueError("manifest paths must be relative POSIX paths")
    if any(segment in {"", ".", ".."} for segment in value.split("/")):
        raise ValueError("manifest paths contain an unsafe segment")
    return value


class WorkspaceSpec(StrictModel):
    schema_version: Literal[1] = 1
    source_uri: NonEmptyString
    source_revision: NonEmptyString
    source_tree_digest: Sha256Digest
    allowed_paths: list[str]
    forbidden_paths: list[str]
    required_paths: list[str]
    max_file_bytes: PositiveInt
    max_tree_bytes: PositiveInt
    submodules: Literal["deny", "pinned_only"] = "deny"
    symlinks: Literal["deny", "internal_only"] = "deny"

    @field_validator("allowed_paths", "forbidden_paths", "required_paths")
    @classmethod
    def validate_paths(cls, values: list[str]) -> list[str]:
        paths = [validate_manifest_path(value) for value in values]
        if len(paths) != len(set(paths)):
            raise ValueError("manifest paths must be unique")
        return paths

    @model_validator(mode="after")
    def validate_sizes(self) -> "WorkspaceSpec":
        if self.max_file_bytes > self.max_tree_bytes:
            raise ValueError("max_file_bytes cannot exceed max_tree_bytes")
        return self


class SearchSpec(StrictModel):
    schema_version: Literal[1] = 1
    method: Literal["single_lineage_agentic"] = "single_lineage_agentic"
    method_version: NonEmptyString
    max_committed_candidates: PositiveInt
    stopping_rules: list[NonEmptyString] = Field(min_length=1)


class HarnessSpec(StrictModel):
    schema_version: Literal[1] = 1
    component: VersionedComponentRef
    model_config_digest: Sha256Digest
    configuration_digest: Sha256Digest


class EvaluatorSpec(StrictModel):
    schema_version: Literal[1] = 1
    component: VersionedComponentRef
    tier: Literal["development", "admission", "audit"]
    profile_digest: Sha256Digest
    execution_image_digest: Sha256Digest


class ReviewPolicy(StrictModel):
    schema_version: Literal[1] = 1
    required: bool = False
    eligible_roles: list[NonEmptyString] = Field(default_factory=list)
    approvals_required: int = Field(default=0, ge=0, le=2)
    proposer_may_review: bool = False
    expires_after_seconds: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def validate_requirement(self) -> "ReviewPolicy":
        if self.required != (self.approvals_required > 0):
            raise ValueError("required and approvals_required must agree")
        return self


class ExperimentSpec(StrictModel):
    schema_version: Literal[1] = 1
    experiment_id: NonEmptyString
    title: NonEmptyString
    objective: NonEmptyString
    success_criteria: list[NonEmptyString] = Field(min_length=1)
    workspace: WorkspaceSpec
    search: SearchSpec
    harness: HarnessSpec
    development_evaluators: list[EvaluatorSpec] = Field(min_length=1)
    admission_evaluators: list[EvaluatorSpec] = Field(min_length=1)
    audit_evaluators: list[EvaluatorSpec] = Field(default_factory=list[EvaluatorSpec])
    budget: BudgetSpec
    sandbox_profile_id: NonEmptyString
    policy_bundle_digest: Sha256Digest
    retention_policy_id: NonEmptyString
    review_policy: ReviewPolicy
    created_by: ActorRef

    @model_validator(mode="after")
    def validate_evaluator_tiers(self) -> "ExperimentSpec":
        groups = (
            (self.development_evaluators, "development"),
            (self.admission_evaluators, "admission"),
            (self.audit_evaluators, "audit"),
        )
        for evaluators, tier in groups:
            if any(evaluator.tier != tier for evaluator in evaluators):
                raise ValueError(f"{tier} evaluator list contains another tier")
        return self
