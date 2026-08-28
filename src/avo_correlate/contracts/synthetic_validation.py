"""Contracts for exact-SHA synthetic validation ref publication.

The records in this module are intentionally independent of a particular hosted
Git provider.  A validation ref is an idempotency key and the operation digest
binds every value that can affect the base-controlled validation workflow.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import AliasChoices, Field, field_validator, model_validator

from avo_correlate.contracts.base import NonEmptyString, Sha256Digest, StrictModel
from avo_correlate.domain.canonical import canonical_digest

_GIT_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_BAD_REF = re.compile(r"[\x00-\x20~^:?*\\\[]")
_VALIDATION_PREFIX = "refs/heads/avo/validation/"


def _git_object(value: str) -> str:
    if not _GIT_OBJECT.fullmatch(value):
        raise ValueError("Git object IDs must be lowercase 40- or 64-hex values")
    return value


def _ref(value: str, *, integration_only: bool = False) -> str:
    if (
        not value
        or value.startswith("-")
        or value.startswith("/")
        or value.endswith(("/", "."))
        or ".." in value
        or "@{" in value
        or _BAD_REF.search(value)
    ):
        raise ValueError("malformed Git ref")
    if integration_only and value != "refs/heads/integration":
        raise ValueError("synthetic validation may target only integration refs")
    lowered = value.casefold()
    if lowered.rsplit("/", 1)[-1] in {"main", "master"} or any(
        term in lowered for term in ("production", "deploy")
    ):
        raise ValueError("synthetic validation cannot target main or deployment refs")
    return value


def validation_ref_for(operation_id: str) -> str:
    """Return the normalized, deterministic remote ref for an operation."""
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", operation_id):
        raise ValueError("operation_id must be a SHA-256 digest")
    return f"{_VALIDATION_PREFIX}{operation_id[7:]}"


class SyntheticValidationObservation(StrictModel):
    """The exact current PR and synthetic merge observation being validated."""

    schema_version: Literal[1] = 1
    repository_digest: Sha256Digest
    base_ref: NonEmptyString
    base_commit: str
    base_tree: str
    head_ref: NonEmptyString
    head_commit: str
    head_tree: str
    synthetic_commit: str = Field(
        validation_alias=AliasChoices("synthetic_commit", "synthetic_sha", "synthetic_merge_commit")
    )
    synthetic_tree: str = Field(
        validation_alias=AliasChoices("synthetic_tree", "synthetic_merge_tree")
    )

    @field_validator(
        "base_commit",
        "base_tree",
        "head_commit",
        "head_tree",
        "synthetic_commit",
        "synthetic_tree",
    )
    @classmethod
    def _objects(cls, value: str) -> str:
        return _git_object(value)

    @model_validator(mode="after")
    def _validate_refs(self) -> SyntheticValidationObservation:
        _ref(self.base_ref, integration_only=True)
        _ref(self.head_ref)
        if self.base_ref.casefold() == self.head_ref.casefold():
            raise ValueError("base and head refs must differ")
        return self

    @property
    def synthetic_sha(self) -> str:
        return self.synthetic_commit

    @property
    def synthetic_merge_commit(self) -> str:
        return self.synthetic_commit

    @property
    def synthetic_merge_tree(self) -> str:
        return self.synthetic_tree


class SyntheticValidationRequest(StrictModel):
    """Immutable request including target identity and trusted check contexts."""

    schema_version: Literal[1] = 1
    observation: SyntheticValidationObservation
    target_repository_digest: Sha256Digest
    target_ref: NonEmptyString
    target_identity: NonEmptyString
    trusted_check_contexts: list[NonEmptyString] = Field(min_length=1)
    provider_identity: NonEmptyString = "synthetic-validation-provider"
    provider_api_version: NonEmptyString = "1"

    @field_validator("target_ref")
    @classmethod
    def _target_ref(cls, value: str) -> str:
        return _ref(value, integration_only=True)

    @field_validator("trusted_check_contexts")
    @classmethod
    def _contexts(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("trusted check contexts must be unique")
        return sorted(values)

    @model_validator(mode="after")
    def _bindings(self) -> SyntheticValidationRequest:
        if self.target_repository_digest != self.observation.repository_digest:
            raise ValueError("target repository differs from observed repository")
        if self.target_ref.casefold() != self.observation.base_ref.casefold():
            raise ValueError("target ref differs from the observed PR base ref")
        return self


def synthetic_validation_operation_id(request: SyntheticValidationRequest) -> Sha256Digest:
    """Digest the complete request identity, excluding no workflow input."""
    return canonical_digest(request)


class SyntheticValidationPlan(StrictModel):
    """Durable immutable intent written before touching the remote ref."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    request: SyntheticValidationRequest
    validation_ref: NonEmptyString
    expected_commit: str
    expected_tree: str

    @model_validator(mode="after")
    def _validate_plan(self) -> SyntheticValidationPlan:
        expected = synthetic_validation_operation_id(self.request)
        if self.operation_id != expected:
            raise ValueError("synthetic validation operation ID mismatch")
        if self.validation_ref != validation_ref_for(self.operation_id):
            raise ValueError("synthetic validation ref is not deterministic")
        if self.expected_commit != self.request.observation.synthetic_commit:
            raise ValueError("expected commit differs from observation")
        if self.expected_tree != self.request.observation.synthetic_tree:
            raise ValueError("expected tree differs from observation")
        return self

    @property
    def plan_digest(self) -> Sha256Digest:
        return canonical_digest(self)


class SyntheticValidationOutcome(StrictModel):
    """Durable result of trigger/ref reconciliation or cleanup."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    plan_digest: Sha256Digest
    validation_ref: NonEmptyString
    expected_commit: str
    expected_tree: str
    outcome: Literal[
        "created",
        "already_present",
        "reconciled",
        "reconciliation_required",
        "invalid",
        "quarantined",
        "cleaned",
    ]
    observed_commit: str | None = None
    observed_tree: str | None = None
    error: NonEmptyString | None = None

    @model_validator(mode="after")
    def _validity(self) -> SyntheticValidationOutcome:
        if self.validation_ref != validation_ref_for(self.operation_id):
            raise ValueError("outcome validation ref is not bound to operation")
        _git_object(self.expected_commit)
        _git_object(self.expected_tree)
        if self.observed_commit is not None:
            _git_object(self.observed_commit)
        if self.observed_tree is not None:
            _git_object(self.observed_tree)
        if self.outcome in {"reconciliation_required", "invalid", "quarantined"} and not self.error:
            raise ValueError("terminal or uncertain outcome requires an error")
        if (
            self.outcome in {"created", "already_present", "reconciled", "invalid", "quarantined"}
            and (self.observed_commit is None or self.observed_tree is None)
        ):
            raise ValueError("ref outcome requires both observed commit and tree")
        if self.outcome in {"created", "already_present", "reconciled"} and (
            self.observed_commit != self.expected_commit or self.observed_tree != self.expected_tree
        ):
            raise ValueError("successful ref outcome is not exact")
        if self.outcome == "invalid" and (
            self.observed_commit == self.expected_commit
            and self.observed_tree == self.expected_tree
        ):
            raise ValueError("invalid ref outcome claims an exact ref")
        return self


class SyntheticValidationAttempt(StrictModel):
    """Normalized, immutable uncertainty evidence kept separate from outcomes."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    plan_digest: Sha256Digest
    validation_ref: NonEmptyString
    expected_commit: str
    expected_tree: str
    kind: Literal["create_ambiguous", "read_error"]

    @model_validator(mode="after")
    def _validity(self) -> SyntheticValidationAttempt:
        if self.validation_ref != validation_ref_for(self.operation_id):
            raise ValueError("attempt validation ref is not bound to operation")
        _git_object(self.expected_commit)
        _git_object(self.expected_tree)
        return self


class SyntheticValidationCreateAuthorization(StrictModel):
    """Durable, single-writer authorization recorded immediately before create."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    plan_digest: Sha256Digest
    validation_ref: NonEmptyString
    expected_commit: str
    expected_tree: str

    @model_validator(mode="after")
    def _validity(self) -> SyntheticValidationCreateAuthorization:
        if self.validation_ref != validation_ref_for(self.operation_id):
            raise ValueError("authorization validation ref is not bound to operation")
        _git_object(self.expected_commit)
        _git_object(self.expected_tree)
        return self


class SyntheticValidationCompletionProof(StrictModel):
    """Durable caller proof authorizing deletion of one exact validation ref."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    plan_digest: Sha256Digest
    completion_digest: Sha256Digest = Field(
        validation_alias=AliasChoices("completion_digest", "completion_evidence_digest")
    )
    completed: Literal[True] = True


# Short aliases make the provider-neutral contract convenient for adapters.
ValidationObservation = SyntheticValidationObservation
ValidationRequest = SyntheticValidationRequest
ValidationPlan = SyntheticValidationPlan
ValidationOutcome = SyntheticValidationOutcome
CompletionProof = SyntheticValidationCompletionProof

__all__ = [
    "CompletionProof",
    "SyntheticValidationAttempt",
    "SyntheticValidationCompletionProof",
    "SyntheticValidationCreateAuthorization",
    "SyntheticValidationObservation",
    "SyntheticValidationOutcome",
    "SyntheticValidationPlan",
    "SyntheticValidationRequest",
    "ValidationObservation",
    "ValidationOutcome",
    "ValidationPlan",
    "ValidationRequest",
    "synthetic_validation_operation_id",
    "validation_ref_for",
]
