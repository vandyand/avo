"""Strict, PR-native records for protected integration promotion."""

import re
from datetime import datetime
from typing import Literal

from pydantic import Field, StrictBool, field_validator, model_validator

from avo_correlate.contracts.base import (
    NonEmptyString,
    Sha256Digest,
    StrictModel,
    require_aware_datetime,
)
from avo_correlate.domain.canonical import canonical_digest

_GIT_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_REF_BAD = re.compile(r"[\x00-\x20~^:?*\\\[]")


class IntegrationPromotionPreconditionError(ValueError):
    """A provider precondition failed before the promotion mutation.

    This is intentionally distinct from transport ambiguity: callers must fail
    closed without reconciliation or a receipt because no provider mutation was
    permitted after a precondition failure.
    """


def _git_object(value: str) -> str:
    if not _GIT_OBJECT.fullmatch(value):
        raise ValueError("Git object IDs must be lowercase 40- or 64-hex values")
    return value


def _ref(value: str) -> str:
    if (
        not value
        or value.startswith("-")
        or value.startswith("/")
        or value.endswith(("/", "."))
        or ".." in value
        or "@{" in value
        or _REF_BAD.search(value)
    ):
        raise ValueError("malformed Git ref")
    lowered = value.casefold()
    if lowered.rsplit("/", 1)[-1] in {"main", "master"} or any(
        term in lowered for term in ("production", "deploy")
    ):
        raise ValueError("protected integration contract cannot target main or deployment refs")
    return value


class CandidatePublicationBinding(StrictModel):
    """Trusted proof that the candidate was published from the evaluated source.

    A PR observation is not sufficient provenance: the provider could be showing a
    different head than the controller evaluated.  This record is produced by the
    controller's trusted publication path and is independently verified before any
    provider mutation is allowed.
    """

    schema_version: Literal[1] = 1
    repository_digest: Sha256Digest
    base_commit: str
    base_tree: str
    candidate_digest: Sha256Digest
    candidate_ref: NonEmptyString
    candidate_commit: str
    candidate_tree: str
    controller_publisher_identity: NonEmptyString
    publication_evidence_digest: Sha256Digest
    verified: StrictBool
    changed_paths: list[NonEmptyString] = Field(default_factory=list)

    @field_validator("changed_paths")
    @classmethod
    def sorted_changed_paths(cls, paths: list[str]) -> list[str]:
        if any(
            not value
            or value.startswith(("/", "\\"))
            or ".." in value.split("/")
            for value in paths
        ):
            raise ValueError("changed paths must be normalized relative paths")
        if paths != sorted(paths, key=lambda value: (value.casefold(), value)):
            raise ValueError("changed paths must be sorted")
        if len({value.casefold() for value in paths}) != len(paths):
            raise ValueError("changed paths must be unique")
        return paths

    @model_validator(mode="after")
    def validate_publication(self) -> "CandidatePublicationBinding":
        for name in ("base_commit", "base_tree", "candidate_commit", "candidate_tree"):
            _git_object(getattr(self, name))
        _ref(self.candidate_ref)
        if not self.verified:
            raise ValueError("candidate publication must be verified")
        return self


class PromotionLeaseEvidence(StrictModel):
    """Immutable evidence for the controller lease that fenced a campaign.

    ``digest`` is the digest of the lease payload (the same digest exposed by
    :class:`PromotionLease`).  The surrounding ``ArtifactRef`` addresses this
    complete record, so timestamps and identity remain auditable after the
    ephemeral lease file is released.
    """

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: NonEmptyString
    identity: NonEmptyString
    acquired_at: datetime
    expires_at: datetime
    digest: Sha256Digest

    _aware_acquired_at = field_validator("acquired_at")(require_aware_datetime)
    _aware_expires_at = field_validator("expires_at")(require_aware_datetime)

    @model_validator(mode="after")
    def validate_evidence(self) -> "PromotionLeaseEvidence":
        _ref(self.target_ref)
        if self.expires_at <= self.acquired_at:
            raise ValueError("lease evidence expiry must be after acquisition")
        payload = self.model_dump(mode="json")
        digest = payload.pop("digest")
        if canonical_digest(payload) != digest:
            raise ValueError("lease evidence digest mismatch")
        return self


class PromotionMutationAuthorization(StrictModel):
    """Durable authorization crossing the provider mutation boundary."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    intent_digest: Sha256Digest
    lease_identity: NonEmptyString
    lease_digest: Sha256Digest
    authorized_at: datetime

    @field_validator("authorized_at")
    @classmethod
    def _authorized_time(cls, value: datetime) -> datetime:
        return require_aware_datetime(value)


class IntegrationPromotionIntent(StrictModel):
    """Durable intent written immediately before the provider merge call."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    controller_lease_digest: Sha256Digest
    controller_lease_identity: NonEmptyString
    candidate_ref: NonEmptyString
    target_ref: NonEmptyString
    base_commit: str
    base_tree: str
    candidate_commit: str
    candidate_tree: str
    candidate_repository_digest: Sha256Digest
    candidate_head_ref: NonEmptyString
    candidate_head_commit: str
    candidate_head_tree: str
    target_repository_digest: Sha256Digest
    target_base_ref: NonEmptyString
    target_base_commit: str
    target_base_tree: str
    synthetic_merge_commit: str
    synthetic_merge_tree: str
    bundle_digest: Sha256Digest
    candidate_digest: Sha256Digest
    controller_config_digest: Sha256Digest
    protection_evidence_digest: Sha256Digest
    evidence_manifest_digest: Sha256Digest
    check_evidence_manifest_digest: Sha256Digest
    publication_evidence_digest: Sha256Digest
    pull_request_number: int = Field(gt=0)
    pull_request_url: NonEmptyString
    provider_identity: NonEmptyString
    provider_api_version: NonEmptyString
    merge_method: Literal["squash"]
    # Rollback promotions bind the protected main ref observed immediately
    # before the provider PUT. Ordinary promotions may omit this legacy-safe
    # fence; rollback callers must populate it.
    expected_main_commit: str | None = None
    state: Literal["intent_recorded"] = "intent_recorded"

    @model_validator(mode="after")
    def validate_bindings(self) -> "IntegrationPromotionIntent":
        for name in (
            "base_commit",
            "base_tree",
            "candidate_commit",
            "candidate_tree",
            "candidate_head_commit",
            "candidate_head_tree",
            "target_base_commit",
            "target_base_tree",
            "synthetic_merge_commit",
            "synthetic_merge_tree",
        ):
            _git_object(getattr(self, name))
        _ref(self.candidate_ref)
        _ref(self.target_ref)
        _ref(self.candidate_head_ref)
        _ref(self.target_base_ref)
        if self.candidate_ref == self.target_ref:
            raise ValueError("candidate and target refs must differ")
        if self.candidate_ref.casefold() == self.target_ref.casefold():
            raise ValueError("candidate and target refs must differ case-insensitively")
        if self.base_commit != self.target_base_commit or self.base_tree != self.target_base_tree:
            raise ValueError("base binding differs from target PR base")
        if (
            self.candidate_commit != self.candidate_head_commit
            or self.candidate_tree != self.candidate_head_tree
        ):
            raise ValueError("candidate binding differs from PR head")
        if self.synthetic_merge_tree != self.candidate_tree:
            raise ValueError("synthetic merge tree differs from candidate tree")
        if self.expected_main_commit is not None:
            _git_object(self.expected_main_commit)
        if self.candidate_repository_digest != self.repository_digest:
            raise ValueError("candidate repository binding differs")
        if self.target_repository_digest != self.repository_digest:
            raise ValueError("target repository binding differs")
        if self.candidate_head_ref != self.candidate_ref or self.target_base_ref != self.target_ref:
            raise ValueError("PR base/head ref binding differs")
        if not self.pull_request_url.startswith("https://"):
            raise ValueError("pull request URL must use HTTPS")
        identity = {
            "repository_digest": self.repository_digest,
            "pull_request_number": str(self.pull_request_number),
            "candidate_ref": self.candidate_ref,
            "target_ref": self.target_ref,
            "base_commit": self.base_commit,
            "candidate_commit": self.candidate_commit,
            "candidate_head_commit": self.candidate_head_commit,
            "target_base_commit": self.target_base_commit,
            "synthetic_merge_commit": self.synthetic_merge_commit,
            "bundle_digest": self.bundle_digest,
            "candidate_digest": self.candidate_digest,
            "publication_evidence_digest": self.publication_evidence_digest,
            "provider_identity": self.provider_identity,
            "provider_api_version": self.provider_api_version,
            "merge_method": self.merge_method,
        }
        if self.expected_main_commit is not None:
            identity["expected_main_commit"] = self.expected_main_commit
        expected = canonical_digest(identity)
        if self.operation_id != expected:
            raise ValueError("operation ID does not match deterministic promotion identity")
        return self


class IntegrationPromotionReceipt(StrictModel):
    """Immutable provider observation; soak is intentionally not represented here."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    intent_digest: Sha256Digest
    bundle_digest: Sha256Digest
    expected_target_ref: NonEmptyString
    expected_candidate_commit: str
    expected_candidate_tree: str
    expected_base_commit: str
    expected_protection_evidence_digest: Sha256Digest
    main_protection_evidence_digest: Sha256Digest | None = None
    expected_provider_identity: NonEmptyString
    expected_provider_api_version: NonEmptyString
    merge_method: Literal["squash"]
    expected_main_commit: str | None = None
    applied_result_commit: str | None = None
    applied_result_tree: str | None = None
    applied_result_parent_commit: str | None = None
    outcome: Literal[
        "intent_recorded",
        "applied",
        "already_applied",
        "stale_base",
        "not_applicable",
        "invalid",
        "reconciliation_required",
    ]
    observed_target_ref: NonEmptyString
    observed_base_commit: str
    observed_head_commit: str | None = None
    observed_head_tree: str | None = None
    observed_protection_evidence_digest: Sha256Digest
    observed_provider_identity: NonEmptyString
    observed_provider_api_version: NonEmptyString
    observation_digest: Sha256Digest
    error: NonEmptyString | None = None

    @model_validator(mode="after")
    def validate_observation(self) -> "IntegrationPromotionReceipt":
        _ref(self.observed_target_ref)
        _git_object(self.observed_base_commit)
        _ref(self.expected_target_ref)
        _git_object(self.expected_candidate_commit)
        _git_object(self.expected_candidate_tree)
        _git_object(self.expected_base_commit)
        if self.expected_main_commit is not None:
            _git_object(self.expected_main_commit)
        if self.observed_head_commit is not None:
            _git_object(self.observed_head_commit)
        if self.observed_head_tree is not None:
            _git_object(self.observed_head_tree)
        if self.applied_result_commit is not None:
            _git_object(self.applied_result_commit)
        if self.applied_result_tree is not None:
            _git_object(self.applied_result_tree)
        if self.applied_result_parent_commit is not None:
            _git_object(self.applied_result_parent_commit)
        applied = self.outcome in {"applied", "already_applied"}
        if applied != (
            self.observed_head_commit is not None and self.observed_head_tree is not None
        ):
            raise ValueError("applied outcomes require exact observed head commit and tree")
        if applied and (
            self.observed_target_ref != self.expected_target_ref
            or self.observed_head_tree != self.expected_candidate_tree
            or self.observed_protection_evidence_digest != self.expected_protection_evidence_digest
            or self.observed_provider_identity != self.expected_provider_identity
            or self.observed_provider_api_version != self.expected_provider_api_version
        ):
            raise ValueError("success observation is not bound to the expected protected promotion")
        if applied != (
            self.applied_result_commit is not None
            and self.applied_result_tree is not None
            and self.applied_result_parent_commit is not None
        ):
            raise ValueError("applied outcomes require the provider merge result commit and tree")
        if applied and (
            self.applied_result_commit == self.expected_candidate_commit
            or self.applied_result_tree != self.expected_candidate_tree
            or self.applied_result_parent_commit != self.expected_base_commit
            or self.applied_result_commit != self.observed_head_commit
            or self.applied_result_tree != self.observed_head_tree
        ):
            raise ValueError("merge result, tree, parent, and post-ref observation contradict")
        if self.outcome == "reconciliation_required" and not self.error:
            raise ValueError("reconciliation-required receipt needs an error")
        if self.outcome == "invalid" and not self.error:
            raise ValueError("invalid receipt needs an error")
        return self


class IntegrationProviderObservation(StrictModel):
    """Provider-side PR observation used before requesting a merge."""

    schema_version: Literal[1] = 1
    repository_digest: Sha256Digest
    pull_request_number: int = Field(gt=0)
    pull_request_url: NonEmptyString
    candidate_repository_digest: Sha256Digest
    target_repository_digest: Sha256Digest
    base_ref: NonEmptyString
    base_commit: str
    base_tree: str
    head_ref: NonEmptyString
    head_commit: str
    candidate_tree: str
    synthetic_merge_commit: str
    synthetic_merge_tree: str
    protection_evidence_digest: Sha256Digest
    check_evidence_manifest_digest: Sha256Digest
    provider_identity: NonEmptyString
    provider_api_version: NonEmptyString
    open_state: Literal["open"]
    draft: Literal[False] = False

    @model_validator(mode="after")
    def validate_refs_and_objects(self) -> "IntegrationProviderObservation":
        for value in (
            self.base_commit,
            self.head_commit,
            self.candidate_tree,
            self.base_tree,
            self.synthetic_merge_commit,
            self.synthetic_merge_tree,
        ):
            _git_object(value)
        _ref(self.base_ref)
        _ref(self.head_ref)
        if self.base_ref.casefold() == self.head_ref.casefold():
            raise ValueError("provider base and head refs must differ")
        if self.candidate_repository_digest != self.repository_digest:
            raise ValueError("candidate repository binding differs")
        if self.target_repository_digest != self.repository_digest:
            raise ValueError("target repository binding differs")
        if not self.pull_request_url.startswith("https://"):
            raise ValueError("pull request URL must use HTTPS")
        return self


class IntegrationMergeResult(StrictModel):
    """Provider merge response; ambiguous responses cannot be treated as success."""

    schema_version: Literal[1] = 1
    outcome: Literal["applied", "rejected", "ambiguous"]
    result_commit: str | None = None
    result_tree: str | None = None
    first_parent_commit: str | None = None
    main_protection_evidence_digest: Sha256Digest | None = None
    response_digest: Sha256Digest
    error: NonEmptyString | None = None

    @model_validator(mode="after")
    def validate_result(self) -> "IntegrationMergeResult":
        values = (self.result_commit, self.result_tree, self.first_parent_commit)
        for value in values:
            if value is not None:
                _git_object(value)
        if self.outcome == "applied" and any(value is None for value in values):
            raise ValueError("applied result requires commit, tree, and first parent")
        if self.outcome != "applied" and any(value is not None for value in values):
            raise ValueError("non-applied result cannot claim merge objects")
        if self.outcome in {"rejected", "ambiguous"} and not self.error:
            raise ValueError("rejected or ambiguous result requires an error")
        return self


class IntegrationProviderReconciliation(StrictModel):
    """The single bounded observation used to resolve an ambiguous PR request."""

    schema_version: Literal[1] = 1
    repository_digest: Sha256Digest
    pull_request_number: int = Field(gt=0)
    pull_request_url: NonEmptyString
    provider_identity: NonEmptyString
    provider_api_version: NonEmptyString
    state: Literal["open", "closed"]
    merged: bool
    merge_commit: str | None = None
    target_ref: NonEmptyString
    target_head_commit: str
    target_head_tree: str
    target_first_parent: str
    # The provider must preserve the complete commit-parent topology.
    target_parents: list[str]
    protection_evidence_digest: Sha256Digest
    main_protection_evidence_digest: Sha256Digest | None = None

    @model_validator(mode="after")
    def validate_reconciliation(self) -> "IntegrationProviderReconciliation":
        for value in (self.target_head_commit, self.target_head_tree, self.target_first_parent):
            _git_object(value)
        if self.merge_commit is not None:
            _git_object(self.merge_commit)
        for parent in self.target_parents:
            _git_object(parent)
        if self.target_parents and self.target_parents[0] != self.target_first_parent:
            raise ValueError("target parent topology contradicts first parent")
        if self.merged and self.target_parents != [self.target_first_parent]:
            raise ValueError("merged target must have exactly one parent")
        _ref(self.target_ref)
        if not self.pull_request_url.startswith("https://"):
            raise ValueError("pull request URL must use HTTPS")
        if self.merged != (self.merge_commit is not None):
            raise ValueError("merged state and merge commit contradict")
        if self.merged and self.state != "closed":
            raise ValueError("merged pull request must be closed")
        if not self.merged and self.state != "open":
            raise ValueError("unmerged reconciliation must remain open")
        return self


class IntegrationPromotionReport(StrictModel):
    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    outcome: Literal[
        "ready",
        "intent_recorded",
        "applied",
        "already_applied",
        "stale_base",
        "not_applicable",
        "invalid",
        "reconciliation_required",
    ]
    intent_digest: Sha256Digest | None = None
    receipt_digest: Sha256Digest | None = None
    checks: list[NonEmptyString] = Field(min_length=1)
    errors: list[NonEmptyString] = Field(default_factory=list)


def integration_operation_id(**identity: str) -> Sha256Digest:
    """Compute the stable operation identity from explicitly supplied fields."""
    return canonical_digest(identity)


__all__ = [
    "CandidatePublicationBinding",
    "IntegrationMergeResult",
    "IntegrationPromotionIntent",
    "IntegrationPromotionPreconditionError",
    "IntegrationPromotionReceipt",
    "IntegrationPromotionReport",
    "IntegrationProviderObservation",
    "IntegrationProviderReconciliation",
    "PromotionLeaseEvidence",
    "PromotionMutationAuthorization",
    "integration_operation_id",
]
