"""Immutable records used by the dry-run promotion controller."""

import re
from typing import Literal

from pydantic import Field, StrictBool, field_validator, model_validator

from avo_correlate.contracts.base import ArtifactRef, NonEmptyString, Sha256Digest, StrictModel
from avo_correlate.contracts.promotion_policy import (
    GateAttestation,
    PromotionConfig,
    PromotionDecision,
    PromotionRequest,
    ReviewerAttestation,
    RollbackAttestation,
    is_valid_promotion_path,
    path_manifest_digest,
)

_GIT_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


def _sorted_paths(paths: list[str]) -> list[str]:
    if not paths or any(not is_valid_promotion_path(path) for path in paths):
        raise ValueError("changed paths must be normalized relative paths")
    folded = [path.casefold() for path in paths]
    if len(folded) != len(set(folded)):
        raise ValueError("changed paths must not contain case or Unicode collisions")
    expected = sorted(paths, key=lambda path: (path.casefold(), path))
    if paths != expected:
        raise ValueError("changed paths must be sorted")
    return paths


class GitRefSnapshot(StrictModel):
    """The trusted Git state against which a dry-run was evaluated."""

    repository_digest: Sha256Digest
    target_ref: NonEmptyString
    commit: str
    tree: str
    source_tree_digest: Sha256Digest
    protection_evidence_digest: Sha256Digest

    @field_validator("commit", "tree")
    @classmethod
    def git_object_id(cls, value: str) -> str:
        if not _GIT_OBJECT.fullmatch(value):
            raise ValueError("Git object IDs must be lowercase 40- or 64-hex values")
        return value


class WorkspaceComparison(StrictModel):
    target_ref: NonEmptyString
    base_digest: Sha256Digest
    candidate_digest: Sha256Digest
    changed_paths: list[NonEmptyString] = Field(min_length=1)

    @field_validator("changed_paths")
    @classmethod
    def normalized_sorted_paths(cls, paths: list[str]) -> list[str]:
        return _sorted_paths(paths)


class PromotionControllerConfig(StrictModel):
    controller_identity: NonEmptyString
    controller_version: NonEmptyString
    base_issuer_id: NonEmptyString
    path_issuer_id: NonEmptyString
    policy: PromotionConfig

    @model_validator(mode="after")
    def issuers_are_trusted(self) -> "PromotionControllerConfig":
        if self.base_issuer_id not in self.policy.trusted_base_issuers:
            raise ValueError("base issuer is not trusted by the policy")
        if self.path_issuer_id not in self.policy.trusted_path_issuers:
            raise ValueError("path issuer is not trusted by the policy")
        return self


class PromotionDryRunInput(StrictModel):
    candidate_id: NonEmptyString
    proposer_id: NonEmptyString
    candidate_digest: Sha256Digest
    gate_attestations: list[GateAttestation] = Field(default_factory=list[GateAttestation])
    reviewer_attestations: list[ReviewerAttestation] = Field(
        default_factory=list[ReviewerAttestation]
    )
    rollback_attestation: RollbackAttestation | None = None
    exception_requested: StrictBool = False
    source_provenance_digest: Sha256Digest
    evidence_digests: list[Sha256Digest] = Field(min_length=1)

    @field_validator("evidence_digests")
    @classmethod
    def sorted_unique_evidence(cls, values: list[str]) -> list[str]:
        if values != sorted(set(values)):
            raise ValueError("evidence digests must be sorted and unique")
        return values


class PromotionProvenanceBinding(StrictModel):
    candidate_digest: Sha256Digest
    base_digest: Sha256Digest
    source_provenance_digest: Sha256Digest
    request_digest: Sha256Digest
    controller_config_digest: Sha256Digest
    decision_digest: Sha256Digest
    path_manifest_digest: Sha256Digest
    evidence_manifest_digest: Sha256Digest
    verified: StrictBool


class PromotionBundle(StrictModel):
    schema_version: Literal[1] = 1
    format: Literal["avo-promotion-bundle-v1"] = "avo-promotion-bundle-v1"
    snapshot: GitRefSnapshot
    comparison: WorkspaceComparison
    request: PromotionRequest
    request_digest: Sha256Digest
    controller_config: PromotionControllerConfig
    controller_config_digest: Sha256Digest
    decision: PromotionDecision
    decision_digest: Sha256Digest
    provenance: PromotionProvenanceBinding
    evidence_digests: list[Sha256Digest] = Field(min_length=1)

    @field_validator("evidence_digests")
    @classmethod
    def sorted_unique_evidence(cls, values: list[str]) -> list[str]:
        if values != sorted(set(values)):
            raise ValueError("evidence digests must be sorted and unique")
        return values

    @model_validator(mode="after")
    def linked_digests_match(self) -> "PromotionBundle":
        if self.request.candidate_digest != self.comparison.candidate_digest:
            raise ValueError("request and comparison candidate digests differ")
        if self.request.base_digest != self.comparison.base_digest:
            raise ValueError("request and comparison base digests differ")
        if self.request.changed_paths != self.comparison.changed_paths:
            raise ValueError("request and comparison paths differ")
        if self.comparison.target_ref != self.snapshot.target_ref:
            raise ValueError("comparison and snapshot refs differ")
        if self.comparison.base_digest != self.snapshot.source_tree_digest:
            raise ValueError("comparison is not bound to the snapshot source tree")
        if self.provenance.candidate_digest != self.request.candidate_digest:
            raise ValueError("provenance candidate binding differs")
        if self.provenance.base_digest != self.request.base_digest:
            raise ValueError("provenance base binding differs")
        if self.provenance.request_digest != self.request_digest:
            raise ValueError("provenance request binding differs")
        if self.provenance.controller_config_digest != self.controller_config_digest:
            raise ValueError("provenance controller-config binding differs")
        if self.provenance.decision_digest != self.decision_digest:
            raise ValueError("provenance decision binding differs")
        if (
            self.provenance.path_manifest_digest
            != self.request.path_manifest_attestation.path_manifest_digest
        ):
            raise ValueError("provenance path-manifest binding differs")
        if self.request.path_manifest_attestation.path_manifest_digest != path_manifest_digest(
            self.request.changed_paths
        ):
            raise ValueError("path manifest digest does not match changed paths")
        return self


class PromotionDryRunResult(StrictModel):
    schema_version: Literal[1] = 1
    bundle_digest: Sha256Digest
    bundle: PromotionBundle
    artifact: ArtifactRef


class PromotionReplayReport(StrictModel):
    schema_version: Literal[1] = 1
    bundle_digest: Sha256Digest
    outcome: Literal["would_apply", "not_applicable", "stale_base", "invalid_bundle"]
    checks: list[NonEmptyString] = Field(min_length=1)
    errors: list[NonEmptyString] = Field(default_factory=list)


__all__ = [
    "GitRefSnapshot",
    "PromotionBundle",
    "PromotionControllerConfig",
    "PromotionDryRunInput",
    "PromotionDryRunResult",
    "PromotionProvenanceBinding",
    "PromotionReplayReport",
    "WorkspaceComparison",
]
