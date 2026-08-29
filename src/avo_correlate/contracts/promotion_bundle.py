"""Immutable records used by the dry-run promotion controller."""

import re
from collections.abc import Sequence
from typing import Literal, cast

from pydantic import AliasChoices, Field, StrictBool, field_validator, model_validator

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
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

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


class RollbackPromotionBundleAuthorization(StrictModel):
    """Controller-issued authority for one protected integration rollback.

    This record is deliberately separate from ordinary promotion attestations.
    It is created only after the controller has checked the durable canary,
    drill authorization, candidate publication, and the current repository
    topology.  The ID is a content address of every field except itself.
    """

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    canary_operation_id: Sha256Digest
    canary_package_digest: Sha256Digest
    drill_authorization_id: Sha256Digest | None = None
    repository_digest: Sha256Digest
    target_ref: Literal["refs/heads/integration"]
    main_before_commit: str
    failed_integration_head_commit: str
    failed_integration_head_tree: str
    restore_to_commit: str
    restore_to_tree: str
    rollback_candidate_commit: str
    rollback_candidate_tree: str
    rollback_candidate_parent_commit: str
    candidate_digest: Sha256Digest
    source_tree_digest: Sha256Digest
    restore_tree_digest: Sha256Digest
    publication_evidence_digest: Sha256Digest
    issuer_id: NonEmptyString = Field(validation_alias=AliasChoices("issuer_id", "issuer"))
    reason: NonEmptyString
    authorized: StrictBool = True
    authorization_id: Sha256Digest

    @property
    def issuer(self) -> str:
        """Compatibility view for the drill authorization's issuer field."""

        return self.issuer_id

    @field_validator(
        "main_before_commit",
        "failed_integration_head_commit",
        "failed_integration_head_tree",
        "restore_to_commit",
        "restore_to_tree",
        "rollback_candidate_commit",
        "rollback_candidate_tree",
        "rollback_candidate_parent_commit",
    )
    @classmethod
    def git_object_id(cls, value: str) -> str:
        if not _GIT_OBJECT.fullmatch(value):
            raise ValueError("Git object IDs must be lowercase 40- or 64-hex values")
        return value

    @model_validator(mode="after")
    def validate_authorization(self) -> "RollbackPromotionBundleAuthorization":
        if not self.authorized:
            raise ValueError("rollback promotion authorization must be authorized")
        if self.canary_operation_id == self.operation_id:
            raise ValueError("rollback canary operation must differ from rollback operation")
        if self.rollback_candidate_parent_commit != self.failed_integration_head_commit:
            raise ValueError("rollback candidate parent differs from failed integration head")
        if self.rollback_candidate_tree != self.restore_to_tree:
            raise ValueError("rollback candidate tree differs from restore tree")
        if self.restore_tree_digest != self.candidate_digest:
            raise ValueError("restore tree digest differs from candidate digest")
        if self.rollback_candidate_commit in {
            self.failed_integration_head_commit,
            self.restore_to_commit,
        }:
            raise ValueError("rollback candidate must be a new commit distinct from restore anchor")
        expected = canonical_digest(
            self.model_dump(exclude={"authorization_id"}, mode="json")
        )
        if self.authorization_id != expected:
            raise ValueError("rollback promotion authorization digest mismatch")
        return self


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
    # Explicitly separates ordinary promotion evidence (which may include a
    # rollback-availability attestation) from controller-authorized rollback.
    # ``None`` is retained only so legacy payloads can be parsed and rejected
    # deterministically by replay rather than silently reclassified.
    operation_kind: Literal["ordinary_campaign", "authorized_rollback"] | None = None
    rollback_operation_id: Sha256Digest | None = None
    rollback_authorization: RollbackPromotionBundleAuthorization | None = None

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
        authorization = self.rollback_authorization
        if self.operation_kind == "ordinary_campaign" and (
            self.rollback_operation_id is not None
            or authorization is not None
            or "authorized_rollback" in self.decision.reason_codes
        ):
            raise ValueError("ordinary campaign cannot carry rollback authority")
        if self.operation_kind == "authorized_rollback" and (
            authorization is None
            or self.rollback_operation_id != authorization.operation_id
            or "authorized_rollback" not in self.decision.reason_codes
        ):
            raise ValueError("authorized rollback kind is not bound to controller authority")
        if self.operation_kind is None and authorization is not None:
            raise ValueError("rollback authority requires an explicit operation kind")
        if authorization is not None and (
                self.rollback_operation_id != authorization.operation_id
                or authorization.canary_operation_id == authorization.operation_id
                or authorization.repository_digest != self.snapshot.repository_digest
                or authorization.target_ref != self.snapshot.target_ref
                or authorization.failed_integration_head_commit != self.snapshot.commit
                or authorization.failed_integration_head_tree != self.snapshot.tree
                or authorization.source_tree_digest != self.snapshot.source_tree_digest
                or authorization.source_tree_digest != self.request.base_digest
                or authorization.candidate_digest != self.request.candidate_digest
                or authorization.restore_tree_digest != self.request.candidate_digest
                or authorization.publication_evidence_digest
                != self.provenance.source_provenance_digest
                or authorization.authorization_id not in self.evidence_digests
                or authorization.canary_package_digest not in self.evidence_digests
                or authorization.publication_evidence_digest not in self.evidence_digests
                or self.request.gate_attestations
                or self.request.reviewer_attestations
                or self.request.rollback_attestation is not None
                or self.decision.outcome.value != "allow"
                or "authorized_rollback" not in self.decision.reason_codes
        ):
            raise ValueError("rollback authorization is not bound to this bundle")
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


def promotion_policy_payload(config: PromotionControllerConfig) -> dict[str, object]:
    """Return the canonical, order-independent controller-policy payload."""

    payload = cast(dict[str, object], config.model_dump(mode="json"))
    policy = cast(dict[str, object], payload["policy"])
    for key in ("low_gates", "ordinary_gates"):
        policy[key] = sorted(cast(Sequence[str], policy[key]))
    for key in (
        "trusted_base_issuers",
        "trusted_reviewer_issuers",
        "trusted_path_issuers",
        "rollback_issuer_ids",
    ):
        policy[key] = sorted(cast(Sequence[str], policy[key]))
    trusted_gate_issuers = cast(dict[str, list[str]], policy["trusted_gate_issuers"])
    policy["trusted_gate_issuers"] = {
        gate: sorted(issuers) for gate, issuers in trusted_gate_issuers.items()
    }
    return payload


def promotion_bundle_payload(bundle: PromotionBundle) -> dict[str, object]:
    """Return the authoritative canonical payload for a promotion bundle."""

    payload = cast(dict[str, object], bundle.model_dump(mode="json"))
    request = cast(dict[str, object], payload["request"])
    request["gate_attestations"] = sorted(
        cast(list[dict[str, object]], request["gate_attestations"]),
        key=canonical_bytes,
    )
    request["reviewer_attestations"] = sorted(
        cast(list[dict[str, object]], request["reviewer_attestations"]),
        key=canonical_bytes,
    )
    payload["controller_config"] = promotion_policy_payload(bundle.controller_config)
    payload["evidence_digests"] = sorted(cast(list[str], payload["evidence_digests"]))
    if payload.get("rollback_operation_id") is None:
        payload.pop("rollback_operation_id", None)
    if payload.get("rollback_authorization") is None:
        # Keep ordinary v1 bundles byte-for-byte compatible with the pre-
        # authorization shape; the new field is truly optional on the wire.
        payload.pop("rollback_authorization", None)
    return payload


def promotion_bundle_bytes(bundle: PromotionBundle) -> bytes:
    """Return the exact canonical bytes whose digest identifies ``bundle``."""

    return canonical_bytes(promotion_bundle_payload(bundle))


def promotion_bundle_digest(bundle: PromotionBundle) -> Sha256Digest:
    """Return the authoritative content digest for ``bundle``."""

    return canonical_digest(promotion_bundle_payload(bundle))


__all__ = [
    "GitRefSnapshot",
    "PromotionBundle",
    "PromotionControllerConfig",
    "PromotionDryRunInput",
    "PromotionDryRunResult",
    "PromotionProvenanceBinding",
    "PromotionReplayReport",
    "RollbackPromotionBundleAuthorization",
    "WorkspaceComparison",
    "promotion_bundle_bytes",
    "promotion_bundle_digest",
    "promotion_bundle_payload",
    "promotion_policy_payload",
]
