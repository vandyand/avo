"""Versioned, content-addressed contracts for the AVO-004.6 drills."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import AliasChoices, Field, StrictBool, StrictInt, model_validator

from avo_correlate.contracts.base import ArtifactRef, NonEmptyString, Sha256Digest, StrictModel
from avo_correlate.domain.canonical import canonical_digest

_GIT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


def _git(value: str) -> str:
    if not _GIT.fullmatch(value):
        raise ValueError("Git object IDs must be lowercase 40- or 64-hex values")
    return value


def _ref(value: str) -> str:
    if value != "refs/heads/integration":
        raise ValueError("v1 drill target must be refs/heads/integration")
    if (
        not value
        or value.startswith(("-", "/"))
        or value.endswith(("/", "."))
        or ".." in value
        or any(c in value for c in " ~^:?*[\\\x00")
    ):
        raise ValueError("malformed Git ref")
    low = value.casefold()
    if low.rsplit("/", 1)[-1] in {"main", "master"} or "deploy" in low or "production" in low:
        raise ValueError("drill must not target main or deployment refs")
    return value


class DrillEvidenceBinding(StrictModel):
    schema_version: Literal[1] = 1
    repository_digest: Sha256Digest
    target_ref: NonEmptyString
    main_before_commit: str
    main_after_commit: str
    target_head_commit: str
    target_head_tree: str
    target_parents: list[str] = Field(min_length=0, max_length=2)
    deploy_performed: Literal[False] = False

    @model_validator(mode="after")
    def validate_binding(self):
        for name in (
            "main_before_commit",
            "main_after_commit",
            "target_head_commit",
            "target_head_tree",
        ):
            _git(getattr(self, name))
        for parent in self.target_parents:
            _git(parent)
        _ref(self.target_ref)
        if self.main_before_commit != self.main_after_commit:
            raise ValueError("main-before and main-after must match")
        return self


class IntegrationDrillSoakObservation(DrillEvidenceBinding):
    observation_id: Sha256Digest
    operation_id: Sha256Digest
    outcome: Literal["passed", "failed", "timeout", "partial_success"]
    evidence_artifacts: list[ArtifactRef] = Field(default_factory=list)  # pyright: ignore[reportUnknownVariableType]
    error: NonEmptyString | None = None

    @model_validator(mode="after")
    def validate_outcome(self):
        if self.outcome != "passed" and not self.error:
            raise ValueError("failed soak observations require an error")
        if self.outcome != "passed" and self.target_parents:
            raise ValueError("non-passed soak observations must not assert target parents")
        if self.observation_id != canonical_digest(
            self.model_dump(exclude={"observation_id"}, mode="json")
        ):
            raise ValueError("soak observation digest mismatch")
        return self


class IntegrationDrillRollbackAuthorization(DrillEvidenceBinding):
    operation_id: Sha256Digest
    authorization_id: Sha256Digest
    failed_integration_head_commit: str
    failed_integration_head_tree: str
    restore_to_commit: str
    restore_to_tree: str
    rollback_candidate_commit: str = Field(
        validation_alias=AliasChoices("rollback_candidate_commit", "candidate_commit")
    )
    rollback_candidate_parent_commit: str = Field(
        validation_alias=AliasChoices(
            "rollback_candidate_parent_commit", "candidate_parent_commit"
        )
    )
    issuer: NonEmptyString
    reason: NonEmptyString
    authorized: StrictBool = True

    @model_validator(mode="after")
    def validate_authorization(self):
        for value in (
            self.failed_integration_head_commit,
            self.failed_integration_head_tree,
            self.restore_to_commit,
            self.restore_to_tree,
            self.rollback_candidate_commit,
            self.rollback_candidate_parent_commit,
        ):
            _git(value)
        if not self.authorized:
            raise ValueError("rollback authorization must be authorized")
        if (
            self.target_head_commit != self.failed_integration_head_commit
            or self.target_head_tree != self.failed_integration_head_tree
        ):
            raise ValueError("rollback authorization failed topology is not target-bound")
        if self.rollback_candidate_parent_commit != self.failed_integration_head_commit:
            raise ValueError("rollback candidate parent differs from failed integration head")
        if self.rollback_candidate_commit in {
            self.failed_integration_head_commit,
            self.restore_to_commit,
        }:
            raise ValueError("rollback candidate must be a new commit distinct from restore anchor")
        return self


class IntegrationDrillRollbackIntent(DrillEvidenceBinding):
    operation_id: Sha256Digest
    promotion_operation_id: Sha256Digest
    intent_digest: Sha256Digest
    authorization_id: Sha256Digest
    attester_identity: NonEmptyString
    authorized: StrictBool
    reason: NonEmptyString
    failed_integration_head_commit: str
    failed_integration_head_tree: str
    restore_to_commit: str
    restore_to_tree: str
    rollback_candidate_commit: str = Field(
        validation_alias=AliasChoices("rollback_candidate_commit", "candidate_commit")
    )
    rollback_candidate_parent_commit: str = Field(
        validation_alias=AliasChoices(
            "rollback_candidate_parent_commit", "candidate_parent_commit"
        )
    )

    @model_validator(mode="after")
    def validate_intent(self):
        for value in (
            self.failed_integration_head_commit,
            self.failed_integration_head_tree,
            self.restore_to_commit,
            self.restore_to_tree,
            self.rollback_candidate_commit,
            self.rollback_candidate_parent_commit,
        ):
            _git(value)
        if not self.authorized:
            raise ValueError("rollback intent must be authorized")
        if (
            self.target_head_commit != self.failed_integration_head_commit
            or self.target_head_tree != self.failed_integration_head_tree
        ):
            raise ValueError("rollback intent failed topology is not target-bound")
        if self.rollback_candidate_parent_commit != self.failed_integration_head_commit:
            raise ValueError("rollback candidate parent differs from failed integration head")
        if self.intent_digest != canonical_digest(
            self.model_dump(exclude={"intent_digest"}, mode="json")
        ):
            raise ValueError("rollback intent digest mismatch")
        return self


class IntegrationDrillRollbackReceipt(DrillEvidenceBinding):
    operation_id: Sha256Digest
    promotion_operation_id: Sha256Digest
    intent_digest: Sha256Digest
    receipt_digest: Sha256Digest
    outcome: Literal[
        "applied",
        "already_applied",
        "rejected",
        "ambiguous",
        "stale_target",
        "reconciliation_required",
    ]
    attester_identity: NonEmptyString
    failed_integration_head_commit: str
    failed_integration_head_tree: str
    restore_to_commit: str
    restore_to_tree: str
    rollback_candidate_commit: str = Field(
        validation_alias=AliasChoices("rollback_candidate_commit", "candidate_commit")
    )
    rollback_candidate_parent_commit: str = Field(
        validation_alias=AliasChoices(
            "rollback_candidate_parent_commit", "candidate_parent_commit"
        )
    )
    result_commit: str | None = None
    result_tree: str | None = None
    error: NonEmptyString | None = None

    @model_validator(mode="after")
    def validate_receipt(self):
        for value in (
            self.failed_integration_head_commit,
            self.failed_integration_head_tree,
            self.restore_to_commit,
            self.restore_to_tree,
            self.rollback_candidate_commit,
            self.rollback_candidate_parent_commit,
        ):
            _git(value)
        if (
            self.target_head_commit != self.failed_integration_head_commit
            and self.outcome not in {"applied", "already_applied"}
        ):
            raise ValueError("rollback receipt failed topology is not target-bound")
        if self.outcome in {"applied", "already_applied"}:
            if not self.result_commit or not self.result_tree:
                raise ValueError("successful rollback requires exact result")
            _git(self.result_commit)
            _git(self.result_tree)
            if self.result_tree != self.restore_to_tree:
                raise ValueError("successful rollback tree differs from authorized restore tree")
            if self.target_head_tree != self.restore_to_tree or self.target_parents != [
                self.failed_integration_head_commit
            ]:
                raise ValueError("successful rollback topology differs from authorization")
            if self.rollback_candidate_parent_commit != self.failed_integration_head_commit:
                raise ValueError("rollback candidate parent differs from failed integration head")
        elif not self.error:
            raise ValueError("non-success rollback requires error")
        if self.receipt_digest != canonical_digest(
            self.model_dump(exclude={"receipt_digest"}, mode="json")
        ):
            raise ValueError("rollback receipt digest mismatch")
        return self


class IntegrationDrillPromotionEvidenceLink(StrictModel):
    """A typed link to one durable child promotion record."""

    schema_version: Literal[1] = 1
    kind: Literal[
        "intent", "lease_evidence", "mutation_authorization", "receipt"
    ]
    operation_id: Sha256Digest
    record_digest: Sha256Digest
    artifact: ArtifactRef

    @model_validator(mode="after")
    def validate_link(self):
        if self.record_digest != self.artifact.digest:
            raise ValueError("promotion evidence link digest differs from artifact")
        expected_role = {
            "intent": "promotion-intent",
            "lease_evidence": "promotion-lease-evidence",
            "mutation_authorization": "promotion-mutation-authorization",
            "receipt": "promotion-receipt",
        }[self.kind]
        if self.artifact.role != expected_role:
            raise ValueError("promotion evidence link role is not trusted")
        if self.artifact.media_type != "application/vnd.avo.integration-promotion+json":
            raise ValueError("promotion evidence link media type is not trusted")
        return self


class IntegrationDrillPromotionEvidenceManifest(StrictModel):
    """Root-journal manifest for reconstructing case-7 promotion evidence."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    promotion_operation_id: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: NonEmptyString
    failed_integration_head_commit: str
    failed_integration_head_tree: str
    restore_to_tree: str
    rollback_candidate_commit: str
    rollback_candidate_parent_commit: str
    result_commit: str
    result_tree: str
    links: list[IntegrationDrillPromotionEvidenceLink] = Field(min_length=4, max_length=4)
    manifest_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_manifest(self):
        for value in (
            self.failed_integration_head_commit,
            self.failed_integration_head_tree,
            self.restore_to_tree,
            self.rollback_candidate_commit,
            self.rollback_candidate_parent_commit,
            self.result_commit,
            self.result_tree,
        ):
            _git(value)
        _ref(self.target_ref)
        expected_kinds = {
            "intent", "lease_evidence", "mutation_authorization", "receipt"
        }
        if {link.kind for link in self.links} != expected_kinds:
            raise ValueError("promotion evidence manifest must contain each child record once")
        if any(link.operation_id != self.promotion_operation_id for link in self.links):
            raise ValueError("promotion evidence link operation differs from manifest")
        if len({link.artifact.digest for link in self.links}) != len(self.links):
            raise ValueError("promotion evidence links must be content-address distinct")
        if self.rollback_candidate_parent_commit != self.failed_integration_head_commit:
            raise ValueError("promotion evidence candidate parent differs from failed head")
        if self.result_tree != self.restore_to_tree:
            raise ValueError("promotion evidence result tree differs from restore tree")
        if self.manifest_digest != canonical_digest(
            self.model_dump(exclude={"manifest_digest"}, mode="json")
        ):
            raise ValueError("promotion evidence manifest digest mismatch")
        return self


class IntegrationDrillCaseResult(DrillEvidenceBinding):
    case_id: StrictInt = Field(ge=1, le=8)
    operation_id: Sha256Digest
    outcome: Literal[
        "passed",
        "failed",
        "rejected",
        "applied",
        "already_applied",
        "reconciliation_required",
    ]
    attester_identity: NonEmptyString
    evidence_artifacts: list[ArtifactRef] = Field(default_factory=list)  # pyright: ignore[reportUnknownVariableType]
    soak_observation: Sha256Digest | None = None
    rollback_intent: Sha256Digest | None = None
    rollback_receipt: Sha256Digest | None = None
    error: NonEmptyString | None = None

    @model_validator(mode="after")
    def validate_case(self):
        if self.outcome in {"passed", "applied", "already_applied"} and not self.evidence_artifacts:
            raise ValueError("successful case requires immutable evidence")
        if self.outcome in {"failed", "rejected", "reconciliation_required"} and not self.error:
            raise ValueError("non-success case requires an error")
        if len({a.digest for a in self.evidence_artifacts}) != len(self.evidence_artifacts):
            raise ValueError("case evidence artifacts must be unique")
        return self


class IntegrationDrillPlan(StrictModel):
    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: NonEmptyString
    main_before_commit: str
    main_before_tree: str
    case_ids: list[StrictInt] = Field(min_length=8, max_length=8)
    evidence_artifacts: list[ArtifactRef] = Field(default_factory=list)  # pyright: ignore[reportUnknownVariableType]
    plan_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_plan(self):
        _ref(self.target_ref)
        _git(self.main_before_commit)
        _git(self.main_before_tree)
        if self.case_ids != list(range(1, 9)):
            raise ValueError("plan must contain cases 1 through 8 exactly once")
        if self.plan_digest != canonical_digest(
            self.model_dump(exclude={"plan_digest"}, mode="json")
        ):
            raise ValueError("plan digest mismatch")
        return self


class IntegrationDrillResult(StrictModel):
    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    plan_digest: Sha256Digest
    cases: list[IntegrationDrillCaseResult] = Field(min_length=8, max_length=8)
    repository_digest: Sha256Digest
    target_ref: NonEmptyString
    main_before_commit: str
    main_after_commit: str
    deploy_performed: Literal[False] = False
    result_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_result(self):
        if sorted(c.case_id for c in self.cases) != list(range(1, 9)):
            raise ValueError("aggregate must contain cases 1 through 8 exactly once")
        if any(
            case.operation_id != self.operation_id
            or case.repository_digest != self.repository_digest
            or case.target_ref != self.target_ref
            or case.main_before_commit != self.main_before_commit
            or case.main_after_commit != self.main_after_commit
            or case.deploy_performed
            for case in self.cases
        ):
            raise ValueError("aggregate case identity differs from root drill identity")
        _git(self.main_before_commit)
        _git(self.main_after_commit)
        if self.main_before_commit != self.main_after_commit:
            raise ValueError("drill changed main")
        if self.result_digest != canonical_digest(
            self.model_dump(exclude={"result_digest"}, mode="json")
        ):
            raise ValueError("result digest mismatch")
        return self


SoakObservation = IntegrationDrillSoakObservation
RollbackAuthorization = IntegrationDrillRollbackAuthorization
RollbackIntent = IntegrationDrillRollbackIntent
RollbackReceipt = IntegrationDrillRollbackReceipt
DrillCaseResult = IntegrationDrillCaseResult
DrillPlan = IntegrationDrillPlan
DrillResult = IntegrationDrillResult

__all__ = [
    "DrillCaseResult",
    "DrillEvidenceBinding",
    "DrillPlan",
    "DrillResult",
    "IntegrationDrillCaseResult",
    "IntegrationDrillPlan",
    "IntegrationDrillResult",
    "IntegrationDrillRollbackAuthorization",
    "IntegrationDrillRollbackIntent",
    "IntegrationDrillRollbackReceipt",
    "IntegrationDrillSoakObservation",
    "RollbackAuthorization",
    "RollbackIntent",
    "RollbackReceipt",
    "SoakObservation",
]
