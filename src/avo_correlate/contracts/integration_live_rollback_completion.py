"""Hosted-live completion evidence layered over the core rollback package."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import Field, field_validator, model_validator

from avo_correlate.contracts.base import (
    ArtifactRef,
    NonEmptyString,
    Sha256Digest,
    StrictModel,
    require_aware_datetime,
)
from avo_correlate.contracts.integration_live_rollback import LiveRollbackEvidencePackage
from avo_correlate.contracts.integration_promotion import (
    IntegrationProviderObservation,
    IntegrationProviderReconciliation,
)
from avo_correlate.contracts.synthetic_validation import (
    SyntheticValidationCompletionProof,
    SyntheticValidationCreateAuthorization,
    SyntheticValidationOutcome,
    SyntheticValidationPlan,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

_GIT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_VALIDATION_WORKFLOW = ".github/workflows/synthetic-validation.yml"
_TRUSTED_CONTEXTS = frozenset(
    {
        "avo synthetic validate (ubuntu-latest)",
        "avo synthetic validate (windows-latest)",
    }
)
_PROTECTION_CONTEXTS = frozenset({"validate (ubuntu-latest)", "validate (windows-latest)"})


def _empty_check_entries() -> list[LiveRollbackCheckEntry]:
    return []


def _empty_protection_entries() -> list[LiveRollbackProtectionEntry]:
    return []


class LiveRollbackCheckEntry(StrictModel):
    """Reconstructable trusted check identity and successful result."""

    name: NonEmptyString
    app_id: int = Field(gt=0)
    context: NonEmptyString
    sha: str
    status: Literal["completed"]
    conclusion: Literal["success"]
    completed_at: datetime

    _aware_completed_at = field_validator("completed_at")(require_aware_datetime)

    @model_validator(mode="after")
    def validate_entry(self) -> LiveRollbackCheckEntry:
        if _GIT.fullmatch(self.sha) is None:
            raise ValueError("check entry SHA is malformed")
        return self


class LiveRollbackProtectionEntry(StrictModel):
    """Reconstructable required branch-protection context."""

    context: NonEmptyString
    required: Literal[True] = True
    enforced: Literal[True] = True


class LiveRollbackPublicationPlan(StrictModel):
    """Controller-owned candidate publication intent and exact source facts."""

    schema_version: Literal[1] = 1
    publication_id: Sha256Digest
    repository_digest: Sha256Digest
    base_commit: str
    base_tree: str
    candidate_digest: Sha256Digest
    candidate_ref: NonEmptyString
    candidate_commit: str
    candidate_tree: str
    controller_identity: NonEmptyString
    target_ref: NonEmptyString

    @model_validator(mode="after")
    def validate_plan(self) -> LiveRollbackPublicationPlan:
        values = (
            self.base_commit,
            self.base_tree,
            self.candidate_commit,
            self.candidate_tree,
        )
        if any(_GIT.fullmatch(value) is None for value in values):
            raise ValueError("publication plan contains malformed Git identity")
        expected = canonical_digest(self.model_dump(exclude={"publication_id"}, mode="json"))
        if self.publication_id != expected:
            raise ValueError("publication plan digest mismatch")
        return self


class LiveRollbackPublicationOutcome(StrictModel):
    """Provider-independent verified result of candidate publication."""

    schema_version: Literal[1] = 1
    publication_id: Sha256Digest
    repository_digest: Sha256Digest
    base_commit: str
    base_tree: str
    candidate_ref: NonEmptyString
    candidate_commit: str
    candidate_tree: str
    candidate_digest: Sha256Digest
    outcome: Literal["verified", "reconciled"]
    evidence_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_outcome(self) -> LiveRollbackPublicationOutcome:
        if any(
            _GIT.fullmatch(value) is None
            for value in (
                self.base_commit,
                self.base_tree,
                self.candidate_commit,
                self.candidate_tree,
            )
        ):
            raise ValueError("publication outcome contains malformed Git identity")
        return self


class LiveRollbackPublicationEvidence(StrictModel):
    """Content-addressable proof emitted by the candidate publisher."""

    schema_version: Literal[1] = 1
    publication_id: Sha256Digest
    repository_digest: Sha256Digest
    remote: NonEmptyString
    candidate_ref: NonEmptyString
    candidate_commit: str
    candidate_tree: str
    base_commit: str
    base_tree: str
    candidate_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_evidence(self) -> LiveRollbackPublicationEvidence:
        if any(
            _GIT.fullmatch(value) is None
            for value in (
                self.base_commit,
                self.base_tree,
                self.candidate_commit,
                self.candidate_tree,
            )
        ):
            raise ValueError("publication evidence contains malformed Git identity")
        return self


class LiveRollbackManifestEvidence(StrictModel):
    """Source-pinned trusted check or protection manifest."""

    schema_version: Literal[1] = 1
    kind: Literal["trusted-check-manifest", "protection-manifest"]
    repository_digest: Sha256Digest
    target_ref: NonEmptyString
    source_commit: str
    manifest_digest: Sha256Digest
    provider_identity: NonEmptyString
    provider_api_version: NonEmptyString
    entries: list[NonEmptyString] = Field(min_length=1)
    check_entries: list[LiveRollbackCheckEntry] = Field(default_factory=_empty_check_entries)
    protection_entries: list[LiveRollbackProtectionEntry] = Field(
        default_factory=_empty_protection_entries
    )
    freshness_cutoff: datetime
    observed_at: datetime
    source_pinned: Literal[True] = True

    _aware_freshness_cutoff = field_validator("freshness_cutoff")(require_aware_datetime)
    _aware_observed_at = field_validator("observed_at")(require_aware_datetime)

    @model_validator(mode="after")
    def validate_manifest(self) -> LiveRollbackManifestEvidence:
        if _GIT.fullmatch(self.source_commit) is None:
            raise ValueError("manifest source commit is malformed")
        if len(self.entries) != len(set(self.entries)):
            raise ValueError("manifest entries must be unique")
        if self.observed_at < self.freshness_cutoff:
            raise ValueError("manifest observation predates freshness cutoff")
        if self.kind == "trusted-check-manifest":
            if not self.check_entries or self.protection_entries:
                raise ValueError("check manifest must carry typed check entries")
            if len({entry.context for entry in self.check_entries}) != len(self.check_entries):
                raise ValueError("trusted check contexts must be unique")
        elif not self.protection_entries or self.check_entries:
            raise ValueError("protection manifest must carry typed protection entries")
        elif len({entry.context for entry in self.protection_entries}) != len(
            self.protection_entries
        ):
            raise ValueError("protection contexts must be unique")
        return self


class LiveRollbackWorkflowEvidence(StrictModel):
    """Workflow blob hash and repository-variable match proof."""

    schema_version: Literal[1] = 1
    repository_digest: Sha256Digest
    target_ref: NonEmptyString
    source_commit: str
    workflow_path: NonEmptyString
    workflow_blob_digest: Sha256Digest
    repository_variables_digest: Sha256Digest
    repository_variables_match: Literal[True] = True
    provider_identity: NonEmptyString
    provider_api_version: NonEmptyString

    @model_validator(mode="after")
    def validate_workflow(self) -> LiveRollbackWorkflowEvidence:
        if _GIT.fullmatch(self.source_commit) is None:
            raise ValueError("workflow source commit is malformed")
        if self.workflow_path != _VALIDATION_WORKFLOW:
            raise ValueError("workflow evidence must identify synthetic validation")
        if self.workflow_blob_digest != self.repository_variables_digest:
            raise ValueError("workflow and repository-variable evidence differ")
        return self


class LiveRollbackCompletionPackage(StrictModel):
    """Complete hosted-live proof, indexed only after proof-bound cleanup.

    ``core_package`` is the Phase A semantic rollback core.  This outer record
    owns hosted publication/provider/manifest/workflow evidence and the
    synthetic-validation cleanup lifecycle; it is the only record eligible for
    completion indexing after ``cleanup_outcome`` is durably ``cleaned``.
    """

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    core_package: LiveRollbackEvidencePackage
    core_package_artifact: ArtifactRef
    publication_plan: LiveRollbackPublicationPlan
    publication_outcome: LiveRollbackPublicationOutcome
    publication_evidence: LiveRollbackPublicationEvidence
    provider_observation: IntegrationProviderObservation
    provider_reconciliation: IntegrationProviderReconciliation
    check_manifest: LiveRollbackManifestEvidence
    protection_manifest: LiveRollbackManifestEvidence
    workflow_evidence: LiveRollbackWorkflowEvidence
    validation_plan: SyntheticValidationPlan
    validation_authorization: SyntheticValidationCreateAuthorization
    validation_outcome: SyntheticValidationOutcome
    cleanup_proof: SyntheticValidationCompletionProof
    cleanup_outcome: SyntheticValidationOutcome
    artifacts: list[ArtifactRef] = Field(min_length=14, max_length=14)
    main_before_commit: str
    main_after_commit: str
    deploy_performed: Literal[False] = False

    @model_validator(mode="after")
    def validate_package(self) -> LiveRollbackCompletionPackage:
        core = self.core_package
        request = core.request
        if (
            self.operation_id != core.operation_id
            or self.core_package_artifact.digest != canonical_digest(core)
            or self.core_package_artifact.role != "integration-live-rollback-package"
            or self.core_package_artifact.media_type
            != "application/vnd.avo.integration-live-rollback+json"
            or self.core_package_artifact.size_bytes != len(canonical_bytes(core))
            or self.main_before_commit != request.main_before_commit
            or self.main_after_commit != request.main_before_commit
            or self.deploy_performed
            or self.publication_plan.repository_digest != request.repository_digest
            or self.publication_plan.target_ref != request.target_ref
            or self.publication_plan.base_commit != request.failed_integration_head_commit
            or self.publication_plan.base_tree != request.failed_integration_head_tree
            or self.publication_plan.candidate_commit != request.rollback_candidate_commit
            or self.publication_plan.candidate_tree != request.restore_to_tree
            or self.publication_plan.candidate_digest != core.bundle.request.candidate_digest
            or self.publication_plan.candidate_ref != core.promotion_intent.candidate_ref
            or self.publication_plan.controller_identity
            != core.publication.controller_publisher_identity
            or self.publication_plan.base_commit != core.promotion_intent.base_commit
            or self.publication_plan.base_tree != core.promotion_intent.base_tree
            or self.publication_plan.publication_id
            != canonical_digest(
                self.publication_plan.model_dump(exclude={"publication_id"}, mode="json")
            )
            or self.publication_outcome.publication_id != self.publication_plan.publication_id
            or self.publication_outcome.repository_digest != self.publication_plan.repository_digest
            or self.publication_outcome.base_commit != self.publication_plan.base_commit
            or self.publication_outcome.base_tree != self.publication_plan.base_tree
            or self.publication_outcome.candidate_ref != self.publication_plan.candidate_ref
            or self.publication_outcome.candidate_commit != self.publication_plan.candidate_commit
            or self.publication_outcome.candidate_tree != self.publication_plan.candidate_tree
            or self.publication_outcome.candidate_digest != self.publication_plan.candidate_digest
            or self.publication_outcome.evidence_digest
            != self.publication_evidence_digest
        ):
            raise ValueError("live completion publication binding is inconsistent")
        self._validate_publication_evidence()
        self._validate_provider()
        self._validate_validation()
        self._validate_artifacts()
        return self

    @property
    def publication_evidence_digest(self) -> Sha256Digest:
        return canonical_digest(self.publication_evidence)

    def _validate_publication_evidence(self) -> None:
        evidence = self.publication_evidence
        plan = self.publication_plan
        if (
            evidence.publication_id != plan.publication_id
            or evidence.repository_digest != plan.repository_digest
            or evidence.candidate_ref != plan.candidate_ref
            or evidence.candidate_commit != plan.candidate_commit
            or evidence.candidate_tree != plan.candidate_tree
            or evidence.base_commit != plan.base_commit
            or evidence.base_tree != plan.base_tree
            or evidence.candidate_digest != plan.candidate_digest
        ):
            raise ValueError("live completion publication evidence is stale")

    def _validate_provider(self) -> None:
        observation = self.provider_observation
        reconciliation = self.provider_reconciliation
        request = self.core_package.request
        receipt = self.core_package.promotion_receipt
        intent = self.core_package.promotion_intent
        lease = self.core_package.promotion_lease_evidence
        mutation = self.core_package.promotion_mutation_authorization
        if (
            observation.repository_digest != request.repository_digest
            or observation.base_ref != request.target_ref
            or observation.base_commit != request.failed_integration_head_commit
            or observation.base_tree != request.failed_integration_head_tree
            or observation.head_commit != request.rollback_candidate_commit
            or observation.pull_request_number != intent.pull_request_number
            or observation.pull_request_url != intent.pull_request_url
            or observation.head_ref != intent.candidate_ref
            or observation.candidate_tree != request.restore_to_tree
            or observation.synthetic_merge_tree != request.restore_to_tree
            or observation.synthetic_merge_commit
            != self.core_package.promotion_intent.synthetic_merge_commit
            or observation.synthetic_merge_tree
            != self.core_package.promotion_intent.synthetic_merge_tree
            or reconciliation.repository_digest != request.repository_digest
            or reconciliation.pull_request_number != intent.pull_request_number
            or reconciliation.pull_request_url != intent.pull_request_url
            or reconciliation.provider_identity != intent.provider_identity
            or reconciliation.provider_api_version != intent.provider_api_version
            or reconciliation.target_ref != request.target_ref
            or reconciliation.protection_evidence_digest
            != observation.protection_evidence_digest
            or reconciliation.target_head_commit != receipt.applied_result_commit
            or reconciliation.target_head_tree != receipt.applied_result_tree
            or reconciliation.target_parents != [request.failed_integration_head_commit]
            or reconciliation.merge_commit != receipt.applied_result_commit
            or not reconciliation.merged
            or reconciliation.state != "closed"
            or mutation.operation_id != intent.operation_id
            or mutation.intent_digest != canonical_digest(intent)
            or mutation.lease_identity != lease.identity
            or mutation.lease_digest != lease.digest
            or receipt.operation_id != intent.operation_id
            or receipt.intent_digest != canonical_digest(intent)
            or receipt.bundle_digest != intent.bundle_digest
            or receipt.expected_target_ref != intent.target_ref
            or receipt.expected_candidate_commit != intent.candidate_commit
            or receipt.expected_candidate_tree != intent.candidate_tree
            or receipt.merge_method != "squash"
            or self.check_manifest.manifest_digest != intent.check_evidence_manifest_digest
            or self.protection_manifest.manifest_digest != intent.protection_evidence_digest
        ):
            raise ValueError("live completion provider topology is stale")
        if (
            self.check_manifest.manifest_digest != observation.check_evidence_manifest_digest
            or self.protection_manifest.manifest_digest != observation.protection_evidence_digest
            or self.check_manifest.kind != "trusted-check-manifest"
            or self.protection_manifest.kind != "protection-manifest"
        ):
            raise ValueError("live completion trusted manifests are not provider-bound")
        for manifest in (self.check_manifest, self.protection_manifest):
            if (
                manifest.repository_digest != request.repository_digest
                or manifest.target_ref != request.target_ref
                or manifest.provider_identity != observation.provider_identity
                or manifest.provider_api_version != observation.provider_api_version
            ):
                raise ValueError("live completion manifest identity is stale")
        workflow = self.workflow_evidence
        if (
            workflow.repository_digest != request.repository_digest
            or workflow.target_ref != request.target_ref
            or workflow.provider_identity != observation.provider_identity
            or workflow.provider_api_version != observation.provider_api_version
            or workflow.workflow_path != _VALIDATION_WORKFLOW
            or workflow.source_commit != request.failed_integration_head_commit
            or workflow.workflow_blob_digest != workflow.repository_variables_digest
            or not workflow.repository_variables_match
        ):
            raise ValueError("live completion workflow evidence is stale")
        if (
            self.check_manifest.source_commit != observation.synthetic_merge_commit
            or self.protection_manifest.source_commit != request.failed_integration_head_commit
            or not self.check_manifest.check_entries
            or self.check_manifest.protection_entries
            or not self.protection_manifest.protection_entries
            or self.protection_manifest.check_entries
        ):
            raise ValueError("live completion manifests lack exact typed evidence")

    def _validate_validation(self) -> None:
        plan = self.validation_plan
        request = self.core_package.request
        observation = self.provider_observation
        if (
            plan.request.target_repository_digest != request.repository_digest
            or plan.request.target_ref != request.target_ref
            or plan.request.observation.repository_digest != request.repository_digest
            or plan.request.observation.base_ref != request.target_ref
            or plan.request.observation.base_commit != observation.base_commit
            or plan.request.observation.base_tree != observation.base_tree
            or plan.request.observation.head_commit != observation.head_commit
            or plan.request.observation.synthetic_commit != observation.synthetic_merge_commit
            or plan.request.observation.synthetic_tree != observation.synthetic_merge_tree
            or plan.expected_commit != observation.synthetic_merge_commit
            or plan.expected_tree != observation.synthetic_merge_tree
            or self.validation_authorization.operation_id != plan.operation_id
            or self.validation_authorization.plan_digest != plan.plan_digest
            or self.validation_authorization.validation_ref != plan.validation_ref
            or self.validation_authorization.expected_commit != plan.expected_commit
            or self.validation_authorization.expected_tree != plan.expected_tree
            or self.validation_outcome.operation_id != plan.operation_id
            or self.validation_outcome.plan_digest != plan.plan_digest
            or self.validation_outcome.outcome
            not in {"created", "already_present", "reconciled"}
            or self.validation_outcome.observed_commit != plan.expected_commit
            or self.validation_outcome.observed_tree != plan.expected_tree
            or self.cleanup_proof.operation_id != plan.operation_id
            or self.cleanup_proof.plan_digest != plan.plan_digest
            or self.cleanup_proof.completed is not True
            or self.cleanup_proof.completion_digest != canonical_digest(self.core_package)
            or self.cleanup_outcome.operation_id != plan.operation_id
            or self.cleanup_outcome.plan_digest != plan.plan_digest
            or self.cleanup_outcome.outcome != "cleaned"
            or self.cleanup_outcome.validation_ref != plan.validation_ref
            or self.cleanup_outcome.observed_commit is not None
            or self.cleanup_outcome.observed_tree is not None
            or self.cleanup_outcome.error is not None
        ):
            raise ValueError("live completion validation or cleanup binding is inconsistent")
        expected_contexts = set(plan.request.trusted_check_contexts)
        if (
            expected_contexts != set(_TRUSTED_CONTEXTS)
            or {entry.context for entry in self.check_manifest.check_entries}
            != set(_TRUSTED_CONTEXTS)
            or set(self.check_manifest.entries) != set(_TRUSTED_CONTEXTS)
            or any(
                entry.sha != observation.synthetic_merge_commit
                or entry.completed_at < self.check_manifest.freshness_cutoff
                or entry.completed_at > self.check_manifest.observed_at
                for entry in self.check_manifest.check_entries
            )
            or {
                entry.context for entry in self.protection_manifest.protection_entries
            }
            != set(_PROTECTION_CONTEXTS)
            or set(self.protection_manifest.entries) != set(_PROTECTION_CONTEXTS)
            or any(
                entry.app_id != 15368
                or entry.status != "completed"
                or entry.conclusion != "success"
                for entry in self.check_manifest.check_entries
            )
            or any(
                not entry.required or not entry.enforced
                for entry in self.protection_manifest.protection_entries
            )
        ):
            raise ValueError("live completion check or protection evidence is not exact")

    def _validate_artifacts(self) -> None:
        children = {
            "integration-live-rollback-package": (
                self.core_package,
                "application/vnd.avo.integration-live-rollback+json",
            ),
            "candidate-publication-plan": (
                self.publication_plan,
                "application/vnd.avo.candidate-publication+json",
            ),
            "candidate-publication-outcome": (
                self.publication_outcome,
                "application/vnd.avo.candidate-publication+json",
            ),
            "candidate-publication-evidence": (
                self.publication_evidence,
                "application/vnd.avo.candidate-publication+json",
            ),
            "integration-provider-observation": (
                self.provider_observation,
                "application/vnd.avo.integration-provider+json",
            ),
            "integration-provider-reconciliation": (
                self.provider_reconciliation,
                "application/vnd.avo.integration-provider+json",
            ),
            "trusted-check-manifest": (
                self.check_manifest,
                "application/vnd.avo.integration-manifest+json",
            ),
            "protection-manifest": (
                self.protection_manifest,
                "application/vnd.avo.integration-manifest+json",
            ),
            "workflow-evidence": (
                self.workflow_evidence,
                "application/vnd.avo.workflow-evidence+json",
            ),
            "synthetic-validation-plan": (
                self.validation_plan,
                "application/vnd.avo.synthetic-validation+json",
            ),
            "synthetic-validation-authorization": (
                self.validation_authorization,
                "application/vnd.avo.synthetic-validation+json",
            ),
            "synthetic-validation-outcome": (
                self.validation_outcome,
                "application/vnd.avo.synthetic-validation+json",
            ),
            "synthetic-validation-cleanup-proof": (
                self.cleanup_proof,
                "application/vnd.avo.synthetic-validation+json",
            ),
            "synthetic-validation-cleanup": (
                self.cleanup_outcome,
                "application/vnd.avo.synthetic-validation+json",
            ),
        }
        if {item.role for item in self.artifacts} != set(children):
            raise ValueError("live completion artifact roles are incomplete")
        if len({item.digest for item in self.artifacts}) != len(self.artifacts):
            raise ValueError("live completion artifacts must be distinct")
        core_child = next(
            item for item in self.artifacts if item.role == "integration-live-rollback-package"
        )
        if (
            core_child.digest != self.core_package_artifact.digest
            or core_child.media_type != self.core_package_artifact.media_type
            or core_child.size_bytes != self.core_package_artifact.size_bytes
        ):
            raise ValueError("live completion core artifact references differ")
        if any(
            item.digest != canonical_digest(children[item.role][0])
            or item.media_type != children[item.role][1]
            or item.size_bytes != len(canonical_bytes(children[item.role][0]))
            for item in self.artifacts
        ):
            raise ValueError("live completion artifact metadata is incorrect")


__all__ = [
    "LiveRollbackCheckEntry",
    "LiveRollbackCompletionPackage",
    "LiveRollbackManifestEvidence",
    "LiveRollbackProtectionEntry",
    "LiveRollbackPublicationEvidence",
    "LiveRollbackPublicationOutcome",
    "LiveRollbackPublicationPlan",
    "LiveRollbackWorkflowEvidence",
]
