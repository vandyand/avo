"""Self-contained evidence records for a bounded live integration campaign."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import Field, model_validator

from avo_correlate.contracts.base import ArtifactRef, NonEmptyString, Sha256Digest, StrictModel
from avo_correlate.contracts.integration_promotion import (
    CandidatePublicationBinding,
    IntegrationMergeResult,
    IntegrationPromotionIntent,
    IntegrationPromotionReceipt,
    IntegrationPromotionReport,
    IntegrationProviderObservation,
    IntegrationProviderReconciliation,
    PromotionLeaseEvidence,
)
from avo_correlate.contracts.promotion_bundle import PromotionBundle, promotion_bundle_digest
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest


def _operation_identity(values: dict[str, object]) -> str:
    identity: dict[str, object] = {
        "repository_digest": values["repository_digest"],
        "pull_request_number": str(values["pull_request_number"]),
        "candidate_ref": values["candidate_ref"],
        "target_ref": values["target_ref"],
        "base_commit": values["base_commit"],
        "candidate_commit": values["candidate_commit"],
        "candidate_head_commit": values["candidate_head_commit"],
        "target_base_commit": values["target_base_commit"],
        "synthetic_merge_commit": values["synthetic_merge_commit"],
        "bundle_digest": values["bundle_digest"],
        "candidate_digest": values["candidate_digest"],
        "publication_evidence_digest": values["publication_evidence_digest"],
        "provider_identity": values["provider_identity"],
        "provider_api_version": values["provider_api_version"],
        "merge_method": values["merge_method"],
    }
    expected_main = values.get("expected_main_commit")
    if expected_main is not None:
        identity["expected_main_commit"] = expected_main
    return canonical_digest(identity)


def campaign_marker_digest(intent: IntegrationPromotionIntent) -> Sha256Digest:
    return canonical_digest(
        {
            "operation_id": intent.operation_id,
            "bundle_digest": intent.bundle_digest,
            "repository_digest": intent.repository_digest,
            "pull_request_number": intent.pull_request_number,
            "candidate_ref": intent.candidate_ref,
            "candidate_commit": intent.candidate_commit,
            "target_ref": intent.target_ref,
            "base_commit": intent.base_commit,
        }
    )


class IntegrationIntentTemplate(StrictModel):
    """Lease-independent promotion identity awaiting a fresh controller lease."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    repository_digest: Sha256Digest
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
    expected_main_commit: str | None = None

    @model_validator(mode="after")
    def validate_identity(self) -> IntegrationIntentTemplate:
        if self.operation_id != _operation_identity(self.model_dump(mode="python")):
            raise ValueError("operation ID does not match lease-independent promotion identity")
        # The bound intent owns the detailed Git/ref and cross-object validation.
        IntegrationPromotionIntent.model_validate(
            {
                **self.model_dump(mode="python"),
                "controller_lease_identity": "template-validation-lease",
                "controller_lease_digest": "sha256:" + "0" * 64,
                "state": "intent_recorded",
            }
        )
        return self

    def bind_lease(self, identity: str, digest: str) -> IntegrationPromotionIntent:
        return IntegrationPromotionIntent.model_validate(
            {
                **self.model_dump(mode="python"),
                "controller_lease_identity": identity,
                "controller_lease_digest": digest,
                "state": "intent_recorded",
            }
        )


class CampaignOpenedEvidence(StrictModel):
    """Durable, provider-returned identity for the opened campaign PR."""

    schema_version: Literal[1] = 1
    pull_request_number: int = Field(gt=0)
    pull_request_url: NonEmptyString
    target_ref: NonEmptyString
    base_commit: str
    base_tree: str
    open_identity: Sha256Digest


class CampaignDiscoveryEvidence(StrictModel):
    """Durable provider discovery captured before the promotion attempt."""

    schema_version: Literal[1] = 1
    observation: IntegrationProviderObservation
    main_before_commit: str
    open_identity: Sha256Digest


class CampaignPreparationEvidence(StrictModel):
    """Durable marker/template binding immediately before promotion."""

    schema_version: Literal[1] = 1
    template: IntegrationIntentTemplate
    observation: IntegrationProviderObservation
    marker_verified: bool
    open_identity: Sha256Digest
    marker_digest: Sha256Digest | None = None


class CampaignCompletionPlan(StrictModel):
    """Content-addressed plan needed to finish a campaign after a crash.

    This record is written before the promotion service is called.  It contains
    every immutable input needed to reconstruct the final evidence package, so
    recovery never reruns candidate evaluation or opens a second PR.
    """

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    bundle: PromotionBundle
    publication: CandidatePublicationBinding
    evidence_artifacts: list[ArtifactRef] = Field(min_length=1)
    bundle_digest: Sha256Digest
    opened: CampaignOpenedEvidence
    discovery: CampaignDiscoveryEvidence
    preparation: CampaignPreparationEvidence
    main_before_commit: str

    @model_validator(mode="after")
    def validate_plan(self) -> CampaignCompletionPlan:
        if self.operation_id != self.preparation.template.operation_id:
            raise ValueError("completion plan operation ID differs from preparation")
        if self.bundle_digest != promotion_bundle_digest(self.bundle):
            raise ValueError("completion plan bundle digest mismatch")
        if self.preparation.template.bundle_digest != self.bundle_digest:
            raise ValueError("completion plan template is not bundle-bound")
        if self.publication.publication_evidence_digest not in {
            artifact.digest for artifact in self.evidence_artifacts
        }:
            raise ValueError("completion plan publication evidence is missing")
        if {artifact.digest for artifact in self.evidence_artifacts} != set(
            self.bundle.evidence_digests
        ):
            raise ValueError("completion plan evidence does not match bundle")
        if self.opened.open_identity != self.preparation.open_identity:
            raise ValueError("completion plan open identities differ")
        if self.discovery.open_identity != self.opened.open_identity:
            raise ValueError("completion plan discovery is not open-bound")
        if self.preparation.template.bundle_digest != self.bundle_digest:
            raise ValueError("completion plan preparation is not bundle-bound")
        snapshot = self.bundle.snapshot
        request = self.bundle.request
        provenance = self.bundle.provenance
        if (
            self.publication.repository_digest != snapshot.repository_digest
            or self.publication.base_commit != snapshot.commit
            or self.publication.base_tree != snapshot.tree
            or self.publication.candidate_digest != request.candidate_digest
            or self.publication.publication_evidence_digest != provenance.source_provenance_digest
            or self.publication.controller_publisher_identity
            != self.bundle.controller_config.controller_identity
        ):
            raise ValueError("completion plan publication is not bundle-bound")
        if self.preparation.marker_digest is not None:
            marker = campaign_marker_digest(
                self.preparation.template.bind_lease("plan-validation", "sha256:" + "0" * 64)
            )
            if self.preparation.marker_digest != marker:
                raise ValueError("completion plan marker digest mismatch")
        if self.discovery.main_before_commit != self.main_before_commit:
            raise ValueError("completion plan main-before bindings differ")
        if (
            self.opened.base_commit != self.publication.base_commit
            or self.opened.base_tree != self.publication.base_tree
        ):
            raise ValueError("completion plan opened base differs from publication")
        if self.opened.target_ref != snapshot.target_ref:
            raise ValueError("completion plan opened target differs from bundle")
        discovered = self.discovery.observation
        if (
            discovered.repository_digest != self.publication.repository_digest
            or discovered.pull_request_url != self.opened.pull_request_url
            or discovered.base_ref != self.opened.target_ref
            or discovered.base_commit != self.publication.base_commit
            or discovered.base_tree != self.publication.base_tree
            or discovered.head_ref != self.publication.candidate_ref
            or discovered.head_commit != self.publication.candidate_commit
            or discovered.candidate_tree != self.publication.candidate_tree
        ):
            raise ValueError("completion plan discovery is not publication-bound")
        if self.discovery.observation.pull_request_number != self.opened.pull_request_number:
            raise ValueError("completion plan discovery PR differs from opened PR")
        prepared = self.preparation
        if not prepared.marker_verified or prepared.observation != discovered:
            raise ValueError("completion plan preparation differs from discovery")
        template = prepared.template
        if (
            template.repository_digest != self.publication.repository_digest
            or template.target_ref != self.opened.target_ref
            or template.base_commit != self.publication.base_commit
            or template.base_tree != self.publication.base_tree
            or template.candidate_ref != self.publication.candidate_ref
            or template.candidate_commit != self.publication.candidate_commit
            or template.candidate_tree != self.publication.candidate_tree
            or template.synthetic_merge_commit != discovered.synthetic_merge_commit
            or template.synthetic_merge_tree != discovered.synthetic_merge_tree
            or template.protection_evidence_digest != discovered.protection_evidence_digest
            or template.check_evidence_manifest_digest != discovered.check_evidence_manifest_digest
        ):
            raise ValueError("completion plan template is not discovery-bound")
        if not re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", self.main_before_commit):
            raise ValueError("completion plan main-before commit is not a Git object")
        return self


class CampaignFinalEvidenceRecord(StrictModel):
    """Durable post-merge provider evidence, saved before package assembly."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    reconciliation: IntegrationProviderReconciliation
    merge_result: IntegrationMergeResult


class IntegrationCampaignEvidencePackage(StrictModel):
    """Immutable, replayable evidence for one sanitized live campaign."""

    schema_version: Literal[1] = 1
    bundle: PromotionBundle
    publication: CandidatePublicationBinding
    evidence_artifacts: list[ArtifactRef] = Field(min_length=1)
    intent: IntegrationPromotionIntent
    observation: IntegrationProviderObservation
    merge_result: IntegrationMergeResult
    reconciliation: IntegrationProviderReconciliation
    receipt: IntegrationPromotionReceipt
    report: IntegrationPromotionReport
    bundle_digest: Sha256Digest
    intent_digest: Sha256Digest
    receipt_digest: Sha256Digest
    campaign_marker_digest: Sha256Digest
    # Control-plane evidence is deliberately outside ``bundle.evidence_digests``:
    # the lease is acquired by the promotion service after the dry-run bundle is
    # frozen.  The referenced immutable artifact preserves its actual lease
    # timestamps and identity after the lease file is released.
    lease_evidence: PromotionLeaseEvidence
    lease_evidence_artifact: ArtifactRef
    main_before_commit: str
    main_after_commit: str
    deploy_performed: Literal[False] = False

    @model_validator(mode="after")
    def validate_package(self) -> IntegrationCampaignEvidencePackage:
        expected_bundle = promotion_bundle_digest(self.bundle)
        if self.bundle_digest != expected_bundle:
            raise ValueError("campaign bundle digest mismatch")
        if self.intent_digest != canonical_digest(self.intent):
            raise ValueError("campaign intent digest mismatch")
        if self.receipt_digest != canonical_digest(self.receipt):
            raise ValueError("campaign receipt digest mismatch")
        if not (
            self.intent.operation_id == self.receipt.operation_id
            and self.intent.operation_id == self.report.operation_id
        ):
            raise ValueError("campaign operation IDs differ")
        if (
            self.intent.bundle_digest != self.bundle_digest
            or self.receipt.bundle_digest != self.bundle_digest
        ):
            raise ValueError("campaign bundle bindings differ")
        if self.receipt.intent_digest != self.intent_digest:
            raise ValueError("receipt intent binding differs")
        if (
            self.report.intent_digest != self.intent_digest
            or self.report.receipt_digest != self.receipt_digest
        ):
            raise ValueError("report digest bindings differ")
        if self.report.outcome != self.receipt.outcome:
            raise ValueError("report and receipt outcomes differ")
        if self.receipt.observation_digest != canonical_digest(self.reconciliation):
            raise ValueError("receipt observation digest differs")
        if self.campaign_marker_digest != campaign_marker_digest(self.intent):
            raise ValueError("campaign marker digest differs")
        evidence_digests = [artifact.digest for artifact in self.evidence_artifacts]
        if len(evidence_digests) != len(set(evidence_digests)):
            raise ValueError("campaign evidence artifacts must have unique digests")
        evidence_roles = [artifact.role for artifact in self.evidence_artifacts]
        if len(evidence_roles) != len(set(evidence_roles)):
            raise ValueError("campaign evidence artifacts must have unique roles")
        if set(evidence_digests) != set(self.bundle.evidence_digests):
            raise ValueError("campaign evidence artifacts do not match bundle evidence")
        if self.publication.publication_evidence_digest not in evidence_digests:
            raise ValueError("publication evidence artifact is missing")
        lease_bytes = canonical_bytes(self.lease_evidence)
        if (
            self.lease_evidence_artifact.role != "promotion-lease-evidence"
            or self.lease_evidence_artifact.media_type
            != "application/vnd.avo.integration-promotion+json"
            or self.lease_evidence_artifact.digest != canonical_digest(self.lease_evidence)
            or self.lease_evidence_artifact.size_bytes != len(lease_bytes)
        ):
            raise ValueError("lease evidence artifact has an unexpected role")
        if (
            self.lease_evidence.operation_id != self.intent.operation_id
            or self.lease_evidence.repository_digest != self.intent.repository_digest
            or self.lease_evidence.target_ref != self.intent.target_ref
            or self.lease_evidence.identity != self.intent.controller_lease_identity
            or self.lease_evidence.digest != self.intent.controller_lease_digest
            or self.lease_evidence.expires_at <= self.lease_evidence.acquired_at
        ):
            raise ValueError("lease evidence is not bound to the intent")
        self._validate_bundle_binding()
        self._validate_publication_binding()
        self._validate_provider_binding()
        self._validate_reconciliation_binding()
        if not re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", self.main_before_commit):
            raise ValueError("main-before commit is not a Git object")
        if not re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", self.main_after_commit):
            raise ValueError("main-after commit is not a Git object")
        if self.main_before_commit != self.main_after_commit:
            raise ValueError("campaign changed main")
        if self.deploy_performed is not False:
            raise ValueError("campaign evidence must not claim deployment")
        applied = self.receipt.outcome in {"applied", "already_applied"}
        if applied:
            if not self.reconciliation.merged:
                raise ValueError("successful campaign requires merged reconciliation")
            if (
                self.reconciliation.merge_commit != self.reconciliation.target_head_commit
                or self.reconciliation.target_head_tree != self.intent.candidate_tree
                or self.reconciliation.target_first_parent != self.intent.base_commit
                or self.reconciliation.target_parents != [self.intent.base_commit]
            ):
                raise ValueError("successful campaign has inexact target result")
        if self.receipt.outcome == "applied" and self.merge_result.outcome != "applied":
            raise ValueError("applied campaign requires an applied merge result")
        if self.receipt.outcome == "already_applied" and self.merge_result.outcome != "ambiguous":
            raise ValueError("already-applied campaign requires an ambiguous merge result")
        # An already-applied recovery is proven by the durable receipt and
        # reconciliation.  Its merge response is intentionally ambiguous and
        # cannot carry provider response objects under the merge-result
        # contract; only a directly applied response has exact merge fields.
        if self.receipt.outcome == "applied" and (
            self.merge_result.result_commit != self.reconciliation.target_head_commit
            or self.merge_result.result_tree != self.reconciliation.target_head_tree
            or self.merge_result.first_parent_commit != self.reconciliation.target_first_parent
            or self.receipt.applied_result_commit != self.merge_result.result_commit
            or self.receipt.applied_result_tree != self.merge_result.result_tree
            or self.receipt.applied_result_parent_commit != self.merge_result.first_parent_commit
        ):
            raise ValueError("merge result does not exactly match applied evidence")
        if not applied and self.merge_result.outcome == "applied":
            raise ValueError("non-success package cannot contain an applied merge result")
        return self

    def _validate_bundle_binding(self) -> None:
        snapshot = self.bundle.snapshot.model_dump(mode="python")
        request = self.bundle.request.model_dump(mode="python")
        provenance = self.bundle.provenance.model_dump(mode="python")
        if (
            self.intent.repository_digest != snapshot["repository_digest"]
            or self.intent.target_ref != snapshot["target_ref"]
            or self.intent.base_commit != snapshot["commit"]
            or self.intent.base_tree != snapshot["tree"]
            or self.intent.candidate_digest != request["candidate_digest"]
            or self.intent.protection_evidence_digest != snapshot["protection_evidence_digest"]
            or self.intent.controller_config_digest != self.bundle.controller_config_digest
            or self.intent.evidence_manifest_digest != provenance["evidence_manifest_digest"]
            or self.intent.publication_evidence_digest != provenance["source_provenance_digest"]
        ):
            raise ValueError("intent is not bound to the promotion bundle")

    def _validate_publication_binding(self) -> None:
        publication = self.publication
        if (
            publication.repository_digest != self.intent.repository_digest
            or publication.base_commit != self.intent.base_commit
            or publication.base_tree != self.intent.base_tree
            or publication.candidate_digest != self.intent.candidate_digest
            or publication.candidate_ref != self.intent.candidate_ref
            or publication.candidate_commit != self.intent.candidate_commit
            or publication.candidate_tree != self.intent.candidate_tree
            or publication.publication_evidence_digest != self.intent.publication_evidence_digest
            or publication.publication_evidence_digest
            != self.bundle.provenance.source_provenance_digest
            or publication.controller_publisher_identity
            != self.bundle.controller_config.controller_identity
        ):
            raise ValueError("candidate publication is not bound to the campaign")

    def _validate_provider_binding(self) -> None:
        expected = {
            "repository_digest": self.intent.repository_digest,
            "pull_request_number": self.intent.pull_request_number,
            "pull_request_url": self.intent.pull_request_url,
            "candidate_repository_digest": self.intent.repository_digest,
            "target_repository_digest": self.intent.repository_digest,
            "base_ref": self.intent.target_ref,
            "base_commit": self.intent.base_commit,
            "base_tree": self.intent.base_tree,
            "head_ref": self.intent.candidate_ref,
            "head_commit": self.intent.candidate_commit,
            "candidate_tree": self.intent.candidate_tree,
            "synthetic_merge_commit": self.intent.synthetic_merge_commit,
            "synthetic_merge_tree": self.intent.synthetic_merge_tree,
            "protection_evidence_digest": self.intent.protection_evidence_digest,
            "check_evidence_manifest_digest": self.intent.check_evidence_manifest_digest,
            "provider_identity": self.intent.provider_identity,
            "provider_api_version": self.intent.provider_api_version,
            "open_state": "open",
            "draft": False,
        }
        actual = self.observation.model_dump(mode="python")
        if any(actual[key] != value for key, value in expected.items()):
            raise ValueError("provider observation is not bound to the intent")

    def _validate_reconciliation_binding(self) -> None:
        expected = {
            "repository_digest": self.intent.repository_digest,
            "pull_request_number": self.intent.pull_request_number,
            "pull_request_url": self.intent.pull_request_url,
            "provider_identity": self.intent.provider_identity,
            "provider_api_version": self.intent.provider_api_version,
            "target_ref": self.intent.target_ref,
            "protection_evidence_digest": self.intent.protection_evidence_digest,
        }
        actual = self.reconciliation.model_dump(mode="python")
        if any(actual[key] != value for key, value in expected.items()):
            raise ValueError("reconciliation is not bound to the intent")

        expected_receipt = {
            "operation_id": self.intent.operation_id,
            "intent_digest": self.intent_digest,
            "bundle_digest": self.bundle_digest,
            "expected_target_ref": self.intent.target_ref,
            "expected_candidate_commit": self.intent.candidate_commit,
            "expected_candidate_tree": self.intent.candidate_tree,
            "expected_base_commit": self.intent.base_commit,
            "expected_protection_evidence_digest": self.intent.protection_evidence_digest,
            "expected_provider_identity": self.intent.provider_identity,
            "expected_provider_api_version": self.intent.provider_api_version,
            "observed_target_ref": self.intent.target_ref,
            "observed_base_commit": self.intent.base_commit,
            "observed_protection_evidence_digest": self.intent.protection_evidence_digest,
            "observed_provider_identity": self.intent.provider_identity,
            "observed_provider_api_version": self.intent.provider_api_version,
        }
        receipt = self.receipt.model_dump(mode="python")
        if any(receipt[key] != value for key, value in expected_receipt.items()):
            raise ValueError("receipt is not bound to the intent")
        if self.receipt.outcome in {"applied", "already_applied"} and (
            receipt["observed_head_tree"] != self.intent.candidate_tree
            or receipt["observed_head_commit"] != self.reconciliation.target_head_commit
        ):
            raise ValueError("receipt applied observation is not bound to the intent")


__all__ = [
    "CampaignCompletionPlan",
    "CampaignDiscoveryEvidence",
    "CampaignFinalEvidenceRecord",
    "CampaignOpenedEvidence",
    "CampaignPreparationEvidence",
    "IntegrationCampaignEvidencePackage",
    "IntegrationIntentTemplate",
    "campaign_marker_digest",
]
