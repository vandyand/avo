"""Typed, content-addressed evidence for one live protected rollback."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import Field, model_validator

from avo_correlate.contracts.base import ArtifactRef, Sha256Digest, StrictModel
from avo_correlate.contracts.integration_campaign import IntegrationCampaignEvidencePackage
from avo_correlate.contracts.integration_drill import (
    IntegrationDrillCaseResult,
    IntegrationDrillRollbackAuthorization,
    IntegrationDrillRollbackIntent,
    IntegrationDrillRollbackReceipt,
    IntegrationDrillSoakObservation,
    IntegrationRollbackRequest,
)
from avo_correlate.contracts.integration_promotion import (
    CandidatePublicationBinding,
    IntegrationPromotionIntent,
    IntegrationPromotionReceipt,
    IntegrationPromotionReport,
    PromotionLeaseEvidence,
    PromotionMutationAuthorization,
)
from avo_correlate.contracts.promotion_bundle import PromotionBundle, promotion_bundle_digest
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

_GIT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


class LiveRollbackEvidencePackage(StrictModel):
    """Core durable join between a canary and its protected rollback.

    This is the semantic core, not the complete hosted-live completion package.
    JSON Schema describes wire shape only; callers must use Pydantic validation
    because the cross-record topology, authorization, and content-addressing
    invariants below are not delegated to JSON Schema.
    """

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    canary_operation_id: Sha256Digest
    canary_package: IntegrationCampaignEvidencePackage
    canary_package_artifact: ArtifactRef
    request: IntegrationRollbackRequest
    soak: IntegrationDrillSoakObservation
    authorization: IntegrationDrillRollbackAuthorization
    rollback_intent: IntegrationDrillRollbackIntent
    rollback_receipt: IntegrationDrillRollbackReceipt
    rollback_case: IntegrationDrillCaseResult
    bundle: PromotionBundle
    publication: CandidatePublicationBinding
    bundle_digest: Sha256Digest
    promotion_intent: IntegrationPromotionIntent
    promotion_lease_evidence: PromotionLeaseEvidence
    promotion_mutation_authorization: PromotionMutationAuthorization
    promotion_receipt: IntegrationPromotionReceipt
    promotion_report: IntegrationPromotionReport
    artifacts: list[ArtifactRef] = Field(min_length=10, max_length=10)
    main_before_commit: str
    main_after_commit: str
    deploy_performed: Literal[False] = False

    @model_validator(mode="after")
    def validate_package(self) -> LiveRollbackEvidencePackage:
        request = self.request
        if (
            self.operation_id != request.operation_id
            or self.canary_operation_id != self.canary_package.intent.operation_id
            or self.canary_operation_id == self.operation_id
            or request.repository_digest != self.canary_package.intent.repository_digest
            or self.bundle_digest != promotion_bundle_digest(self.bundle)
            or self.main_before_commit != request.main_before_commit
            or self.main_after_commit != request.main_before_commit
            or self.rollback_case.operation_id != self.operation_id
            or self.promotion_report.operation_id != request.promotion_operation_id
        ):
            raise ValueError("live rollback package identity is inconsistent")
        for value in (
            self.main_before_commit,
            self.main_after_commit,
            request.failed_integration_head_commit,
            request.failed_integration_head_tree,
            request.restore_to_commit,
            request.restore_to_tree,
            request.rollback_candidate_commit,
            request.rollback_candidate_parent_commit,
        ):
            if not _GIT.fullmatch(value):
                raise ValueError("live rollback package contains malformed Git identity")
        if self.main_before_commit != self.main_after_commit:
            raise ValueError("live rollback package changed main")

        canary = self.canary_package
        if (
            self.canary_package_artifact.role != "integration-campaign-package"
            or self.canary_package_artifact.media_type
            != "application/vnd.avo.integration-campaign+json"
            or canary.report.outcome not in {"applied", "already_applied"}
            or canary.intent.target_ref != request.target_ref
            or canary.main_before_commit != request.main_before_commit
            or canary.main_after_commit != request.main_before_commit
            or canary.deploy_performed
            or canary.receipt.applied_result_commit != request.failed_integration_head_commit
            or canary.receipt.applied_result_tree != request.failed_integration_head_tree
            or canary.reconciliation.target_parents != [canary.intent.base_commit]
            or request.restore_to_commit != canary.intent.base_commit
            or request.restore_to_tree != canary.intent.base_tree
        ):
            raise ValueError("live rollback package is not bound to the successful canary")

        if (
            self.soak.operation_id != self.operation_id
            or self.soak.repository_digest != request.repository_digest
            or self.soak.target_ref != request.target_ref
            or self.soak.outcome != "failed"
            or self.soak.error is None
            or self.soak.target_head_commit != request.failed_integration_head_commit
            or self.soak.target_head_tree != request.failed_integration_head_tree
            or self.soak.main_before_commit != request.main_before_commit
            or self.soak.main_after_commit != request.main_before_commit
            or self.soak.target_parents
            or self.soak.deploy_performed
        ):
            raise ValueError("live rollback package has invalid failed-soak evidence")

        auth = self.authorization
        if (
            auth.operation_id != self.operation_id
            or auth.repository_digest != request.repository_digest
            or auth.target_ref != request.target_ref
            or auth.main_before_commit != request.main_before_commit
            or auth.main_after_commit != request.main_before_commit
            or auth.deploy_performed
            or not auth.authorized
            or auth.authorization_id != self.rollback_intent.authorization_id
            or auth.failed_integration_head_commit != request.failed_integration_head_commit
            or auth.failed_integration_head_tree != request.failed_integration_head_tree
            or auth.restore_to_commit != request.restore_to_commit
            or auth.restore_to_tree != request.restore_to_tree
            or auth.rollback_candidate_commit != request.rollback_candidate_commit
            or auth.rollback_candidate_parent_commit != request.rollback_candidate_parent_commit
        ):
            raise ValueError("live rollback authorization is not request-bound")

        intent = self.rollback_intent
        receipt = self.rollback_receipt
        if (
            intent.operation_id != self.operation_id
            or intent.repository_digest != request.repository_digest
            or intent.target_ref != request.target_ref
            or intent.main_before_commit != request.main_before_commit
            or intent.main_after_commit != request.main_before_commit
            or intent.deploy_performed
            or not intent.authorized
            or intent.promotion_operation_id != request.promotion_operation_id
            or intent.authorization_id != auth.authorization_id
            or intent.failed_integration_head_commit != request.failed_integration_head_commit
            or intent.failed_integration_head_tree != request.failed_integration_head_tree
            or intent.restore_to_commit != request.restore_to_commit
            or intent.restore_to_tree != request.restore_to_tree
            or intent.rollback_candidate_commit != request.rollback_candidate_commit
            or intent.rollback_candidate_parent_commit != request.rollback_candidate_parent_commit
            or receipt.operation_id != self.operation_id
            or receipt.repository_digest != request.repository_digest
            or receipt.target_ref != request.target_ref
            or receipt.main_before_commit != request.main_before_commit
            or receipt.main_after_commit != request.main_before_commit
            or receipt.deploy_performed
            or receipt.promotion_operation_id != request.promotion_operation_id
            or receipt.intent_digest != intent.intent_digest
            or receipt.outcome not in {"applied", "already_applied"}
            or receipt.result_tree != request.restore_to_tree
            or receipt.target_head_commit != receipt.result_commit
            or receipt.target_head_tree != request.restore_to_tree
            or receipt.target_parents != [request.failed_integration_head_commit]
        ):
            raise ValueError("live rollback records are not mutually bound")

        if (
            self.rollback_case.case_id != 7
            or self.publication.repository_digest != request.repository_digest
            or self.publication.base_commit != request.failed_integration_head_commit
            or self.publication.base_tree != request.failed_integration_head_tree
            or self.publication.candidate_commit != request.rollback_candidate_commit
            or self.publication.candidate_tree != request.restore_to_tree
            or self.publication.candidate_digest != self.bundle.request.candidate_digest
            or self.bundle.snapshot.repository_digest != request.repository_digest
            or self.bundle.snapshot.target_ref != request.target_ref
            or self.bundle.snapshot.commit != request.failed_integration_head_commit
            or self.bundle.snapshot.tree != request.failed_integration_head_tree
            or self.rollback_case.repository_digest != request.repository_digest
            or self.rollback_case.target_ref != request.target_ref
            or self.rollback_case.main_before_commit != request.main_before_commit
            or self.rollback_case.main_after_commit != request.main_before_commit
            or self.rollback_case.target_head_commit != receipt.result_commit
            or self.rollback_case.target_head_tree != request.restore_to_tree
            or self.rollback_case.target_parents != [request.failed_integration_head_commit]
            or self.rollback_case.deploy_performed
            or self.rollback_case.outcome != receipt.outcome
            or self.rollback_case.attester_identity != receipt.attester_identity
            or self.rollback_case.soak_observation != self.soak.observation_id
            or self.rollback_case.rollback_intent != intent.intent_digest
            or self.rollback_case.rollback_receipt != receipt.receipt_digest
        ):
            raise ValueError("live rollback publication or bundle is stale")

        promotion = self.promotion_intent
        if (
            promotion.operation_id != request.promotion_operation_id
            or promotion.target_ref != request.target_ref
            or promotion.repository_digest != request.repository_digest
            or promotion.base_commit != request.failed_integration_head_commit
            or promotion.base_tree != request.failed_integration_head_tree
            or promotion.candidate_commit != request.rollback_candidate_commit
            or promotion.candidate_tree != request.restore_to_tree
            or promotion.bundle_digest != self.bundle_digest
            or not promotion_lease_binding(self.promotion_lease_evidence, promotion)
            or self.promotion_mutation_authorization.operation_id != promotion.operation_id
            or self.promotion_mutation_authorization.intent_digest != canonical_digest(promotion)
            or self.promotion_mutation_authorization.lease_identity
            != promotion.controller_lease_identity
            or self.promotion_mutation_authorization.lease_digest
            != promotion.controller_lease_digest
            or self.promotion_receipt.operation_id != promotion.operation_id
            or self.promotion_receipt.intent_digest != canonical_digest(promotion)
            or self.promotion_receipt.bundle_digest != self.bundle_digest
            or self.promotion_receipt.expected_target_ref != request.target_ref
            or self.promotion_receipt.expected_candidate_commit
            != request.rollback_candidate_commit
            or self.promotion_receipt.expected_candidate_tree != request.restore_to_tree
            or self.promotion_receipt.expected_base_commit
            != request.failed_integration_head_commit
            or self.promotion_receipt.expected_protection_evidence_digest
            != promotion.protection_evidence_digest
            or self.promotion_receipt.expected_provider_identity != promotion.provider_identity
            or self.promotion_receipt.expected_provider_api_version
            != promotion.provider_api_version
            or self.promotion_receipt.merge_method != promotion.merge_method
            or self.promotion_receipt.outcome not in {"applied", "already_applied"}
            or self.promotion_receipt.applied_result_commit != receipt.result_commit
            or self.promotion_receipt.applied_result_tree != receipt.result_tree
            or self.promotion_receipt.applied_result_parent_commit
            != request.failed_integration_head_commit
            or self.promotion_report.outcome != self.promotion_receipt.outcome
            or self.promotion_report.intent_digest != canonical_digest(promotion)
            or self.promotion_report.receipt_digest != canonical_digest(self.promotion_receipt)
        ):
            raise ValueError("live promotion records are not rollback-bound")

        expected_roles = {
            "integration-campaign-package",
            "integration-drill-soak",
            "integration-drill-rollback-authorization",
            "integration-drill-rollback-intent",
            "integration-drill-rollback-receipt",
            "integration-drill-case",
            "promotion-intent",
            "promotion-lease-evidence",
            "promotion-mutation-authorization",
            "promotion-receipt",
        }
        if {item.role for item in self.artifacts} != expected_roles:
            raise ValueError("live rollback package artifact roles are incomplete")
        if len({item.digest for item in self.artifacts}) != len(self.artifacts):
            raise ValueError("live rollback package artifacts must be distinct")
        expected_digests = {
            "integration-campaign-package": self.canary_package_artifact.digest,
            "integration-drill-soak": canonical_digest(self.soak),
            "integration-drill-rollback-authorization": canonical_digest(auth),
            "integration-drill-rollback-intent": canonical_digest(intent),
            "integration-drill-rollback-receipt": canonical_digest(receipt),
            "integration-drill-case": canonical_digest(self.rollback_case),
            "promotion-intent": canonical_digest(promotion),
            "promotion-lease-evidence": canonical_digest(self.promotion_lease_evidence),
            "promotion-mutation-authorization": canonical_digest(
                self.promotion_mutation_authorization
            ),
            "promotion-receipt": canonical_digest(self.promotion_receipt),
        }
        expected_children = {
            "integration-campaign-package": (
                canary,
                "application/vnd.avo.integration-campaign+json",
            ),
            "integration-drill-soak": (
                self.soak,
                "application/vnd.avo.integration-drill-soak+json",
            ),
            "integration-drill-rollback-authorization": (
                auth,
                "application/vnd.avo.integration-drill-rollback-authorization+json",
            ),
            "integration-drill-rollback-intent": (
                intent,
                "application/vnd.avo.integration-drill-rollback-intent+json",
            ),
            "integration-drill-rollback-receipt": (
                receipt,
                "application/vnd.avo.integration-drill-rollback-receipt+json",
            ),
            "integration-drill-case": (
                self.rollback_case,
                "application/vnd.avo.integration-drill-case+json",
            ),
            "promotion-intent": (
                promotion,
                "application/vnd.avo.integration-promotion+json",
            ),
            "promotion-lease-evidence": (
                self.promotion_lease_evidence,
                "application/vnd.avo.integration-promotion+json",
            ),
            "promotion-mutation-authorization": (
                self.promotion_mutation_authorization,
                "application/vnd.avo.integration-promotion+json",
            ),
            "promotion-receipt": (
                self.promotion_receipt,
                "application/vnd.avo.integration-promotion+json",
            ),
        }
        for item in self.artifacts:
            if (
                item.digest != expected_digests[item.role]
                or item.media_type != expected_children[item.role][1]
            ):
                raise ValueError("live rollback package artifact digest is incorrect")
            # The legacy compatibility form only permutes array entries, so
            # its byte length remains exactly the semantic package length.
            if item.size_bytes != len(canonical_bytes(expected_children[item.role][0])):
                raise ValueError("live rollback package artifact size is incorrect")
        artifact_digests = {item.digest for item in self.artifacts}
        expected_case_evidence = {
            "integration-drill-soak": (
                self.soak,
                "application/vnd.avo.integration-drill-soak+json",
            ),
            "integration-drill-rollback-authorization": (
                auth,
                "application/vnd.avo.integration-drill-rollback-authorization+json",
            ),
            "integration-drill-rollback-intent": (
                intent,
                "application/vnd.avo.integration-drill-rollback-intent+json",
            ),
            "integration-drill-rollback-receipt": (
                receipt,
                "application/vnd.avo.integration-drill-rollback-receipt+json",
            ),
        }
        if (
            len(self.rollback_case.evidence_artifacts) != len(expected_case_evidence)
            or {reference.role for reference in self.rollback_case.evidence_artifacts}
            != set(expected_case_evidence)
        ):
            raise ValueError("live rollback case evidence is not included in package artifacts")
        if any(
            reference.digest != canonical_digest(expected_case_evidence[reference.role][0])
            or reference.digest not in artifact_digests
            or reference.media_type != expected_case_evidence[reference.role][1]
            or reference.size_bytes
            != len(canonical_bytes(expected_case_evidence[reference.role][0]))
            for reference in self.rollback_case.evidence_artifacts
        ):
            raise ValueError("live rollback case evidence metadata is incorrect")
        return self


def promotion_lease_binding(
    evidence: PromotionLeaseEvidence, intent: IntegrationPromotionIntent
) -> bool:
    return (
        evidence.operation_id == intent.operation_id
        and evidence.repository_digest == intent.repository_digest
        and evidence.target_ref == intent.target_ref
        and evidence.identity == intent.controller_lease_identity
        and evidence.digest == intent.controller_lease_digest
    )


__all__ = ["LiveRollbackEvidencePackage", "promotion_lease_binding"]
