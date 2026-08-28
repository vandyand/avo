"""Two-phase controller authority for rollback candidate publication."""

# Runtime type checks are intentional: public callers may pass untrusted objects.
# pyright: reportUnnecessaryIsInstance=false

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from avo_correlate.adapters.artifacts.rollback_bundle_authority import (
    RollbackBundleAuthorityJournal,
)
from avo_correlate.adapters.git.publisher import PreparedPublication
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_campaign import IntegrationCampaignEvidencePackage
from avo_correlate.contracts.integration_drill import IntegrationRollbackRequest
from avo_correlate.contracts.integration_promotion import CandidatePublicationBinding
from avo_correlate.contracts.prepublication import (
    FailedSoakAttestation,
    RollbackPublicationAuthorityConfig,
    RollbackPublicationAuthorization,
    RollbackSnapshotRestoreFacts,
)
from avo_correlate.contracts.promotion_bundle import RollbackPromotionBundleAuthorization
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest


def prepared_publication_evidence_digest(prepared: PreparedPublication) -> str:
    """Return the deterministic evidence digest known before the push."""

    plan = prepared.plan
    payload = {
        "schema_version": 1,
        "publication_id": plan.publication_id,
        "repository_digest": plan.repository_digest,
        "base_commit": plan.base_commit,
        "base_tree": plan.base_tree,
        "candidate_digest": plan.candidate_digest,
        "candidate_ref": plan.candidate_ref,
        "candidate_commit": plan.candidate_commit,
        "candidate_tree": plan.candidate_tree,
        "controller_publisher_identity": plan.controller_publisher_identity,
        "changed_paths": list(plan.changed_paths),
        "verified": True,
    }
    return canonical_digest(payload)


class RollbackBundleAuthority:
    """Authorize locally, then finalize only after exact publication evidence."""

    def __init__(
        self,
        config: RollbackPublicationAuthorityConfig,
        journal: RollbackBundleAuthorityJournal,
        *,
        finalizer: Callable[
            [RollbackPublicationAuthorization, CandidatePublicationBinding], object
        ]
        | None = None,
    ) -> None:
        self.config = config
        self.journal = journal
        self._finalizer = finalizer

    def authorize(
        self,
        operation: IntegrationRollbackRequest,
        *,
        canary_package_artifact: ArtifactRef,
        canary_package: IntegrationCampaignEvidencePackage,
        failed_soak: FailedSoakAttestation,
        facts: RollbackSnapshotRestoreFacts,
        prepared: PreparedPublication,
    ) -> RollbackPublicationAuthorization:
        """Create and durably record authority before a candidate push."""

        if not isinstance(operation, IntegrationRollbackRequest):
            raise TypeError("operation must be a trusted IntegrationRollbackRequest")
        if not isinstance(canary_package, IntegrationCampaignEvidencePackage):
            raise TypeError("canary package must be a trusted semantic package")
        if not isinstance(canary_package_artifact, ArtifactRef):
            raise TypeError("canary package artifact must be a typed ArtifactRef")
        if not isinstance(facts, RollbackSnapshotRestoreFacts):
            raise TypeError("snapshot/restore facts must be authenticated typed facts")
        if not isinstance(prepared, PreparedPublication):
            raise TypeError("prepared must be a trusted PreparedPublication")
        self._validate_soak(failed_soak)
        plan = prepared.plan
        config = self.config
        canary = canary_package
        if (
            canary_package_artifact.digest != canonical_digest(canary)
            or canary_package_artifact.role != "integration-campaign-package"
            or canary_package_artifact.media_type != "application/vnd.avo.integration-campaign+json"
            or canary_package_artifact.size_bytes != len(canonical_bytes(canary))
        ):
            raise ValueError("canary package artifact is not the canonical semantic package")
        if (
            facts.repository_digest != config.repository_digest
            or facts.repository_digest != operation.repository_digest
            or facts.failed_head_commit != operation.failed_integration_head_commit
            or facts.failed_head_tree != operation.failed_integration_head_tree
            or facts.restore_commit != operation.restore_to_commit
            or facts.restore_tree != operation.restore_to_tree
            or operation.target_ref != config.target_ref
            or canary.intent.operation_id == operation.operation_id
            or canary.intent.base_commit != operation.restore_to_commit
            or canary.intent.base_tree != operation.restore_to_tree
            or canary.receipt.applied_result_commit != facts.failed_head_commit
            or canary.receipt.applied_result_tree != facts.failed_head_tree
            or self._soak_value(failed_soak, "operation_id") != operation.operation_id
            or plan.repository_digest != config.repository_digest
            or plan.base_commit != facts.failed_head_commit
            or plan.base_tree != facts.failed_head_tree
            or plan.candidate_commit != operation.rollback_candidate_commit
            or plan.candidate_tree != operation.restore_to_tree
            or plan.candidate_ref == config.target_ref
            or plan.controller_publisher_identity != config.publisher_identity
        ):
            raise ValueError("rollback operation, canary, facts, or prepared plan are mixed")
        if not plan.changed_paths:
            raise ValueError("prepared publication has no authenticated changed paths")
        soak_id = self._soak_id(failed_soak)
        soak_digest = self._soak_digest(failed_soak)
        values: dict[str, Any] = {
            "schema_version": 1,
            "operation_id": operation.operation_id,
            "canary_operation_id": canary.intent.operation_id,
            "canary_package_digest": canonical_digest(canary),
            "repository_digest": config.repository_digest,
            "target_ref": config.target_ref,
            "main_before_commit": operation.main_before_commit,
            "failed_integration_head_commit": facts.failed_head_commit,
            "failed_integration_head_tree": facts.failed_head_tree,
            "restore_to_commit": facts.restore_commit,
            "restore_to_tree": facts.restore_tree,
            "rollback_candidate_commit": plan.candidate_commit,
            "rollback_candidate_tree": plan.candidate_tree,
            "rollback_candidate_parent_commit": facts.failed_head_commit,
            "candidate_digest": plan.candidate_digest,
            "candidate_ref": plan.candidate_ref,
            "changed_paths": list(plan.changed_paths),
            "publication_plan_digest": plan.publication_id,
            "publication_evidence_digest": prepared.evidence_digest,
            "failed_soak_attestation_id": soak_id,
            "failed_soak_attestation_digest": soak_digest,
            "authority_config_digest": config.trusted_config_digest,
            "controller_identity": config.controller_identity,
            "publisher_identity": config.publisher_identity,
            "issuer_id": config.soak_issuer_id,
            "reason": "authorized rollback after failed soak",
            "authorized": True,
        }
        authorization = RollbackPublicationAuthorization.model_validate(
            {**values, "authorization_id": canonical_digest(values)}
        )
        plan_artifact = prepared.plan_artifact
        if plan_artifact is None:
            raise ValueError("prepared publication has no durable plan artifact")
        self.journal.record(
            authorization,
            canary_package_artifact=canary_package_artifact,
            publication_plan_artifact=plan_artifact,
        )
        return authorization

    def finalize(
        self,
        authorization: RollbackPublicationAuthorization,
        publication: CandidatePublicationBinding,
        *,
        evidence: bytes | ArtifactRef | None = None,
    ) -> object:
        """Verify post-push evidence and produce controller-owned authority."""

        if not isinstance(authorization, RollbackPublicationAuthorization):
            raise TypeError("authorization must be a trusted RollbackPublicationAuthorization")
        self.journal.require(authorization)
        if not isinstance(publication, CandidatePublicationBinding):
            raise TypeError("publication must be a trusted CandidatePublicationBinding")
        if (
            publication.repository_digest != authorization.repository_digest
            or publication.base_commit != authorization.failed_integration_head_commit
            or publication.base_tree != authorization.failed_integration_head_tree
            or publication.candidate_commit != authorization.rollback_candidate_commit
            or publication.candidate_tree != authorization.rollback_candidate_tree
            or publication.candidate_digest != authorization.candidate_digest
            or publication.candidate_ref != authorization.candidate_ref
            or publication.controller_publisher_identity != authorization.publisher_identity
            or publication.publication_evidence_digest != authorization.publication_evidence_digest
            or publication.changed_paths != authorization.changed_paths
            or not publication.verified
        ):
            raise ValueError("candidate publication does not match pre-publication authority")
        if evidence is not None:
            if isinstance(evidence, bytes):
                try:
                    raw = json.loads(evidence)
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise ValueError("publication evidence is malformed") from exc
                if (
                    canonical_bytes(raw) != evidence
                    or canonical_digest(raw) != authorization.publication_evidence_digest
                ):
                    raise ValueError("publication evidence differs from pre-authorization")
            elif isinstance(evidence, ArtifactRef):
                if evidence.digest != authorization.publication_evidence_digest:
                    raise ValueError("publication evidence artifact differs from authorization")
            else:
                raise TypeError("evidence must be canonical bytes or ArtifactRef")
        if self._finalizer is not None:
            return self._finalizer(authorization, publication)
        values = {
            "schema_version": 1,
            "operation_id": authorization.operation_id,
            "canary_operation_id": authorization.canary_operation_id,
            "canary_package_digest": authorization.canary_package_digest,
            "drill_authorization_id": authorization.failed_soak_attestation_id,
            "repository_digest": authorization.repository_digest,
            "target_ref": authorization.target_ref,
            "main_before_commit": authorization.main_before_commit,
            "failed_integration_head_commit": authorization.failed_integration_head_commit,
            "failed_integration_head_tree": authorization.failed_integration_head_tree,
            "restore_to_commit": authorization.restore_to_commit,
            "restore_to_tree": authorization.restore_to_tree,
            "rollback_candidate_commit": authorization.rollback_candidate_commit,
            "rollback_candidate_tree": authorization.rollback_candidate_tree,
            "rollback_candidate_parent_commit": authorization.rollback_candidate_parent_commit,
            "candidate_digest": authorization.candidate_digest,
            "source_tree_digest": authorization.candidate_digest,
            "restore_tree_digest": authorization.candidate_digest,
            "publication_evidence_digest": publication.publication_evidence_digest,
            "issuer_id": self.config.controller_identity,
            "reason": authorization.reason,
            "authorized": True,
        }
        return RollbackPromotionBundleAuthorization.model_validate(
            {**values, "authorization_id": canonical_digest(values)}
        )

    def _validate_soak(self, soak: FailedSoakAttestation) -> None:
        if not isinstance(soak, FailedSoakAttestation):
            raise TypeError("failed soak must implement FailedSoakAttestation")
        if (
            not self._soak_id(soak).startswith("sha256:")
            or not self._soak_digest(soak).startswith("sha256:")
        ):
            raise ValueError("failed soak attestation identities must be digests")
        issuer = self._soak_value(soak, "issuer_id", "issuer")
        if not self._soak_value(soak, "operation_id") or issuer != self.config.soak_issuer_id:
            raise ValueError("failed soak issuer or operation is not trusted")
        outcome = self._soak_value(soak, "outcome")
        if outcome not in {"failed", "timeout", "partial_success"}:
            raise ValueError("rollback authorization requires a failed soak")
        for name, expected in (
            ("repository_digest", self.config.repository_digest),
            ("target_ref", self.config.target_ref),
            ("app_id", self.config.soak_app_id),
            ("context", self.config.soak_context),
            ("workflow_path", self.config.soak_workflow_path),
        ):
            actual = getattr(soak, name, None)
            if actual is not None and actual != expected:
                raise ValueError("failed soak authority context is not trusted")

    @staticmethod
    def _soak_id(soak: FailedSoakAttestation) -> str:
        return RollbackBundleAuthority._soak_value(
            soak, "attestation_id", "observation_id"
        )

    @staticmethod
    def _soak_digest(soak: FailedSoakAttestation) -> str:
        value = getattr(soak, "attestation_digest", None)
        return str(value if value is not None else canonical_digest(soak))

    @staticmethod
    def _soak_value(soak: FailedSoakAttestation, *names: str) -> str:
        for name in names:
            value = getattr(soak, name, None)
            if value is not None:
                return str(value)
        return ""


__all__ = ["RollbackBundleAuthority", "prepared_publication_evidence_digest"]
