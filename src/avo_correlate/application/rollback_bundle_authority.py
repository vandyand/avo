"""Two-phase controller authority for rollback candidate publication."""

# Runtime type checks are intentional: public callers may pass untrusted objects.
# pyright: reportUnnecessaryIsInstance=false

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from avo_correlate.adapters.artifacts.filesystem import ArtifactIntegrityError
from avo_correlate.adapters.artifacts.rollback_bundle_authority import (
    RollbackBundleAuthorityJournal,
)
from avo_correlate.adapters.git.publisher import PreparedPublication
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_campaign import (
    IntegrationCampaignEvidencePackage,
    verify_campaign_package_artifact,
)
from avo_correlate.contracts.integration_drill import (
    IntegrationDrillRollbackAuthorization,
    IntegrationRollbackRequest,
)
from avo_correlate.contracts.integration_promotion import CandidatePublicationBinding
from avo_correlate.contracts.integration_soak import FailedSoakAttestation
from avo_correlate.contracts.prepublication import (
    RollbackPublicationAuthorityConfig,
    RollbackPublicationAuthorization,
    RollbackSnapshotRestoreFacts,
)
from avo_correlate.contracts.promotion_bundle import RollbackPromotionBundleAuthorization
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

_CANDIDATE_REF = re.compile(r"^refs/heads/avo/candidate/[0-9a-f]{64}$")


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
        recovery_absence_verifier: Callable[[str, str, str], object] | None = None,
    ) -> None:
        self.config = config
        self.journal = journal
        self._finalizer = finalizer
        self._recovery_absence_verifier = recovery_absence_verifier

    def authorize(
        self,
        operation: IntegrationRollbackRequest,
        *,
        canary_package_artifact: ArtifactRef,
        canary_package: IntegrationCampaignEvidencePackage,
        failed_soak: FailedSoakAttestation,
        facts: RollbackSnapshotRestoreFacts,
        prepared: PreparedPublication,
        recovery_failed_soak: FailedSoakAttestation | None = None,
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
        # Public callers can hand us Pydantic model instances created with
        # model_construct(), which bypasses nested validators.  Round-trip all
        # provider evidence before the create-once authority is written.
        operation = IntegrationRollbackRequest.model_validate_json(
            canonical_bytes(operation)
        )
        canary_package = IntegrationCampaignEvidencePackage.model_validate_json(
            canonical_bytes(canary_package)
        )
        canary_package_artifact = ArtifactRef.model_validate_json(
            canonical_bytes(canary_package_artifact)
        )
        facts = RollbackSnapshotRestoreFacts.model_validate_json(canonical_bytes(facts))
        failed_soak = FailedSoakAttestation.model_validate_json(canonical_bytes(failed_soak))
        if recovery_failed_soak is not None:
            recovery_failed_soak = FailedSoakAttestation.model_validate_json(
                canonical_bytes(recovery_failed_soak)
            )
        self._validate_soak(failed_soak)
        plan = prepared.plan
        config = self.config
        canary = canary_package
        try:
            verify_campaign_package_artifact(
                canary,
                canary_package_artifact,
                self.journal.read_artifact(canary_package_artifact),
            )
            lease_reference = canary.lease_evidence_artifact
            lease_payload = canonical_bytes(canary.lease_evidence)
            if (
                lease_reference.digest != canonical_digest(canary.lease_evidence)
                or lease_reference.size_bytes != len(lease_payload)
                or self.journal.read_artifact(lease_reference) != lease_payload
            ):
                raise ValueError("canary lease evidence child is not content-bound")
            for evidence_reference in canary.evidence_artifacts:
                evidence_payload = self.journal.read_artifact(evidence_reference)
                parsed = json.loads(evidence_payload)
                if (
                    canonical_bytes(parsed) != evidence_payload
                    or canonical_digest(parsed) != evidence_reference.digest
                ):
                    raise ValueError("canary evidence child is not canonical")
        except (
            ArtifactIntegrityError,
            OSError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            raise ValueError("durable canary child evidence is missing or tampered") from exc
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
            or failed_soak.integration_commit != facts.failed_head_commit
            or failed_soak.integration_tree != facts.failed_head_tree
            or failed_soak.integration_parent_commit != facts.restore_commit
            or failed_soak.restore_commit != facts.restore_commit
            or failed_soak.restore_tree != facts.restore_tree
            or failed_soak.main_commit != operation.main_before_commit
            or plan.repository_digest != config.repository_digest
            or plan.base_commit != facts.failed_head_commit
            or plan.base_tree != facts.failed_head_tree
            or plan.candidate_commit != operation.rollback_candidate_commit
            or plan.candidate_tree != operation.restore_to_tree
            or _CANDIDATE_REF.fullmatch(plan.candidate_ref) is None
            or plan.controller_publisher_identity != config.publisher_identity
        ):
            raise ValueError("rollback operation, canary, facts, or prepared plan are mixed")
        if not plan.changed_paths:
            raise ValueError("prepared publication has no authenticated changed paths")
        plan_artifact = prepared.plan_artifact
        if plan_artifact is None:
            raise ValueError("prepared publication has no durable plan artifact")
        existing = self.journal.read_authorization(operation.operation_id)
        if existing is not None:
            if (
                existing.canary_operation_id != canary.intent.operation_id
                or existing.canary_package_digest != canary_package_artifact.digest
                or existing.repository_digest != config.repository_digest
                or existing.target_ref != config.target_ref
                or existing.main_before_commit != operation.main_before_commit
                or existing.failed_integration_head_commit != facts.failed_head_commit
                or existing.failed_integration_head_tree != facts.failed_head_tree
                or existing.restore_to_commit != facts.restore_commit
                or existing.restore_to_tree != facts.restore_tree
                or existing.rollback_candidate_commit != plan.candidate_commit
                or existing.rollback_candidate_tree != plan.candidate_tree
                or existing.rollback_candidate_parent_commit != facts.failed_head_commit
                or existing.candidate_digest != plan.candidate_digest
                or existing.candidate_ref != plan.candidate_ref
                or existing.changed_paths != list(plan.changed_paths)
                or existing.publication_plan_digest != plan.publication_id
                or existing.publication_evidence_digest != prepared.evidence_digest
                or existing.authority_config_digest != config.trusted_config_digest
                or existing.publisher_identity != config.publisher_identity
            ):
                raise ValueError("existing rollback authorization differs from trusted inputs")
            indexed_plan_artifact = self.journal.read_publication_plan_artifact(existing)
            if indexed_plan_artifact.digest != plan_artifact.digest:
                raise ValueError("existing publication plan differs from trusted inputs")
            plan_data = canonical_bytes(plan.payload())
            self.journal.record(
                existing,
                canary_package_artifact=canary_package_artifact,
                publication_plan_artifact=indexed_plan_artifact,
                publication_plan_data=plan_data,
            )
            exact_soak = (
                existing.failed_soak_attestation_id == failed_soak.attestation_id
                and existing.failed_soak_attestation_digest == canonical_digest(failed_soak)
            )
            stored_soak_data = self.journal.read_failed_soak_data(existing)
            bridge_exists = self.journal.recovery_bridge_exists(existing)
            if bridge_exists:
                self.journal.require_recovery_bridge(existing)
                legacy_data = stored_soak_data
                if legacy_data is None:
                    legacy_data = self.journal.read_recovery_bridge_legacy_soak_data(existing)
                legacy_soak = FailedSoakAttestation.model_validate_json(legacy_data)
                if not _same_soak_observation(legacy_soak, failed_soak):
                    raise ValueError("fresh failed soak differs from durable recovery bridge")
                self.journal.require(existing)
                return existing
            if exact_soak and stored_soak_data is not None:
                self.journal.require(existing)
                return existing
            legacy_soak = (
                failed_soak
                if stored_soak_data is None
                else FailedSoakAttestation.model_validate_json(stored_soak_data)
            )
            if not exact_soak and recovery_failed_soak is not None:
                # An explicitly supplied historical observation must itself be
                # the exact attestation bound into the immutable authority.
                legacy_soak = recovery_failed_soak
            if (
                legacy_soak.attestation_id != existing.failed_soak_attestation_id
                or canonical_digest(legacy_soak)
                != existing.failed_soak_attestation_digest
            ):
                raise ValueError("recovery failed soak is not the stored authority")
            self._validate_soak(legacy_soak)
            if self._recovery_absence_verifier is None:
                raise ValueError("recovery absence verifier is required")
            self._recovery_absence_verifier(
                plan.candidate_ref, plan.candidate_commit, plan.base_commit
            )
            self.journal.record_recovery_bridge(
                existing,
                legacy_failed_soak_data=canonical_bytes(legacy_soak),
                fresh_failed_soak_data=canonical_bytes(failed_soak),
                publication_plan_artifact=indexed_plan_artifact,
                publication_plan_data=plan_data,
            )
            self.journal.require(existing)
            return existing
        soak_id = failed_soak.attestation_id
        soak_digest = canonical_digest(failed_soak)
        values: dict[str, Any] = {
            "schema_version": 1,
            "operation_id": operation.operation_id,
            "canary_operation_id": canary.intent.operation_id,
            "canary_package_digest": canary_package_artifact.digest,
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
        self.journal.record(
            authorization,
            canary_package_artifact=canary_package_artifact,
            publication_plan_artifact=plan_artifact,
            publication_plan_data=canonical_bytes(plan.payload()),
            failed_soak_data=canonical_bytes(failed_soak),
        )
        return authorization

    def finalize(
        self,
        authorization: RollbackPublicationAuthorization,
        publication: CandidatePublicationBinding,
        *,
        evidence: bytes | ArtifactRef,
        drill_authorization: IntegrationDrillRollbackAuthorization,
    ) -> RollbackPromotionBundleAuthorization:
        """Verify post-push evidence and produce controller-owned authority."""

        if not isinstance(authorization, RollbackPublicationAuthorization):
            raise TypeError("authorization must be a trusted RollbackPublicationAuthorization")
        self.journal.require(authorization)
        if not isinstance(publication, CandidatePublicationBinding):
            raise TypeError("publication must be a trusted CandidatePublicationBinding")
        if not isinstance(drill_authorization, IntegrationDrillRollbackAuthorization):
            raise TypeError("drill authorization must be an authority projection")
        if (
            drill_authorization.operation_id != authorization.operation_id
            or drill_authorization.prepublication_authorization_id
            != authorization.authorization_id
            or drill_authorization.failed_soak_attestation_id
            != authorization.failed_soak_attestation_id
            or drill_authorization.repository_digest != authorization.repository_digest
            or drill_authorization.target_ref != authorization.target_ref
            or drill_authorization.main_before_commit != authorization.main_before_commit
            or drill_authorization.failed_integration_head_commit
            != authorization.failed_integration_head_commit
            or drill_authorization.failed_integration_head_tree
            != authorization.failed_integration_head_tree
            or drill_authorization.restore_to_commit != authorization.restore_to_commit
            or drill_authorization.restore_to_tree != authorization.restore_to_tree
            or drill_authorization.rollback_candidate_commit
            != authorization.rollback_candidate_commit
            or drill_authorization.rollback_candidate_parent_commit
            != authorization.rollback_candidate_parent_commit
        ):
            raise ValueError("drill authorization is not bound to pre-publication authority")
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
        if isinstance(evidence, ArtifactRef):
            if evidence.digest != authorization.publication_evidence_digest:
                raise ValueError("publication evidence artifact differs from authorization")
            evidence_bytes = self.journal.read_artifact(evidence)
        elif isinstance(evidence, bytes):
            evidence_bytes = evidence
        else:
            raise TypeError("evidence must be canonical bytes or ArtifactRef")
        try:
            raw = json.loads(evidence_bytes)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("publication evidence is malformed") from exc
        expected_evidence = {
            "schema_version": 1,
            "publication_id": authorization.publication_plan_digest,
            "repository_digest": authorization.repository_digest,
            "base_commit": authorization.failed_integration_head_commit,
            "base_tree": authorization.failed_integration_head_tree,
            "candidate_digest": authorization.candidate_digest,
            "candidate_ref": authorization.candidate_ref,
            "candidate_commit": authorization.rollback_candidate_commit,
            "candidate_tree": authorization.rollback_candidate_tree,
            "controller_publisher_identity": authorization.publisher_identity,
            "changed_paths": authorization.changed_paths,
            "verified": True,
        }
        if (
            canonical_bytes(raw) != evidence_bytes
            or raw != expected_evidence
            or canonical_digest(raw) != authorization.publication_evidence_digest
        ):
            raise ValueError("publication evidence differs from pre-authorization")
        if self._finalizer is not None:
            finalized = self._finalizer(authorization, publication)
            if not isinstance(finalized, RollbackPromotionBundleAuthorization):
                raise TypeError("rollback authority finalizer returned an invalid authorization")
            return finalized
        values = {
            "schema_version": 1,
            "operation_id": authorization.operation_id,
            "canary_operation_id": authorization.canary_operation_id,
            "canary_package_digest": authorization.canary_package_digest,
            "drill_authorization_id": canonical_digest(drill_authorization),
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

    def drill_authorization(
        self,
        authorization: RollbackPublicationAuthorization,
        failed_soak: FailedSoakAttestation,
    ) -> IntegrationDrillRollbackAuthorization:
        """Project only durable preauthorization plus provider soak into drill auth."""

        if not isinstance(authorization, RollbackPublicationAuthorization):
            raise TypeError("authorization must be a trusted RollbackPublicationAuthorization")
        self.journal.require(authorization)
        self._validate_soak(failed_soak)
        exact_soak = (
            authorization.failed_soak_attestation_id == failed_soak.attestation_id
            and authorization.failed_soak_attestation_digest == canonical_digest(failed_soak)
        )
        if (
            authorization.repository_digest != failed_soak.repository_digest
            or authorization.failed_integration_head_commit != failed_soak.integration_commit
            or authorization.failed_integration_head_tree != failed_soak.integration_tree
            or authorization.restore_to_commit != failed_soak.restore_commit
            or authorization.restore_to_tree != failed_soak.restore_tree
            or authorization.main_before_commit != failed_soak.main_commit
        ):
            raise ValueError("stored preauthorization is not bound to failed soak authority")
        if not exact_soak:
            self.journal.require_recovery_bridge(authorization)
        values: dict[str, Any] = {
            "schema_version": 1,
            "operation_id": authorization.operation_id,
            "prepublication_authorization_id": authorization.authorization_id,
            "failed_soak_attestation_id": authorization.failed_soak_attestation_id,
            "repository_digest": authorization.repository_digest,
            "target_ref": authorization.target_ref,
            "main_before_commit": authorization.main_before_commit,
            "main_after_commit": authorization.main_before_commit,
            "target_head_commit": authorization.failed_integration_head_commit,
            "target_head_tree": authorization.failed_integration_head_tree,
            "target_parents": [],
            "failed_integration_head_commit": authorization.failed_integration_head_commit,
            "failed_integration_head_tree": authorization.failed_integration_head_tree,
            "restore_to_commit": authorization.restore_to_commit,
            "restore_to_tree": authorization.restore_to_tree,
            "rollback_candidate_commit": authorization.rollback_candidate_commit,
            "rollback_candidate_parent_commit": authorization.rollback_candidate_parent_commit,
            "issuer": self.config.controller_identity,
            "reason": authorization.reason,
            "authorized": True,
        }
        unsigned = IntegrationDrillRollbackAuthorization.model_construct(**values)
        return IntegrationDrillRollbackAuthorization.model_validate(
            {
                **values,
                "authorization_id": canonical_digest(
                    unsigned.model_dump(
                        exclude={"authorization_id"}, exclude_none=True, mode="json"
                    )
                ),
            },
        )

    def _validate_soak(self, soak: FailedSoakAttestation) -> None:
        if not isinstance(soak, FailedSoakAttestation):
            raise TypeError("failed soak must implement FailedSoakAttestation")
        if soak.attestation_id != canonical_digest(
            soak.model_dump(exclude={"attestation_id"}, mode="json")
        ):
            raise ValueError("failed soak attestation digest is not canonical")
        if soak.repository_digest != self.config.repository_digest:
            raise ValueError("failed soak repository is not trusted")
        if soak.integration_ref != self.config.target_ref or soak.app_id != self.config.soak_app_id:
            raise ValueError("failed soak repository or app is not trusted")
        if (
            soak.context != self.config.soak_context
            or soak.workflow_path != self.config.soak_workflow_path
        ):
            raise ValueError("failed soak context or workflow is not trusted")
        if soak.status != "completed" or soak.conclusion != "failure":
            raise ValueError("rollback authorization requires a failed completed soak")


__all__ = ["RollbackBundleAuthority", "prepared_publication_evidence_digest"]


def _same_soak_observation(
    left: FailedSoakAttestation, right: FailedSoakAttestation
) -> bool:
    """Compare all provider facts except freshness-derived identity fields."""

    return left.model_dump(
        exclude={"freshness_cutoff", "attestation_id"}, mode="json"
    ) == right.model_dump(exclude={"freshness_cutoff", "attestation_id"}, mode="json")
