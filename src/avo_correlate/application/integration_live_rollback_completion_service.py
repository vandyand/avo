"""Resumable orchestration for the complete hosted-live rollback proof."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any

from avo_correlate.application.integration_live_rollback_service import (
    LiveIntegrationRollbackService,
    LiveRollbackExecution,
    LiveRollbackTargetObservation,
)
from avo_correlate.application.synthetic_validation_service import SyntheticValidationService
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_campaign import IntegrationCampaignEvidencePackage
from avo_correlate.contracts.integration_drill import (
    IntegrationDrillRollbackAuthorization,
    IntegrationRollbackRequest,
)
from avo_correlate.contracts.integration_live_rollback import LiveRollbackEvidencePackage
from avo_correlate.contracts.integration_live_rollback_completion import (
    LiveRollbackCompletionPackage,
    LiveRollbackManifestEvidence,
    LiveRollbackPublicationEvidence,
    LiveRollbackPublicationOutcome,
    LiveRollbackPublicationPlan,
    LiveRollbackWorkflowEvidence,
)
from avo_correlate.contracts.integration_promotion import (
    CandidatePublicationBinding,
    IntegrationPromotionIntent,
    IntegrationProviderObservation,
    IntegrationProviderReconciliation,
)
from avo_correlate.contracts.promotion_bundle import PromotionBundle
from avo_correlate.contracts.synthetic_validation import (
    SyntheticValidationCreateAuthorization,
    SyntheticValidationOutcome,
    SyntheticValidationPlan,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest


class LiveRollbackCompletionError(RuntimeError):
    """Completion evidence is incomplete, stale, or requires reconciliation."""


class LiveRollbackCoreCompletionProofVerifier:
    """Accept cleanup proof only for this operation's durable core artifact."""

    def __init__(self, core: LiveRollbackEvidencePackage, reference: ArtifactRef) -> None:
        expected = canonical_digest(core)
        if (
            reference.digest != expected
            or reference.role != "integration-live-rollback-package"
            or reference.media_type != "application/vnd.avo.integration-live-rollback+json"
            or reference.size_bytes != len(canonical_bytes(core))
        ):
            raise ValueError("core package artifact is not content-bound")
        self._digest = expected

    def verify(self, _plan: SyntheticValidationPlan, proof: Any) -> None:
        if proof.completion_digest != self._digest:
            raise ValueError("completion proof is not bound to the durable rollback core")


class LiveRollbackCoreJournalCompletionProofVerifier:
    """Verify a proof against the core package currently durable in a journal."""

    def __init__(
        self,
        reader: Callable[[], tuple[LiveRollbackEvidencePackage, ArtifactRef] | None],
    ) -> None:
        self._reader = reader

    def verify(self, _plan: SyntheticValidationPlan, proof: Any) -> None:
        loaded = self._reader()
        if loaded is None:
            raise ValueError("durable rollback core package is missing")
        core, reference = loaded
        expected = canonical_digest(core)
        if (
            proof.completion_digest != expected
            or reference.digest != expected
            or reference.role != "integration-live-rollback-package"
            or reference.media_type != "application/vnd.avo.integration-live-rollback+json"
            or reference.size_bytes != len(canonical_bytes(core))
        ):
            raise ValueError("completion proof is not bound to the durable rollback core")


class LiveRollbackCompletionJournalPort:
    def record_package(self, package: LiveRollbackCompletionPackage) -> ArtifactRef: ...

    def read_package(
        self, operation_id: str
    ) -> tuple[LiveRollbackCompletionPackage, ArtifactRef] | None: ...


@dataclass(frozen=True, slots=True)
class LiveRollbackCompletionInputs:
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


@dataclass(frozen=True, slots=True)
class LiveRollbackCompletionExecution:
    core: LiveRollbackExecution
    package: LiveRollbackCompletionPackage | None
    package_artifact: ArtifactRef | None
    validation_outcome: SyntheticValidationOutcome | None
    cleanup_outcome: SyntheticValidationOutcome | None
    replayed: bool = False


class LiveRollbackCompletionService:
    """Finish one core rollback only after exact validation cleanup is proven."""

    def __init__(
        self,
        core: LiveIntegrationRollbackService,
        validation: SyntheticValidationService,
        completion_journal: LiveRollbackCompletionJournalPort,
        *,
        current_target_observation: Callable[[], LiveRollbackTargetObservation],
        main_head_reader: Callable[[], str],
        provider_reconciliation_reader: Callable[
            [IntegrationPromotionIntent], IntegrationProviderReconciliation
        ]
        | None = None,
    ) -> None:
        self._core = core
        self._validation = validation
        self._completion_journal = completion_journal
        self._current_target_observation = current_target_observation
        self._main_head_reader = main_head_reader
        self._provider_reconciliation_reader = provider_reconciliation_reader

    def run(
        self,
        request: IntegrationRollbackRequest,
        *,
        canary_package: IntegrationCampaignEvidencePackage,
        canary_package_artifact: ArtifactRef,
        authorization: IntegrationDrillRollbackAuthorization,
        bundle: PromotionBundle,
        publication: CandidatePublicationBinding,
        bundle_digest: str,
        intent_factory: Callable[[Any], IntegrationPromotionIntent],
        inputs: LiveRollbackCompletionInputs,
    ) -> LiveRollbackCompletionExecution:
        existing = self._completion_journal.read_package(request.operation_id)
        core_existing = self._read_core_package(request.operation_id)
        self._validate_durable_validation_inputs(inputs)
        durable_validation = self._validation.read_durable_outcome(inputs.validation_plan)
        validation_outcome = durable_validation
        if existing is None and core_existing is None and validation_outcome is None:
            validation_outcome = self._validation.trigger(inputs.validation_plan)
        elif existing is None and core_existing is not None and validation_outcome is None:
            raise LiveRollbackCompletionError(
                "durable validation evidence is missing for core-package recovery"
            )
        if validation_outcome is not None and validation_outcome.outcome not in {
            "created",
            "already_present",
            "reconciled",
        }:
            raise LiveRollbackCompletionError("synthetic validation did not produce exact evidence")
        core = self._core.run(
            request,
            canary_package=canary_package,
            canary_package_artifact=canary_package_artifact,
            authorization=authorization,
            bundle=bundle,
            publication=publication,
            bundle_digest=bundle_digest,
            intent_factory=intent_factory,
        )
        if existing is not None:
            package, package_ref = existing
            if package.core_package != core.package:
                raise LiveRollbackCompletionError("completion core differs during replay")
            self._validate_current_target(package)
            return LiveRollbackCompletionExecution(
                core,
                package,
                package_ref,
                package.validation_outcome,
                package.cleanup_outcome,
                True,
            )
        if core.package is None:
            return LiveRollbackCompletionExecution(
                core, None, None, None, None, core.rollback.replayed
            )

        if self._provider_reconciliation_reader is not None:
            inputs = replace(
                inputs,
                provider_reconciliation=self._provider_reconciliation_reader(
                    core.package.promotion_intent
                ),
            )

        if validation_outcome is None:
            raise LiveRollbackCompletionError("validation outcome is missing before promotion")
        proof = self._completion_proof(inputs.validation_plan, core.package)
        self._validate_final_state(request, inputs.provider_reconciliation)
        cleanup_outcome = self._validation.cleanup(inputs.validation_plan, proof)
        if cleanup_outcome.outcome != "cleaned":
            raise LiveRollbackCompletionError(
                "synthetic validation cleanup requires reconciliation"
            )
        self._validate_final_state(request, inputs.provider_reconciliation)
        package = self._package(
            core.package,
            core.package_artifact,
            inputs,
            validation_outcome,
            proof,
            cleanup_outcome,
        )
        package_ref = self._completion_journal.record_package(package)
        return LiveRollbackCompletionExecution(
            core, package, package_ref, validation_outcome, cleanup_outcome, core.rollback.replayed
        )

    def _package(
        self,
        core: LiveRollbackEvidencePackage,
        core_ref: ArtifactRef | None,
        inputs: LiveRollbackCompletionInputs,
        validation_outcome: SyntheticValidationOutcome,
        proof: Any,
        cleanup_outcome: SyntheticValidationOutcome,
    ) -> LiveRollbackCompletionPackage:
        if core_ref is None:
            raise LiveRollbackCompletionError("core package has no durable artifact")
        records: dict[str, object] = {
            "integration-live-rollback-package": core,
            "candidate-publication-plan": inputs.publication_plan,
            "candidate-publication-outcome": inputs.publication_outcome,
            "candidate-publication-evidence": inputs.publication_evidence,
            "integration-provider-observation": inputs.provider_observation,
            "integration-provider-reconciliation": inputs.provider_reconciliation,
            "trusted-check-manifest": inputs.check_manifest,
            "protection-manifest": inputs.protection_manifest,
            "workflow-evidence": inputs.workflow_evidence,
            "synthetic-validation-plan": inputs.validation_plan,
            "synthetic-validation-authorization": inputs.validation_authorization,
            "synthetic-validation-outcome": validation_outcome,
            "synthetic-validation-cleanup-proof": proof,
            "synthetic-validation-cleanup": cleanup_outcome,
        }
        artifacts = [
            _artifact_ref(value, role, _media_type(role)) for role, value in records.items()
        ]
        return LiveRollbackCompletionPackage(
            operation_id=core.operation_id,
            core_package=core,
            core_package_artifact=core_ref,
            publication_plan=inputs.publication_plan,
            publication_outcome=inputs.publication_outcome,
            publication_evidence=inputs.publication_evidence,
            provider_observation=inputs.provider_observation,
            provider_reconciliation=inputs.provider_reconciliation,
            check_manifest=inputs.check_manifest,
            protection_manifest=inputs.protection_manifest,
            workflow_evidence=inputs.workflow_evidence,
            validation_plan=inputs.validation_plan,
            validation_authorization=inputs.validation_authorization,
            validation_outcome=validation_outcome,
            cleanup_proof=proof,
            cleanup_outcome=cleanup_outcome,
            artifacts=artifacts,
            main_before_commit=core.request.main_before_commit,
            main_after_commit=core.request.main_before_commit,
        )

    def _validate_current_target(self, package: LiveRollbackCompletionPackage) -> None:
        current = self._current_target_observation()
        expected = package.provider_reconciliation
        if (
            current.repository_digest != expected.repository_digest
            or current.target_ref != expected.target_ref
            or current.commit != expected.target_head_commit
            or current.tree != expected.target_head_tree
            or current.parent_commits
            != (package.core_package.request.failed_integration_head_commit,)
        ):
            raise LiveRollbackCompletionError("current provider target is stale during replay")
        if self._main_head_reader() != package.main_before_commit:
            raise LiveRollbackCompletionError("main head is stale during replay")

    def _validate_final_state(
        self,
        request: IntegrationRollbackRequest,
        reconciliation: IntegrationProviderReconciliation,
    ) -> None:
        current = self._current_target_observation()
        if (
            current.repository_digest != reconciliation.repository_digest
            or current.target_ref != reconciliation.target_ref
            or current.commit != reconciliation.target_head_commit
            or current.tree != reconciliation.target_head_tree
            or current.parent_commits != (request.failed_integration_head_commit,)
            or self._main_head_reader() != request.main_before_commit
        ):
            raise LiveRollbackCompletionError("current target or main is stale before completion")

    def _read_core_package(
        self, operation_id: str
    ) -> tuple[LiveRollbackEvidencePackage, ArtifactRef] | None:
        reader = getattr(self._core, "read_package", None)
        if reader is None:
            return None
        return reader(operation_id)

    def _validate_durable_validation_inputs(self, inputs: LiveRollbackCompletionInputs) -> None:
        plan_reader = getattr(self._validation, "read_durable_plan", None)
        authorization_reader = getattr(self._validation, "read_durable_authorization", None)
        if plan_reader is not None:
            loaded_plan = plan_reader(inputs.validation_plan)
            if loaded_plan is not None and loaded_plan != inputs.validation_plan:
                raise LiveRollbackCompletionError("validation plan differs from durable state")
        if authorization_reader is not None:
            loaded_authorization = authorization_reader(inputs.validation_authorization)
            if (
                loaded_authorization is not None
                and loaded_authorization != inputs.validation_authorization
            ):
                raise LiveRollbackCompletionError(
                    "validation authorization differs from durable state"
                )

    @staticmethod
    def _completion_proof(plan: SyntheticValidationPlan, core: LiveRollbackEvidencePackage) -> Any:
        from avo_correlate.contracts.synthetic_validation import SyntheticValidationCompletionProof

        return SyntheticValidationCompletionProof(
            operation_id=plan.operation_id,
            plan_digest=plan.plan_digest,
            completion_digest=canonical_digest(core),
            completed=True,
        )


def _artifact_ref(value: object, role: str, media_type: str) -> ArtifactRef:
    return ArtifactRef(
        digest=canonical_digest(value),
        size_bytes=len(canonical_bytes(value)),
        media_type=media_type,
        role=role,
        created_at=datetime(1970, 1, 1, tzinfo=UTC),
    )


def _media_type(role: str) -> str:
    if role == "integration-live-rollback-package":
        return "application/vnd.avo.integration-live-rollback+json"
    if role.startswith("candidate-publication"):
        return "application/vnd.avo.candidate-publication+json"
    if role.startswith("integration-provider"):
        return "application/vnd.avo.integration-provider+json"
    if role in {"trusted-check-manifest", "protection-manifest"}:
        return "application/vnd.avo.integration-manifest+json"
    if role == "workflow-evidence":
        return "application/vnd.avo.workflow-evidence+json"
    return "application/vnd.avo.synthetic-validation+json"


__all__ = [
    "LiveRollbackCompletionError",
    "LiveRollbackCompletionExecution",
    "LiveRollbackCompletionInputs",
    "LiveRollbackCompletionService",
    "LiveRollbackCoreCompletionProofVerifier",
    "LiveRollbackCoreJournalCompletionProofVerifier",
]
