"""Application boundary for a live rollback after a successful canary."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol, cast

from avo_correlate.adapters.artifacts.drill_journal import IntegrationDrillJournal
from avo_correlate.application.integration_rollback_service import (
    IntegrationDrillRollbackService,
    IntegrationRollbackDrillExecution,
)
from avo_correlate.contracts.base import ArtifactRef, Sha256Digest
from avo_correlate.contracts.integration_campaign import IntegrationCampaignEvidencePackage
from avo_correlate.contracts.integration_drill import (
    IntegrationDrillCaseResult,
    IntegrationDrillRollbackAuthorization,
    IntegrationRollbackRequest,
)
from avo_correlate.contracts.integration_live_rollback import LiveRollbackEvidencePackage
from avo_correlate.contracts.integration_promotion import (
    CandidatePublicationBinding,
    IntegrationPromotionIntent,
    IntegrationPromotionReceipt,
    IntegrationPromotionReport,
    PromotionLeaseEvidence,
    PromotionMutationAuthorization,
)
from avo_correlate.contracts.promotion_bundle import PromotionBundle
from avo_correlate.domain.canonical import canonical_digest


class LiveRollbackEvidenceError(RuntimeError):
    """Live rollback evidence is incomplete, stale, or conflicts with history."""


@dataclass(frozen=True, slots=True)
class LiveRollbackTargetObservation:
    """Trusted read-only observation of the protected integration ref."""

    repository_digest: str
    target_ref: str
    commit: str
    tree: str
    parent_commits: tuple[str, ...]


class PromotionEvidenceReader(Protocol):
    def read_intent(
        self, operation_id: str
    ) -> tuple[IntegrationPromotionIntent, ArtifactRef] | None: ...

    def read_receipt(
        self, operation_id: str
    ) -> tuple[IntegrationPromotionReceipt, ArtifactRef] | None: ...

    def read_lease_evidence(
        self, operation_id: str
    ) -> tuple[PromotionLeaseEvidence, ArtifactRef] | None: ...

    def read_mutation_authorization(
        self, operation_id: str
    ) -> tuple[PromotionMutationAuthorization, ArtifactRef] | None: ...


class LiveRollbackPackageJournal(Protocol):
    def record_package(self, package: LiveRollbackEvidencePackage) -> ArtifactRef: ...

    def read_package(
        self, operation_id: str
    ) -> tuple[LiveRollbackEvidencePackage, ArtifactRef] | None: ...


@dataclass(frozen=True, slots=True)
class LiveRollbackExecution:
    rollback: IntegrationRollbackDrillExecution
    package: LiveRollbackEvidencePackage | None
    package_artifact: ArtifactRef | None
    replayed: bool = False


class LiveIntegrationRollbackService:
    """Wrap case-7 rollback with canary binding and durable package assembly.

    ``target_observation_reader`` must be backed by the authenticated provider
    read path; callers must not adapt arbitrary request JSON into an observation.
    """

    def __init__(
        self,
        rollback: IntegrationDrillRollbackService,
        rollback_journal: IntegrationDrillJournal,
        package_journal: LiveRollbackPackageJournal,
        promotion_evidence: PromotionEvidenceReader,
        *,
        main_head_reader: Callable[[], str],
        target_observation_reader: Callable[[], LiveRollbackTargetObservation],
    ) -> None:
        self._rollback = rollback
        self._rollback_journal = rollback_journal
        self._package_journal = package_journal
        self._promotion_evidence = promotion_evidence
        self._main_head_reader = main_head_reader
        self._target_observation_reader = target_observation_reader

    def run(
        self,
        request: IntegrationRollbackRequest,
        *,
        canary_package: IntegrationCampaignEvidencePackage,
        canary_package_artifact: ArtifactRef,
        authorization: IntegrationDrillRollbackAuthorization,
        bundle: PromotionBundle,
        publication: CandidatePublicationBinding,
        bundle_digest: Sha256Digest,
        intent_factory: Callable[[Any], IntegrationPromotionIntent],
    ) -> LiveRollbackExecution:
        self._validate_canary(request, canary_package, canary_package_artifact)
        self._assert_main(request.main_before_commit)

        existing = self._package_journal.read_package(request.operation_id)
        if existing is not None:
            package, package_ref = existing
            self._rollback.verify_replay(request, authorization)
            self._validate_replay(package, request, canary_package_artifact, authorization)
            self._validate_target_observation(
                request,
                self._target_observation_reader(),
                package.rollback_receipt.result_commit,
                package.rollback_receipt.result_tree,
            )
            return LiveRollbackExecution(
                rollback=self._execution_from_package(package),
                package=package,
                package_artifact=package_ref,
                replayed=True,
            )

        execution = self._rollback.run(
            request,
            authorization=authorization,
            bundle=bundle,
            publication=publication,
            bundle_digest=bundle_digest,
            intent_factory=intent_factory,
        )
        self._assert_main(request.main_before_commit)
        if execution.receipt.outcome not in {"applied", "already_applied"}:
            return LiveRollbackExecution(execution, None, None)
        self._validate_target_observation(
            request,
            self._target_observation_reader(),
            execution.receipt.result_commit,
            execution.receipt.result_tree,
        )
        package = self._package(
            execution,
            canary_package,
            canary_package_artifact,
            bundle,
            publication,
            bundle_digest,
        )
        self._validate_target_observation(
            request,
            self._target_observation_reader(),
            package.rollback_receipt.result_commit,
            package.rollback_receipt.result_tree,
        )
        self._assert_main(request.main_before_commit)
        package_ref = self._package_journal.record_package(package)
        return LiveRollbackExecution(execution, package, package_ref)

    def read_package(
        self, operation_id: str
    ) -> tuple[LiveRollbackEvidencePackage, ArtifactRef] | None:
        """Read the durable core package without invoking any hosted mutation."""

        return self._package_journal.read_package(operation_id)

    def _package(
        self,
        execution: IntegrationRollbackDrillExecution,
        canary: IntegrationCampaignEvidencePackage,
        canary_ref: ArtifactRef,
        bundle: PromotionBundle,
        publication: CandidatePublicationBinding,
        bundle_digest: Sha256Digest,
    ) -> LiveRollbackEvidencePackage:
        request = execution.request
        promotion_id = request.promotion_operation_id
        loaded_intent = self._promotion_evidence.read_intent(promotion_id)
        loaded_lease = self._promotion_evidence.read_lease_evidence(promotion_id)
        loaded_authorization = self._promotion_evidence.read_mutation_authorization(promotion_id)
        loaded_receipt = self._promotion_evidence.read_receipt(promotion_id)
        loaded_case = self._rollback_journal.read_case_result(request.operation_id, 7)
        if any(item is None for item in (
            loaded_intent,
            loaded_lease,
            loaded_authorization,
            loaded_receipt,
            loaded_case,
        )):
            raise LiveRollbackEvidenceError("live rollback promotion evidence is incomplete")
        promotion_intent, promotion_intent_ref = cast(
            tuple[IntegrationPromotionIntent, ArtifactRef], loaded_intent
        )
        lease, lease_ref = cast(tuple[PromotionLeaseEvidence, ArtifactRef], loaded_lease)
        mutation_authorization, mutation_authorization_ref = cast(
            tuple[PromotionMutationAuthorization, ArtifactRef], loaded_authorization
        )
        promotion_receipt, promotion_receipt_ref = cast(
            tuple[IntegrationPromotionReceipt, ArtifactRef], loaded_receipt
        )
        rollback_case, case_ref = cast(tuple[IntegrationDrillCaseResult, ArtifactRef], loaded_case)
        rollback_refs = {
            reference.role: reference for reference in execution.evidence_artifacts
        }
        required_rollback_roles = {
            "integration-drill-soak",
            "integration-drill-rollback-authorization",
            "integration-drill-rollback-intent",
            "integration-drill-rollback-receipt",
        }
        if set(rollback_refs) != required_rollback_roles:
            raise LiveRollbackEvidenceError("live rollback evidence artifacts are incomplete")
        artifacts = [
            canary_ref,
            *rollback_refs.values(),
            case_ref,
            promotion_intent_ref,
            lease_ref,
            mutation_authorization_ref,
            promotion_receipt_ref,
        ]
        report = execution.report
        expected_intent_digest = canonical_digest(promotion_intent)
        expected_receipt_digest = canonical_digest(promotion_receipt)
        if report.intent_digest is None and report.receipt_digest is None:
            report = IntegrationPromotionReport(
                operation_id=request.promotion_operation_id,
                outcome=promotion_receipt.outcome,
                intent_digest=expected_intent_digest,
                receipt_digest=expected_receipt_digest,
                checks=["case_7_recovery"],
                errors=[],
            )
        elif (
            report.intent_digest != expected_intent_digest
            or report.receipt_digest != expected_receipt_digest
        ):
            raise LiveRollbackEvidenceError("promotion report is not bound to durable records")
        observed_main = self._assert_main(request.main_before_commit)
        return LiveRollbackEvidencePackage(
            operation_id=request.operation_id,
            canary_operation_id=canary.intent.operation_id,
            canary_package=canary,
            canary_package_artifact=canary_ref,
            request=request,
            soak=execution.soak,
            authorization=execution.authorization,
            rollback_intent=execution.intent,
            rollback_receipt=execution.receipt,
            rollback_case=rollback_case,
            bundle=bundle,
            publication=publication,
            bundle_digest=bundle_digest,
            promotion_intent=promotion_intent,
            promotion_lease_evidence=lease,
            promotion_mutation_authorization=mutation_authorization,
            promotion_receipt=promotion_receipt,
            promotion_report=report,
            artifacts=artifacts,
            main_before_commit=observed_main,
            main_after_commit=observed_main,
        )

    @staticmethod
    def _validate_canary(
        request: IntegrationRollbackRequest,
        canary: IntegrationCampaignEvidencePackage,
        canary_ref: ArtifactRef,
    ) -> None:
        if (
            canary_ref.role != "integration-campaign-package"
            or canary_ref.media_type != "application/vnd.avo.integration-campaign+json"
            or canary_ref.digest != canonical_digest(canary)
            or canary.report.outcome not in {"applied", "already_applied"}
            or canary.intent.repository_digest != request.repository_digest
            or canary.intent.target_ref != request.target_ref
            or canary.receipt.applied_result_commit != request.failed_integration_head_commit
            or canary.receipt.applied_result_tree != request.failed_integration_head_tree
            or canary.main_before_commit != request.main_before_commit
            or canary.main_after_commit != request.main_before_commit
            or canary.reconciliation.target_parents != [canary.intent.base_commit]
            or request.restore_to_commit != canary.intent.base_commit
            or request.restore_to_tree != canary.intent.base_tree
        ):
            raise LiveRollbackEvidenceError("successful canary is stale or not rollback-bound")

    @staticmethod
    def _validate_replay(
        package: LiveRollbackEvidencePackage,
        request: IntegrationRollbackRequest,
        canary_ref: ArtifactRef,
        authorization: IntegrationDrillRollbackAuthorization,
    ) -> None:
        try:
            cast(Any, package).validate_package()
        except ValueError as exc:
            raise LiveRollbackEvidenceError(
                "live rollback replay package is semantically invalid"
            ) from exc
        if (
            package.request != request
            or package.canary_package_artifact != canary_ref
            or package.authorization != authorization
        ):
            raise LiveRollbackEvidenceError("live rollback replay binding differs")

    @staticmethod
    def _validate_target_observation(
        request: IntegrationRollbackRequest,
        observation: LiveRollbackTargetObservation,
        expected_commit: str | None,
        expected_tree: str | None,
    ) -> None:
        if (
            expected_commit is None
            or expected_tree is None
            or observation.repository_digest != request.repository_digest
            or observation.target_ref != request.target_ref
            or observation.commit != expected_commit
            or observation.tree != expected_tree
            or observation.parent_commits != (request.failed_integration_head_commit,)
        ):
            raise LiveRollbackEvidenceError(
                "current integration target is stale or has unexpected topology"
            )

    def _assert_main(self, expected: str) -> str:
        observed = self._main_head_reader()
        if observed != expected:
            raise LiveRollbackEvidenceError("main head changed during live rollback")
        return observed

    @staticmethod
    def _execution_from_package(
        package: LiveRollbackEvidencePackage,
    ) -> IntegrationRollbackDrillExecution:
        rollback_roles = {
            "integration-drill-soak",
            "integration-drill-rollback-authorization",
            "integration-drill-rollback-intent",
            "integration-drill-rollback-receipt",
        }
        evidence = tuple(
            reference for reference in package.artifacts if reference.role in rollback_roles
        )
        return IntegrationRollbackDrillExecution(
            request=package.request,
            soak=package.soak,
            authorization=package.authorization,
            intent=package.rollback_intent,
            receipt=package.rollback_receipt,
            case=package.rollback_case,
            report=package.promotion_report,
            evidence_artifacts=evidence,
            replayed=True,
        )
__all__ = [
    "LiveIntegrationRollbackService",
    "LiveRollbackEvidenceError",
    "LiveRollbackExecution",
    "LiveRollbackPackageJournal",
    "LiveRollbackTargetObservation",
    "PromotionEvidenceReader",
]
