"""Fail-closed orchestration for one AVO-004.5 integration campaign.

The lifecycle is deliberately staged around the hosted pull request:
publication/intake -> PR open -> provider discovery -> trusted quality gates ->
immutable dry-run bundle -> marker binding -> one durable promotion attempt.
This ordering avoids the otherwise circular requirement that hosted CI be
observed before the bundle which carries its attestations can be frozen.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from avo_correlate.adapters.artifacts.campaign_journal import CampaignCompletionJournal
from avo_correlate.application.integration_promotion_service import (
    IntegrationPromotionJournal,
    IntegrationPromotionService,
)
from avo_correlate.application.promotion_service import PromotionController
from avo_correlate.contracts.base import ArtifactRef, Sha256Digest
from avo_correlate.contracts.integration_campaign import (
    CampaignCompletionPlan,
    CampaignDiscoveryEvidence,
    CampaignFinalEvidenceRecord,
    CampaignOpenedEvidence,
    CampaignPreparationEvidence,
    IntegrationCampaignEvidencePackage,
    IntegrationIntentTemplate,
    campaign_marker_digest,
)
from avo_correlate.contracts.integration_promotion import (
    CandidatePublicationBinding,
    IntegrationMergeResult,
    IntegrationPromotionIntent,
    IntegrationPromotionReceipt,
    IntegrationPromotionReport,
    IntegrationProviderObservation,
    IntegrationProviderReconciliation,
)
from avo_correlate.contracts.promotion_bundle import (
    PromotionBundle,
    PromotionControllerConfig,
    PromotionDryRunInput,
    PromotionDryRunResult,
)
from avo_correlate.contracts.promotion_policy import (
    GateAttestation,
    ReviewerAttestation,
    RollbackAttestation,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest


class IntegrationCampaignPrerequisiteError(ValueError):
    """A trusted prerequisite failed before a merge could be requested."""


class IntegrationCampaignUnsafeError(RuntimeError):
    """A provider mutation occurred without complete reconstructable evidence."""


@dataclass(frozen=True, slots=True)
class IntegrationCampaignRequest:
    """Candidate facts only; policy and evidence are owned by trusted ports."""

    candidate_root: Path
    candidate_id: str
    proposer_id: str
    source_provenance_digest: Sha256Digest


@dataclass(frozen=True, slots=True)
class CampaignQualityEvidence:
    gate_attestations: tuple[GateAttestation, ...]
    reviewer_attestations: tuple[ReviewerAttestation, ...]
    rollback_attestation: RollbackAttestation
    evidence_artifacts: tuple[ArtifactRef, ...]
    synthetic_merge_commit: str
    synthetic_merge_tree: str
    protection_evidence_digest: Sha256Digest
    check_evidence_manifest_digest: Sha256Digest


@dataclass(frozen=True, slots=True)
class CampaignOpened:
    """Provider-owned PR identity created without a bundle or merge authority."""

    pull_request_number: int
    pull_request_url: str
    target_ref: str
    base_commit: str
    base_tree: str
    open_identity: Sha256Digest


@dataclass(frozen=True, slots=True)
class CampaignDiscovery:
    """Exact synthetic merge, check, protection, and pre-merge state."""

    observation: IntegrationProviderObservation
    main_before_commit: str
    open_identity: Sha256Digest


@dataclass(frozen=True, slots=True)
class CampaignPreparation:
    """Bundle-bound template and marker proof, produced after discovery."""

    template: IntegrationIntentTemplate
    observation: IntegrationProviderObservation
    marker_verified: bool
    open_identity: Sha256Digest
    marker_digest: Sha256Digest | None = None


@dataclass(frozen=True, slots=True)
class CampaignFinalEvidence:
    reconciliation: IntegrationProviderReconciliation
    merge_result: IntegrationMergeResult


@dataclass(frozen=True, slots=True)
class IntegrationCampaignResult:
    report: IntegrationPromotionReport
    package: IntegrationCampaignEvidencePackage | None = None
    package_artifact: ArtifactRef | None = None


class CampaignIntakePort(Protocol):
    def collect(self, request: IntegrationCampaignRequest) -> PromotionDryRunInput: ...


class CampaignQualityPort(Protocol):
    def evaluate(
        self,
        request: IntegrationCampaignRequest,
        intake: PromotionDryRunInput,
        discovery: CampaignDiscovery,
    ) -> CampaignQualityEvidence: ...


class CampaignProviderPort(Protocol):
    """Provider lifecycle; implementations own all hosted API details.

    ``open_or_reconcile`` must be idempotent and durable: an ambiguous create
    response is reconciled to the exact ``open_identity`` rather than retried
    as a second PR creation.  ``bind`` similarly must retain that identity.
    """

    def open_or_reconcile(self, publication: CandidatePublicationBinding) -> CampaignOpened: ...

    def discover(
        self, opened: CampaignOpened, publication: CandidatePublicationBinding
    ) -> CampaignDiscovery: ...

    def bind(
        self,
        publication: CandidatePublicationBinding,
        bundle: PromotionBundle,
        bundle_digest: str,
        opened: CampaignOpened,
        discovery: CampaignDiscovery,
    ) -> CampaignPreparation: ...

    def final_evidence(
        self,
        intent: IntegrationPromotionIntent,
        report: IntegrationPromotionReport,
        observation: IntegrationProviderObservation,
    ) -> CampaignFinalEvidence: ...


class CampaignEvidenceResolver(Protocol):
    def resolve(self, digests: Sequence[str]) -> tuple[ArtifactRef, ...]: ...


class CampaignPublicationVerifier(Protocol):
    def __call__(
        self, publication: CandidatePublicationBinding, bundle: PromotionBundle
    ) -> bool: ...


class CampaignArtifactWriter(Protocol):
    def put_bytes(
        self, data: bytes, *, media_type: str, role: str, max_bytes: int
    ) -> ArtifactRef: ...


class CampaignCompletionStore(Protocol):
    """Durable plan/package index used by crash recovery."""

    def record_plan(self, plan: CampaignCompletionPlan) -> ArtifactRef: ...
    def read_plan(self, operation_id: str) -> tuple[CampaignCompletionPlan, ArtifactRef] | None: ...
    def record_final_evidence(self, evidence: CampaignFinalEvidenceRecord) -> ArtifactRef: ...
    def read_final_evidence(
        self, operation_id: str
    ) -> tuple[CampaignFinalEvidenceRecord, ArtifactRef] | None: ...
    def record_package(self, package: IntegrationCampaignEvidencePackage) -> ArtifactRef: ...
    def read_package(
        self, operation_id: str
    ) -> tuple[IntegrationCampaignEvidencePackage, ArtifactRef] | None: ...


class CampaignMainState(Protocol):
    def head_commit(self) -> str: ...


def campaign_open_identity(
    publication: CandidatePublicationBinding, opened: CampaignOpened
) -> Sha256Digest:
    """Bind a recoverable PR preparation to its exact publication and target."""
    return canonical_digest(
        {
            "repository_digest": publication.repository_digest,
            "publication_evidence_digest": publication.publication_evidence_digest,
            "candidate_ref": publication.candidate_ref,
            "candidate_commit": publication.candidate_commit,
            "pull_request_number": opened.pull_request_number,
            "pull_request_url": opened.pull_request_url,
            "target_ref": opened.target_ref,
            "base_commit": opened.base_commit,
            "base_tree": opened.base_tree,
        }
    )


class IntegrationCampaignService:
    """Execute one staged campaign and persist its immutable evidence package."""

    _REQUIRED_GATES = frozenset(
        {"trusted_ci", "private_evaluation", "provenance", "integration_soak"}
    )

    def __init__(
        self,
        *,
        controller: PromotionController,
        promotion: IntegrationPromotionService,
        journal: IntegrationPromotionJournal,
        intake: CampaignIntakePort,
        quality: CampaignQualityPort,
        provider: CampaignProviderPort,
        publication_verifier: CampaignPublicationVerifier,
        evidence_resolver: CampaignEvidenceResolver,
        artifact_writer: CampaignArtifactWriter,
        main_state: CampaignMainState,
        trusted_config: PromotionControllerConfig,
        completion_journal: CampaignCompletionStore | None = None,
        max_package_bytes: int = 4 * 1024 * 1024,
    ) -> None:
        if max_package_bytes <= 0:
            raise ValueError("max_package_bytes must be positive")
        self._controller = controller
        self._promotion = promotion
        self._journal = journal
        if completion_journal is not None:
            self._completion_journal: CampaignCompletionStore | None = completion_journal
        elif hasattr(journal, "root"):
            self._completion_journal = CampaignCompletionJournal(journal.root)  # type: ignore[attr-defined]
        else:
            # Retain compatibility with small pre-recovery test doubles. Real
            # journal wiring always has a root and takes the durable path.
            self._completion_journal = None
        self._intake = intake
        self._quality = quality
        self._provider = provider
        self._publication_verifier = publication_verifier
        self._evidence_resolver = evidence_resolver
        self._artifact_writer = artifact_writer
        self._main_state = main_state
        self._trusted_config = trusted_config
        self._max_package_bytes = max_package_bytes

    def run(
        self,
        request: IntegrationCampaignRequest,
        *,
        publication: CandidatePublicationBinding,
    ) -> IntegrationCampaignResult:
        """Run the non-circular lifecycle; never retry the promotion call."""

        main_before = self._main_state.head_commit()
        intake = self._intake.collect(request)
        self._validate_intake(request, publication, intake)
        self._validate_publication(publication)

        # Opening a PR is the first hosted mutation and intentionally requires
        # only trusted publication/base facts, never a candidate-selected policy.
        opened = self._provider.open_or_reconcile(publication)
        self._validate_opened(opened, publication)
        discovery = self._provider.discover(opened, publication)
        self._validate_discovery(discovery, opened, publication)
        if discovery.main_before_commit != main_before:
            raise IntegrationCampaignPrerequisiteError(
                "provider main observation changed during preparation"
            )

        quality = self._quality.evaluate(request, intake, discovery)
        self._validate_quality(intake, quality, discovery)
        promotion_input = intake.model_copy(
            update={
                "gate_attestations": list(quality.gate_attestations),
                "reviewer_attestations": list(quality.reviewer_attestations),
                "rollback_attestation": quality.rollback_attestation,
                "evidence_digests": sorted(
                    {
                        intake.source_provenance_digest,
                        *(item.evidence_digest for item in quality.gate_attestations),
                        *(item.evidence_digest for item in quality.reviewer_attestations),
                        quality.rollback_attestation.evidence_digest,
                    }
                ),
            }
        )
        dry_run = self._controller.dry_run(
            promotion_input,
            candidate_root=request.candidate_root,
            config=self._trusted_config,
        )
        self._validate_quality_base(quality, dry_run.bundle.snapshot.source_tree_digest)
        if not self._publication_verifier(publication, dry_run.bundle):
            raise IntegrationCampaignPrerequisiteError(
                "candidate publication verifier rejected evidence"
            )
        evidence_artifacts = self._evidence_resolver.resolve(dry_run.bundle.evidence_digests)
        self._validate_artifacts(evidence_artifacts, dry_run.bundle.evidence_digests)

        prepared = self._provider.bind(
            publication, dry_run.bundle, dry_run.bundle_digest, opened, discovery
        )
        self._validate_preparation(prepared, publication, dry_run, discovery)
        if not prepared.marker_verified:
            raise IntegrationCampaignPrerequisiteError("provider campaign marker was not verified")
        if prepared.marker_digest is not None:
            marker_check = campaign_marker_digest(
                prepared.template.bind_lease("marker-check", "sha256:" + "0" * 64)
            )
            if marker_check != prepared.marker_digest:
                raise IntegrationCampaignPrerequisiteError(
                    "provider campaign marker does not match operation identity"
                )

        operation_id = prepared.template.operation_id
        if self._completion_journal is not None:
            self._completion_journal.record_plan(
                self._completion_plan(
                    publication=publication,
                    dry_run=dry_run,
                    evidence_artifacts=evidence_artifacts,
                    opened=opened,
                    discovery=discovery,
                    prepared=prepared,
                )
            )
        report = self._promotion.promote(
            dry_run.bundle,
            publication=publication,
            bundle_digest=dry_run.bundle_digest,
            operation_id=operation_id,
            intent_factory=lambda lease: prepared.template.bind_lease(lease.identity, lease.digest),
        )
        if report.outcome not in {"applied", "already_applied"}:
            return IntegrationCampaignResult(report=report)

        if self._completion_journal is not None:
            return self.finalize(operation_id)

        intent = self._read_intent(operation_id)
        receipt = self._read_receipt(operation_id)
        final = self._provider.final_evidence(intent, report, prepared.observation)
        main_after = self._main_state.head_commit()
        if main_before != main_after:
            raise IntegrationCampaignUnsafeError("main changed during integration campaign")
        lease_record = self._journal.read_lease_evidence(operation_id)
        if lease_record is None:
            raise IntegrationCampaignUnsafeError(
                "promotion lease timestamps were not durably captured"
            )
        _, lease_ref = lease_record
        if lease_ref.role != "promotion-lease-evidence":
            raise IntegrationCampaignUnsafeError("lease evidence artifact has an unexpected role")
        package = IntegrationCampaignEvidencePackage(
            bundle=dry_run.bundle,
            publication=publication,
            evidence_artifacts=list(evidence_artifacts),
            intent=intent,
            observation=prepared.observation,
            merge_result=final.merge_result,
            reconciliation=final.reconciliation,
            receipt=receipt,
            report=report,
            bundle_digest=dry_run.bundle_digest,
            intent_digest=canonical_digest(intent),
            receipt_digest=canonical_digest(receipt),
            campaign_marker_digest=campaign_marker_digest(intent),
            lease_evidence=lease_record[0],
            lease_evidence_artifact=lease_ref,
            main_before_commit=discovery.main_before_commit,
            main_after_commit=main_after,
            deploy_performed=False,
        )
        package_data = canonical_bytes(package)
        package_ref = self._artifact_writer.put_bytes(
            package_data,
            media_type="application/vnd.avo.integration-campaign+json",
            role="integration-campaign-evidence",
            max_bytes=self._max_package_bytes,
        )
        if package_ref.digest != "sha256:" + hashlib.sha256(package_data).hexdigest():
            raise IntegrationCampaignUnsafeError("campaign package artifact digest mismatch")
        return IntegrationCampaignResult(
            report=report, package=package, package_artifact=package_ref
        )

    def finalize(self, operation_id: str) -> IntegrationCampaignResult:
        """Finish a promoted campaign solely from durable records.

        Recovery never reruns intake, quality evaluation, PR preparation, or
        promotion. A package already indexed is returned byte-for-byte by its
        content address; otherwise the durable plan is completed exactly once.
        """
        store = self._completion_journal
        if store is None:
            raise IntegrationCampaignUnsafeError("campaign completion journal is not configured")
        try:
            planned = store.read_plan(operation_id)
            if planned is None:
                raise IntegrationCampaignUnsafeError("campaign completion plan is missing")
            plan, _plan_ref = planned
            if plan.operation_id != operation_id:
                raise IntegrationCampaignUnsafeError("campaign completion plan operation mismatch")
            existing = store.read_package(operation_id)
            if existing is not None:
                package, package_ref = existing
                self._assert_package_plan(package, plan)
                self._release_recovered_lease(package.intent)
                return IntegrationCampaignResult(
                    report=package.report, package=package, package_artifact=package_ref
                )
            intent = self._read_intent(operation_id)
            receipt = self._read_receipt(operation_id)
            lease_record = self._journal.read_lease_evidence(operation_id)
            if lease_record is None:
                raise IntegrationCampaignUnsafeError("promotion lease evidence is missing")
            self._assert_plan_intent_receipt(plan, intent, receipt)
            if receipt.outcome not in {"applied", "already_applied"}:
                raise IntegrationCampaignUnsafeError(
                    "completion requires an applied or already-applied receipt"
                )
            report = IntegrationPromotionReport(
                operation_id=operation_id,
                outcome=receipt.outcome,
                intent_digest=canonical_digest(intent),
                receipt_digest=canonical_digest(receipt),
                checks=["recovered", "receipt_durable"],
                errors=[receipt.error] if receipt.error else [],
            )
            durable_final = store.read_final_evidence(operation_id)
            if durable_final is None:
                final = self._provider.final_evidence(intent, report, plan.preparation.observation)
                store.record_final_evidence(
                    CampaignFinalEvidenceRecord(
                        operation_id=operation_id,
                        reconciliation=final.reconciliation,
                        merge_result=final.merge_result,
                    )
                )
            else:
                final_record, _final_ref = durable_final
                if final_record.operation_id != operation_id:
                    raise IntegrationCampaignUnsafeError(
                        "durable final evidence operation mismatch"
                    )
                final = CampaignFinalEvidence(
                    reconciliation=final_record.reconciliation,
                    merge_result=final_record.merge_result,
                )
            main_after = self._main_state.head_commit()
            if main_after != plan.main_before_commit:
                raise IntegrationCampaignUnsafeError("main changed during integration campaign")
            package = IntegrationCampaignEvidencePackage(
                bundle=plan.bundle,
                publication=plan.publication,
                evidence_artifacts=list(plan.evidence_artifacts),
                intent=intent,
                observation=plan.preparation.observation,
                merge_result=final.merge_result,
                reconciliation=final.reconciliation,
                receipt=receipt,
                report=report,
                bundle_digest=plan.bundle_digest,
                intent_digest=canonical_digest(intent),
                receipt_digest=canonical_digest(receipt),
                campaign_marker_digest=campaign_marker_digest(intent),
                lease_evidence=lease_record[0],
                lease_evidence_artifact=lease_record[1],
                main_before_commit=plan.main_before_commit,
                main_after_commit=main_after,
                deploy_performed=False,
            )
            data = canonical_bytes(package)
            written = self._artifact_writer.put_bytes(
                data,
                media_type="application/vnd.avo.integration-campaign+json",
                role="integration-campaign-evidence",
                max_bytes=self._max_package_bytes,
            )
            if written.digest != "sha256:" + hashlib.sha256(data).hexdigest():
                raise IntegrationCampaignUnsafeError("campaign package artifact digest mismatch")
            package_ref = store.record_package(package)
            self._release_recovered_lease(intent)
            return IntegrationCampaignResult(
                report=package.report, package=package, package_artifact=package_ref
            )
        except IntegrationCampaignUnsafeError:
            raise
        except (ValueError, RuntimeError, OSError) as exc:
            raise IntegrationCampaignUnsafeError(str(exc)) from exc

    def resume(self, operation_id: str) -> IntegrationCampaignResult:
        """Resume a prepared campaign without rerunning publication or PR setup.

        This is the restart path for a durable plan whose promotion intent was
        written but whose receipt/package was not.  The promotion service's
        existing-intent branch performs read-only reconciliation and therefore
        cannot submit a second merge.  A plan without an intent is deliberately
        rejected: replaying preparation after a crash would risk a new hosted
        mutation and must be operator-reconciled instead.
        """
        store = self._completion_journal
        if store is None:
            raise IntegrationCampaignUnsafeError("campaign completion journal is not configured")
        planned = store.read_plan(operation_id)
        if planned is None:
            raise IntegrationCampaignUnsafeError("campaign completion plan is missing")
        intent = self._journal.read_intent(operation_id)
        if intent is None:
            raise IntegrationCampaignUnsafeError(
                "campaign plan has no durable promotion intent; manual reconciliation required"
            )
        if self._journal.read_receipt(operation_id) is not None:
            return self.finalize(operation_id)
        plan, _plan_ref = planned
        report = self._promotion.promote(
            plan.bundle,
            publication=plan.publication,
            bundle_digest=plan.bundle_digest,
            operation_id=operation_id,
            intent_factory=lambda lease: plan.preparation.template.bind_lease(
                lease.identity, lease.digest
            ),
        )
        if report.outcome not in {"applied", "already_applied"}:
            return IntegrationCampaignResult(report=report)
        return self.finalize(operation_id)

    @staticmethod
    def _completion_plan(
        *,
        publication: CandidatePublicationBinding,
        dry_run: PromotionDryRunResult,
        evidence_artifacts: Sequence[ArtifactRef],
        opened: CampaignOpened,
        discovery: CampaignDiscovery,
        prepared: CampaignPreparation,
    ) -> CampaignCompletionPlan:
        return CampaignCompletionPlan(
            operation_id=prepared.template.operation_id,
            bundle=dry_run.bundle,
            publication=publication,
            evidence_artifacts=list(evidence_artifacts),
            bundle_digest=dry_run.bundle_digest,
            opened=CampaignOpenedEvidence(
                pull_request_number=opened.pull_request_number,
                pull_request_url=opened.pull_request_url,
                target_ref=opened.target_ref,
                base_commit=opened.base_commit,
                base_tree=opened.base_tree,
                open_identity=opened.open_identity,
            ),
            discovery=CampaignDiscoveryEvidence(
                observation=discovery.observation,
                main_before_commit=discovery.main_before_commit,
                open_identity=discovery.open_identity,
            ),
            preparation=CampaignPreparationEvidence(
                template=prepared.template,
                observation=prepared.observation,
                marker_verified=prepared.marker_verified,
                open_identity=prepared.open_identity,
                marker_digest=prepared.marker_digest,
            ),
            main_before_commit=discovery.main_before_commit,
        )

    @staticmethod
    def _assert_plan_intent_receipt(
        plan: CampaignCompletionPlan,
        intent: IntegrationPromotionIntent,
        receipt: IntegrationPromotionReceipt,
    ) -> None:
        expected = plan.preparation.template.bind_lease(
            intent.controller_lease_identity, intent.controller_lease_digest
        )
        if intent != expected:
            raise IntegrationCampaignUnsafeError("durable intent conflicts with completion plan")
        if receipt.operation_id != plan.operation_id or receipt.intent_digest != canonical_digest(
            intent
        ):
            raise IntegrationCampaignUnsafeError("durable receipt conflicts with completion plan")

    @staticmethod
    def _assert_package_plan(
        package: IntegrationCampaignEvidencePackage, plan: CampaignCompletionPlan
    ) -> None:
        if (
            package.intent.operation_id != plan.operation_id
            or package.bundle_digest != plan.bundle_digest
            or package.publication != plan.publication
            or {item.digest for item in package.evidence_artifacts}
            != {item.digest for item in plan.evidence_artifacts}
            or package.main_before_commit != plan.main_before_commit
        ):
            raise IntegrationCampaignUnsafeError("durable package conflicts with completion plan")

    def _release_recovered_lease(self, intent: IntegrationPromotionIntent) -> None:
        try:
            self._journal.release_matching_lease(
                intent.repository_digest,
                intent.target_ref,
                intent.operation_id,
                intent.controller_lease_identity,
                intent.controller_lease_digest,
            )
        except (ValueError, RuntimeError, OSError) as exc:
            raise IntegrationCampaignUnsafeError("recovered lease could not be released") from exc

    @staticmethod
    def _validate_intake(
        request: IntegrationCampaignRequest,
        publication: CandidatePublicationBinding,
        intake: PromotionDryRunInput,
    ) -> None:
        if (
            intake.candidate_id != request.candidate_id
            or intake.proposer_id != request.proposer_id
            or intake.source_provenance_digest != request.source_provenance_digest
            or request.source_provenance_digest != publication.publication_evidence_digest
        ):
            raise IntegrationCampaignPrerequisiteError(
                "candidate intake provenance is not bound to controller publication"
            )
        if intake.gate_attestations or intake.reviewer_attestations or intake.rollback_attestation:
            raise IntegrationCampaignPrerequisiteError(
                "candidate intake cannot supply policy or gate evidence"
            )
        if intake.evidence_digests != [intake.source_provenance_digest]:
            raise IntegrationCampaignPrerequisiteError(
                "candidate intake evidence manifest is not source-only"
            )

    @staticmethod
    def _validate_publication(publication: CandidatePublicationBinding) -> None:
        if not publication.verified:
            raise IntegrationCampaignPrerequisiteError("candidate publication is not verified")

    @staticmethod
    def _validate_opened(opened: CampaignOpened, publication: CandidatePublicationBinding) -> None:
        if (
            opened.pull_request_number <= 0
            or not opened.pull_request_url.startswith("https://")
            or opened.base_commit != publication.base_commit
            or opened.base_tree != publication.base_tree
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", opened.open_identity)
            or opened.open_identity != campaign_open_identity(publication, opened)
        ):
            raise IntegrationCampaignPrerequisiteError("opened PR is not bound to publication base")

    @staticmethod
    def _validate_discovery(
        discovery: CampaignDiscovery,
        opened: CampaignOpened,
        publication: CandidatePublicationBinding,
    ) -> None:
        observation = discovery.observation
        if (
            discovery.open_identity != opened.open_identity
            or observation.pull_request_number != opened.pull_request_number
            or observation.pull_request_url != opened.pull_request_url
            or observation.base_commit != publication.base_commit
            or observation.base_tree != publication.base_tree
            or observation.head_ref != publication.candidate_ref
            or observation.head_commit != publication.candidate_commit
            or observation.candidate_tree != publication.candidate_tree
            or observation.base_ref != opened.target_ref
        ):
            raise IntegrationCampaignPrerequisiteError(
                "provider discovery is not publication-bound"
            )

    def _validate_quality(
        self,
        intake: PromotionDryRunInput,
        quality: CampaignQualityEvidence,
        discovery: CampaignDiscovery,
    ) -> None:
        gates = list(quality.gate_attestations)
        names = {item.gate_name for item in gates}
        if frozenset(names) != self._REQUIRED_GATES or len(gates) != len(names):
            raise IntegrationCampaignPrerequisiteError("ordinary campaign gates are incomplete")
        if any(
            not item.passed or item.candidate_digest != intake.candidate_digest for item in gates
        ):
            raise IntegrationCampaignPrerequisiteError("ordinary campaign gate failed")
        observation = discovery.observation
        if (
            quality.synthetic_merge_commit != observation.synthetic_merge_commit
            or quality.synthetic_merge_tree != observation.synthetic_merge_tree
            or quality.protection_evidence_digest != observation.protection_evidence_digest
            or quality.check_evidence_manifest_digest != observation.check_evidence_manifest_digest
        ):
            raise IntegrationCampaignPrerequisiteError(
                "quality evidence is not bound to provider discovery"
            )
        trusted_ci = next(item for item in gates if item.gate_name == "trusted_ci")
        if trusted_ci.evidence_digest != quality.check_evidence_manifest_digest:
            raise IntegrationCampaignPrerequisiteError(
                "trusted CI attestation is not the discovered check manifest"
            )
        reviewers = list(quality.reviewer_attestations)
        if len(reviewers) < 2 or len({item.reviewer_id for item in reviewers}) != len(reviewers):
            raise IntegrationCampaignPrerequisiteError("two independent reviewers are required")
        policy = self._trusted_config.policy
        proposer_domain = policy.proposer_domains.get(intake.proposer_id)
        domains: set[str] = set()
        for reviewer in reviewers:
            if not reviewer.approved or reviewer.candidate_digest != intake.candidate_digest:
                raise IntegrationCampaignPrerequisiteError("independent review did not approve")
            domain = policy.reviewer_domains.get(reviewer.reviewer_id)
            if domain is None or domain == proposer_domain:
                raise IntegrationCampaignPrerequisiteError("reviewer domain is not independent")
            domains.add(domain)
        if len(domains) < 2:
            raise IntegrationCampaignPrerequisiteError("reviewers must represent two domains")
        rollback = quality.rollback_attestation
        if not rollback.available or rollback.candidate_digest != intake.candidate_digest:
            raise IntegrationCampaignPrerequisiteError("rollback evidence is unavailable")
        refs = {item.digest for item in quality.evidence_artifacts}
        expected = {
            *(item.evidence_digest for item in gates),
            *(item.evidence_digest for item in reviewers),
            rollback.evidence_digest,
        }
        if refs != expected:
            raise IntegrationCampaignPrerequisiteError(
                "quality artifacts do not match attestations"
            )

    @staticmethod
    def _validate_quality_base(quality: CampaignQualityEvidence, base_digest: str) -> None:
        evidence = [
            *quality.gate_attestations,
            *quality.reviewer_attestations,
            quality.rollback_attestation,
        ]
        if any(item.base_digest != base_digest for item in evidence):
            raise IntegrationCampaignPrerequisiteError(
                "quality evidence is bound to a different integration base"
            )

    @staticmethod
    def _validate_preparation(
        prepared: CampaignPreparation,
        publication: CandidatePublicationBinding,
        dry_run: PromotionDryRunResult,
        discovery: CampaignDiscovery,
    ) -> None:
        template = prepared.template
        if (
            prepared.open_identity != discovery.open_identity
            or template.bundle_digest != dry_run.bundle_digest
            or template.candidate_digest != publication.candidate_digest
            or template.base_commit != publication.base_commit
            or template.base_tree != publication.base_tree
            or template.candidate_ref != publication.candidate_ref
            or template.candidate_commit != publication.candidate_commit
            or template.candidate_tree != publication.candidate_tree
        ):
            raise IntegrationCampaignPrerequisiteError(
                "provider binding is not bound to publication and bundle"
            )
        observation = prepared.observation
        discovered = discovery.observation
        if (
            observation.pull_request_number != template.pull_request_number
            or observation.pull_request_url != template.pull_request_url
            or observation.head_ref != template.candidate_ref
            or observation.head_commit != template.candidate_commit
            or observation.candidate_tree != template.candidate_tree
            or observation.base_ref != template.target_ref
            or observation.base_commit != template.base_commit
            or observation.synthetic_merge_tree != template.synthetic_merge_tree
            or observation.protection_evidence_digest != template.protection_evidence_digest
            or observation.check_evidence_manifest_digest != template.check_evidence_manifest_digest
            or observation.pull_request_number != discovered.pull_request_number
        ):
            raise IntegrationCampaignPrerequisiteError("provider observation is not intent-bound")

    @staticmethod
    def _validate_artifacts(refs: Sequence[ArtifactRef], digests: Sequence[str]) -> None:
        if {ref.digest for ref in refs} != set(digests):
            raise IntegrationCampaignPrerequisiteError(
                "evidence resolver returned incomplete artifacts"
            )

    def _read_intent(self, operation_id: str) -> IntegrationPromotionIntent:
        record = self._journal.read_intent(operation_id)
        if record is None:
            raise IntegrationCampaignUnsafeError("promotion intent was not durably recorded")
        return record[0]

    def _read_receipt(self, operation_id: str) -> IntegrationPromotionReceipt:
        record = self._journal.read_receipt(operation_id)
        if record is None:
            raise IntegrationCampaignUnsafeError("promotion receipt was not durably recorded")
        return record[0]


__all__ = [
    "CampaignArtifactWriter",
    "CampaignCompletionStore",
    "CampaignDiscovery",
    "CampaignEvidenceResolver",
    "CampaignFinalEvidence",
    "CampaignIntakePort",
    "CampaignMainState",
    "CampaignOpened",
    "CampaignPreparation",
    "CampaignProviderPort",
    "CampaignPublicationVerifier",
    "CampaignQualityEvidence",
    "CampaignQualityPort",
    "IntegrationCampaignPrerequisiteError",
    "IntegrationCampaignRequest",
    "IntegrationCampaignResult",
    "IntegrationCampaignService",
    "IntegrationCampaignUnsafeError",
    "campaign_open_identity",
]
