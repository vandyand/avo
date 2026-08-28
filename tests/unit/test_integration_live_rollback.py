from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from avo_correlate.adapters.artifacts.live_rollback_journal import (
    LiveRollbackJournal,
    LiveRollbackJournalError,
)
from avo_correlate.application.integration_live_rollback_service import (
    LiveIntegrationRollbackService,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_drill import (
    IntegrationDrillCaseResult,
    IntegrationDrillRollbackAuthorization,
    IntegrationDrillRollbackIntent,
    IntegrationDrillRollbackReceipt,
    IntegrationDrillSoakObservation,
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
    integration_operation_id,
)
from avo_correlate.contracts.promotion_bundle import promotion_bundle_digest
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.test_integration_campaign_contracts import (
    _package,  # pyright: ignore[reportPrivateUsage]
)

D = "sha256:" + "a" * 64
MAIN = "a" * 40
CANDIDATE = "d" * 40


def _ref(value: object, role: str, media_type: str) -> ArtifactRef:
    return ArtifactRef(
        digest=canonical_digest(value),
        size_bytes=1,
        media_type=media_type,
        role=role,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def _package_fixture() -> LiveRollbackEvidencePackage:
    canary = _package()
    failed = canary.receipt.applied_result_commit
    failed_tree = canary.receipt.applied_result_tree
    assert failed is not None and failed_tree is not None
    request = IntegrationRollbackRequest(
        operation_id=canonical_digest({"live": "rollback"}),
        promotion_operation_id=canonical_digest({"live": "promotion"}),
        repository_digest=canary.intent.repository_digest,
        target_ref=canary.intent.target_ref,
        main_before_commit=MAIN,
        failed_integration_head_commit=failed,
        failed_integration_head_tree=failed_tree,
        restore_to_commit=canary.intent.base_commit,
        restore_to_tree=canary.intent.base_tree,
        rollback_candidate_commit=CANDIDATE,
        rollback_candidate_parent_commit=failed,
    )
    bundle = canary.bundle.model_copy(
        update={
            "snapshot": canary.bundle.snapshot.model_copy(
                update={"commit": failed, "tree": failed_tree}
            )
        }
    )
    bundle_digest = promotion_bundle_digest(bundle)
    promotion_candidate_ref = "refs/heads/avo/rollback/live"
    promotion_operation_id = integration_operation_id(
        repository_digest=request.repository_digest,
        pull_request_number="99",
        candidate_ref=promotion_candidate_ref,
        target_ref=request.target_ref,
        base_commit=failed,
        candidate_commit=CANDIDATE,
        candidate_head_commit=CANDIDATE,
        target_base_commit=failed,
        synthetic_merge_commit="7" * 40,
        bundle_digest=bundle_digest,
        candidate_digest=D,
        publication_evidence_digest=D,
        provider_identity="github",
        provider_api_version="2026-01",
        merge_method="squash",
    )
    request = request.model_copy(update={"promotion_operation_id": promotion_operation_id})
    publication = CandidatePublicationBinding.model_construct(
        repository_digest=request.repository_digest,
        base_commit=failed,
        base_tree=failed_tree,
        candidate_digest=D,
        candidate_ref=promotion_candidate_ref,
        candidate_commit=CANDIDATE,
        candidate_tree=request.restore_to_tree,
        controller_publisher_identity="controller",
        publication_evidence_digest=D,
        verified=True,
    )
    promotion_intent = IntegrationPromotionIntent.model_construct(
        operation_id=request.promotion_operation_id,
        repository_digest=request.repository_digest,
        controller_lease_digest=D,
        controller_lease_identity="lease",
        candidate_ref=publication.candidate_ref,
        target_ref=request.target_ref,
        base_commit=failed,
        base_tree=failed_tree,
        candidate_commit=CANDIDATE,
        candidate_tree=request.restore_to_tree,
        candidate_repository_digest=request.repository_digest,
        candidate_head_ref=publication.candidate_ref,
        candidate_head_commit=CANDIDATE,
        candidate_head_tree=request.restore_to_tree,
        target_repository_digest=request.repository_digest,
        target_base_ref=request.target_ref,
        target_base_commit=failed,
        target_base_tree=failed_tree,
        synthetic_merge_commit="7" * 40,
        synthetic_merge_tree=request.restore_to_tree,
        bundle_digest=bundle_digest,
        candidate_digest=D,
        controller_config_digest=D,
        protection_evidence_digest=D,
        evidence_manifest_digest=D,
        check_evidence_manifest_digest=D,
        publication_evidence_digest=D,
        pull_request_number=99,
        pull_request_url="https://github.com/vandyand/avo/pull/99",
        provider_identity="github",
        provider_api_version="2026-01",
        merge_method="squash",
    )
    promotion_receipt = IntegrationPromotionReceipt.model_construct(
        operation_id=request.promotion_operation_id,
        intent_digest=canonical_digest(promotion_intent),
        bundle_digest=bundle_digest,
        expected_target_ref=request.target_ref,
        expected_candidate_commit=CANDIDATE,
        expected_candidate_tree=request.restore_to_tree,
        expected_base_commit=failed,
        expected_protection_evidence_digest=D,
        expected_provider_identity="github",
        expected_provider_api_version="2026-01",
        merge_method="squash",
        applied_result_commit="6" * 40,
        applied_result_tree=request.restore_to_tree,
        applied_result_parent_commit=failed,
        outcome="applied",
        observed_target_ref=request.target_ref,
        observed_base_commit=failed,
        observed_head_commit="6" * 40,
        observed_head_tree=request.restore_to_tree,
        observed_protection_evidence_digest=D,
        observed_provider_identity="github",
        observed_provider_api_version="2026-01",
        observation_digest=D,
    )
    auth = IntegrationDrillRollbackAuthorization.model_construct(
        operation_id=request.operation_id,
        authorization_id=D,
        repository_digest=request.repository_digest,
        target_ref=request.target_ref,
        main_before_commit=MAIN,
        main_after_commit=MAIN,
        target_head_commit=failed,
        target_head_tree=failed_tree,
        target_parents=[],
        failed_integration_head_commit=failed,
        failed_integration_head_tree=failed_tree,
        restore_to_commit=request.restore_to_commit,
        restore_to_tree=request.restore_to_tree,
        rollback_candidate_commit=CANDIDATE,
        rollback_candidate_parent_commit=failed,
        issuer="trusted-rollback",
        reason="failed integration soak",
        authorized=True,
    )
    rollback_intent = IntegrationDrillRollbackIntent.model_construct(
        operation_id=request.operation_id,
        promotion_operation_id=request.promotion_operation_id,
        intent_digest=D,
        authorization_id=D,
        attester_identity="live-attester",
        authorized=True,
        reason="failed integration soak",
        repository_digest=request.repository_digest,
        target_ref=request.target_ref,
        main_before_commit=MAIN,
        main_after_commit=MAIN,
        target_head_commit=failed,
        target_head_tree=failed_tree,
        target_parents=[],
        deploy_performed=False,
        failed_integration_head_commit=failed,
        failed_integration_head_tree=failed_tree,
        restore_to_commit=request.restore_to_commit,
        restore_to_tree=request.restore_to_tree,
        rollback_candidate_commit=CANDIDATE,
        rollback_candidate_parent_commit=failed,
    )
    rollback_intent = rollback_intent.model_copy(
        update={
            "intent_digest": canonical_digest(
                rollback_intent.model_dump(exclude={"intent_digest"}, mode="json")
            )
        }
    )
    rollback_receipt = IntegrationDrillRollbackReceipt.model_construct(
        operation_id=request.operation_id,
        promotion_operation_id=request.promotion_operation_id,
        intent_digest=rollback_intent.intent_digest,
        receipt_digest=D,
        outcome="applied",
        attester_identity="live-attester",
        repository_digest=request.repository_digest,
        target_ref=request.target_ref,
        main_before_commit=MAIN,
        main_after_commit=MAIN,
        target_head_commit=promotion_receipt.applied_result_commit,
        target_head_tree=request.restore_to_tree,
        target_parents=[failed],
        deploy_performed=False,
        failed_integration_head_commit=failed,
        failed_integration_head_tree=failed_tree,
        restore_to_commit=request.restore_to_commit,
        restore_to_tree=request.restore_to_tree,
        rollback_candidate_commit=CANDIDATE,
        rollback_candidate_parent_commit=failed,
        result_commit=promotion_receipt.applied_result_commit,
        result_tree=request.restore_to_tree,
    )
    rollback_receipt = rollback_receipt.model_copy(
        update={
            "receipt_digest": canonical_digest(
                rollback_receipt.model_dump(exclude={"receipt_digest"}, mode="json")
            )
        }
    )
    soak = IntegrationDrillSoakObservation.model_construct(
        operation_id=request.operation_id,
        observation_id=D,
        repository_digest=request.repository_digest,
        target_ref=request.target_ref,
        main_before_commit=MAIN,
        main_after_commit=MAIN,
        target_head_commit=failed,
        target_head_tree=failed_tree,
        target_parents=[],
        deploy_performed=False,
        outcome="failed",
        error="soak failed",
        evidence_artifacts=[],
    )
    soak = soak.model_copy(
        update={
            "observation_id": canonical_digest(
                soak.model_dump(exclude={"observation_id"}, mode="json")
            )
        }
    )
    case = IntegrationDrillCaseResult.model_construct(
        case_id=7,
        operation_id=request.operation_id,
        repository_digest=request.repository_digest,
        target_ref=request.target_ref,
        main_before_commit=MAIN,
        main_after_commit=MAIN,
        target_head_commit=promotion_receipt.applied_result_commit,
        target_head_tree=request.restore_to_tree,
        target_parents=[failed],
        deploy_performed=False,
        outcome="applied",
        attester_identity="live-attester",
        evidence_artifacts=[
            ArtifactRef.model_construct(digest=D, size_bytes=1, media_type="x", role="x")
        ],
    )
    lease = PromotionLeaseEvidence.model_construct(
        operation_id=request.promotion_operation_id,
        repository_digest=request.repository_digest,
        target_ref=request.target_ref,
        identity="lease",
        acquired_at=datetime(2026, 1, 1, tzinfo=UTC),
        expires_at=datetime(2026, 1, 1, 0, 5, tzinfo=UTC),
        digest=D,
    )
    lease = lease.model_copy(
        update={
            "digest": canonical_digest(lease.model_dump(exclude={"digest"}, mode="json"))
        }
    )
    promotion_intent = promotion_intent.model_copy(
        update={"controller_lease_digest": lease.digest}
    )
    promotion_receipt = promotion_receipt.model_copy(
        update={"intent_digest": canonical_digest(promotion_intent)}
    )
    mutation = PromotionMutationAuthorization.model_construct(
        operation_id=request.promotion_operation_id,
        intent_digest=canonical_digest(promotion_intent),
        lease_identity="lease",
        lease_digest=D,
        authorized_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    report = IntegrationPromotionReport.model_construct(
        operation_id=request.promotion_operation_id,
        outcome="applied",
        intent_digest=canonical_digest(promotion_intent),
        receipt_digest=canonical_digest(promotion_receipt),
        checks=["protected_pr_squash"],
        errors=[],
    )
    values: dict[str, Any] = {
        "operation_id": request.operation_id,
        "canary_operation_id": canary.intent.operation_id,
        "canary_package": canary,
        "canary_package_artifact": _ref(
            canary, "integration-campaign-package", "application/vnd.avo.integration-campaign+json"
        ),
        "request": request,
        "soak": soak,
        "authorization": auth,
        "rollback_intent": rollback_intent,
        "rollback_receipt": rollback_receipt,
        "rollback_case": case,
        "bundle": bundle,
        "publication": publication,
        "bundle_digest": bundle_digest,
        "promotion_intent": promotion_intent,
        "promotion_lease_evidence": lease,
        "promotion_mutation_authorization": mutation,
        "promotion_receipt": promotion_receipt,
        "promotion_report": report,
        "main_before_commit": MAIN,
        "main_after_commit": MAIN,
    }
    records = {
        "integration-drill-soak": soak,
        "integration-drill-rollback-authorization": auth,
        "integration-drill-rollback-intent": rollback_intent,
        "integration-drill-rollback-receipt": rollback_receipt,
        "integration-drill-case": case,
        "promotion-intent": promotion_intent,
        "promotion-lease-evidence": lease,
        "promotion-mutation-authorization": mutation,
        "promotion-receipt": promotion_receipt,
    }
    values["artifacts"] = [values["canary_package_artifact"]] + [
            _ref(
                record,
                role,
                "application/vnd.avo.integration-promotion+json"
                if role.startswith("promotion-")
                else "application/vnd.avo.integration-drill-"
                f"{role.removeprefix('integration-drill-')}+json",
            )
        for role, record in records.items()
    ]
    return LiveRollbackEvidencePackage.model_validate(values)


def test_live_package_rejects_stale_canary_topology() -> None:
    package = _package_fixture()
    stale_request = package.request.model_copy(
        update={"failed_integration_head_commit": "1" * 40}
    )
    with pytest.raises(ValueError, match=r"canary|stale"):
        package.model_copy(update={"request": stale_request}).validate_package()  # pyright: ignore[reportCallIssue]


def test_live_package_journal_replays_and_rejects_tamper(tmp_path: Path) -> None:
    package = _package_fixture()
    journal = LiveRollbackJournal(tmp_path)
    first = journal.record_package(package)
    second = journal.record_package(package)
    assert second == first

    index = tmp_path / "live-rollback-index" / "package" / (
        package.operation_id.removeprefix("sha256:") + ".json"
    )
    index.write_text(
        index.read_text(encoding="utf-8").replace(first.digest, "sha256:" + "f" * 64),
        encoding="utf-8",
    )
    with pytest.raises(LiveRollbackJournalError):
        journal.read_package(package.operation_id)


def test_live_service_completed_package_is_read_only_replay(tmp_path: Path) -> None:
    package = _package_fixture()
    del tmp_path
    journal = _ReplayJournal(package)
    rollback_journal = cast(Any, SimpleNamespace())
    service = LiveIntegrationRollbackService(
        cast(Any, _FailIfCalledRollback()),
        rollback_journal,
        journal,
        cast(Any, SimpleNamespace()),
        main_head_reader=lambda: package.request.main_before_commit,
    )
    result = service.run(
        package.request,
        canary_package=package.canary_package,
        canary_package_artifact=package.canary_package_artifact,
        authorization=package.authorization,
        bundle=package.bundle,
        publication=package.publication,
        bundle_digest=package.bundle_digest,
        intent_factory=lambda _lease: cast(Any, object()),
    )
    assert result.replayed
    assert result.package == package


def test_live_service_assembles_package_after_successful_rollback() -> None:
    package = _package_fixture()
    rollback = _SuccessfulRollback(package)
    service = LiveIntegrationRollbackService(
        cast(Any, rollback),
        cast(Any, _CaseJournal(package)),
        _RecordingJournal(),
        cast(Any, _PromotionEvidence(package)),
        main_head_reader=lambda: package.request.main_before_commit,
    )
    result = service.run(
        package.request,
        canary_package=package.canary_package,
        canary_package_artifact=package.canary_package_artifact,
        authorization=package.authorization,
        bundle=package.bundle,
        publication=package.publication,
        bundle_digest=package.bundle_digest,
        intent_factory=lambda _lease: cast(Any, object()),
    )
    assert not result.replayed
    assert result.package == package
    assert result.package_artifact is not None
    assert rollback.calls == 1


class _FailIfCalledRollback:
    def run(self, *_args: object, **_kwargs: object) -> object:
        raise AssertionError("completed live rollback replay must not call provider")


class _SuccessfulRollback:
    def __init__(self, package: LiveRollbackEvidencePackage) -> None:
        self.execution = LiveIntegrationRollbackService._execution_from_package(  # pyright: ignore[reportPrivateUsage]
            package
        )
        self.calls = 0

    def run(self, *_args: object, **_kwargs: object) -> object:
        self.calls += 1
        return self.execution


class _RecordingJournal:
    def __init__(self) -> None:
        self.package: LiveRollbackEvidencePackage | None = None

    def read_package(
        self, operation_id: str
    ) -> tuple[LiveRollbackEvidencePackage, ArtifactRef] | None:
        del operation_id
        return None

    def record_package(self, package: LiveRollbackEvidencePackage) -> ArtifactRef:
        self.package = package
        return _ref(
            package,
            "integration-live-rollback-package",
            "application/vnd.avo.integration-live-rollback+json",
        )


class _CaseJournal:
    def __init__(self, package: LiveRollbackEvidencePackage) -> None:
        self.package = package

    def read_case_result(
        self, operation_id: str, case_id: int
    ) -> tuple[IntegrationDrillCaseResult, ArtifactRef] | None:
        if operation_id != self.package.operation_id or case_id != 7:
            return None
        return self.package.rollback_case, next(
            reference
            for reference in self.package.artifacts
            if reference.role == "integration-drill-case"
        )


class _PromotionEvidence:
    def __init__(self, package: LiveRollbackEvidencePackage) -> None:
        self.package = package
        self.records = {
            "intent": (package.promotion_intent, "promotion-intent"),
            "lease": (package.promotion_lease_evidence, "promotion-lease-evidence"),
            "mutation": (
                package.promotion_mutation_authorization,
                "promotion-mutation-authorization",
            ),
            "receipt": (package.promotion_receipt, "promotion-receipt"),
        }

    def _read(self, operation_id: str, key: str) -> tuple[Any, ArtifactRef] | None:
        if operation_id != self.package.request.promotion_operation_id:
            return None
        value, role = self.records[key]
        return value, next(
            reference for reference in self.package.artifacts if reference.role == role
        )

    def read_intent(self, operation_id: str) -> tuple[Any, ArtifactRef] | None:
        return self._read(operation_id, "intent")

    def read_lease_evidence(self, operation_id: str) -> tuple[Any, ArtifactRef] | None:
        return self._read(operation_id, "lease")

    def read_mutation_authorization(self, operation_id: str) -> tuple[Any, ArtifactRef] | None:
        return self._read(operation_id, "mutation")

    def read_receipt(self, operation_id: str) -> tuple[Any, ArtifactRef] | None:
        return self._read(operation_id, "receipt")


class _ReplayJournal:
    def __init__(self, package: LiveRollbackEvidencePackage) -> None:
        self.package = package
        self.reference = _ref(
            package,
            "integration-live-rollback-package",
            "application/vnd.avo.integration-live-rollback+json",
        )

    def read_package(
        self, operation_id: str
    ) -> tuple[LiveRollbackEvidencePackage, ArtifactRef] | None:
        return (self.package, self.reference) if operation_id == self.package.operation_id else None

    def record_package(self, package: LiveRollbackEvidencePackage) -> ArtifactRef:
        assert package == self.package
        return self.reference
