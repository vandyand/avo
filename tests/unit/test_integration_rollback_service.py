from pathlib import Path
from typing import Any

import pytest

from avo_correlate.adapters.artifacts.drill_journal import IntegrationDrillJournal
from avo_correlate.application.integration_rollback_service import (
    IntegrationDrillRollbackService,
    IntegrationRollbackDrillError,
    IntegrationRollbackRequest,
    rollback_authorization_digest,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_drill import IntegrationDrillRollbackAuthorization
from avo_correlate.contracts.integration_promotion import (
    CandidatePublicationBinding,
    IntegrationPromotionIntent,
    IntegrationPromotionReceipt,
    IntegrationPromotionReport,
)
from avo_correlate.domain.canonical import canonical_digest

D = "sha256:" + "a" * 64
MAIN = "1" * 40
FAILED = "2" * 40
FAILED_TREE = "3" * 40
RESTORE = "4" * 40
RESTORE_TREE = "5" * 40
RESULT = "6" * 40
CANDIDATE = "7" * 40


class PromotionJournal:
    def __init__(self, receipt: IntegrationPromotionReceipt) -> None:
        self.receipt = receipt
        self.intent = IntegrationPromotionIntent.model_construct(
            operation_id=PROMOTION_OPERATION,
            repository_digest=D,
            target_ref="refs/heads/integration",
            candidate_ref="refs/heads/avo/rollback/case-7",
            base_commit=FAILED,
            base_tree=FAILED_TREE,
            candidate_commit=CANDIDATE,
            candidate_tree=RESTORE_TREE,
            candidate_head_ref="refs/heads/avo/rollback/case-7",
            candidate_head_commit=CANDIDATE,
            candidate_head_tree=RESTORE_TREE,
            target_base_ref="refs/heads/integration",
            target_base_commit=FAILED,
            target_base_tree=FAILED_TREE,
        )

    def read_receipt(
        self, operation_id: str
    ) -> tuple[IntegrationPromotionReceipt, ArtifactRef] | None:
        assert operation_id == self.receipt.operation_id
        return self.receipt, ArtifactRef.model_construct(
            digest=D, size_bytes=1, media_type="x", role="x"
        )

    def read_intent(
        self, operation_id: str
    ) -> tuple[IntegrationPromotionIntent, ArtifactRef] | None:
        assert operation_id == self.intent.operation_id
        return self.intent, ArtifactRef.model_construct(
            digest=D, size_bytes=1, media_type="x", role="x"
        )


class Promotion:
    def __init__(self) -> None:
        self.calls = 0

    def promote(self, *_args: Any, **kwargs: Any) -> IntegrationPromotionReport:
        self.calls += 1
        assert kwargs["operation_id"] == PROMOTION_OPERATION
        return IntegrationPromotionReport(
            operation_id=PROMOTION_OPERATION, outcome="applied", checks=["protected_pr_merge"]
        )


class Verifier:
    def verify(self, request: IntegrationRollbackRequest) -> None:
        del request


class RejectingVerifier:
    def verify(self, request: IntegrationRollbackRequest) -> None:
        del request
        raise RuntimeError("repository identity mismatch")


class RecoveringPromotionJournal(PromotionJournal):
    def __init__(self) -> None:
        super().__init__(promotion_receipt())
        self.ready = False

    def read_receipt(self, operation_id: str):
        return super().read_receipt(operation_id) if self.ready else None

    def read_intent(self, operation_id: str):
        return super().read_intent(operation_id) if self.ready else None


class RecoveringPromotion:
    def __init__(self, journal: RecoveringPromotionJournal) -> None:
        self.calls = 0
        self.journal = journal

    def promote(self, *_args: Any, **kwargs: Any) -> IntegrationPromotionReport:
        self.calls += 1
        assert kwargs["operation_id"] == PROMOTION_OPERATION
        if self.calls == 1:
            return IntegrationPromotionReport(
                operation_id=PROMOTION_OPERATION,
                outcome="reconciliation_required",
                checks=["merge_submitted"],
                errors=["receipt write interrupted"],
            )
        self.journal.ready = True
        return IntegrationPromotionReport(
            operation_id=PROMOTION_OPERATION, outcome="applied", checks=["reconciled_once"]
        )


OPERATION = canonical_digest({"drill": "case-7"})
PROMOTION_OPERATION = canonical_digest({"promotion": "case-7"})


def request() -> IntegrationRollbackRequest:
    return IntegrationRollbackRequest(
        operation_id=OPERATION,
        promotion_operation_id=PROMOTION_OPERATION,
        repository_digest=D,
        target_ref="refs/heads/integration",
        main_before_commit=MAIN,
        failed_integration_head_commit=FAILED,
        failed_integration_head_tree=FAILED_TREE,
        restore_to_commit=RESTORE,
        restore_to_tree=RESTORE_TREE,
        rollback_candidate_commit=CANDIDATE,
        rollback_candidate_parent_commit=FAILED,
    )


def authorization() -> IntegrationDrillRollbackAuthorization:
    auth = IntegrationDrillRollbackAuthorization(
        operation_id=OPERATION,
        authorization_id=D,
        repository_digest=D,
        target_ref="refs/heads/integration",
        main_before_commit=MAIN,
        main_after_commit=MAIN,
        target_head_commit=FAILED,
        target_head_tree=FAILED_TREE,
        target_parents=[MAIN],
        failed_integration_head_commit=FAILED,
        failed_integration_head_tree=FAILED_TREE,
        restore_to_commit=RESTORE,
        restore_to_tree=RESTORE_TREE,
        rollback_candidate_commit=CANDIDATE,
        rollback_candidate_parent_commit=FAILED,
        issuer="release-attester",
        reason="integration soak failed",
    )
    return auth.model_copy(update={"authorization_id": rollback_authorization_digest(auth)})


def publication() -> CandidatePublicationBinding:
    return CandidatePublicationBinding.model_construct(
        repository_digest=D,
        base_commit=FAILED,
        base_tree=FAILED_TREE,
        candidate_digest=D,
        candidate_ref="refs/heads/avo/rollback/case-7",
        candidate_commit=CANDIDATE,
        candidate_tree=RESTORE_TREE,
        controller_publisher_identity="controller",
        publication_evidence_digest=D,
        verified=True,
    )


def bundle() -> Any:
    return type(
        "Bundle",
        (),
        {
            "snapshot": type(
                "Snapshot",
                (),
                {
                    "repository_digest": D,
                    "target_ref": "refs/heads/integration",
                    "commit": FAILED,
                    "tree": FAILED_TREE,
                },
            )()
        },
    )()


def promotion_receipt() -> IntegrationPromotionReceipt:
    return IntegrationPromotionReceipt.model_construct(
        operation_id=PROMOTION_OPERATION,
        intent_digest=D,
        bundle_digest=D,
        expected_target_ref="refs/heads/integration",
        expected_candidate_commit=CANDIDATE,
        expected_candidate_tree=RESTORE_TREE,
        expected_base_commit=FAILED,
        expected_protection_evidence_digest=D,
        expected_provider_identity="github",
        expected_provider_api_version="v1",
        merge_method="squash",
        applied_result_commit=RESULT,
        applied_result_tree=RESTORE_TREE,
        applied_result_parent_commit=FAILED,
        outcome="applied",
        observed_target_ref="refs/heads/integration",
        observed_base_commit=FAILED,
        observed_head_commit=RESULT,
        observed_head_tree=RESTORE_TREE,
        observed_protection_evidence_digest=D,
        observed_provider_identity="github",
        observed_provider_api_version="v1",
        observation_digest=D,
    )


def service(tmp_path: Path, promotion: Promotion) -> IntegrationDrillRollbackService:
    return IntegrationDrillRollbackService(
        IntegrationDrillJournal(tmp_path),
        promotion,  # type: ignore[arg-type]
        PromotionJournal(promotion_receipt()),  # type: ignore[arg-type]
        main_head_reader=lambda: MAIN,
        repository_verifier=Verifier(),
        trusted_rollback_issuers=("release-attester",),
    )


def test_failed_soak_delegates_one_protected_rollback_and_replays(tmp_path: Path) -> None:
    promotion = Promotion()
    controller = service(tmp_path, promotion)
    result = controller.run(
        request(),
        authorization=authorization(),
        bundle=bundle(),
        publication=publication(),
        bundle_digest=D,
        intent_factory=lambda _lease: object(),  # type: ignore[return-value]
    )
    assert result.soak.outcome == "failed"
    assert result.receipt.result_tree == RESTORE_TREE
    assert result.receipt.target_head_commit == RESULT
    assert result.case.main_before_commit == result.case.main_after_commit == MAIN
    assert len(result.evidence_artifacts) == 4
    assert promotion.calls == 1

    replay = controller.run(
        request(),
        authorization=authorization(),
        bundle=bundle(),
        publication=publication(),
        bundle_digest=D,
        intent_factory=lambda _lease: object(),  # type: ignore[return-value]
    )
    assert replay.replayed
    assert promotion.calls == 1


def test_reconciliation_required_is_pending_until_read_only_recovery(tmp_path: Path) -> None:
    promotion_journal = RecoveringPromotionJournal()
    promotion = RecoveringPromotion(promotion_journal)
    drill_journal = IntegrationDrillJournal(tmp_path)
    controller = IntegrationDrillRollbackService(
        drill_journal,
        promotion,  # type: ignore[arg-type]
        promotion_journal,  # type: ignore[arg-type]
        main_head_reader=lambda: MAIN,
        repository_verifier=Verifier(),
        trusted_rollback_issuers=("release-attester",),
    )
    pending = controller.run(
        request(),
        authorization=authorization(),
        bundle=bundle(),
        publication=publication(),
        bundle_digest=D,
        intent_factory=lambda _lease: object(),  # type: ignore[return-value]
    )
    assert pending.receipt.outcome == "reconciliation_required"
    assert pending.case.outcome == "reconciliation_required"
    assert drill_journal.read_case_result(OPERATION, 7) is None

    recovered = controller.run(
        request(),
        authorization=authorization(),
        bundle=bundle(),
        publication=publication(),
        bundle_digest=D,
        intent_factory=lambda _lease: object(),  # type: ignore[return-value]
    )
    assert recovered.receipt.outcome == "applied"
    assert recovered.case.outcome == "applied"
    assert promotion.calls == 2

def test_wrong_authorization_fails_before_promotion(tmp_path: Path) -> None:
    promotion = Promotion()
    stale = authorization().model_copy(update={"failed_integration_head_commit": MAIN})
    with pytest.raises(IntegrationRollbackDrillError, match="authorization"):
        service(tmp_path, promotion).run(
            request(),
            authorization=stale,
            bundle=bundle(),
            publication=publication(),
            bundle_digest=D,
            intent_factory=lambda _lease: object(),  # type: ignore[return-value]
        )
    assert promotion.calls == 0


def test_authorization_digest_mismatch_fails_closed(tmp_path: Path) -> None:
    promotion = Promotion()
    stale = authorization().model_copy(update={"authorization_id": D})
    with pytest.raises(IntegrationRollbackDrillError, match="digest"):
        service(tmp_path, promotion).run(
            request(),
            authorization=stale,
            bundle=bundle(),
            publication=publication(),
            bundle_digest=D,
            intent_factory=lambda _lease: object(),  # type: ignore[return-value]
        )
    assert promotion.calls == 0


def test_repository_identity_is_verified_before_durable_authorization(tmp_path: Path) -> None:
    promotion = Promotion()
    journal = IntegrationDrillJournal(tmp_path)
    controller = IntegrationDrillRollbackService(
        journal,
        promotion,  # type: ignore[arg-type]
        PromotionJournal(promotion_receipt()),  # type: ignore[arg-type]
        main_head_reader=lambda: MAIN,
        repository_verifier=RejectingVerifier(),
        trusted_rollback_issuers=("release-attester",),
    )
    with pytest.raises(RuntimeError, match="repository identity"):
        controller.run(
            request(),
            authorization=authorization(),
            bundle=bundle(),
            publication=publication(),
            bundle_digest=D,
            intent_factory=lambda _lease: object(),  # type: ignore[return-value]
        )
    assert journal.read_rollback_authorization(OPERATION) is None
    assert promotion.calls == 0


def test_untrusted_issuer_fails_closed_before_promotion(tmp_path: Path) -> None:
    promotion = Promotion()
    stale = authorization().model_copy(update={"issuer": "untrusted"})
    with pytest.raises(IntegrationRollbackDrillError, match="authorization"):
        service(tmp_path, promotion).run(
            request(),
            authorization=stale,
            bundle=bundle(),
            publication=publication(),
            bundle_digest=D,
            intent_factory=lambda _lease: object(),  # type: ignore[return-value]
        )
    assert promotion.calls == 0


@pytest.mark.parametrize(
    ("request_update", "publication_update", "match"),
    [
        (
            {"rollback_candidate_commit": RESTORE},
            {"candidate_commit": RESTORE},
            "new commit",
        ),
        (
            {},
            {"candidate_tree": FAILED_TREE},
            "publication",
        ),
        (
            {"rollback_candidate_parent_commit": MAIN},
            {},
            "parented",
        ),
        (
            {
                "failed_integration_head_commit": MAIN,
                "rollback_candidate_parent_commit": MAIN,
            },
            {},
            "authorization",
        ),
    ],
)
def test_adversarial_rollback_topology_fails_before_mutation(
    tmp_path: Path,
    request_update: dict[str, str],
    publication_update: dict[str, str],
    match: str,
) -> None:
    promotion = Promotion()
    with pytest.raises(IntegrationRollbackDrillError, match=match):
        service(tmp_path, promotion).run(
            request().model_copy(update=request_update),
            authorization=authorization(),
            bundle=bundle(),
            publication=publication().model_copy(update=publication_update),
            bundle_digest=D,
            intent_factory=lambda _lease: object(),  # type: ignore[return-value]
        )
    assert promotion.calls == 0
