"""Adversarial recovery and reconstruction coverage for the live rollback services."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from avo_correlate.adapters.artifacts.drill_journal import IntegrationDrillJournal
from avo_correlate.application.integration_live_rollback_service import (
    LiveIntegrationRollbackService,
    LiveRollbackEvidenceError,
    LiveRollbackTargetObservation,
)
from avo_correlate.application.integration_rollback_service import (
    IntegrationDrillRollbackService,
    IntegrationRollbackDrillError,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_drill import IntegrationDrillRollbackIntent
from avo_correlate.contracts.integration_promotion import (
    IntegrationPromotionReport,
)
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.test_integration_live_rollback import (
    _CaseJournal,  # pyright: ignore[reportPrivateUsage]
    _FailIfCalledRollback,  # pyright: ignore[reportPrivateUsage]
    _package_fixture,  # pyright: ignore[reportPrivateUsage]
    _PromotionEvidence,  # pyright: ignore[reportPrivateUsage]
    _RecordingJournal,  # pyright: ignore[reportPrivateUsage]
    _ReplayJournal,  # pyright: ignore[reportPrivateUsage]
    _SuccessfulRollback,  # pyright: ignore[reportPrivateUsage]
    _target_observation,  # pyright: ignore[reportPrivateUsage]
)
from tests.unit.test_integration_rollback_service import (
    MAIN,
    PROMOTION_OPERATION,
    D,
    Promotion,
    PromotionJournal,
    Verifier,
    authorization,
    bundle,
    promotion_receipt,
    publication,
    request,
    service,
)


def test_constructor_requires_attester_and_trusted_issuer(tmp_path: Path) -> None:
    kwargs: dict[str, Any] = {
        "journal": IntegrationDrillJournal(tmp_path),
        "promotion": Promotion(),
        "promotion_journal": PromotionJournal(promotion_receipt()),
        "main_head_reader": lambda: MAIN,
        "repository_verifier": Verifier(),
        "trusted_rollback_issuers": ("release-attester",),
    }
    with pytest.raises(ValueError, match="attester_identity"):
        IntegrationDrillRollbackService(**cast(Any, {**kwargs, "attester_identity": " "}))
    with pytest.raises(ValueError, match="trusted_rollback_issuers"):
        IntegrationDrillRollbackService(
            **cast(Any, {**kwargs, "trusted_rollback_issuers": ()})
        )


class _WrongReportPromotion(Promotion):
    def promote(self, *_args: Any, **_kwargs: Any) -> IntegrationPromotionReport:
        self.calls += 1
        return IntegrationPromotionReport.model_construct(
            operation_id=canonical_digest({"wrong": "operation"}),
            outcome="rejected",
            checks=[],
        )


class _MissingIntentJournal(PromotionJournal):
    def read_intent(self, operation_id: str) -> None:
        del operation_id
        return None


def test_wrong_promotion_identity_and_missing_intent_fail_closed(tmp_path: Path) -> None:
    wrong = _WrongReportPromotion()
    with pytest.raises(IntegrationRollbackDrillError, match="identity"):
        service(tmp_path / "wrong", wrong).run(
            request(),
            authorization=authorization(),
            bundle=bundle(),
            publication=publication(),
            bundle_digest=D,
            intent_factory=lambda _lease: cast(Any, object()),
        )
    assert wrong.calls == 1

    promotion = Promotion()
    controller = IntegrationDrillRollbackService(
        IntegrationDrillJournal(tmp_path / "missing-intent"),
        promotion,  # type: ignore[arg-type]
        _MissingIntentJournal(promotion_receipt()),  # type: ignore[arg-type]
        main_head_reader=lambda: MAIN,
        repository_verifier=Verifier(),
        trusted_rollback_issuers=("release-attester",),
    )
    with pytest.raises(IntegrationRollbackDrillError, match="no durable promotion intent"):
        controller.run(
            request(),
            authorization=authorization(),
            bundle=bundle(),
            publication=publication(),
            bundle_digest=D,
            intent_factory=lambda _lease: cast(Any, object()),
        )


def test_main_change_after_promotion_is_detected(tmp_path: Path) -> None:
    heads = iter((MAIN, "f" * 40))
    controller = IntegrationDrillRollbackService(
        IntegrationDrillJournal(tmp_path),
        Promotion(),  # type: ignore[arg-type]
        PromotionJournal(promotion_receipt()),  # type: ignore[arg-type]
        main_head_reader=lambda: next(heads),
        repository_verifier=Verifier(),
        trusted_rollback_issuers=("release-attester",),
    )
    with pytest.raises(IntegrationRollbackDrillError, match="stale or malformed"):
        controller.run(
            request(),
            authorization=authorization(),
            bundle=bundle(),
            publication=publication(),
            bundle_digest=D,
            intent_factory=lambda _lease: cast(Any, object()),
        )


def test_replay_rejects_identity_evidence_and_topology_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controller = service(tmp_path, Promotion())
    first = controller.run(
        request(),
        authorization=authorization(),
        bundle=bundle(),
        publication=publication(),
        bundle_digest=D,
        intent_factory=lambda _lease: cast(Any, object()),
    )
    with pytest.raises(IntegrationRollbackDrillError, match="identity mismatch"):
        controller._replay(  # pyright: ignore[reportPrivateUsage]
            request(), first.case.model_copy(update={"case_id": 6}), authorization()
        )
    with pytest.raises(IntegrationRollbackDrillError, match="main unchanged"):
        controller._replay(  # pyright: ignore[reportPrivateUsage]
            request(),
            first.case.model_copy(update={"main_after_commit": "f" * 40}),
            authorization(),
        )
    def missing_soak(_operation_id: str) -> None:
        return None

    monkeypatch.setattr(cast(Any, controller)._journal, "read_soak_observation", missing_soak)
    with pytest.raises(IntegrationRollbackDrillError, match="incomplete"):
        controller._replay(  # pyright: ignore[reportPrivateUsage]
            request(), first.case, authorization()
        )

    # Recreate a clean controller so the remaining checks see the durable records.
    controller = service(tmp_path / "topology", Promotion())
    first = controller.run(
        request(),
        authorization=authorization(),
        bundle=bundle(),
        publication=publication(),
        bundle_digest=D,
        intent_factory=lambda _lease: cast(Any, object()),
    )
    with pytest.raises(IntegrationRollbackDrillError, match="references differ"):
        controller._replay(  # pyright: ignore[reportPrivateUsage]
            request(), first.case.model_copy(update={"rollback_receipt": D}), authorization()
        )
    altered_intent = first.intent.model_copy(update={"target_ref": "refs/heads/other"})
    def altered_read_intent(
        _operation_id: str,
    ) -> tuple[IntegrationDrillRollbackIntent, ArtifactRef]:
        return altered_intent, first.evidence_artifacts[2]

    monkeypatch.setattr(
        controller._journal,  # type: ignore[reportPrivateUsage]
        "read_rollback_intent",
        altered_read_intent,
    )
    with pytest.raises(IntegrationRollbackDrillError, match="topology"):
        controller._replay(  # pyright: ignore[reportPrivateUsage]
            request(), first.case, authorization()
        )


@pytest.mark.parametrize(
    ("report", "outcome"),
    [
        (
            IntegrationPromotionReport(
                operation_id=PROMOTION_OPERATION, outcome="applied", checks=["test"]
            ),
            "reconciliation_required",
        ),
        (
            IntegrationPromotionReport(
                operation_id=PROMOTION_OPERATION, outcome="stale_base", checks=["test"]
            ),
            "stale_target",
        ),
        (
            IntegrationPromotionReport.model_construct(
                operation_id=PROMOTION_OPERATION,
                outcome="rejected",
                checks=["test"],
            ),
            "rejected",
        ),
    ],
)
def test_receipt_construction_preserves_uncertain_outcomes(
    report: IntegrationPromotionReport,
    outcome: str,
) -> None:
    controller = service(Path("."), Promotion())
    intent = controller._make_intent(  # pyright: ignore[reportPrivateUsage]
        request(), authorization(), "test-attester"
    )
    receipt = controller._make_receipt(  # pyright: ignore[reportPrivateUsage]
        request(), authorization(), intent, "test-attester", report, None
    )
    assert receipt.outcome == outcome
    if outcome == "rejected":
        assert receipt.error == "rollback promotion outcome: rejected"


def test_live_service_returns_non_success_without_package() -> None:
    package = _package_fixture()
    execution = LiveIntegrationRollbackService._execution_from_package(package)  # pyright: ignore[reportPrivateUsage]
    execution = execution.__class__(
        request=execution.request,
        soak=execution.soak,
        authorization=execution.authorization,
        intent=execution.intent,
        receipt=execution.receipt.model_copy(update={"outcome": "rejected"}),
        case=execution.case,
        report=execution.report.model_copy(update={"outcome": "rejected"}),
        evidence_artifacts=execution.evidence_artifacts,
    )

    class RejectedRollback:
        def run(self, *_args: object, **_kwargs: object) -> object:
            return execution

    service = LiveIntegrationRollbackService(
        cast(Any, RejectedRollback()),
        cast(Any, SimpleNamespace()),
        _RecordingJournal(),
        cast(Any, SimpleNamespace()),
        main_head_reader=lambda: package.request.main_before_commit,
        target_observation_reader=lambda: _target_observation(package),
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
    assert result.package is None
    assert result.rollback.receipt.outcome == "rejected"


def _live_service(
    package: Any,
    rollback: Any,
    evidence: Any | None = None,
    case_journal: Any | None = None,
    package_journal: Any | None = None,
) -> LiveIntegrationRollbackService:
    return LiveIntegrationRollbackService(
        rollback,
        cast(Any, case_journal or _CaseJournal(package)),
        cast(Any, package_journal or _RecordingJournal()),
        cast(Any, evidence or _PromotionEvidence(package)),
        main_head_reader=lambda: package.request.main_before_commit,
        target_observation_reader=lambda: _target_observation(package),
    )


def test_package_reconstruction_fences_missing_children_roles_and_report() -> None:
    package = _package_fixture()
    execution = LiveIntegrationRollbackService._execution_from_package(package)  # pyright: ignore[reportPrivateUsage]
    base: dict[str, Any] = dict(
        execution=execution,
        canary=package.canary_package,
        canary_ref=package.canary_package_artifact,
        bundle=package.bundle,
        publication=package.publication,
        bundle_digest=package.bundle_digest,
    )

    class MissingReceipt(_PromotionEvidence):
        def read_receipt(self, operation_id: str) -> None:
            del operation_id
            return None

    service = _live_service(package, _SuccessfulRollback(package), evidence=MissingReceipt(package))
    with pytest.raises(LiveRollbackEvidenceError, match="incomplete"):
        cast(Any, service)._package(**base)

    service = _live_service(package, _SuccessfulRollback(package))
    incomplete = execution.__class__(
        request=execution.request,
        soak=execution.soak,
        authorization=execution.authorization,
        intent=execution.intent,
        receipt=execution.receipt,
        case=execution.case,
        report=execution.report,
        evidence_artifacts=execution.evidence_artifacts[:-1],
    )
    with pytest.raises(LiveRollbackEvidenceError, match="artifacts are incomplete"):
        cast(Any, service)._package(**{**base, "execution": incomplete})

    mismatched = execution.__class__(
        request=execution.request,
        soak=execution.soak,
        authorization=execution.authorization,
        intent=execution.intent,
        receipt=execution.receipt,
        case=execution.case,
        report=execution.report.model_copy(update={"intent_digest": D}),
        evidence_artifacts=execution.evidence_artifacts,
    )
    with pytest.raises(LiveRollbackEvidenceError, match="not bound"):
        cast(Any, service)._package(**{**base, "execution": mismatched})


def test_live_replay_and_target_fences_reject_bad_evidence() -> None:
    package = _package_fixture()
    bad_request = package.request.model_copy(update={"restore_to_tree": "f" * 40})
    bad_package = package.model_copy(update={"request": bad_request})
    with pytest.raises(LiveRollbackEvidenceError, match="semantically invalid"):
        LiveIntegrationRollbackService._validate_replay(  # pyright: ignore[reportPrivateUsage]
            bad_package, bad_request, package.canary_package_artifact, package.authorization
        )
    with pytest.raises(LiveRollbackEvidenceError, match="binding differs"):
        LiveIntegrationRollbackService._validate_replay(  # pyright: ignore[reportPrivateUsage]
            package,
            package.request,
            package.canary_package_artifact.model_copy(update={"size_bytes": 1}),
            package.authorization,
        )

    request_value = package.request
    valid = _target_observation(package)
    observations = [
        (valid, None, None),
        (valid, "f" * 40, valid.tree),
        (valid, valid.commit, None),
        (
            LiveRollbackTargetObservation(
                repository_digest=request_value.repository_digest,
                target_ref=request_value.target_ref,
                commit=valid.commit,
                tree=valid.tree,
                parent_commits=("f" * 40,),
            ),
            valid.commit,
            valid.tree,
        ),
    ]
    for observation, expected_commit, expected_tree in observations:
        with pytest.raises(LiveRollbackEvidenceError, match=r"stale|topology"):
            LiveIntegrationRollbackService._validate_target_observation(  # pyright: ignore[reportPrivateUsage]
                request_value, observation, expected_commit, expected_tree
            )


def test_live_read_package_is_a_read_only_delegation() -> None:
    package = _package_fixture()
    journal = _ReplayJournal(package)
    service = _live_service(package, _FailIfCalledRollback(), package_journal=journal)
    result = service.read_package(package.operation_id)
    assert result is not None
    assert result[0] == package
