"""Adversarial recovery coverage for the non-live journal adapters.

These tests deliberately use tiny valid records where possible and narrow
test doubles for package-child verification.  They exercise persistence
boundaries without changing the journal implementations.
"""

# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownVariableType=false

import errno
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import avo_correlate.adapters.artifacts.campaign_journal as campaign_module
import avo_correlate.adapters.artifacts.promotion_journal as promotion_module
import avo_correlate.adapters.artifacts.synthetic_validation_journal as validation_module
from avo_correlate.adapters.artifacts.campaign_journal import (
    CampaignCompletionJournal,
    CampaignJournalError,
)
from avo_correlate.adapters.artifacts.promotion_journal import (
    IntegrationPromotionJournal,
    PromotionJournalError,
    PromotionLease,
    PromotionLeaseConflictError,
    PromotionRecordConflictError,
)
from avo_correlate.adapters.artifacts.synthetic_validation_journal import (
    SyntheticValidationJournal,
    SyntheticValidationJournalError,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.synthetic_validation import (
    SyntheticValidationAttempt,
    SyntheticValidationCreateAuthorization,
    SyntheticValidationOutcome,
    SyntheticValidationPlan,
    synthetic_validation_operation_id,
    validation_ref_for,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest
from tests.unit.test_integration_campaign_contracts import _package
from tests.unit.test_promotion_journal import D2, D, receipt
from tests.unit.test_synthetic_validation_contracts import request


def _plan() -> SyntheticValidationPlan:
    value = request()
    operation = synthetic_validation_operation_id(value)
    return SyntheticValidationPlan(
        operation_id=operation,
        request=value,
        validation_ref=validation_ref_for(operation),
        expected_commit="5" * 40,
        expected_tree="6" * 40,
    )


def _authorization(plan: SyntheticValidationPlan) -> SyntheticValidationCreateAuthorization:
    return SyntheticValidationCreateAuthorization(
        operation_id=plan.operation_id,
        plan_digest=plan.plan_digest,
        validation_ref=plan.validation_ref,
        expected_commit=plan.expected_commit,
        expected_tree=plan.expected_tree,
    )


def _outcome(plan: SyntheticValidationPlan) -> SyntheticValidationOutcome:
    return SyntheticValidationOutcome(
        operation_id=plan.operation_id,
        plan_digest=plan.plan_digest,
        validation_ref=plan.validation_ref,
        expected_commit=plan.expected_commit,
        expected_tree=plan.expected_tree,
        outcome="created",
        observed_commit=plan.expected_commit,
        observed_tree=plan.expected_tree,
    )


def _attempt(plan: SyntheticValidationPlan) -> SyntheticValidationAttempt:
    return SyntheticValidationAttempt(
        operation_id=plan.operation_id,
        plan_digest=plan.plan_digest,
        validation_ref=plan.validation_ref,
        expected_commit=plan.expected_commit,
        expected_tree=plan.expected_tree,
        kind="read_error",
    )


def test_campaign_plan_recovery_listing_and_missing_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _package()
    # The shared campaign fixture contains model_construct records; the journal
    # read path is tested with its exact recorded object via this adapter hook.
    from tests.unit.test_campaign_completion_recovery import _plan as campaign_plan

    plan = campaign_plan(fixture)
    journal = CampaignCompletionJournal(tmp_path)
    monkeypatch.setattr(
        campaign_module.CampaignCompletionPlan,
        "model_validate",
        classmethod(lambda cls, _data: plan),
    )
    reference = journal.record_plan(plan)
    assert journal.record_plan(plan) == reference
    assert journal.read_plan(plan.operation_id) == (plan, reference)
    assert journal.list_plan_operations() == (plan.operation_id,)
    assert CampaignCompletionJournal(tmp_path / "empty").list_plan_operations() == ()

    monkeypatch.setattr(journal, "read_plan", lambda _operation: None)
    with pytest.raises(CampaignJournalError, match="disappeared"):
        journal.list_plan_operations()


def test_campaign_index_and_record_tamper_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _package()
    from tests.unit.test_campaign_completion_recovery import _plan as campaign_plan

    plan = campaign_plan(fixture)
    journal = CampaignCompletionJournal(tmp_path)
    monkeypatch.setattr(
        campaign_module.CampaignCompletionPlan,
        "model_validate",
        classmethod(lambda cls, _data: plan),
    )
    journal.record_plan(plan)
    index = tmp_path / "campaign-completion-index" / "plan" / f"{plan.operation_id[7:]}.json"
    reference = json.loads(index.read_text(encoding="utf-8"))
    reference["role"] = "wrong"
    index.write_text(json.dumps(reference), encoding="utf-8")
    with pytest.raises(CampaignJournalError, match="malformed"):
        journal.read_plan(plan.operation_id)

    # A valid index pointing to a record with a different identity is rejected.
    other_index = tmp_path / "campaign-completion-index" / "plan" / f"{D2[7:]}.json"
    other_index.write_bytes(index.read_bytes())
    monkeypatch.setattr(
        campaign_module.CampaignCompletionPlan,
        "model_validate",
        classmethod(lambda cls, _data: plan),
    )
    with pytest.raises(CampaignJournalError, match="malformed"):
        journal.read_plan(D2)


def test_campaign_child_verification_detects_missing_and_tamper() -> None:
    lease = {"operation_id": D}
    lease_payload = canonical_bytes(lease)
    ref = ArtifactRef(
        digest=canonical_digest(lease),
        size_bytes=len(lease_payload),
        media_type="application/json",
        role="lease",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    package = SimpleNamespace(
        lease_evidence=lease,
        lease_evidence_artifact=ref,
        evidence_artifacts=[ref],
    )

    class Store:
        def __init__(self, payload: bytes) -> None:
            self.payload = payload

        def read_bytes(self, _reference: ArtifactRef) -> bytes:
            return self.payload

    campaign_module._verify_package_children(package, Store(lease_payload))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="missing or tampered"):
        campaign_module._verify_package_children(package, Store(b"tampered"))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="content-bound"):
        bad_ref = ref.model_copy(update={"size_bytes": 1})
        campaign_module._verify_package_children(  # type: ignore[arg-type]
            SimpleNamespace(
                lease_evidence=lease,
                lease_evidence_artifact=bad_ref,
                evidence_artifacts=[bad_ref],
            ),  # type: ignore[arg-type]
            Store(lease_payload),  # type: ignore[arg-type]
        )


def test_campaign_sync_and_operation_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(ValueError, match="SHA-256"):
        CampaignCompletionJournal(tmp_path).read_plan("bad")

    def unsupported(*_args: Any, **_kwargs: Any) -> Any:
        raise OSError(errno.EINVAL, "unsupported")

    original_name = campaign_module.os.name
    monkeypatch.setattr(campaign_module.os, "name", "nt")
    monkeypatch.setattr(campaign_module.os, "open", unsupported)
    campaign_module._sync_directory(tmp_path)
    monkeypatch.setattr(campaign_module.os, "name", "posix")
    with pytest.raises(OSError, match="unsupported"):
        campaign_module._sync_directory(tmp_path)
    monkeypatch.setattr(campaign_module.os, "name", original_name)


def test_promotion_lease_scope_and_recovery_edges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = IntegrationPromotionJournal(tmp_path, identity_factory=lambda: "identity")
    with pytest.raises(ValueError, match="positive"):
        journal.acquire_lease(D, "integration", D, lease_seconds=0)
    with pytest.raises(ValueError, match="trimmed"):
        journal.acquire_lease(D, " integration", D, lease_seconds=1)
    with pytest.raises(ValueError, match="timezone"):
        journal.acquire_lease(D, "integration", D, lease_seconds=1, now=datetime(2026, 1, 1))

    now = datetime(2026, 1, 1, tzinfo=UTC)
    lease = journal.acquire_lease(D, "integration", D, lease_seconds=2, now=now)
    assert journal.read_lease(D, "integration") == lease
    original_parser = journal._lease_from_document
    monkeypatch.setattr(
        journal,
        "_lease_from_document",
        lambda _document: PromotionLease(
            lease.operation_id,
            lease.repository_digest,
            "other",
            lease.identity,
            lease.acquired_at,
            lease.expires_at,
            lease.digest,
        ),
    )
    with pytest.raises(PromotionLeaseConflictError, match="scope"):
        journal.read_lease(D, "integration")
    monkeypatch.setattr(journal, "_lease_from_document", original_parser)
    with pytest.raises(PromotionLeaseConflictError, match="expired"):
        journal.assert_current(lease, now=now + timedelta(seconds=2))
    with pytest.raises(PromotionLeaseConflictError, match="bindings"):
        journal.release_matching_lease(D, "integration", D2, lease.identity, lease.digest)
    journal.release_lease(lease)
    assert (
        journal.release_matching_lease(D, "integration", D, lease.identity, lease.digest) is False
    )

    # Missing and malformed lease documents are fail-closed.
    key = promotion_module.canonical_digest(
        {"repository_digest": D, "target_ref": "integration"}
    ).removeprefix("sha256:")
    path = tmp_path / "promotion-leases" / f"{key}.json"
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(PromotionLeaseConflictError, match="malformed"):
        journal.read_lease(D, "integration")


def test_promotion_record_read_and_conflict_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = IntegrationPromotionJournal(tmp_path)
    value = receipt()
    monkeypatch.setattr(
        promotion_module.IntegrationPromotionReceipt,
        "model_validate",
        classmethod(lambda cls, _data: value),
    )
    reference = journal.record_receipt(value)
    assert journal.record_receipt(value) == reference
    assert journal.read_receipt(D) == (value, reference)
    assert journal.read_intent(D) is None
    conflicting = value.model_copy(update={"outcome": "applied"})
    with pytest.raises(PromotionRecordConflictError, match="conflicting"):
        journal.record_receipt(conflicting)

    index = tmp_path / "promotion-record-index" / "receipt" / f"{D[7:]}.json"
    raw = json.loads(index.read_text(encoding="utf-8"))
    raw["media_type"] = "wrong"
    index.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(PromotionJournalError, match="malformed"):
        journal.read_receipt(D)


@pytest.mark.parametrize(
    "document",
    [None, {}, {"digest": D}, {"digest": D, "schema_version": 2}],
)
def test_promotion_lease_document_parser_rejects_malformed(document: object) -> None:
    with pytest.raises(ValueError):
        IntegrationPromotionJournal._lease_from_document(document)


def test_promotion_sync_and_lease_evidence_failure_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_sync = promotion_module._sync_directory
    journal = IntegrationPromotionJournal(tmp_path, identity_factory=lambda: "identity")
    now = datetime(2026, 1, 1, tzinfo=UTC)
    monkeypatch.setattr(
        journal,
        "record_lease_evidence",
        lambda _value: (_ for _ in ()).throw(OSError("evidence")),
    )
    with pytest.raises(PromotionJournalError, match="evidence"):
        journal.acquire_lease(D, "integration", D, lease_seconds=1, now=now)

    def fail_sync(_path: Path) -> None:
        raise OSError("sync")

    monkeypatch.setattr(promotion_module, "_sync_directory", fail_sync)
    journal = IntegrationPromotionJournal(tmp_path / "sync", identity_factory=lambda: "identity")
    with pytest.raises(PromotionJournalError, match="reconciliation"):
        journal.acquire_lease(D, "integration", D, lease_seconds=1, now=now)
    # Exercise the successful open/close path and the propagated unsupported path.
    monkeypatch.setattr(promotion_module, "_sync_directory", real_sync)
    closed: list[int] = []
    monkeypatch.setattr(promotion_module.os, "name", "posix")
    monkeypatch.setattr(promotion_module.os, "open", lambda *_args, **_kwargs: 3)
    monkeypatch.setattr(promotion_module.os, "fsync", lambda _fd: None)
    monkeypatch.setattr(promotion_module.os, "close", closed.append)
    promotion_module._sync_directory(tmp_path)
    assert closed == [3]


def test_synthetic_journal_records_claims_and_recovery(tmp_path: Path) -> None:
    journal = SyntheticValidationJournal(tmp_path)
    plan = _plan()
    outcome = _outcome(plan)
    attempt = _attempt(plan)
    authorization = _authorization(plan)
    assert journal.record_plan(plan) == journal.record_plan(plan)
    assert journal.record_outcome(outcome) == journal.record_receipt(outcome)
    assert journal.record_attempt(attempt) == journal.record_attempt(attempt)
    assert journal.read_plan(plan.operation_id) is not None
    assert journal.read_outcome(plan.operation_id) is not None
    assert journal.read_attempt(plan.operation_id) is not None
    assert journal.read_cleanup(plan.operation_id) is None
    assert journal.claim_create_authorization(authorization)
    assert not journal.claim_create_authorization(authorization)
    loaded = journal.read_create_authorization(plan.operation_id)
    assert isinstance(loaded, tuple)
    assert loaded[0] == authorization

    conflicting = authorization.model_copy(update={"expected_tree": "7" * 40})
    with pytest.raises(SyntheticValidationJournalError, match="conflicting"):
        journal.claim_create_authorization(conflicting)


def test_synthetic_claim_and_record_tamper_paths(tmp_path: Path) -> None:
    plan = _plan()
    authorization = _authorization(plan)
    journal = SyntheticValidationJournal(tmp_path)
    claim = (
        tmp_path / "synthetic-validation-index" / "authorization" / f"{plan.operation_id[7:]}.claim"
    )
    claim.mkdir(parents=True)
    assert not journal.claim_create_authorization(authorization)
    (claim / "record.json").write_text("{}", encoding="utf-8")
    with pytest.raises(SyntheticValidationJournalError, match="malformed"):
        journal.read_create_authorization(plan.operation_id)

    journal = SyntheticValidationJournal(tmp_path / "records")
    journal.record_plan(plan)
    index = (
        tmp_path
        / "records"
        / "synthetic-validation-index"
        / "plan"
        / f"{plan.operation_id[7:]}.json"
    )
    raw = json.loads(index.read_text(encoding="utf-8"))
    raw["role"] = "wrong"
    index.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(SyntheticValidationJournalError, match="malformed"):
        journal.read_plan(plan.operation_id)


def test_synthetic_invalid_ids_limits_and_sync_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = SyntheticValidationJournal(tmp_path)
    with pytest.raises(ValueError, match="SHA-256"):
        journal.read_plan("bad")
    with pytest.raises(ValueError, match="SHA-256"):
        journal.claim_create_authorization(
            _authorization(_plan()).model_copy(update={"operation_id": "bad"})
        )

    original_name = validation_module.os.name
    monkeypatch.setattr(validation_module.os, "name", "nt")
    monkeypatch.setattr(
        validation_module.os,
        "open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError(errno.EINVAL, "unsupported")),
    )
    validation_module._sync_directory(tmp_path)
    monkeypatch.setattr(validation_module.os, "name", "posix")
    with pytest.raises(OSError, match="unsupported"):
        validation_module._sync_directory(tmp_path)
    monkeypatch.setattr(validation_module.os, "name", original_name)
