from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import avo_correlate.adapters.artifacts.promotion_journal as promotion_journal
from avo_correlate.adapters.artifacts.promotion_journal import (
    IntegrationPromotionJournal,
    PromotionJournalError,
    PromotionLeaseConflictError,
    PromotionRecordConflictError,
)
from avo_correlate.contracts.integration_promotion import IntegrationPromotionReceipt

D = "sha256:" + "a" * 64
D2 = "sha256:" + "b" * 64
G = "a" * 40


def receipt(**updates: object) -> IntegrationPromotionReceipt:
    values: dict[str, object] = {
        "operation_id": D,
        "intent_digest": D,
        "bundle_digest": D,
        "expected_target_ref": "integration",
        "expected_candidate_commit": G,
        "expected_candidate_tree": G,
        "expected_base_commit": G,
        "expected_protection_evidence_digest": D,
        "expected_provider_identity": "provider",
        "expected_provider_api_version": "v1",
        "merge_method": "squash",
        "outcome": "intent_recorded",
        "observed_target_ref": "integration",
        "observed_base_commit": G,
        "observed_protection_evidence_digest": D,
        "observed_provider_identity": "provider",
        "observed_provider_api_version": "v1",
        "observation_digest": D,
    }
    values.update(updates)
    return IntegrationPromotionReceipt.model_validate(values)


def test_lease_is_exclusive_and_release_is_fenced(tmp_path: Path) -> None:
    journal = IntegrationPromotionJournal(tmp_path)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    lease = journal.acquire_lease(D, "integration", D, lease_seconds=1, now=now)
    with pytest.raises(PromotionLeaseConflictError):
        journal.acquire_lease(D, "integration", D, lease_seconds=1, now=now + timedelta(days=1))
    journal.release_lease(lease)
    replacement = journal.acquire_lease(D, "integration", D2, lease_seconds=1, now=now)
    with pytest.raises(PromotionLeaseConflictError):
        journal.release_lease(lease)
    journal.release_lease(replacement)


def test_assert_current_rejects_expiry_and_tampering(tmp_path: Path) -> None:
    journal = IntegrationPromotionJournal(tmp_path)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    lease = journal.acquire_lease(D, "integration", D, lease_seconds=1, now=now)
    journal.assert_current(lease, now=now + timedelta(milliseconds=1))
    with pytest.raises(PromotionLeaseConflictError, match="expired"):
        journal.assert_current(lease, now=now + timedelta(seconds=1))
    journal.release_lease(lease)
    replacement = journal.acquire_lease(D, "integration", D2, lease_seconds=10, now=now)
    lease_files = list((tmp_path / "promotion-leases").glob("*.json"))
    lease_files[0].write_text("{}", encoding="utf-8")
    with pytest.raises(PromotionLeaseConflictError, match="malformed"):
        journal.assert_current(replacement, now=now)


def test_recovery_reads_and_releases_exact_expired_lease(tmp_path: Path) -> None:
    journal = IntegrationPromotionJournal(tmp_path)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    assert journal.read_lease(D, "integration") is None
    lease = journal.acquire_lease(D, "integration", D, lease_seconds=1, now=now)
    found = journal.read_lease(D, "integration")
    assert found == lease
    with pytest.raises(PromotionLeaseConflictError):
        journal.release_matching_lease(D, "integration", D, "wrong", lease.digest)
    assert journal.read_lease(D, "integration") == lease
    with pytest.raises(PromotionLeaseConflictError):
        journal.release_matching_lease(
            D, "integration", "sha256:" + "b" * 64, lease.identity, lease.digest
        )
    assert journal.read_lease(D, "integration") == lease
    assert journal.release_matching_lease(
        D, "integration", lease.operation_id, lease.identity, lease.digest
    )
    assert journal.read_lease(D, "integration") is None
    assert not journal.release_matching_lease(
        D, "integration", lease.operation_id, lease.identity, lease.digest
    )

    expired = journal.acquire_lease(D, "integration", D2, lease_seconds=1, now=now)
    assert journal.release_matching_lease(
        D, "integration", expired.operation_id, expired.identity, expired.digest
    )


def test_lease_evidence_is_content_addressed_and_survives_release(tmp_path: Path) -> None:
    journal = IntegrationPromotionJournal(tmp_path)
    lease = journal.acquire_lease(D, "integration", D, lease_seconds=10)

    loaded = journal.read_lease_evidence(D)
    assert loaded is not None
    evidence, reference = loaded
    assert reference.role == "promotion-lease-evidence"
    assert evidence.operation_id == lease.operation_id
    assert evidence.repository_digest == lease.repository_digest
    assert evidence.target_ref == lease.target_ref
    assert evidence.identity == lease.identity
    assert evidence.digest == lease.digest

    journal.release_lease(lease)
    assert journal.read_lease(D, "integration") is None
    assert journal.read_lease_evidence(D) == loaded


def test_lease_evidence_index_rejects_reuse_with_different_lease(tmp_path: Path) -> None:
    journal = IntegrationPromotionJournal(tmp_path)
    lease = journal.acquire_lease(D, "integration", D, lease_seconds=10)
    journal.release_lease(lease)

    with pytest.raises(PromotionLeaseConflictError, match="durable promotion lease evidence"):
        journal.acquire_lease(D, "integration", D, lease_seconds=10)


def test_lease_evidence_write_failure_cleans_unpublished_live_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = IntegrationPromotionJournal(tmp_path)

    def fail(_evidence: object) -> None:
        raise OSError("evidence unavailable")

    monkeypatch.setattr(journal, "record_lease_evidence", fail)
    with pytest.raises(PromotionJournalError, match="evidence is not durably recorded"):
        journal.acquire_lease(D, "integration", D, lease_seconds=10)
    assert journal.read_lease(D, "integration") is None


def test_tampered_lease_evidence_is_not_readable(tmp_path: Path) -> None:
    journal = IntegrationPromotionJournal(tmp_path)
    lease = journal.acquire_lease(D, "integration", D, lease_seconds=10)
    loaded = journal.read_lease_evidence(D)
    assert loaded is not None
    reference = loaded[1]
    hex_digest = reference.digest.removeprefix("sha256:")
    artifact_path = tmp_path / "artifacts" / "objects" / "sha256" / hex_digest[:2] / hex_digest[2:]
    artifact_path.write_bytes(b"tampered")

    with pytest.raises(PromotionJournalError, match="malformed or unverifiable"):
        journal.read_lease_evidence(D)
    journal.release_lease(lease)


def test_records_are_content_addressed_idempotent_and_conflict_checked(tmp_path: Path) -> None:
    journal = IntegrationPromotionJournal(tmp_path)
    first = journal.record_receipt(receipt())
    second = journal.record_receipt(receipt())
    assert first.digest == second.digest
    loaded = journal.read_receipt(D)
    assert loaded is not None
    assert loaded[0] == receipt()
    assert loaded[1].digest == first.digest
    assert journal.read_intent(D) is None
    with pytest.raises(PromotionRecordConflictError):
        journal.record_receipt(receipt(error="different"))


def test_directory_sync_follows_lease_index_create_and_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    synced: list[Path] = []

    def record_sync(path: Path) -> None:
        synced.append(path)

    monkeypatch.setattr(promotion_journal, "_sync_directory", record_sync)
    journal = IntegrationPromotionJournal(tmp_path)
    lease = journal.acquire_lease(D, "integration", D, lease_seconds=10)
    journal.record_receipt(receipt())
    journal.release_lease(lease)
    assert tmp_path / "promotion-leases" in synced
    assert tmp_path / "promotion-record-index" / "receipt" in synced


def test_lease_directory_sync_failure_leaves_lease_for_reconciliation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(_path: Path) -> None:
        raise OSError("directory sync failed")

    monkeypatch.setattr(promotion_journal, "_sync_directory", fail)
    journal = IntegrationPromotionJournal(tmp_path)
    with pytest.raises(promotion_journal.PromotionJournalError, match="reconciliation"):
        journal.acquire_lease(D, "integration", D, lease_seconds=10)
    assert journal.read_lease(D, "integration") is not None


def test_release_sync_failure_reports_reconciliation_after_unlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = IntegrationPromotionJournal(tmp_path)
    lease = journal.acquire_lease(D, "integration", D, lease_seconds=10)

    def fail(_path: Path) -> None:
        raise OSError("directory sync failed")

    monkeypatch.setattr(promotion_journal, "_sync_directory", fail)
    with pytest.raises(promotion_journal.PromotionJournalError, match="reconciliation"):
        journal.release_lease(lease)
    assert journal.read_lease(D, "integration") is None
