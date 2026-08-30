from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
    MainGraduationRecordConflictError,
)
from avo_correlate.contracts import MainLeaseEvidenceReadRequest, MainLeaseEvidenceRecord
from avo_correlate.domain.canonical import canonical_digest

R = "sha256:" + "1" * 64
OP = "sha256:" + "2" * 64
OP2 = "sha256:" + "3" * 64
P = "sha256:" + "4" * 64
NOW = datetime(2026, 1, 1, tzinfo=UTC)


def lease(operation_id: str = OP) -> MainLeaseEvidenceRecord:
    values = {
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "operation_id": operation_id,
        "owner": "avo-controller",
        "policy_epoch": P,
        "lease_epoch_digest": P,
        "acquired_at": NOW,
        "expires_at": NOW + timedelta(hours=1),
    }
    construct = cast(Any, MainLeaseEvidenceRecord.model_construct)
    probe = construct(**cast(dict[str, Any], values), lease_digest=OP, evidence_digest=OP)
    values["lease_digest"] = canonical_digest(
        probe.model_dump(exclude={"lease_digest", "evidence_digest"}, mode="json")
    )
    probe = construct(**cast(dict[str, Any], values), evidence_digest=OP)
    values["evidence_digest"] = canonical_digest(
        probe.model_dump(exclude={"evidence_digest"}, mode="json")
    )
    return MainLeaseEvidenceRecord.model_validate(values)


def test_lease_pointer_replays_and_repairs_a_crash_window(tmp_path: Path) -> None:
    journal = MainGraduationJournal(tmp_path)
    record = lease()
    reference = journal.record_lease_evidence_record(record)
    local = journal._phase_local_path("lease-evidence-record", record.operation_id)  # pyright: ignore[reportPrivateUsage]
    local.unlink()

    restarted = MainGraduationJournal(tmp_path)
    assert restarted.record_lease_evidence_record(record) == reference
    assert restarted.read_lease_evidence_record(record.operation_id) is not None
    assert (
        restarted.assert_lease_evidence(
            MainLeaseEvidenceReadRequest(
                repository_digest=R,
                target_ref="refs/heads/main",
                operation_id=record.operation_id,
                lease_digest=record.lease_digest,
                requested_at=NOW,
            )
        )
        == record
    )


def test_target_lease_is_create_once_and_exactly_releasable(tmp_path: Path) -> None:
    journal = MainGraduationJournal(tmp_path)
    record = lease()
    journal.record_lease_evidence_record(record)
    with pytest.raises(MainGraduationRecordConflictError):
        journal.record_lease_evidence_record(lease(OP2))
    assert journal.release_target_lease(R, "refs/heads/main", OP, record.lease_digest)
    replacement = lease(OP2)
    assert journal.record_lease_evidence_record(replacement)


def test_same_lease_is_safe_under_concurrent_replay(tmp_path: Path) -> None:
    record = lease()

    def write(_: int) -> str:
        return MainGraduationJournal(tmp_path).record_lease_evidence_record(record).digest

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(write, range(4)))
    assert results == [results[0]] * 4
