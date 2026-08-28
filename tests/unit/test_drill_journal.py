from pathlib import Path

import pytest

from avo_correlate.adapters.artifacts.drill_journal import (
    DrillJournalError,
    DrillRecordConflictError,
    IntegrationDrillJournal,
)
from avo_correlate.contracts.integration_drill import IntegrationDrillPlan
from avo_correlate.domain.canonical import canonical_digest

D = "sha256:" + "b" * 64
G = "b" * 40


def plan():
    values = dict(
        schema_version=1,
        operation_id=D,
        repository_digest=D,
        target_ref="refs/heads/integration",
        main_before_commit=G,
        main_before_tree=G,
        case_ids=list(range(1, 9)),
        evidence_artifacts=[],
    )
    values["plan_digest"] = canonical_digest(values)
    return IntegrationDrillPlan.model_validate(values)


def test_create_once_replay_and_conflict(tmp_path: Path):
    journal = IntegrationDrillJournal(tmp_path)
    record = plan()
    first = journal.record_plan(record)
    assert journal.record_plan(record) == first
    altered = record.model_copy(update={"main_before_tree": "c" * 40})
    with pytest.raises(DrillRecordConflictError):
        journal.record_plan(altered)
    loaded = journal.read_plan(record.operation_id)
    assert loaded is not None and loaded[0] == record


def test_missing_artifact_is_rejected(tmp_path: Path):
    journal = IntegrationDrillJournal(tmp_path)
    record = plan()
    ref = journal.record_plan(record)
    journal.delete_artifact(ref.digest)
    with pytest.raises(DrillJournalError):
        journal.read_plan(record.operation_id)
