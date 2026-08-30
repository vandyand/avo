from pathlib import Path

import pytest
from pydantic import ValidationError

from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
    MainGraduationJournalError,
)
from avo_correlate.contracts.main_graduation import MainCompletionPackage


def test_c4_authority_fields_are_required() -> None:
    for name in (
        "lease_evidence_record",
        "release_claim",
        "claimed_transition_receipt",
        "release_transition_intent",
        "release_transition_mutation_receipt",
        "release_transition_fence_resolution",
    ):
        assert MainCompletionPackage.model_fields[name].is_required()


def test_legacy_completion_cannot_be_recorded_as_c4(tmp_path: Path) -> None:
    # model_construct simulates a legacy caller that tries to bypass the
    # required C4 fields.  The journal reparses at its boundary and rejects it
    # before any completion artifact or index is published.
    legacy = MainCompletionPackage.model_construct(
        operation_id="sha256:" + "1" * 64,
        repository_digest="sha256:" + "2" * 64,
    )
    with pytest.raises((ValidationError, MainGraduationJournalError)):
        MainGraduationJournal(tmp_path).record_completion(legacy)
    assert not (tmp_path / "main-graduation-index" / "completion").exists()
