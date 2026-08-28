import json
from pathlib import Path

import pytest
from test_synthetic_validation_contracts import request

from avo_correlate.adapters.artifacts.synthetic_validation_journal import (
    SyntheticValidationJournal,
    SyntheticValidationJournalError,
)
from avo_correlate.contracts.synthetic_validation import (
    SyntheticValidationCreateAuthorization,
    SyntheticValidationPlan,
    synthetic_validation_operation_id,
    validation_ref_for,
)


def plan() -> SyntheticValidationPlan:
    req = request()
    operation = synthetic_validation_operation_id(req)
    return SyntheticValidationPlan(
        operation_id=operation,
        request=req,
        validation_ref=validation_ref_for(operation),
        expected_commit="5" * 40,
        expected_tree="6" * 40,
    )


def test_plan_is_create_once_and_tamper_evident(tmp_path: Path) -> None:
    journal = SyntheticValidationJournal(tmp_path)
    value = plan()
    first = journal.record_plan(value)
    second = journal.record_plan(value)
    assert first == second
    loaded = journal.read_plan(value.operation_id)
    assert loaded is not None and loaded[0] == value
    index = tmp_path / "synthetic-validation-index" / "plan" / f"{value.operation_id[7:]}.json"
    index.write_text("{}", encoding="utf-8")
    with pytest.raises(SyntheticValidationJournalError):
        journal.read_plan(value.operation_id)


def test_conflicting_replay_is_rejected(tmp_path: Path) -> None:
    journal = SyntheticValidationJournal(tmp_path)
    value = plan()
    journal.record_plan(value)
    # A plan with a different operation cannot be indexed under this identity.
    raw = json.loads(value.model_dump_json())
    raw["expected_commit"] = "7" * 40
    with pytest.raises(ValueError):
        journal.record_plan(SyntheticValidationPlan.model_validate(raw))


def test_create_authorization_is_an_atomic_create_once_fence(tmp_path: Path) -> None:
    journal = SyntheticValidationJournal(tmp_path)
    value = plan()
    authorization = SyntheticValidationCreateAuthorization(
        operation_id=value.operation_id,
        plan_digest=value.plan_digest,
        validation_ref=value.validation_ref,
        expected_commit=value.expected_commit,
        expected_tree=value.expected_tree,
    )
    assert journal.claim_create_authorization(authorization)
    assert not journal.claim_create_authorization(authorization)
    loaded = journal.read_create_authorization(value.operation_id)
    assert loaded is not None
    loaded_authorization = loaded[0] if isinstance(loaded, tuple) else loaded
    assert loaded_authorization == authorization


def test_index_publication_uses_short_temp_name_in_deep_windows_root(tmp_path: Path) -> None:
    # Keep the final 64-hex index path within ordinary Windows limits while
    # ensuring the former repeated-index-plus-UUID temporary name would not.
    deep_root = tmp_path / ("nested-" + "x" * 15) / ("segment-" + "y" * 15)
    deep_root.mkdir(parents=True)
    journal = SyntheticValidationJournal(deep_root)
    value = plan()
    journal.record_plan(value)
    assert journal.read_plan(value.operation_id) is not None
