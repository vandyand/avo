from __future__ import annotations

import json
from pathlib import Path

import pytest

from avo_correlate.adapters.artifacts.rollback_quarantine import (
    RollbackOperationQuarantineJournal,
)
from avo_correlate.contracts.prepublication import RollbackRemoteAbsenceObservation
from avo_correlate.domain.canonical import canonical_digest
from scripts.run_avo0046_live_rollback import quarantine_rollback_operation
from tests.unit.test_rollback_bundle_authority import Fixture


def _absence(authorization: object) -> RollbackRemoteAbsenceObservation:
    values = {
        "schema_version": 1,
        "repository_digest": authorization.repository_digest,
        "candidate_ref": authorization.candidate_ref,
        "candidate_commit": authorization.rollback_candidate_commit,
        "base_commit": authorization.failed_integration_head_commit,
        "ref_absent": True,
        "pull_request_numbers": [],
    }
    return RollbackRemoteAbsenceObservation.model_validate(
        {**values, "observation_id": canonical_digest(values)}
    )


def test_quarantine_is_create_once_and_binds_authority_children(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path / "fixture")
    authorization = fixture.authorize()
    index_path = fixture.journal._root / authorization.operation_id.removeprefix("sha256:")  # pyright: ignore[reportPrivateUsage]
    index_data = index_path.read_bytes()
    value = json.loads(index_data)
    canary_ref = fixture.canary_ref
    plan_ref = fixture.plan_ref
    calls: list[tuple[str, str, str]] = []

    def verifier(ref: str, commit: str, base: str) -> object:
        calls.append((ref, commit, base))
        return _absence(authorization)

    journal = RollbackOperationQuarantineJournal(tmp_path / "quarantine")
    first = journal.create_for_authorization(
        authorization,
        authorization_index_data=index_data,
        canary_package_artifact=canary_ref,
        publication_plan_artifact=plan_ref,
        reason="operator abandoned before publication",
        absence_verifier=verifier,
    )
    second = journal.create_for_authorization(
        authorization,
        authorization_index_data=index_data,
        canary_package_artifact=canary_ref,
        publication_plan_artifact=plan_ref,
        reason="operator abandoned before publication",
        absence_verifier=verifier,
    )
    assert first == second
    assert journal.read(authorization.operation_id) == first
    assert calls
    assert value["authorization"]["operation_id"] == authorization.operation_id

    with pytest.raises(ValueError, match="conflicting"):
        journal.create_for_authorization(
            authorization,
            authorization_index_data=index_data,
            canary_package_artifact=canary_ref,
            publication_plan_artifact=plan_ref,
            reason="different terminal reason",
            absence_verifier=verifier,
        )


def test_quarantine_rejects_mixed_or_tampered_authority_index(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path / "fixture")
    authorization = fixture.authorize()
    index_path = fixture.journal._root / authorization.operation_id.removeprefix("sha256:")  # pyright: ignore[reportPrivateUsage]
    value = json.loads(index_path.read_bytes())
    value["authorization"]["operation_id"] = "sha256:" + "f" * 64
    journal = RollbackOperationQuarantineJournal(tmp_path / "quarantine")
    with pytest.raises(ValueError, match="authorization index"):
        journal.create_for_authorization(
            authorization,
            authorization_index_data=json.dumps(value).encode(),
            canary_package_artifact=fixture.canary_ref,
            publication_plan_artifact=fixture.plan_ref,
            reason="abandoned",
            absence_verifier=lambda *_: pytest.fail("absence must not be checked"),
        )


def test_operator_quarantine_helper_reads_authority_without_modifying_it(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path / "fixture")
    authorization = fixture.authorize()
    state_root = tmp_path / "state"
    index_path = (
        state_root
        / "artifacts"
        / "rollback-publication-authorizations"
        / authorization.operation_id.removeprefix("sha256:")
    )
    index_path.parent.mkdir(parents=True)
    original_index = (
        fixture.journal._root / authorization.operation_id.removeprefix("sha256:")  # pyright: ignore[reportPrivateUsage]
    ).read_bytes()
    index_path.write_bytes(original_index)
    result = quarantine_rollback_operation(
        state_root,
        authorization,
        canary_package_artifact=fixture.canary_ref,
        publication_plan_artifact=fixture.plan_ref,
        reason="operator abandoned before publication",
        absence_verifier=lambda _ref, _commit, _base: _absence(authorization),
    )
    assert result.operation_id == authorization.operation_id
    assert index_path.read_bytes() == original_index
