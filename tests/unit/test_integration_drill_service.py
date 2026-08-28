import json
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from avo_correlate.adapters.artifacts.drill_journal import IntegrationDrillJournal
from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.adapters.artifacts.promotion_journal import (
    IntegrationPromotionJournal,
    PromotionJournalError,
)
from avo_correlate.application.integration_drill_service import (
    AVO0046_CASES,
    DeterministicIntegrationDrillPorts,
    DrillObservation,
    IntegrationDrillService,
    quality_failure,
)
from avo_correlate.contracts.integration_drill import IntegrationDrillResult
from avo_correlate.domain.canonical import canonical_digest


def test_fixed_plan_and_six_boundary_faults(tmp_path: Path) -> None:
    ports = DeterministicIntegrationDrillPorts()
    service = IntegrationDrillService(tmp_path, ports)
    plan = service.prepare()
    assert plan.case_ids == list(range(1, 9))
    observations = [ports.execute(case_id, plan.operation_id) for case_id in AVO0046_CASES]
    assert [item.fault for item in observations] == [
        "duplicate_runner",
        "stale_base_and_head",
        "check_identity_mismatch",
        "reviewer_quorum_private_gate",
        "ambiguous_provider_mutation",
        "invalid_topology",
    ]
    assert ports.mutation_counts == {1: 1, 2: 0, 3: 0, 4: 0, 5: 1, 6: 0}
    assert all(item.main_before == item.main_after for item in observations)


def test_case_four_quality_adapter_rejects_policy_downgrade_fixture() -> None:
    outcome, error = quality_failure()
    assert outcome == "rejected_quality"
    assert error == "reviewer did not approve"


@pytest.mark.parametrize(
    ("case_id", "expected", "observed"),
    [(2, "stale_base", "applied"), (3, "rejected", "accepted")],
)
def test_wrong_typed_boundary_outcome_is_not_journaled(
    tmp_path: Path, case_id: int, expected: str, observed: str
) -> None:
    service = IntegrationDrillService(tmp_path)
    plan = service.prepare()
    wrong = DrillObservation(
        case_id=case_id,
        fault="injected",
        expected_outcome=expected,
        observed_outcome=observed,
        integration_before="3" * 40,
        integration_after="3" * 40,
        main_before="1" * 40,
        main_after="1" * 40,
        provider_mutations=0,
        provider_reconciles=1 if case_id == 2 else 0,
        fault_consumed=True,
        boundary="adversarial fake",
        error="wrong typed outcome",
    )
    with pytest.raises(RuntimeError, match="unexpected typed outcome"):
        service._validate_observation(plan, wrong)  # pyright: ignore[reportPrivateUsage]
    assert service.journal.read_case_result(plan.operation_id, case_id) is None


def test_aggregate_rejects_missing_or_wrong_root_case(tmp_path: Path) -> None:
    execution = IntegrationDrillService(tmp_path).run()
    assert execution.result is not None
    values = execution.result.model_dump(mode="json")
    values["cases"][-1]["operation_id"] = "sha256:" + "f" * 64
    with pytest.raises(ValidationError, match="root drill identity"):
        IntegrationDrillResult.model_validate(values)
    values["cases"][-1] = values["cases"][0]
    with pytest.raises(ValidationError):
        IntegrationDrillResult.model_validate(values)


def test_replay_is_durable_and_pending_cases_are_explicit(tmp_path: Path) -> None:
    ports = DeterministicIntegrationDrillPorts()
    controller = IntegrationDrillService(tmp_path, ports)
    first = controller.run()
    assert first.status == "complete"
    assert first.pending_case_ids == ()
    assert [case.case_id for case in first.cases] == list(range(1, 9))
    assert first.plan.main_before_commit == first.plan.main_before_commit
    assert first.result is not None
    assert controller.journal.read_result(first.plan.operation_id) is not None
    assert ports.mutation_counts == {1: 1, 2: 0, 3: 0, 4: 0, 5: 1, 6: 0}

    replay = IntegrationDrillService(tmp_path, ports).run()
    assert replay.result is not None
    assert replay.result.result_digest == first.result.result_digest
    assert replay.plan.plan_digest == first.plan.plan_digest
    assert ports.mutation_counts == {1: 1, 2: 0, 3: 0, 4: 0, 5: 1, 6: 0}
    assert [case.outcome for case in replay.cases[:6]] == [
        "passed",
        "rejected",
        "rejected",
        "rejected",
        "passed",
        "rejected",
    ]


def test_case_seven_promotion_intent_revalidates_after_fresh_journal(tmp_path: Path) -> None:
    service = IntegrationDrillService(tmp_path)
    service._execute_case7(service.prepare())  # pyright: ignore[reportPrivateUsage]
    promotion = IntegrationPromotionJournal(
        tmp_path / "case-7-promotion",
        artifact_store=FilesystemArtifactStore(tmp_path / "artifacts"),
    )
    index = next(
        (tmp_path / "case-7-promotion" / "promotion-record-index" / "intent").glob("*.json")
    )
    operation_id = "sha256:" + index.stem
    loaded = promotion.read_intent(operation_id)
    assert loaded is not None
    assert loaded[0].operation_id == operation_id


def test_case_seven_manifest_reconstructs_and_detects_missing_child(
    tmp_path: Path,
) -> None:
    service = IntegrationDrillService(tmp_path)
    case = service._execute_case7(service.prepare())  # pyright: ignore[reportPrivateUsage]
    rollback = IntegrationDrillJournal(
        tmp_path / "case-7-rollback",
        artifact_store=FilesystemArtifactStore(tmp_path / "artifacts"),
    )
    loaded = rollback.read_promotion_evidence_manifest(case.operation_id)
    assert loaded is not None
    manifest, manifest_ref = loaded
    assert manifest_ref.digest in {ref.digest for ref in case.evidence_artifacts}
    assert {link.kind for link in manifest.links} == {
        "intent", "lease_evidence", "mutation_authorization", "receipt"
    }
    root_store = FilesystemArtifactStore(tmp_path / "artifacts")
    for reference in case.evidence_artifacts:
        assert root_store.read_bytes(reference)

    replay = IntegrationDrillService(tmp_path)
    replay._validate_case7_promotion_evidence(case)  # pyright: ignore[reportPrivateUsage]

    child_intent = next(link for link in manifest.links if link.kind == "intent")
    child_store = FilesystemArtifactStore(tmp_path / "artifacts")
    assert child_store.delete(child_intent.artifact.digest)
    with pytest.raises(PromotionJournalError):
        IntegrationDrillService(tmp_path).run()


def test_case_seven_reconstruction_is_deterministic_across_fresh_roots(
    tmp_path: Path,
) -> None:
    first_root = tmp_path.parent / f"{tmp_path.name}-first"
    second_root = tmp_path.parent / f"{tmp_path.name}-second"
    first_root.mkdir()
    second_root.mkdir()
    first_service = IntegrationDrillService(first_root)
    second_service = IntegrationDrillService(second_root)
    first_case = first_service._execute_case7(first_service.prepare())  # pyright: ignore[reportPrivateUsage]
    second_case = second_service._execute_case7(second_service.prepare())  # pyright: ignore[reportPrivateUsage]
    assert canonical_digest(first_case) == canonical_digest(second_case)


def test_case_eight_uses_root_operation_without_orphan_indexes(tmp_path: Path) -> None:
    execution = IntegrationDrillService(tmp_path).run()
    assert execution.result is not None
    root_operation = execution.plan.operation_id
    case = next(item for item in execution.cases if item.case_id == 8)
    assert case.operation_id == root_operation

    synthetic_root = tmp_path / "synthetic-validation"
    synthetic_payloads: list[dict[str, Any]] = []
    for path in synthetic_root.rglob("*.json"):
        payload = cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))
        if "operation_id" in payload:
            synthetic_payloads.append(payload)
    assert synthetic_payloads
    assert all(payload["operation_id"] == root_operation for payload in synthetic_payloads)

    store = FilesystemArtifactStore(tmp_path / "artifacts")
    for reference in case.evidence_artifacts:
        payload = cast(dict[str, Any], json.loads(store.read_bytes(reference).decode("utf-8")))
        operation_values = [
            value for key, value in payload.items() if key.endswith("operation_id")
        ]
        assert all(value == root_operation for value in operation_values)

    case_indexes = list((tmp_path / "integration-drill-index" / "case").glob("*.json"))
    assert len(case_indexes) == 8
    assert {path.stem.rsplit("-", 1)[0] for path in case_indexes} == {
        root_operation.removeprefix("sha256:")
    }
