from pathlib import Path

import pytest

from avo_correlate.adapters.hosted_git.github import (
    GitHubEvidenceSnapshot,
    GitHubIntegrationProvider,
)
from avo_correlate.application.integration_attester_drill_service import (
    ATTESTER_IDENTITY,
    AttesterScenario,
    IntegrationAttesterDrillService,
)


def test_case_8_runs_real_boundaries_and_records_immutable_result(tmp_path: Path) -> None:
    service = IntegrationAttesterDrillService(tmp_path)

    run = service.run()

    assert run.case.case_id == 8
    assert run.case.outcome == "passed"
    assert run.case.attester_identity == ATTESTER_IDENTITY
    assert run.case.main_before_commit == run.case.main_after_commit
    assert run.case.target_head_commit == run.case.main_before_commit
    assert run.case.target_head_tree == "2" * 40
    assert run.case.deploy_performed is False
    assert run.validation_outcome in {"created", "already_present", "reconciled"}
    assert run.create_calls == 1
    assert [item.name for item in run.scenarios] == [
        "exact_synthetic_success",
        "head_only_check",
        "wrong_app_identity",
        "wrong_synthetic_sha",
        "stale_check",
        "incomplete_check",
        "duplicate_trusted_context",
    ]
    assert all(item.observed == item.expected for item in run.scenarios)
    assert len(run.case.evidence_artifacts) == 1
    assert service.journal.read_case_result(run.case.operation_id, 8) is not None


def test_exact_ref_replay_is_read_only_and_case_replay_is_durable(tmp_path: Path) -> None:
    first_service = IntegrationAttesterDrillService(tmp_path)
    first = first_service.run()
    assert first_service.last_transport is not None
    assert first_service.last_transport.create_calls == 1

    replay_service = IntegrationAttesterDrillService(tmp_path)
    replay = replay_service.run()

    assert replay.case == first.case
    assert replay.validation_outcome == "replayed"
    assert replay.create_calls == 0
    assert replay_service.last_transport is None


def test_wrong_typed_attestation_outcome_fails_closed_before_journaling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = IntegrationAttesterDrillService(tmp_path)

    monkeypatch.setattr(
        service,
        "_check_scenarios",
        lambda: [AttesterScenario("wrong", "rejected", "accepted")],
    )
    with pytest.raises(RuntimeError, match="wrong typed result"):
        service.run()
    assert service.journal.read_case_result(service.operation_id(), 8) is None


def test_head_only_parser_acceptance_fails_closed_before_journaling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = IntegrationAttesterDrillService(tmp_path)
    original = GitHubIntegrationProvider._evidence_snapshot  # pyright: ignore[reportPrivateUsage]

    def bypass_head_only(
        provider: GitHubIntegrationProvider, synthetic: str, synthetic_tree: str
    ) -> GitHubEvidenceSnapshot:
        if getattr(provider.transport, "check_mode", None) == "head_only":
            return GitHubEvidenceSnapshot(
                synthetic_merge_commit=synthetic,
                synthetic_merge_tree=synthetic_tree,
                protection_evidence_digest="sha256:" + "a" * 64,
                check_evidence_manifest_digest="sha256:" + "b" * 64,
                protection_evidence={},
                check_evidence_manifest={},
            )
        return original(provider, synthetic, synthetic_tree)

    monkeypatch.setattr(GitHubIntegrationProvider, "_evidence_snapshot", bypass_head_only)
    with pytest.raises(RuntimeError, match="wrong typed result"):
        service.run()
    assert service.journal.read_case_result(service.operation_id(), 8) is None
