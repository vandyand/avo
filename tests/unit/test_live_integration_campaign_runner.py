from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar, cast

import pytest

import scripts.run_sanitized_integration_campaign as runner
from avo_correlate.contracts.integration_promotion import CandidatePublicationBinding


def config(tmp_path: Path, **updates: object) -> runner.CampaignRunnerConfig:
    values: dict[str, Any] = {
        "state_root": tmp_path / "state",
        "repository_root": tmp_path / "checkout",
        "candidate_root": tmp_path / "candidate",
        "evidence_root": tmp_path / "evidence",
        "controller_config": tmp_path / "policy.json",
        "candidate_id": "sanitized-1",
        "proposer_id": "avo-controller",
        "trusted_checks": (("validate (ubuntu-latest)", 15368),),
        "freshness_cutoff": datetime.now(UTC),
    }
    values.update(updates)
    return runner.CampaignRunnerConfig(**values)


def test_preflight_is_local_and_reports_no_remote_mutations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    checkout = tmp_path / "checkout"
    candidate = tmp_path / "candidate"
    evidence = tmp_path / "evidence"
    checkout.mkdir()
    candidate.mkdir()
    evidence.mkdir()
    policy = tmp_path / "policy.json"
    policy.write_bytes(b"{}")

    class Snapshot:
        commit = "a" * 40
        tree = "b" * 40
        source_tree_digest = "sha256:" + "c" * 64

    class Comparison:
        candidate_digest = "sha256:" + "d" * 64
        changed_paths: ClassVar[list[str]] = ["docs/change.md"]

    calls: list[str] = []

    class Reader:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def snapshot(self) -> Snapshot:
            calls.append("snapshot")
            return Snapshot()

        def compare_candidate(self, _root: Path, _snapshot: Snapshot) -> Comparison:
            calls.append("compare")
            return Comparison()

    monkeypatch.setattr(runner, "GitRepositoryReader", Reader)
    def fake_evidence(_root: Path) -> Any:
        return ({f"sha256:{'e' * 64}": (object(), b"{}")}, ("fixture.json",))

    monkeypatch.setattr(runner, "load_evidence", fake_evidence)
    value = runner.preflight(config(tmp_path, preflight=True))

    assert value.remote_mutations == ()
    assert calls == ["snapshot", "compare"]
    assert value.base_digest == Snapshot.source_tree_digest


@pytest.mark.parametrize(
    "field,value",
    [("remote", "https://example.invalid/avo.git"), ("target_ref", "refs/heads/main")],
)
def test_preflight_refuses_scope_drift(tmp_path: Path, field: str, value: str) -> None:
    with pytest.raises(runner.CampaignRunnerError, match="fixed"):
        runner.preflight(config(tmp_path, **{field: value}))


def test_askpass_contains_no_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "ghp-test-secret-that-must-not-be-written"
    monkeypatch.setenv("GITHUB_TOKEN", secret)
    helper = runner.askpass_path(tmp_path / "state")
    content = helper.read_text(encoding="utf-8")
    assert secret not in content
    assert "GITHUB_TOKEN" in content
    assert "x-access-token" in content
    assert "username" in content.lower()
    assert "password" in content.lower()


def test_redact_secret_is_used_for_diagnostics() -> None:
    secret = "sensitive-token"
    assert secret not in runner.redact_secret(f"request failed with {secret}", secret)
    assert "[REDACTED]" in runner.redact_secret(f"request failed with {secret}", secret)


def test_wait_discovery_is_bounded(tmp_path: Path) -> None:
    class Provider:
        def discover(self, _opened: object, _publication: object) -> object:
            raise ValueError("checks pending")

    candidate = tmp_path / "candidate"
    candidate.mkdir()
    cfg = config(tmp_path, wait_seconds=0)
    with pytest.raises(runner.CampaignRunnerError, match="within the bound"):
        runner.wait_discovery(
            cast(Any, Provider()), object(), cast(CandidatePublicationBinding, object()), cfg
        )


def test_result_write_is_canonical_and_resume_safe(tmp_path: Path) -> None:
    path = tmp_path / "state" / "result.json"
    payload = {"schema_version": 1, "state": "preflight", "remote": runner.REMOTE}
    runner.write_result(path, payload)
    first = path.read_bytes()
    runner.write_result(path, payload)
    assert path.read_bytes() == first
    assert json.loads(first) == payload


def test_live_main_recovers_before_mutable_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Report:
        def model_dump(self, *, mode: str) -> dict[str, object]:
            assert mode == "json"
            return {"operation_id": "sha256:" + "a" * 64, "outcome": "applied"}

    class Recovered:
        report = Report()
        package = None
        package_artifact = None

    def recover(_config: runner.CampaignRunnerConfig) -> Any:
        return Recovered()

    def forbidden_preflight(_config: runner.CampaignRunnerConfig) -> Any:
        return pytest.fail("mutable checkout preflight must not run during recovery")

    monkeypatch.setattr(runner, "_recover_before_preflight", recover)
    monkeypatch.setattr(runner, "preflight", forbidden_preflight)
    state = tmp_path / "state"
    result = runner.main(
        [
            "--state-root", str(state),
            "--candidate-root", str(tmp_path / "candidate"),
            "--evidence-root", str(tmp_path / "evidence"),
            "--controller-config", str(tmp_path / "policy.json"),
            "--candidate-id", "candidate",
            "--proposer-id", "proposer",
            "--trusted-check", "validate=15368",
        ]
    )
    assert result == 0
    assert json.loads((state / "result.json").read_text(encoding="utf-8"))["state"] == "report"


def test_recovery_fails_closed_on_multiple_durable_plans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class MultiplePlans:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def list_plan_operations(self) -> tuple[str, ...]:
            return ("sha256:" + "a" * 64, "sha256:" + "b" * 64)

    monkeypatch.setattr(runner, "CampaignCompletionJournal", MultiplePlans)
    with pytest.raises(runner.CampaignRunnerError, match="multiple durable campaign plans"):
        runner.recover_before_preflight(config(tmp_path))


def test_recovery_finalizes_crash_after_final_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    operation_id = "sha256:" + "a" * 64
    finalized = object()

    class FinalEvidenceWithoutPackage:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def list_plan_operations(self) -> tuple[str, ...]:
            return (operation_id,)

        def read_package(self, _operation_id: str) -> None:
            return None

        def read_final_evidence(self, _operation_id: str) -> tuple[object, object]:
            return object(), object()

    class RecoveryService:
        def finalize(self, recovered_operation_id: str) -> object:
            assert recovered_operation_id == operation_id
            return finalized

        def resume(self, _operation_id: str) -> object:
            return pytest.fail("final-evidence recovery must not resume promotion")

    def recovery_service(_config: runner.CampaignRunnerConfig) -> RecoveryService:
        return RecoveryService()

    monkeypatch.setattr(runner, "CampaignCompletionJournal", FinalEvidenceWithoutPackage)
    monkeypatch.setattr(runner, "_build_recovery_service", recovery_service)

    assert runner.recover_before_preflight(config(tmp_path)) is finalized
