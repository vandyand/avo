from __future__ import annotations

import json
import os
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar, cast

import pytest

import scripts.run_sanitized_integration_campaign as runner
from avo_correlate.adapters.artifacts.synthetic_validation_journal import (
    SyntheticValidationJournal,
)
from avo_correlate.application.integration_campaign_service import (
    CampaignOpened,
    campaign_open_identity,
)
from avo_correlate.application.synthetic_validation_service import SyntheticValidationService
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_campaign import IntegrationCampaignEvidencePackage
from avo_correlate.contracts.integration_promotion import CandidatePublicationBinding
from avo_correlate.contracts.synthetic_validation import (
    SyntheticValidationCompletionProof,
    SyntheticValidationObservation,
    SyntheticValidationOutcome,
    SyntheticValidationPlan,
    SyntheticValidationRequest,
    synthetic_validation_operation_id,
    validation_ref_for,
)
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.test_integration_campaign_contracts import (
    _package,  # pyright: ignore[reportPrivateUsage]
)

# This suite intentionally exercises private runner seams to prove mutation
# ordering and recovery behavior.
# pyright: reportPrivateUsage=false


def config(tmp_path: Path, **updates: object) -> runner.CampaignRunnerConfig:
    values: dict[str, Any] = {
        "state_root": tmp_path / "state",
        "repository_root": tmp_path / "checkout",
        "candidate_root": tmp_path / "candidate",
        "evidence_root": tmp_path / "evidence",
        "controller_config": tmp_path / "policy.json",
        "candidate_id": "sanitized-1",
        "proposer_id": "avo-controller",
    }
    values.update(updates)
    return runner.CampaignRunnerConfig(**values)


def test_runner_pins_synthetic_checks_and_derives_bounded_freshness(tmp_path: Path) -> None:
    trusted_now = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
    configured = config(tmp_path, _trusted_clock=lambda: trusted_now)
    assert configured.trusted_checks == runner.TRUSTED_SYNTHETIC_CHECKS
    assert configured.protection_checks == runner.PROTECTION_CHECKS
    assert configured.protection_checks != configured.trusted_checks
    assert configured.freshness_cutoff == trusted_now - timedelta(hours=1)
    with pytest.raises(TypeError):
        runner.CampaignRunnerConfig(
            state_root=tmp_path / "state",
            repository_root=tmp_path / "checkout",
            candidate_root=tmp_path / "candidate",
            evidence_root=tmp_path / "evidence",
            controller_config=tmp_path / "policy.json",
            candidate_id="candidate",
            proposer_id="proposer",
            trusted_checks=(("ci", 7),),  # type: ignore[call-arg]
        )


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


@pytest.mark.parametrize(
    "changed_path", [".github/workflows/synthetic-validation.yml", "pyproject.toml"]
)
def test_preflight_blocks_trusted_authority_changes_before_hosted_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, changed_path: str
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
        changed_paths: ClassVar[list[str]] = [changed_path]

    class Reader:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def snapshot(self) -> Snapshot:
            return Snapshot()

        def compare_candidate(self, _root: Path, _snapshot: Snapshot) -> Comparison:
            return Comparison()

    monkeypatch.setattr(runner, "GitRepositoryReader", Reader)
    with pytest.raises(runner.CampaignRunnerError, match="before hosted writes"):
        runner.preflight(config(tmp_path, preflight=True))


def test_askpass_contains_no_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "ghp-test-secret-that-must-not-be-written"
    monkeypatch.setenv("GITHUB_TOKEN", secret)
    helper = runner.askpass_path(tmp_path / "state")
    assert secret not in helper.read_text(encoding="utf-8")
    content = helper.read_text(encoding="utf-8")
    assert secret not in content
    assert "GITHUB_TOKEN" in content
    assert "x-access-token" in content
    lowered = content.lower()
    assert "username" in lowered or "[uu]sername" in lowered
    assert "password" in lowered or "[pp]assword" in lowered


@pytest.mark.skipif(os.name != "nt", reason="Windows batch helper requires cmd.exe")
@pytest.mark.parametrize("secret", ["ghp-fake-token-for-regression", "a&b|c<d>e^f%g!h"])
def test_windows_askpass_returns_exact_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, secret: str
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", secret)
    helper = runner.askpass_path(tmp_path / "state")

    def run_helper(prompt: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["cmd.exe", "/d", "/c", str(helper), prompt],
            capture_output=True,
            check=False,
        )

    username = run_helper("Username for github.com")
    password = run_helper("Password for github.com")
    unrelated = run_helper("Unrelated prompt")
    assert (username.returncode, username.stdout) == (0, b"x-access-token\r\n")
    assert (password.returncode, password.stdout) == (0, secret.encode() + b"\r\n")
    assert (unrelated.returncode, unrelated.stdout) == (1, b"")


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


class _CleanupProvider:
    def __init__(self, *, delete_error: bool = False) -> None:
        self.ref: dict[str, str] | None = None
        self.delete_error = delete_error
        self.create_calls = 0
        self.delete_calls = 0

    def read_validation_ref(self, repository_digest: str, ref: str) -> object | None:
        del repository_digest, ref
        return self.ref

    def create_validation_ref(self, repository_digest: str, ref: str, commit: str) -> object:
        del repository_digest, ref
        self.create_calls += 1
        self.ref = {"commit": commit, "tree": "b" * 40}
        return self.ref

    def delete_validation_ref(self, repository_digest: str, ref: str) -> object:
        del repository_digest, ref
        self.delete_calls += 1
        if self.delete_error:
            raise RuntimeError("lost delete acknowledgment")
        self.ref = None
        return {}


class _CompletionProofVerifier:
    """Test double for the runner's durable campaign-package verifier."""

    def verify(
        self,
        plan: SyntheticValidationPlan,
        proof: SyntheticValidationCompletionProof,
    ) -> None:
        del plan
        if proof.completion_digest != "sha256:" + "d" * 64:
            raise ValueError("completion package is not durable test evidence")


def _validation_plan(
    tmp_path: Path, provider: _CleanupProvider
) -> tuple[SyntheticValidationService, SyntheticValidationPlan]:
    service = SyntheticValidationService(
        provider,
        SyntheticValidationJournal(tmp_path),
        completion_proof_verifier=_CompletionProofVerifier(),
    )
    observation = SyntheticValidationObservation(
        repository_digest="sha256:" + "a" * 64,
        base_ref="refs/heads/integration",
        base_commit="a" * 40,
        base_tree="a" * 40,
        head_ref="refs/heads/candidate/x",
        head_commit="b" * 40,
        head_tree="b" * 40,
        synthetic_commit="c" * 40,
        synthetic_tree="b" * 40,
    )
    plan = service.prepare(
        observation,
        target_repository_digest=observation.repository_digest,
        target_ref=observation.base_ref,
        target_identity="campaign-open-identity",
        trusted_check_contexts=["avo synthetic validate (ubuntu-latest)"],
    )
    service.trigger(plan)
    return service, plan


def _completed_result() -> Any:
    return SimpleNamespace(
        package=object(),
        package_artifact=SimpleNamespace(digest="sha256:" + "d" * 64),
    )


def test_cleanup_requires_durable_package_and_uses_package_digest(
    tmp_path: Path,
) -> None:
    provider = _CleanupProvider()
    service, plan = _validation_plan(tmp_path, provider)
    result = _completed_result()
    cleanup = runner._cleanup_completed_validation(config(tmp_path), service, plan, result)
    assert cleanup is not None
    assert isinstance(cleanup, SyntheticValidationOutcome)
    assert cleanup.outcome == "cleaned"
    assert provider.delete_calls == 1
    state = json.loads(
        (tmp_path / "state" / "synthetic-validation-cleanup.json").read_text(encoding="utf-8")
    )
    assert state["synthetic_validation_cleanup"]["outcome"] == "cleaned"


def test_cleanup_ambiguity_replays_cleanup_to_success(tmp_path: Path) -> None:
    provider = _CleanupProvider(delete_error=True)
    service, plan = _validation_plan(tmp_path, provider)
    result = _completed_result()
    first = runner._cleanup_completed_validation(config(tmp_path), service, plan, result)
    assert first is not None
    assert isinstance(first, SyntheticValidationOutcome)
    assert first.outcome == "reconciliation_required"
    provider.delete_error = False
    second = runner._cleanup_completed_validation(config(tmp_path), service, plan, result)
    assert second is not None
    assert isinstance(second, SyntheticValidationOutcome)
    assert second.outcome == "cleaned"
    assert provider.delete_calls == 2
    assert provider.create_calls == 1


def test_cleanup_after_restart_reuses_durable_plan_and_package_proof(tmp_path: Path) -> None:
    provider = _CleanupProvider()
    service, plan = _validation_plan(tmp_path, provider)
    result = _completed_result()
    del service  # Simulate the process that triggered validation crashing.
    restarted = SyntheticValidationService(
        provider,
        SyntheticValidationJournal(tmp_path),
        completion_proof_verifier=_CompletionProofVerifier(),
    )
    cleanup = runner._cleanup_completed_validation(config(tmp_path), restarted, plan, result)
    assert isinstance(cleanup, SyntheticValidationOutcome)
    assert cleanup.outcome == "cleaned"
    assert provider.delete_calls == 1


def _package_validation_plan(package: Any) -> SyntheticValidationPlan:
    observation = package.observation
    opened = CampaignOpened(
        pull_request_number=package.intent.pull_request_number,
        pull_request_url=package.intent.pull_request_url,
        target_ref=package.intent.target_ref,
        base_commit=package.intent.base_commit,
        base_tree=package.intent.base_tree,
        open_identity="sha256:" + "0" * 64,
    )
    validation_observation = SyntheticValidationObservation(
        repository_digest=observation.repository_digest,
        base_ref=observation.base_ref,
        base_commit=observation.base_commit,
        base_tree=observation.base_tree,
        head_ref=observation.head_ref,
        head_commit=observation.head_commit,
        head_tree=observation.candidate_tree,
        synthetic_commit=observation.synthetic_merge_commit,
        synthetic_tree=observation.synthetic_merge_tree,
    )
    request = SyntheticValidationRequest(
        observation=validation_observation,
        target_repository_digest=observation.repository_digest,
        target_ref=observation.base_ref,
        target_identity=campaign_open_identity(package.publication, opened),
        trusted_check_contexts=["avo synthetic validate (ubuntu-latest)"],
    )
    operation_id = synthetic_validation_operation_id(request)
    return SyntheticValidationPlan(
        operation_id=operation_id,
        request=request,
        validation_ref=validation_ref_for(operation_id),
        expected_commit=validation_observation.synthetic_commit,
        expected_tree=validation_observation.synthetic_tree,
    )


class _PackageJournal:
    def __init__(self, package: Any | None, *, tampered: bool = False) -> None:
        self.package = package
        self.tampered = tampered

    def list_plan_operations(self) -> tuple[str, ...]:
        return () if self.package is None else (self.package.intent.operation_id,)

    def read_package(self, operation_id: str) -> tuple[Any, ArtifactRef] | None:
        if self.tampered:
            raise ValueError("tampered package artifact")
        if self.package is None or operation_id != self.package.intent.operation_id:
            return None
        return self.package, ArtifactRef.model_construct(
            digest=canonical_digest(self.package),
            size_bytes=1,
            media_type="application/vnd.avo.integration-campaign+json",
            role="integration-campaign-package",
        )


def test_durable_completion_verifier_requires_exact_package_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package = _package()
    plan = _package_validation_plan(package)
    digest = canonical_digest(package)
    journal = cast(Any, _PackageJournal(package))
    verifier = runner._DurableCompletionProofVerifier(journal)
    verifier.verify(
        plan,
        SyntheticValidationCompletionProof(
            operation_id=plan.operation_id,
            plan_digest=plan.plan_digest,
            completion_digest=digest,
        ),
    )

    def mismatched_binding(
        _package: IntegrationCampaignEvidencePackage, _plan: SyntheticValidationPlan
    ) -> bool:
        return False

    monkeypatch.setattr(runner, "_package_binds_validation_plan", mismatched_binding)
    with pytest.raises(runner.CampaignRunnerError):
        verifier.verify(
            plan,
            SyntheticValidationCompletionProof(
                operation_id=plan.operation_id,
                plan_digest=plan.plan_digest,
                completion_digest=digest,
            ),
        )


@pytest.mark.parametrize("mode", ["forged-digest", "missing-package", "tampered-artifact"])
def test_durable_completion_verifier_rejects_unproven_package(
    mode: str,
) -> None:
    package = _package()
    plan = _package_validation_plan(package)
    journal = _PackageJournal(
        None if mode == "missing-package" else package,
        tampered=mode == "tampered-artifact",
    )
    verifier = runner._DurableCompletionProofVerifier(cast(Any, journal))
    digest = "sha256:" + "f" * 64 if mode == "forged-digest" else canonical_digest(package)
    with pytest.raises((runner.CampaignRunnerError, ValueError)):
        verifier.verify(
            plan,
            SyntheticValidationCompletionProof(
                operation_id=plan.operation_id,
                plan_digest=plan.plan_digest,
                completion_digest=digest,
            ),
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


def test_recovery_finalizes_completed_package_before_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    finalized = object()
    operation_id = "sha256:" + "a" * 64
    package = _package()
    package_ref = ArtifactRef.model_construct(
        digest=canonical_digest(package),
        size_bytes=1,
        media_type="application/vnd.avo.integration-campaign+json",
        role="integration-campaign-package",
    )
    cleanup_results: list[Any] = []

    class CompletedPackage:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def list_plan_operations(self) -> tuple[str, ...]:
            return (operation_id,)

        def read_package(self, recovered_operation_id: str) -> tuple[Any, ArtifactRef]:
            assert recovered_operation_id == operation_id
            return package, package_ref

        def read_final_evidence(self, _operation_id: str) -> None:
            return pytest.fail("completed-package recovery must not read final evidence")

    class RecoveryService:
        def finalize(self, recovered_operation_id: str) -> Any:
            assert recovered_operation_id == operation_id
            return finalized

        def resume(self, _operation_id: str) -> object:
            return pytest.fail("completed-package recovery must not resume")

    def recovery_service(_config: runner.CampaignRunnerConfig) -> RecoveryService:
        return RecoveryService()

    def cleanup(
        _config: runner.CampaignRunnerConfig, _service: object, result: Any
    ) -> None:
        cleanup_results.append(result)

    monkeypatch.setattr(runner, "CampaignCompletionJournal", CompletedPackage)
    monkeypatch.setattr(runner, "_build_recovery_service", recovery_service)
    monkeypatch.setattr(runner, "_cleanup_recovered_validation", cleanup)

    recovered = runner.recover_before_preflight(config(tmp_path))

    assert recovered is finalized
    assert cleanup_results == [finalized]
