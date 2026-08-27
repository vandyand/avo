"""Run the first sanitized AVO-on-AVO Codex campaign and retain a review bundle."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from avo_correlate.adapters.artifacts import FilesystemArtifactStore
from avo_correlate.adapters.harness.codex import CodexCodingAgentRuntime
from avo_correlate.adapters.harness.codex_canary import CodexLiveCanaryRunner
from avo_correlate.adapters.persistence import Database
from avo_correlate.application.activity_service import ActivityService
from avo_correlate.application.artifact_service import ArtifactService
from avo_correlate.application.budget_service import BudgetService
from avo_correlate.application.campaign import (
    AdmissionPackage,
    CampaignWorkspace,
    CandidateAdmissionActivityHandler,
    CandidateEvaluationActivityHandler,
    CodingVariationActivityHandler,
    LocalCampaignWorker,
)
from avo_correlate.application.evidence_service import EvidenceService
from avo_correlate.application.provenance_service import ProvenanceService
from avo_correlate.application.run_service import RunService
from avo_correlate.application.runtime_service import RuntimeService
from avo_correlate.application.session_service import SessionService
from avo_correlate.application.terminal_budget_service import TerminalBudgetService
from avo_correlate.contracts.base import ActorRef, ArtifactRef, VersionedComponentRef
from avo_correlate.contracts.budgets import BudgetSpec, UsageRecord
from avo_correlate.contracts.evaluation import (
    AdmissionDecision,
    ComparisonRecord,
    ConstraintResult,
    EvaluationRecord,
    TrialRecord,
    UncertaintyRecord,
)
from avo_correlate.contracts.experiment import (
    EvaluatorSpec,
    ExperimentSpec,
    HarnessSpec,
    ReviewPolicy,
    SearchSpec,
    WorkspaceSpec,
)
from avo_correlate.contracts.lifecycle import RunState
from avo_correlate.contracts.policy import PolicyDecision
from avo_correlate.contracts.runtime import HarnessRuntimeProfile
from avo_correlate.contracts.variation import (
    CandidateManifest,
    CandidateRef,
    VariationSessionRequest,
)
from avo_correlate.domain.canonical import canonical_digest, file_digest, source_tree_digest

CONTROL_RUNNERS = frozenset(
    {
        "scripts/finalize_recursive_capstone.py",
        "scripts/replay_recursive_terminal_budget.py",
        "scripts/run_recursive_capstone.py",
    }
)
PUBLIC_EVALUATOR_KEY = "admission:repository-gates-v1"
PRIVATE_EVALUATOR_KEY = "admission:runtime-inspection-invariant-v1"
ALLOWED_CHANGED_PATHS = frozenset(
    {
        "schemas/RuntimeInspection.schema.json",
        "src/avo_correlate/contracts/runtime.py",
        "tests/unit/test_coding_agent_runtime.py",
        "tests/unit/test_contracts.py",
    }
)
IGNORED_NAMES = frozenset(
    {
        ".coverage",
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".venv",
        "__pycache__",
    }
)

TASK_PROMPT = """You are proposing the first bounded AVO-on-AVO improvement.

Goal: strengthen the RuntimeInspection contract in
src/avo_correlate/contracts/runtime.py. A completed inspection must carry an
AgentCompletion. Every non-completed inspection must carry no completion. The second
rule already exists; implement the missing first rule without weakening it.

Add focused public regression coverage and regenerate only the affected checked-in
JSON schema if necessary. Keep the change minimal. You may modify only:
- src/avo_correlate/contracts/runtime.py
- tests/unit/test_coding_agent_runtime.py or tests/unit/test_contracts.py
- schemas/RuntimeInspection.schema.json

Do not modify campaign orchestration, evaluator code, policy, provenance, dependencies,
configuration, documentation, or any other path. Do not create Git metadata or agent
configuration. Do not use the network. Avoid generated caches; if you run pytest, use
`-p no:cacheprovider` and the existing frozen environment only. Finish with the required
JSON completion object describing the proposal and any tests actually run.
"""

PRIVATE_ACCEPTANCE = """from pydantic import ValidationError

from avo_correlate.contracts.runtime import AgentCompletion, RuntimeInspection, RuntimeSessionRef

session = RuntimeSessionRef(
    adapter_id="private-check",
    native_session_id="thread-1",
    storage_class="provider",
)
completion = AgentCompletion(outcome="proposal", rationale="bounded improvement")

try:
    RuntimeInspection(state="completed", session=session)
except ValidationError:
    pass
else:
    raise AssertionError("completed inspection accepted without completion")

valid = RuntimeInspection(state="completed", session=session, completion=completion)
assert valid.completion == completion

for state in ("not_started", "running", "interrupted", "missing", "unknown"):
    try:
        RuntimeInspection(state=state, session=session, completion=completion)
    except ValidationError:
        continue
    raise AssertionError(f"{state} inspection accepted a completion")
"""


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--trusted-key", type=Path, required=True)
    parser.add_argument("--model", default="gpt-5.6-luna")
    parser.add_argument("--model-input-budget", type=int, default=200_000)
    parser.add_argument("--model-input-estimate", type=int, default=100_000)
    return parser.parse_args()


def _component(component_id: str, material: object) -> VersionedComponentRef:
    return VersionedComponentRef(
        component_id=component_id,
        component_version="1.0.0",
        package_digest=cast(Any, canonical_digest({"package": material})),
        capability_manifest_digest=cast(Any, canonical_digest({"capabilities": component_id})),
    )


def copy_snapshot(source: Path, destination: Path) -> None:
    def ignore(directory: str, names: list[str]) -> set[str]:
        root = Path(directory)
        ignored = {name for name in names if name in IGNORED_NAMES}
        if root.relative_to(source).as_posix() == "scripts":
            ignored.update(Path(path).name for path in CONTROL_RUNNERS)
        return ignored

    shutil.copytree(source, destination, ignore=ignore)


def _make_read_only(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        path.chmod(0o555 if path.is_dir() else 0o444)
    root.chmod(0o555)


def normalize_snapshot_permissions(root: Path) -> None:
    """Remove DrvFS executable-bit noise before hashing or patch generation."""
    for path in sorted(root.rglob("*"), reverse=True):
        path.chmod(0o755 if path.is_dir() else 0o644)
    root.chmod(0o755)


def changed_paths(baseline: Path, candidate: Path) -> list[str]:
    paths = {
        path.relative_to(root).as_posix()
        for root in (baseline, candidate)
        for path in root.rglob("*")
        if path.is_file()
    }
    return sorted(
        path
        for path in paths
        if not (baseline / path).exists()
        or not (candidate / path).exists()
        or (baseline / path).read_bytes() != (candidate / path).read_bytes()
    )


def run_command(
    command: list[str], *, cwd: Path, timeout: int, python_path: Path | None = None
) -> tuple[int, bytes, int]:
    environment = {
        **os.environ,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
    }
    if python_path is not None:
        environment["PYTHONPATH"] = str(python_path)
    started = time.monotonic()
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
        output = b"command: " + repr(command).encode() + b"\n" + result.stdout + result.stderr
        return result.returncode, output, round((time.monotonic() - started) * 1000)
    except subprocess.TimeoutExpired as exc:
        output = b"command timed out\n" + (exc.stdout or b"") + (exc.stderr or b"")
        return 124, output, round((time.monotonic() - started) * 1000)


def evaluation_record(
    *,
    candidate_id: str,
    evaluator: VersionedComponentRef,
    profile_digest: str,
    execution_digest: str,
    constraint: str,
    passed: bool,
    duration_ms: int,
    artifact: ArtifactRef,
    started_at: datetime,
) -> EvaluationRecord:
    value = Decimal(1 if passed else 0)
    completed_at = datetime.now(UTC)
    return EvaluationRecord(
        evaluation_id=f"evaluation:{evaluator.component_id}:{candidate_id}",
        candidate_id=candidate_id,
        evaluator_ref=evaluator,
        evaluator_tier="admission",
        evaluator_profile_digest=cast(Any, profile_digest),
        execution_image_digest=cast(Any, execution_digest),
        hardware_class="wsl2-x86_64",
        input_artifact_digests=[artifact.digest],
        trial_records=[
            TrialRecord(
                trial_index=0,
                seed=7,
                metrics={"pass": value},
                workload_time_ms=Decimal(duration_ms),
                sandbox_setup_time_ms=Decimal(0),
                queue_time_ms=Decimal(0),
                host_overhead_time_ms=Decimal(0),
            )
        ],
        aggregate_metrics={"pass": value},
        uncertainty={
            "pass": UncertaintyRecord(
                method="deterministic",
                lower=value,
                upper=value,
                confidence_level=Decimal("0.999"),
            )
        },
        constraints=[
            ConstraintResult(
                name=constraint,
                passed=passed,
                evidence_digest=artifact.digest,
            )
        ],
        outcome="passed" if passed else "failed",
        evidence_artifacts=[artifact],
        started_at=started_at,
        completed_at=completed_at,
    )


async def _run(arguments: argparse.Namespace) -> dict[str, Any]:
    if arguments.model_input_budget <= 0:
        raise ValueError("model input budget must be positive")
    if not 0 < arguments.model_input_estimate <= arguments.model_input_budget:
        raise ValueError("model input estimate must be positive and fit within the budget")
    source = arguments.source_root.resolve(strict=True)
    run_root = arguments.run_root.resolve()
    if run_root.exists():
        raise RuntimeError(f"refusing to reuse recursive run root: {run_root}")
    run_root.mkdir(parents=True, mode=0o700)
    baseline = run_root / "baseline"
    candidate = run_root / "candidate"
    control = run_root / "control"
    private = run_root / "private"
    for directory in (control, private):
        directory.mkdir(mode=0o700)
    copy_snapshot(source, baseline)
    copy_snapshot(source, candidate)
    normalize_snapshot_permissions(baseline)
    normalize_snapshot_permissions(candidate)
    _make_read_only(baseline)

    private_acceptance = private / "runtime_inspection_acceptance.py"
    private_acceptance.write_text(PRIVATE_ACCEPTANCE, encoding="utf-8")
    private_acceptance.chmod(0o400)
    private_digest = file_digest(private_acceptance)
    baseline_digest = source_tree_digest(baseline)
    candidate_initial_digest = source_tree_digest(candidate)
    if baseline_digest != candidate_initial_digest:
        raise RuntimeError("baseline and candidate snapshots differ before the campaign")

    baseline_check, baseline_output, _ = run_command(
        [sys.executable, str(private_acceptance)],
        cwd=baseline,
        timeout=60,
        python_path=baseline / "src",
    )
    if baseline_check == 0:
        raise RuntimeError("baseline unexpectedly passes the frozen private acceptance")
    (private / "baseline-private-result.txt").write_bytes(baseline_output)

    profile = HarnessRuntimeProfile.model_validate_json(
        arguments.profile.resolve(strict=True).read_text(encoding="utf-8")
    )
    profile = profile.model_copy(
        update={
            "requested_model": arguments.model,
            "configuration": {
                **profile.configuration,
                "task_prompt": TASK_PROMPT,
                "reasoning_effort": "high",
            },
        }
    )
    trusted_key = arguments.trusted_key.resolve(strict=True).read_bytes()
    preregistration = {
        "schema_version": 1,
        "target": "RuntimeInspection completed-state invariant",
        "baseline_digest": baseline_digest,
        "task_prompt_digest": canonical_digest(TASK_PROMPT),
        "private_acceptance_digest": private_digest,
        "allowed_changed_paths": sorted(ALLOWED_CHANGED_PATHS),
        "baseline_private_outcome": "failed",
        "runtime_profile_digest": canonical_digest(profile),
        "created_at": datetime.now(UTC).isoformat(),
    }
    preregistration_path = control / "preregistration.json"
    preregistration_path.write_text(
        json.dumps(preregistration, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    preregistration_path.chmod(0o400)

    database = Database(control / "state.db")
    database.initialize()
    store = FilesystemArtifactStore(control / "artifacts")
    artifacts = ArtifactService(database, store)
    runs = RunService(database)
    budgets = BudgetService(database)
    sessions = SessionService(database)
    activities = ActivityService(database)
    evidence = EvidenceService(database)
    invocations = RuntimeService(database)
    provenance = ProvenanceService(database)

    harness_component = _component("openai-codex", canonical_digest(profile))
    public_component = _component("repository-gates", "ruff-pyright-pytest")
    private_component = _component("runtime-inspection-private", private_digest)
    policy_digest = canonical_digest(
        {"policy": "recursive-capstone-v1", "allowed_paths": sorted(ALLOWED_CHANGED_PATHS)}
    )
    spec = ExperimentSpec(
        experiment_id="avo-recursive-capstone-runtime-inspection-v1",
        title="AVO improves its RuntimeInspection recovery contract",
        objective="Require every completed runtime inspection to carry its completion",
        success_criteria=[
            "Repository lint, type, schema-parity, and test gates pass",
            "Frozen private completion-state invariant passes",
            "Only preregistered paths change",
            "Provenance verifies and the patch reconstructs exactly",
        ],
        workspace=WorkspaceSpec(
            source_uri=f"file:{baseline}",
            source_revision=baseline_digest,
            source_tree_digest=cast(Any, baseline_digest),
            allowed_paths=sorted(ALLOWED_CHANGED_PATHS),
            forbidden_paths=sorted(CONTROL_RUNNERS),
            required_paths=["pyproject.toml", "src/avo_correlate/contracts/runtime.py"],
            max_file_bytes=4 * 1024 * 1024,
            max_tree_bytes=64 * 1024 * 1024,
        ),
        search=SearchSpec(
            method_version="1.0.0",
            max_committed_candidates=1,
            stopping_rules=["first_admission", "one_variation_session"],
        ),
        harness=HarnessSpec(
            component=harness_component,
            model_config_digest=cast(
                Any,
                canonical_digest({"model": profile.requested_model, "reasoning_effort": "high"}),
            ),
            configuration_digest=cast(Any, canonical_digest(profile.configuration)),
        ),
        development_evaluators=[
            EvaluatorSpec(
                component=public_component,
                tier="development",
                profile_digest=cast(Any, canonical_digest("repository-gates-v1")),
                execution_image_digest=cast(Any, file_digest(Path(sys.executable))),
            )
        ],
        admission_evaluators=[
            EvaluatorSpec(
                component=private_component,
                tier="admission",
                profile_digest=cast(Any, private_digest),
                execution_image_digest=cast(Any, file_digest(Path(sys.executable))),
            )
        ],
        budget=BudgetSpec(
            wall_clock_seconds=1800,
            model_input_tokens=arguments.model_input_budget,
            model_output_tokens=50_000,
            model_cost_microusd=0,
            tool_calls=200,
            sandbox_cpu_seconds=1800,
            sandbox_gpu_seconds=0,
            authoritative_evaluations=2,
            variation_sessions=1,
            artifact_bytes=64 * 1024 * 1024,
        ),
        sandbox_profile_id="codex-workspace-write-wsl-v1",
        policy_bundle_digest=cast(Any, policy_digest),
        retention_policy_id="recursive-review-bundle-v1",
        review_policy=ReviewPolicy(),
        created_by=ActorRef(actor_type="human", actor_id="vandyand"),
    )
    runs.create_experiment(spec, actor_id="operator", idempotency_key="create")
    run_id = "recursive-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8]
    runs.create_run(spec.experiment_id, actor_id="operator", run_id=run_id, prepare=True)
    runs.transition(run_id, RunState.RUNNING, actor_id="operator")
    champion = runs.get_run(run_id).champion_id
    if champion is None:
        raise RuntimeError("recursive run lacks its seed champion")

    variation_estimate = UsageRecord.zero().model_copy(
        update={
            "wall_clock_seconds": 900,
            "model_input_tokens": arguments.model_input_estimate,
            "model_output_tokens": 25_000,
            "tool_calls": 100,
            "variation_sessions": 1,
        }
    )
    reservation = budgets.reserve(
        run_id,
        activity_key="variation:recursive-session-1",
        estimated=variation_estimate,
        actor_id="scheduler",
    )
    request = VariationSessionRequest(
        session_id="recursive-session-1",
        run_id=run_id,
        champion=CandidateRef(
            candidate_id=champion,
            source_tree_digest=cast(Any, baseline_digest),
            lineage_sequence=0,
        ),
        lineage_index_digest=cast(Any, canonical_digest([champion])),
        initial_context_digest=cast(
            Any,
            canonical_digest(
                {"objective": spec.objective, "success_criteria": spec.success_criteria}
            ),
        ),
        tool_capability_token="codex-workspace-write-deny-network",
        development_evaluator_refs=[public_component],
        budget_reservation_id=reservation,
        random_seed=7,
    )
    sessions.enqueue(request)
    activities.enqueue(
        run_id,
        activity_key="variation:recursive-session-1",
        input_digest=canonical_digest(request),
        actor_id="scheduler",
        session_id=request.session_id,
        budget_reservation_id=reservation,
    )

    def artifact_sink(payload: bytes, role: str) -> str:
        return store.put_bytes(
            payload,
            media_type="application/octet-stream",
            role=role,
            max_bytes=8 * 1024 * 1024,
        ).digest

    runtime = CodexCodingAgentRuntime(
        artifact_sink=artifact_sink,
        canary_runner=CodexLiveCanaryRunner(),
        trusted_plugin_keys={profile.plugin.signer_key_id: trusted_key},
    )

    async def evaluate_candidate(
        manifest: CandidateManifest,
    ) -> tuple[tuple[str, EvaluationRecord], ...]:
        if source_tree_digest(candidate) != manifest.source_tree_digest:
            raise RuntimeError("candidate drifted before authoritative evaluation")
        changed = changed_paths(baseline, candidate)
        paths_ok = bool(changed) and set(changed).issubset(ALLOWED_CHANGED_PATHS)
        evaluation_copy = control / "evaluation-workspace"
        copy_snapshot(candidate, evaluation_copy)
        python_bin = Path(sys.executable)
        bin_dir = python_bin.parent
        started_public = datetime.now(UTC)
        commands = [
            [str(bin_dir / "ruff"), "check", "."],
            [str(bin_dir / "pyright"), "--pythonpath", str(python_bin)],
            [str(python_bin), "-m", "pytest", "-p", "no:cacheprovider", "-q"],
        ]
        public_code = 0
        public_duration = 0
        public_output = bytearray(
            ("changed_paths=" + json.dumps(changed, sort_keys=True) + "\n").encode()
        )
        for command in commands:
            code, output, duration = run_command(
                command, cwd=evaluation_copy, timeout=300, python_path=evaluation_copy / "src"
            )
            public_output.extend(output)
            public_duration += duration
            if code != 0:
                public_code = code
                break
        public_passed = public_code == 0 and paths_ok
        public_artifact = artifacts.put_bytes(
            bytes(public_output),
            run_id=run_id,
            owner_type="candidate",
            owner_id=manifest.candidate_id,
            media_type="text/plain",
            role="public-evaluation-log",
            retention_class="recursive-capstone-evidence",
            max_bytes=16 * 1024 * 1024,
            actor_id="authoritative-evaluator",
        )
        public_record = evaluation_record(
            candidate_id=manifest.candidate_id,
            evaluator=public_component,
            profile_digest=canonical_digest("repository-gates-v1"),
            execution_digest=file_digest(python_bin),
            constraint="repository-gates-and-path-scope",
            passed=public_passed,
            duration_ms=public_duration,
            artifact=public_artifact,
            started_at=started_public,
        )

        started_private = datetime.now(UTC)
        private_code, private_output, private_duration = run_command(
            [str(python_bin), str(private_acceptance)],
            cwd=evaluation_copy,
            timeout=60,
            python_path=evaluation_copy / "src",
        )
        private_passed = private_code == 0
        private_artifact = artifacts.put_bytes(
            private_output,
            run_id=run_id,
            owner_type="candidate",
            owner_id=manifest.candidate_id,
            media_type="text/plain",
            role="private-evaluation-log",
            retention_class="recursive-capstone-evidence",
            max_bytes=1024 * 1024,
            actor_id="authoritative-evaluator",
        )
        private_record = evaluation_record(
            candidate_id=manifest.candidate_id,
            evaluator=private_component,
            profile_digest=private_digest,
            execution_digest=file_digest(python_bin),
            constraint="completed-inspection-requires-completion",
            passed=private_passed,
            duration_ms=private_duration,
            artifact=private_artifact,
            started_at=started_private,
        )
        if source_tree_digest(candidate) != manifest.source_tree_digest:
            raise RuntimeError("authoritative evaluation mutated the frozen candidate")
        return (
            (PUBLIC_EVALUATOR_KEY, public_record),
            (PRIVATE_EVALUATOR_KEY, private_record),
        )

    def decide(
        manifest: CandidateManifest, evaluations: tuple[EvaluationRecord, ...]
    ) -> AdmissionPackage:
        all_passed = len(evaluations) == 2 and all(
            record.outcome == "passed" for record in evaluations
        )
        changed = changed_paths(baseline, candidate)
        path_scope_passed = bool(changed) and set(changed).issubset(ALLOWED_CHANGED_PATHS)
        if manifest.patch_artifact is None:
            raise RuntimeError("candidate manifest lacks its frozen patch")
        patch_bytes = store.read_bytes(manifest.patch_artifact)
        hidden_reference_absent = (
            private_acceptance.name.encode() not in patch_bytes
            and private_digest.encode() not in patch_bytes
        )
        allowed = all_passed and path_scope_passed and hidden_reference_absent
        now = datetime.now(UTC)
        policy = PolicyDecision(
            decision_id=f"policy:recursive-capstone:{manifest.candidate_id}",
            policy_engine_id="recursive-capstone-policy-v1",
            policy_bundle_digest=cast(Any, policy_digest),
            action="candidate.admit",
            resource=f"run/{run_id}/candidate/{manifest.candidate_id}",
            input_digest=cast(
                Any,
                canonical_digest(
                    {
                        "manifest": manifest,
                        "evaluations": evaluations,
                        "changed_paths": changed,
                        "hidden_reference_absent": hidden_reference_absent,
                    }
                ),
            ),
            outcome="allow" if allowed else "deny",
            reason_codes=(
                ["all_frozen_controls_passed"] if allowed else ["recursive_capstone_control_failed"]
            ),
            decided_at=now,
        )
        decision = AdmissionDecision(
            admission_id=f"admission:recursive-capstone:{manifest.candidate_id}",
            candidate_id=manifest.candidate_id,
            expected_champion_id=champion,
            evaluation_ids=[record.evaluation_id for record in evaluations],
            policy_decision_ids=[policy.decision_id],
            outcome="admit" if allowed else "reject",
            reason_codes=(
                ["private_and_public_gates_passed", "bounded_contract_improvement"]
                if allowed
                else ["one_or_more_frozen_controls_failed"]
            ),
            comparison=ComparisonRecord(
                metric="frozen_acceptance_pass",
                direction="maximize",
                incumbent_value=Decimal(0),
                candidate_value=Decimal(1 if allowed else 0),
                minimum_effect=Decimal(1),
                conclusion="improved" if allowed else "not_improved",
            ),
            decided_by=ActorRef(actor_type="service", actor_id="admission-controller"),
            decided_at=now,
        )
        return AdmissionPackage(policy_decisions=(policy,), decision=decision)

    evaluation_estimate = UsageRecord.zero().model_copy(
        update={
            "sandbox_cpu_seconds": 600,
            "authoritative_evaluations": 2,
            "artifact_bytes": 16 * 1024 * 1024,
        }
    )
    variation = CodingVariationActivityHandler(
        runtime=runtime,
        profile=profile,
        sessions=sessions,
        invocations=invocations,
        budgets=budgets,
        terminal_budgets=TerminalBudgetService(database),
        evidence=evidence,
        activities=activities,
        artifacts=artifacts,
        workspace_resolver=lambda _: CampaignWorkspace(
            baseline=baseline,
            candidate=candidate,
            git_metadata=control / "git-metadata",
        ),
        event_spool_root=control / "runtime-spool",
        evaluation_estimate=evaluation_estimate,
        harness_ref=harness_component,
        model_config_digest=spec.harness.model_config_digest,
        policy_bundle_digest=cast(Any, policy_digest),
    )
    evaluation = CandidateEvaluationActivityHandler(
        evidence=evidence,
        activities=activities,
        budgets=budgets,
        evaluator_keys=(PUBLIC_EVALUATOR_KEY, PRIVATE_EVALUATOR_KEY),
        runner=evaluate_candidate,
    )
    admission = CandidateAdmissionActivityHandler(
        evidence=evidence,
        runs=runs,
        decider=decide,
    )
    worker = LocalCampaignWorker(
        activities,
        worker_id="recursive-local-worker",
        variation=variation,
        evaluation=evaluation,
        admission=admission,
        lease_seconds=60,
    )
    completed_activities = await worker.run_until_idle(max_activities=6)

    run = runs.get_run(run_id)
    export = provenance.export_run(run_id)
    verification = provenance.verify(export)
    changed = changed_paths(baseline, candidate)
    admissions = cast(list[dict[str, Any]], export.manifest["admissions"])
    admitted = bool(admissions and admissions[0]["outcome"] == "admit")
    result = {
        "schema_version": 1,
        "run_id": run_id,
        "admitted": admitted,
        "run_state": run.state,
        "champion_id": run.champion_id,
        "completed_activities": completed_activities,
        "model_input_budget": arguments.model_input_budget,
        "model_input_estimate": arguments.model_input_estimate,
        "baseline_digest": baseline_digest,
        "candidate_digest": source_tree_digest(candidate),
        "changed_paths": changed,
        "private_acceptance_digest": private_digest,
        "runtime_profile_digest": canonical_digest(profile),
        "provenance_verified": verification.verified,
        "provenance_errors": verification.errors,
        "provenance_digest": export.manifest_digest,
        "candidate_workspace": str(candidate),
        "review_bundle": str(run_root),
        "admissions": admissions,
    }
    (control / "provenance.json").write_text(
        export.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    result_path = control / "result.json"
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True), flush=True)
    return result


def main() -> None:
    asyncio.run(_run(_arguments()))


if __name__ == "__main__":
    main()
