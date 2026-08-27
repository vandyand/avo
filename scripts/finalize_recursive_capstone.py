"""Finalize a frozen recursive candidate after a post-result budget rejection."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

from run_recursive_capstone import (
    ALLOWED_CHANGED_PATHS,
    PRIVATE_EVALUATOR_KEY,
    PUBLIC_EVALUATOR_KEY,
    changed_paths,
    copy_snapshot,
    evaluation_record,
    run_command,
)
from sqlalchemy import select

from avo_correlate.adapters.artifacts import FilesystemArtifactStore
from avo_correlate.adapters.persistence import Database
from avo_correlate.adapters.persistence.models import ActivityRow, ExperimentRow, RunRow
from avo_correlate.application.activity_service import ActivityService
from avo_correlate.application.artifact_service import ArtifactService
from avo_correlate.application.budget_service import BudgetService
from avo_correlate.application.campaign import (
    AdmissionPackage,
    CandidateAdmissionActivityHandler,
    CandidateEvaluationActivityHandler,
)
from avo_correlate.application.evidence_service import EvidenceService
from avo_correlate.application.provenance_service import ProvenanceService
from avo_correlate.application.run_service import RunService
from avo_correlate.application.runtime_service import RuntimeService
from avo_correlate.application.scheduler import Scheduler
from avo_correlate.contracts.base import ActorRef
from avo_correlate.contracts.evaluation import (
    AdmissionDecision,
    ComparisonRecord,
    EvaluationRecord,
)
from avo_correlate.contracts.experiment import ExperimentSpec
from avo_correlate.contracts.lifecycle import RunState
from avo_correlate.contracts.policy import PolicyDecision
from avo_correlate.contracts.runtime import HarnessInvocationRecord
from avo_correlate.contracts.variation import CandidateManifest
from avo_correlate.domain.canonical import canonical_digest, file_digest, source_tree_digest


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-root", type=Path, required=True)
    return parser.parse_args()


def _load_envelope(
    database: Database,
) -> tuple[str, ExperimentSpec, ActivityRow, ActivityRow]:
    with database.session() as session:
        run = session.scalar(select(RunRow))
        if run is None:
            raise RuntimeError("recursive database lacks a run")
        experiment = session.get(ExperimentRow, run.experiment_id)
        if experiment is None:
            raise RuntimeError("recursive database lacks its experiment")
        variation = session.scalar(
            select(ActivityRow).where(ActivityRow.activity_key.like("variation:%"))
        )
        evaluation = session.scalar(
            select(ActivityRow).where(ActivityRow.activity_key.like("evaluate:%"))
        )
        if variation is None or evaluation is None:
            raise RuntimeError("recursive database lacks campaign activities")
        return (
            run.run_id,
            ExperimentSpec.model_validate_json(experiment.spec_json),
            variation,
            evaluation,
        )


def _runtime_tokens(invocation: HarnessInvocationRecord) -> tuple[int, int]:
    usage = invocation.usage

    def maximum(suffix: str) -> int:
        return max(
            (value for key, value in usage.items() if key.endswith(f".{suffix}")),
            default=0,
        )

    return maximum("input_tokens"), maximum("output_tokens")


async def _run(arguments: argparse.Namespace) -> dict[str, Any]:
    run_root = arguments.run_root.resolve(strict=True)
    baseline = (run_root / "baseline").resolve(strict=True)
    candidate = (run_root / "candidate").resolve(strict=True)
    control = (run_root / "control").resolve(strict=True)
    private_acceptance = (run_root / "private" / "runtime_inspection_acceptance.py").resolve(
        strict=True
    )
    private_digest = file_digest(private_acceptance)
    database = Database(control / "state.db")
    run_id, spec, variation_activity, evaluation_activity = _load_envelope(database)
    if variation_activity.state != "reconciliation_required":
        raise RuntimeError("variation is not awaiting budget reconciliation")
    if evaluation_activity.state != "queued":
        raise RuntimeError("authoritative evaluation is not queued")

    runs = RunService(database)
    budgets = BudgetService(database)
    activities = ActivityService(database)
    evidence = EvidenceService(database)
    runtime = RuntimeService(database)
    provenance = ProvenanceService(database)
    store = FilesystemArtifactStore(control / "artifacts")
    artifacts = ArtifactService(database, store)
    invocation = runtime.find_activity_invocation(variation_activity.activity_id)
    if invocation is None or invocation.state != "completed":
        raise RuntimeError("Codex invocation is not durably completed")
    input_tokens, output_tokens = _runtime_tokens(invocation)
    budget_within_limit = (
        input_tokens <= spec.budget.model_input_tokens
        and output_tokens <= spec.budget.model_output_tokens
    )
    if budget_within_limit:
        raise RuntimeError("finalizer is only valid for a confirmed budget overrun")
    if variation_activity.budget_reservation_id is None:
        raise RuntimeError("variation lacks its budget reservation")
    budgets.hold_for_reconciliation(
        variation_activity.budget_reservation_id, actor_id="budget-controller"
    )
    current_run = runs.get_run(run_id)
    if RunState(current_run.state) == RunState.BLOCKED_RECONCILIATION:
        runs.transition(
            run_id,
            RunState.RUNNING,
            actor_id="budget-controller",
            expected_revision=current_run.revision,
            reason="durable_provider_result_confirmed_budget_overrun",
        )
    elif RunState(current_run.state) != RunState.RUNNING:
        raise RuntimeError(f"cannot finalize recursive run from {current_run.state}")

    public_component = spec.development_evaluators[0].component
    private_component = spec.admission_evaluators[0].component
    policy_digest = spec.policy_bundle_digest

    async def evaluate_candidate(
        manifest: CandidateManifest,
    ) -> tuple[tuple[str, EvaluationRecord], ...]:
        if source_tree_digest(candidate) != manifest.source_tree_digest:
            raise RuntimeError("candidate drifted before authoritative evaluation")
        changed = changed_paths(baseline, candidate)
        paths_ok = bool(changed) and set(changed).issubset(ALLOWED_CHANGED_PATHS)
        evaluation_copy = control / "evaluation-workspace-final"
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
                command,
                cwd=evaluation_copy,
                timeout=300,
                python_path=evaluation_copy / "src",
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
            passed=private_code == 0,
            duration_ms=private_duration,
            artifact=private_artifact,
            started_at=started_private,
        )
        return (
            (PUBLIC_EVALUATOR_KEY, public_record),
            (PRIVATE_EVALUATOR_KEY, private_record),
        )

    def reject_over_budget(
        manifest: CandidateManifest, evaluations: tuple[EvaluationRecord, ...]
    ) -> AdmissionPackage:
        now = datetime.now(UTC)
        policy = PolicyDecision(
            decision_id=f"policy:recursive-capstone:{manifest.candidate_id}",
            policy_engine_id="recursive-capstone-policy-v1",
            policy_bundle_digest=policy_digest,
            action="candidate.admit",
            resource=f"run/{run_id}/candidate/{manifest.candidate_id}",
            input_digest=cast(
                Any,
                canonical_digest(
                    {
                        "manifest": manifest,
                        "evaluations": evaluations,
                        "budget_within_limit": False,
                        "input_tokens": input_tokens,
                        "input_token_limit": spec.budget.model_input_tokens,
                    }
                ),
            ),
            outcome="deny",
            reason_codes=["model_input_token_budget_exceeded"],
            decided_at=now,
        )
        decision = AdmissionDecision(
            admission_id=f"admission:recursive-capstone:{manifest.candidate_id}",
            candidate_id=manifest.candidate_id,
            expected_champion_id=runs.get_run(run_id).champion_id or "missing-champion",
            evaluation_ids=[record.evaluation_id for record in evaluations],
            policy_decision_ids=[policy.decision_id],
            outcome="reject",
            reason_codes=["immutable_budget_exceeded"],
            comparison=ComparisonRecord(
                metric="frozen_acceptance_pass",
                direction="maximize",
                incumbent_value=Decimal(0),
                candidate_value=Decimal(
                    1 if all(record.outcome == "passed" for record in evaluations) else 0
                ),
                minimum_effect=Decimal(1),
                conclusion="not_improved",
            ),
            decided_by=ActorRef(actor_type="service", actor_id="admission-controller"),
            decided_at=now,
        )
        return AdmissionPackage(policy_decisions=(policy,), decision=decision)

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
        decider=reject_over_budget,
    )
    scheduler = Scheduler(activities, worker_id="recursive-finalizer", lease_seconds=60)
    scheduler.register(evaluation.activity_kind, evaluation)
    scheduler.register(admission.activity_kind, admission)
    completed = 0
    while completed < 2 and await scheduler.run_once_async():
        completed += 1
    if completed != 2:
        raise RuntimeError(f"expected two finalization activities, completed {completed}")
    current = runs.get_run(run_id)
    if RunState(current.state) == RunState.RUNNING:
        runs.transition(
            run_id,
            RunState.FAILED,
            actor_id="budget-controller",
            expected_revision=current.revision,
            reason="immutable_model_input_token_budget_exceeded",
        )

    manifest = evidence.get_candidate(evaluation_activity.activity_key.partition(":")[2])
    if manifest.patch_artifact is None:
        raise RuntimeError("candidate lacks its frozen patch")
    patch = store.read_bytes(manifest.patch_artifact)
    reconstructed = control / "reconstructed-workspace"
    copy_snapshot(baseline, reconstructed)
    for path in reconstructed.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    patch_path = control / "candidate.patch"
    patch_path.write_bytes(patch)
    applied = subprocess.run(
        ["patch", "--batch", "--forward", "-p1", "-i", str(patch_path)],
        cwd=reconstructed,
        env={
            "PATH": os.environ.get("PATH", ""),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        },
        capture_output=True,
        check=False,
    )
    reconstructed_digest = source_tree_digest(reconstructed)
    reconstruction_verified = (
        applied.returncode == 0 and reconstructed_digest == manifest.source_tree_digest
    )
    export = provenance.export_run(run_id)
    verification = provenance.verify(export)
    admission_decision = evidence.get_admission(manifest.candidate_id)
    result = {
        "schema_version": 1,
        "run_id": run_id,
        "model": invocation.requested_model,
        "provider_thread_id": (
            invocation.runtime_session.native_session_id
            if invocation.runtime_session is not None
            else None
        ),
        "provider_turn_id": (
            invocation.runtime_session.native_operation_id
            if invocation.runtime_session is not None
            else None
        ),
        "candidate_id": manifest.candidate_id,
        "candidate_technical_gates_passed": all(
            record.outcome == "passed"
            for _, record in evidence.list_evaluations(manifest.candidate_id)
        ),
        "admission_outcome": (
            admission_decision.outcome if admission_decision is not None else None
        ),
        "rejection_reason": "immutable_model_input_token_budget_exceeded",
        "input_tokens": input_tokens,
        "input_token_limit": spec.budget.model_input_tokens,
        "output_tokens": output_tokens,
        "output_token_limit": spec.budget.model_output_tokens,
        "changed_paths": changed_paths(baseline, candidate),
        "candidate_digest": manifest.source_tree_digest,
        "reconstruction_verified": reconstruction_verified,
        "reconstructed_digest": reconstructed_digest,
        "provenance_verified": verification.verified,
        "provenance_errors": verification.errors,
        "provenance_digest": export.manifest_digest,
        "run_state": runs.get_run(run_id).state,
        "review_bundle": str(run_root),
    }
    (control / "provenance.json").write_text(
        export.model_dump_json(indent=2) + "\n", encoding="utf-8"
    )
    (control / "result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2, sort_keys=True), flush=True)
    return result


def main() -> None:
    asyncio.run(_run(_arguments()))


if __name__ == "__main__":
    main()
