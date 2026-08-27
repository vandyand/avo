"""Replay the first recursive capstone through the terminal-budget lifecycle."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from run_recursive_capstone import changed_paths, copy_snapshot, normalize_snapshot_permissions
from sqlalchemy import select

from avo_correlate.adapters.artifacts import FilesystemArtifactStore
from avo_correlate.adapters.harness.recorded_runtime import (
    RecordedCodingAgentRuntime,
    RecordedRuntimeEntry,
)
from avo_correlate.adapters.persistence import Database
from avo_correlate.adapters.persistence.models import (
    ActivityRow,
    BudgetLedgerRow,
    BudgetReservationRow,
    CandidateRow,
    HarnessInvocationRow,
    PolicyDecisionRow,
    ReconciliationCaseRow,
)
from avo_correlate.application.activity_service import ActivityService
from avo_correlate.application.artifact_service import ArtifactService
from avo_correlate.application.budget_service import BudgetService
from avo_correlate.application.campaign import CampaignWorkspace, CodingVariationActivityHandler
from avo_correlate.application.evidence_service import EvidenceService
from avo_correlate.application.provenance_service import ProvenanceService
from avo_correlate.application.run_service import RunService
from avo_correlate.application.runtime_service import RuntimeService
from avo_correlate.application.scheduler import Scheduler
from avo_correlate.application.session_service import SessionService
from avo_correlate.application.terminal_budget_service import TerminalBudgetService
from avo_correlate.contracts.base import VersionedComponentRef
from avo_correlate.contracts.budgets import UsageRecord
from avo_correlate.contracts.experiment import ExperimentSpec
from avo_correlate.contracts.lifecycle import RunState
from avo_correlate.contracts.plugins import PluginCapabilityManifest, SignedPluginManifest
from avo_correlate.contracts.policy import PolicyDecision
from avo_correlate.contracts.provenance import ProvenanceExport
from avo_correlate.contracts.runtime import (
    AgentCompletion,
    HarnessInvocationRecord,
    HarnessRuntimeProfile,
    RuntimeEvent,
    RuntimeSessionRef,
)
from avo_correlate.contracts.variation import CandidateRef, VariationSessionRequest
from avo_correlate.domain.canonical import canonical_digest, file_digest, source_tree_digest


class CountingRecordedRuntime(RecordedCodingAgentRuntime):
    """Recorded runtime that proves the replay starts exactly one local turn."""

    def __init__(self, entries: list[RecordedRuntimeEntry]) -> None:
        super().__init__(entries)
        self.turn_starts = 0

    async def start_turn(
        self,
        profile: HarnessRuntimeProfile,
        request: VariationSessionRequest,
        session: RuntimeSessionRef,
    ) -> RuntimeSessionRef:
        self.turn_starts += 1
        return await super().start_turn(profile, request, session)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-run", type=Path, required=True)
    parser.add_argument("--run-root", type=Path, required=True)
    return parser.parse_args()


def _component(component_id: str, material: object) -> VersionedComponentRef:
    return VersionedComponentRef(
        component_id=component_id,
        component_version="1.0.0",
        package_digest=cast(Any, canonical_digest({"package": material})),
        capability_manifest_digest=cast(
            Any, canonical_digest({"capabilities": component_id})
        ),
    )


def _make_read_only(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        path.chmod(0o555 if path.is_dir() else 0o444)
    root.chmod(0o555)


def _runtime_profile(source_digest: str, source_model: str) -> HarnessRuntimeProfile:
    package_digest = canonical_digest(
        {"adapter": "retained-capstone-replay-v1", "source": source_digest}
    )
    manifest = PluginCapabilityManifest(
        plugin_id="retained-capstone-replay",
        plugin_version="1.0.0",
        package_digest=cast(Any, package_digest),
        source_digest=cast(Any, source_digest),
        supported_contract_versions=["HarnessRuntimeProfile.v1"],
        supported_schema_versions=[1],
        operating_systems=["linux"],
        architectures=["x86_64"],
        required_executables=[],
        network_access="none",
        configuration_schema={},
        side_effects=["materialized_workspace_replay"],
        security_classification="retained-evidence-replay",
        health_check=["recording"],
        license="Proprietary",
    )
    return HarnessRuntimeProfile(
        profile_id="retained-recursive-capstone-replay-v1",
        plugin=SignedPluginManifest(
            manifest=manifest,
            signature_algorithm="hmac-sha256",
            signer_key_id="retained-evidence",
            signature_hex="00",
        ),
        transport="sdk",
        requested_model=f"recorded/{source_model}",
        authentication_class="none",
        permission_profile_digest=cast(
            Any, canonical_digest("materialized-workspace-read-only-recording")
        ),
        development_evaluator_id="none-terminal-budget-replay",
        max_wall_time_seconds=60,
        max_turns=1,
        completion_schema_digest=cast(
            Any, canonical_digest(AgentCompletion.model_json_schema())
        ),
        configuration={
            "source_provenance_digest": source_digest,
            "provider_contact": False,
        },
    )


def _source_invocation(exported: ProvenanceExport) -> HarnessInvocationRecord:
    records = cast(list[dict[str, Any]], exported.manifest["harness_invocations"])
    if len(records) != 1:
        raise RuntimeError("source capstone must contain exactly one harness invocation")
    payload = dict(records[0])
    payload.pop("record_digest", None)
    invocation = HarnessInvocationRecord.model_validate(payload)
    if invocation.state != "completed" or invocation.completion is None:
        raise RuntimeError("source capstone invocation is not durably completed")
    return invocation


def _source_events(source_control: Path) -> tuple[RuntimeEvent, ...]:
    spools = list((source_control / "runtime-spool").glob("*.jsonl"))
    if len(spools) != 1:
        raise RuntimeError("source capstone must contain exactly one runtime spool")
    events = tuple(
        RuntimeEvent.model_validate_json(line)
        for line in spools[0].read_text(encoding="utf-8").splitlines()
        if line
    )
    if not events or [event.sequence for event in events] != list(
        range(1, len(events) + 1)
    ):
        raise RuntimeError("source runtime event stream is incomplete")
    return events


async def _run(arguments: argparse.Namespace) -> dict[str, Any]:
    source_run = arguments.source_run.resolve(strict=True)
    source_control = source_run / "control"
    source_export_path = source_control / "provenance.json"
    source_result_path = source_control / "result.json"
    source_export = ProvenanceExport.model_validate_json(
        source_export_path.read_text(encoding="utf-8")
    )
    source_result = cast(
        dict[str, Any], json.loads(source_result_path.read_text(encoding="utf-8"))
    )
    source_invocation = _source_invocation(source_export)
    source_completion = source_invocation.completion
    if source_completion is None:
        raise RuntimeError("source capstone invocation lacks its completion")
    source_events = _source_events(source_control)
    source_digest = source_export.manifest_digest
    source_spec = ExperimentSpec.model_validate(
        cast(dict[str, Any], source_export.manifest["experiment"])["spec"]
    )
    expected_candidate_digest = cast(str, source_result["candidate_digest"])

    run_root = arguments.run_root.resolve()
    if run_root.exists():
        raise RuntimeError(f"refusing to reuse replay root: {run_root}")
    run_root.mkdir(parents=True, mode=0o700)
    baseline = run_root / "baseline"
    candidate = run_root / "candidate"
    control = run_root / "control"
    control.mkdir(mode=0o700)
    copy_snapshot(source_run / "baseline", baseline)
    copy_snapshot(source_run / "candidate", candidate)
    normalize_snapshot_permissions(baseline)
    normalize_snapshot_permissions(candidate)
    baseline_digest = source_tree_digest(baseline)
    candidate_digest = source_tree_digest(candidate)
    if baseline_digest != source_spec.workspace.source_tree_digest:
        raise RuntimeError("retained baseline no longer matches its frozen specification")
    if candidate_digest != expected_candidate_digest:
        raise RuntimeError("retained candidate no longer matches its recorded result")
    _make_read_only(baseline)

    profile = _runtime_profile(source_digest, source_invocation.requested_model)
    replay_component = _component("retained-capstone-replay", source_digest)
    spec = source_spec.model_copy(
        update={
            "experiment_id": source_spec.experiment_id + "-terminal-replay-v1",
            "title": source_spec.title + " — deterministic terminal replay",
            "workspace": source_spec.workspace.model_copy(
                update={
                    "source_uri": f"file:{baseline}",
                    "source_revision": baseline_digest,
                    "source_tree_digest": baseline_digest,
                }
            ),
            "harness": source_spec.harness.model_copy(
                update={
                    "component": replay_component,
                    "model_config_digest": canonical_digest(
                        {
                            "mode": "recorded-replay",
                            "source_model": source_invocation.requested_model,
                        }
                    ),
                    "configuration_digest": canonical_digest(profile.configuration),
                }
            ),
            "sandbox_profile_id": "recorded-replay-no-network-v1",
            "retention_policy_id": "terminal-budget-replay-v1",
        }
    )

    database = Database(control / "state.db")
    database.initialize()
    runs = RunService(database)
    budgets = BudgetService(database)
    sessions = SessionService(database)
    activities = ActivityService(database)
    evidence = EvidenceService(database)
    invocations = RuntimeService(database)
    provenance = ProvenanceService(database)
    artifacts = ArtifactService(
        database, FilesystemArtifactStore(control / "artifacts")
    )
    runs.create_experiment(spec, actor_id="replay-controller", idempotency_key="create")
    run_id = "recursive-terminal-replay-" + uuid4().hex[:12]
    runs.create_run(
        spec.experiment_id,
        actor_id="replay-controller",
        run_id=run_id,
        prepare=True,
    )
    runs.transition(run_id, RunState.RUNNING, actor_id="replay-controller")
    champion = runs.get_run(run_id).champion_id
    if champion is None:
        raise RuntimeError("replay run lacks a seed champion")

    variation_estimate = UsageRecord.zero().model_copy(
        update={
            "wall_clock_seconds": 900,
            "model_input_tokens": 100_000,
            "model_output_tokens": 25_000,
            "tool_calls": 100,
            "variation_sessions": 1,
        }
    )
    reservation_id = budgets.reserve(
        run_id,
        activity_key="variation:recursive-replay-session-1",
        estimated=variation_estimate,
        actor_id="replay-controller",
    )
    request = VariationSessionRequest(
        session_id="recursive-replay-session-1",
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
                {
                    "source_provenance_digest": source_digest,
                    "objective": spec.objective,
                }
            ),
        ),
        tool_capability_token="recorded-replay-no-provider",
        development_evaluator_refs=[spec.development_evaluators[0].component],
        budget_reservation_id=reservation_id,
        random_seed=7,
    )
    sessions.enqueue(request)
    activity_id = activities.enqueue(
        run_id,
        activity_key="variation:recursive-replay-session-1",
        input_digest=canonical_digest(request),
        actor_id="replay-controller",
        session_id=request.session_id,
        budget_reservation_id=reservation_id,
    )
    invocation_id = f"harness:{activity_id}"
    replay_events = tuple(
        event.model_copy(update={"invocation_id": invocation_id})
        for event in source_events
    )
    runtime = CountingRecordedRuntime(
        [
            RecordedRuntimeEntry(
                request_digest=canonical_digest(request),
                events=replay_events,
                completion=source_completion,
            )
        ]
    )
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
        harness_ref=replay_component,
        model_config_digest=spec.harness.model_config_digest,
        policy_bundle_digest=spec.policy_bundle_digest,
        actor_id="recorded-replay-worker",
    )
    scheduler = Scheduler(activities, worker_id="recorded-replay-worker", lease_seconds=60)
    scheduler.register(variation.activity_kind, variation)
    if not await scheduler.run_once_async():
        raise RuntimeError("replay variation activity was not claimed")
    if await scheduler.run_once_async():
        raise RuntimeError("terminal replay unexpectedly scheduled follow-up work")

    exported = provenance.export_run(run_id)
    verification = provenance.verify(exported)
    source_verification = provenance.verify(source_export)
    with database.session() as session:
        run = runs.get_run(run_id)
        variation_row = session.get(ActivityRow, activity_id)
        candidate_row = session.scalar(
            select(CandidateRow).where(CandidateRow.session_id == request.session_id)
        )
        evaluation_row = session.scalar(
            select(ActivityRow).where(ActivityRow.activity_key.like("evaluate:%"))
        )
        variation_reservation = session.get(BudgetReservationRow, reservation_id)
        evaluation_reservation = (
            None
            if evaluation_row is None or evaluation_row.budget_reservation_id is None
            else session.get(BudgetReservationRow, evaluation_row.budget_reservation_id)
        )
        ledger = session.get(BudgetLedgerRow, run_id)
        policies = list(
            session.scalars(select(PolicyDecisionRow).where(PolicyDecisionRow.run_id == run_id))
        )
        reconciliations = list(
            session.scalars(
                select(ReconciliationCaseRow).where(
                    ReconciliationCaseRow.run_id == run_id
                )
            )
        )
        harness_invocations = list(
            session.scalars(
                select(HarnessInvocationRow).where(HarnessInvocationRow.run_id == run_id)
            )
        )
        if variation_row is None or candidate_row is None or variation_reservation is None:
            raise RuntimeError("replay terminal evidence is incomplete")
        if evaluation_row is None or evaluation_reservation is None or ledger is None:
            raise RuntimeError("replay evaluation cancellation evidence is incomplete")
        if len(policies) != 1 or len(harness_invocations) != 1:
            raise RuntimeError("replay policy or invocation evidence is incomplete")
        actual = UsageRecord.model_validate_json(variation_reservation.actual_json or "{}")
        used = UsageRecord.model_validate_json(ledger.used_json)
        reserved = UsageRecord.model_validate_json(ledger.reserved_json)
        policy = PolicyDecision.model_validate_json(policies[0].decision_json)
        persisted_invocation = HarnessInvocationRecord.model_validate_json(
            harness_invocations[0].record_json
        )
        assertions: dict[str, bool] = {
            "run_failed": run.state == RunState.FAILED.value,
            "variation_completed": variation_row.state == "completed",
            "variation_reservation_exceeded": variation_reservation.state == "exceeded",
            "actual_input_tokens_preserved": actual.model_input_tokens == 277_350,
            "actual_output_tokens_preserved": actual.model_output_tokens == 5_341,
            "ledger_usage_preserved": used == actual,
            "ledger_reservations_zero": reserved == UsageRecord.zero(),
            "candidate_policy_blocked": candidate_row.state == "policy_blocked",
            "candidate_digest_preserved": (
                candidate_row.source_tree_digest == expected_candidate_digest
            ),
            "evaluation_cancelled": evaluation_row.state == "cancelled",
            "evaluation_reservation_released": (
                evaluation_reservation.state == "released"
            ),
            "budget_policy_denied": (
                policy.outcome == "deny"
                and policy.reason_codes == ["model_input_token_budget_exceeded"]
            ),
            "no_reconciliation_cases": not reconciliations,
            "one_recorded_turn": runtime.turn_starts == 1,
            "one_local_invocation": (
                harness_invocations[0].state == "completed"
                and persisted_invocation.runtime_version == "recorded-v1"
            ),
            "provenance_verified": verification.verified,
            "historical_fixture_rejected_by_new_invariant": (
                not source_verification.verified
                and source_verification.errors
                == ["terminal_run_has_open_reconciliation"]
            ),
        }

    failed_assertions = [name for name, passed in assertions.items() if not passed]
    if failed_assertions:
        raise RuntimeError("terminal replay failed: " + ", ".join(failed_assertions))
    result: dict[str, Any] = {
        "schema_version": 1,
        "run_id": run_id,
        "run_state": run.state,
        "source_run_id": source_export.run_id,
        "source_provenance_digest": source_digest,
        "source_provenance_file_digest": file_digest(source_export_path),
        "source_provider_thread_id": (
            None
            if source_invocation.runtime_session is None
            else source_invocation.runtime_session.native_session_id
        ),
        "source_provider_turn_id": (
            None
            if source_invocation.runtime_session is None
            else source_invocation.runtime_session.native_operation_id
        ),
        "provider_contacted": False,
        "recorded_event_count": len(replay_events),
        "candidate_digest": candidate_digest,
        "changed_paths": changed_paths(baseline, candidate),
        "actual_usage": actual.model_dump(mode="json"),
        "provenance_verified": verification.verified,
        "provenance_errors": verification.errors,
        "provenance_digest": exported.manifest_digest,
        "assertions": assertions,
        "review_bundle": str(run_root),
    }
    (control / "source-envelope.json").write_text(
        json.dumps(
            {
                "source_run_id": source_export.run_id,
                "source_provenance_digest": source_digest,
                "source_provenance_file_digest": file_digest(source_export_path),
                "source_result_file_digest": file_digest(source_result_path),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (control / "provenance.json").write_text(
        exported.model_dump_json(indent=2) + "\n", encoding="utf-8"
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
