import asyncio
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import pytest
from sqlalchemy import select, update

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
    PolicyDecisionRow,
    ReconciliationCaseRow,
)
from avo_correlate.application.activity_service import ActivityService
from avo_correlate.application.artifact_service import ArtifactService
from avo_correlate.application.budget_service import BudgetService
from avo_correlate.application.campaign import (
    AdmissionPackage,
    CampaignRuntimeError,
    CampaignWorkspace,
    CandidateAdmissionActivityHandler,
    CandidateEvaluationActivityHandler,
    CodingVariationActivityHandler,
    LocalCampaignWorker,
    validate_campaign_workspace,
)
from avo_correlate.application.evidence_service import EvidenceService
from avo_correlate.application.provenance_service import ProvenanceService
from avo_correlate.application.query_service import QueryService
from avo_correlate.application.run_service import RunService
from avo_correlate.application.runtime_service import RuntimeService
from avo_correlate.application.scheduler import (
    FailureDisposition,
    InjectedWorkerCrash,
    RecoveryDisposition,
    Scheduler,
)
from avo_correlate.application.session_service import SessionService
from avo_correlate.application.terminal_budget_service import (
    TerminalBudgetConflictError,
    TerminalBudgetService,
)
from avo_correlate.contracts.base import ActorRef
from avo_correlate.contracts.budgets import UsageRecord
from avo_correlate.contracts.evaluation import (
    AdmissionDecision,
    ComparisonRecord,
    ConstraintResult,
    EvaluationRecord,
    TrialRecord,
    UncertaintyRecord,
)
from avo_correlate.contracts.lifecycle import RunState
from avo_correlate.contracts.plugins import (
    PluginCapabilityManifest,
    SignedPluginManifest,
)
from avo_correlate.contracts.policy import PolicyDecision
from avo_correlate.contracts.runtime import (
    AgentCompletion,
    HarnessRuntimeProfile,
    ReconciliationCaseRecord,
    RuntimeEvent,
    RuntimeSessionRef,
)
from avo_correlate.contracts.variation import (
    CandidateManifest,
    CandidateRef,
    VariationSessionRequest,
    VariationSessionResult,
)
from avo_correlate.domain.canonical import canonical_digest, source_tree_digest
from tests.conftest import DIGEST_A, DIGEST_B, component, experiment_spec


class MutatingRecordedRuntime(RecordedCodingAgentRuntime):
    def __init__(self, entries: list[RecordedRuntimeEntry]) -> None:
        super().__init__(entries)
        self.workspace: Path | None = None
        self.turn_starts = 0

    async def prepare(
        self,
        profile: HarnessRuntimeProfile,
        request: VariationSessionRequest,
        workspace_path: str,
        *,
        invocation_id: str,
    ) -> RuntimeSessionRef:
        self.workspace = Path(workspace_path)
        return await super().prepare(
            profile,
            request,
            workspace_path,
            invocation_id=invocation_id,
        )

    async def start_turn(
        self,
        profile: HarnessRuntimeProfile,
        request: VariationSessionRequest,
        session: RuntimeSessionRef,
    ) -> RuntimeSessionRef:
        self.turn_starts += 1
        return await super().start_turn(profile, request, session)

    async def wait(self, session: RuntimeSessionRef) -> AgentCompletion:
        assert self.workspace is not None
        (self.workspace / "target.py").write_text("VALUE = 2\n", encoding="utf-8")
        return await super().wait(session)


class SimulatedProcessExit(BaseException):
    pass


class CrashOnceBudgetService(BudgetService):
    def __init__(self, database: Database) -> None:
        super().__init__(database)
        self._crash_pending = True

    def complete(
        self,
        reservation_id: str,
        *,
        actual: UsageRecord,
        actor_id: str,
    ) -> None:
        if self._crash_pending:
            self._crash_pending = False
            raise SimulatedProcessExit
        super().complete(reservation_id, actual=actual, actor_id=actor_id)


def _profile() -> HarnessRuntimeProfile:
    manifest = PluginCapabilityManifest(
        plugin_id="recorded-runtime",
        plugin_version="1.0.0",
        package_digest=DIGEST_A,
        source_digest=DIGEST_B,
        supported_contract_versions=["HarnessRuntimeProfile.v1"],
        supported_schema_versions=[1],
        operating_systems=["linux", "windows"],
        architectures=["x86_64"],
        required_executables=[],
        network_access="none",
        configuration_schema={},
        side_effects=["workspace_write"],
        security_classification="recorded-test-runtime",
        health_check=["recording"],
        license="Proprietary",
    )
    return HarnessRuntimeProfile(
        profile_id="recorded-campaign-v1",
        plugin=SignedPluginManifest(
            manifest=manifest,
            signature_algorithm="hmac-sha256",
            signer_key_id="test",
            signature_hex="00",
        ),
        transport="sdk",
        requested_model="recorded-model",
        authentication_class="none",
        permission_profile_digest=DIGEST_A,
        development_evaluator_id="development",
        max_wall_time_seconds=60,
        max_turns=5,
        completion_schema_digest=DIGEST_B,
    )


def test_coding_agent_variation_is_durable_across_post_result_crash(
    tmp_path: Path,
) -> None:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    baseline.mkdir()
    candidate.mkdir()
    for root in (baseline, candidate):
        (root / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
        (root / "target.py").write_text("VALUE = 1\n", encoding="utf-8")
    baseline_digest = source_tree_digest(baseline)

    database = Database(tmp_path / "state.db")
    database.initialize()
    spec = experiment_spec().model_copy(
        update={
            "workspace": experiment_spec().workspace.model_copy(
                update={
                    "source_uri": f"file:{baseline}",
                    "source_tree_digest": baseline_digest,
                    "allowed_paths": ["pyproject.toml", "target.py"],
                    "required_paths": ["pyproject.toml", "target.py"],
                }
            )
        }
    )
    runs = RunService(database)
    runs.create_experiment(spec)
    runs.create_run(spec.experiment_id, actor_id="operator", run_id="run-1", prepare=True)
    runs.transition("run-1", RunState.RUNNING, actor_id="operator")
    champion = runs.get_run("run-1").champion_id
    assert champion is not None

    estimate = UsageRecord.zero().model_copy(
        update={
            "model_input_tokens": 100,
            "model_output_tokens": 100,
            "variation_sessions": 1,
        }
    )
    budgets = BudgetService(database)
    reservation = budgets.reserve(
        "run-1", activity_key="variation:session-1", estimated=estimate, actor_id="scheduler"
    )
    request = VariationSessionRequest(
        session_id="session-1",
        run_id="run-1",
        champion=CandidateRef(
            candidate_id=champion,
            source_tree_digest=baseline_digest,
            lineage_sequence=0,
        ),
        lineage_index_digest=canonical_digest([champion]),
        initial_context_digest=canonical_digest({"objective": spec.objective}),
        tool_capability_token="recorded-capability",
        development_evaluator_refs=[component("development")],
        budget_reservation_id=reservation,
        random_seed=7,
    )
    sessions = SessionService(database)
    sessions.enqueue(request)
    activities = ActivityService(database)
    activity_id = activities.enqueue(
        "run-1",
        activity_key="variation:session-1",
        input_digest=canonical_digest(request),
        actor_id="scheduler",
        session_id=request.session_id,
        budget_reservation_id=reservation,
    )
    event = RuntimeEvent(
        invocation_id="recorded-event",
        sequence=1,
        event_type="usage",
        payload_digest=DIGEST_A,
        usage_delta={"input_tokens": 7, "output_tokens": 3},
        occurred_at=datetime.now(UTC),
    )
    runtime = MutatingRecordedRuntime(
        [
            RecordedRuntimeEntry(
                request_digest=canonical_digest(request),
                events=(event,),
                completion=AgentCompletion(
                    outcome="proposal", rationale="updated target", claimed_tests=["unit"]
                ),
            )
        ]
    )
    handler = CodingVariationActivityHandler(
        runtime=runtime,
        profile=_profile(),
        sessions=sessions,
        invocations=RuntimeService(database),
        budgets=budgets,
        terminal_budgets=TerminalBudgetService(database),
        evidence=EvidenceService(database),
        activities=activities,
        artifacts=ArtifactService(
            database, FilesystemArtifactStore(tmp_path / "artifacts")
        ),
        workspace_resolver=lambda _: CampaignWorkspace(
            baseline=baseline,
            candidate=candidate,
            git_metadata=tmp_path / "external-git",
        ),
        event_spool_root=tmp_path / "runtime-spool",
        evaluation_estimate=UsageRecord.zero().model_copy(
            update={"authoritative_evaluations": 1}
        ),
        harness_ref=component("recorded-runtime"),
        model_config_digest=spec.harness.model_config_digest,
        policy_bundle_digest=spec.policy_bundle_digest,
    )
    scheduler = Scheduler(activities, worker_id="worker-1", lease_seconds=1)
    scheduler.register("variation", handler)

    with pytest.raises(InjectedWorkerCrash):
        asyncio.run(scheduler.run_once_async(crash_after_external_result=True))
    with database.session() as session:
        session.execute(
            update(ActivityRow)
            .where(ActivityRow.activity_id == activity_id)
            .values(lease_expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
    assert asyncio.run(scheduler.run_once_async())

    assert runtime.turn_starts == 1
    projected = QueryService(database).session("session-1")
    assert projected.state == "proposal_ready"
    runtime_projection = QueryService(database).session_runtime("session-1")
    assert runtime_projection.invocations[0]["state"] == "completed"
    assert runtime_projection.invocations[0]["runtime_session"]["native_session_id"] == (
        "recorded:session-1"
    )
    with database.session() as session:
        candidates = list(session.scalars(select(CandidateRow)))
        assert len(candidates) == 2
        candidate_id = next(
            item.candidate_id for item in candidates if item.candidate_id != champion
        )
        variation = session.get(ActivityRow, activity_id)
        assert variation is not None and variation.state == "completed"
        evaluation = session.scalar(
            select(ActivityRow).where(ActivityRow.activity_key.like("evaluate:%"))
        )
        assert evaluation is not None and evaluation.state == "queued"

    now = datetime.now(UTC)

    def evaluate(manifest: CandidateManifest) -> tuple[tuple[str, EvaluationRecord], ...]:
        assert manifest.candidate_id == candidate_id
        record = EvaluationRecord(
            evaluation_id=f"evaluation:{candidate_id}",
            candidate_id=candidate_id,
            evaluator_ref=component("admission"),
            evaluator_tier="admission",
            evaluator_profile_digest=DIGEST_A,
            execution_image_digest=DIGEST_B,
            hardware_class="test-host",
            input_artifact_digests=[manifest.source_tree_digest],
            trial_records=[
                TrialRecord(
                    trial_index=0,
                    seed=7,
                    metrics={"correctness": Decimal("2")},
                    workload_time_ms=Decimal("1"),
                    sandbox_setup_time_ms=Decimal("1"),
                    queue_time_ms=Decimal("0"),
                    host_overhead_time_ms=Decimal("0"),
                )
            ],
            aggregate_metrics={"correctness": Decimal("2")},
            uncertainty={
                "correctness": UncertaintyRecord(
                    method="fixture",
                    lower=Decimal("2"),
                    upper=Decimal("2"),
                    confidence_level=Decimal("0.95"),
                )
            },
            constraints=[ConstraintResult(name="hidden-suite", passed=True)],
            outcome="passed",
            evidence_artifacts=[],
            started_at=now,
            completed_at=now,
        )
        return (("admission:fixture-v1", record),)

    def admit(
        manifest: CandidateManifest, evaluations: tuple[EvaluationRecord, ...]
    ) -> AdmissionPackage:
        policy = PolicyDecision(
            decision_id=f"policy:{candidate_id}",
            policy_engine_id="fixture-policy",
            policy_bundle_digest=DIGEST_A,
            action="candidate.admit",
            resource=f"run/run-1/candidate/{candidate_id}",
            input_digest=canonical_digest(manifest),
            outcome="allow",
            reason_codes=["fixture_allow"],
            decided_at=now,
        )
        decision = AdmissionDecision(
            admission_id=f"admission:{candidate_id}",
            candidate_id=candidate_id,
            expected_champion_id=champion,
            evaluation_ids=[evaluations[0].evaluation_id],
            policy_decision_ids=[policy.decision_id],
            outcome="admit",
            reason_codes=["constraints_passed", "improved"],
            comparison=ComparisonRecord(
                metric="correctness",
                direction="maximize",
                incumbent_value=Decimal("1"),
                candidate_value=Decimal("2"),
                minimum_effect=Decimal("1"),
                conclusion="improved",
            ),
            decided_by=ActorRef(actor_type="service", actor_id="admission-controller"),
            decided_at=now,
        )
        return AdmissionPackage(policy_decisions=(policy,), decision=decision)

    evaluation_handler = CandidateEvaluationActivityHandler(
        evidence=EvidenceService(database),
        activities=activities,
        budgets=budgets,
        evaluator_keys=("admission:fixture-v1",),
        runner=evaluate,
    )
    admission_handler = CandidateAdmissionActivityHandler(
        evidence=EvidenceService(database),
        runs=runs,
        decider=admit,
    )
    worker = LocalCampaignWorker(
        activities,
        worker_id="worker-2",
        variation=handler,
        evaluation=evaluation_handler,
        admission=admission_handler,
        lease_seconds=1,
    )
    assert asyncio.run(worker.run_until_idle()) == 2
    with pytest.raises(ValueError, match="positive"):
        asyncio.run(worker.run_until_idle(max_activities=0))
    final_run = runs.get_run("run-1")
    assert final_run.state == "completed"
    assert final_run.champion_id == candidate_id
    provenance = ProvenanceService(database)
    exported = provenance.export_run("run-1")
    assert provenance.verify(exported).verified
    with database.session() as session:
        evaluation_activity = session.scalar(
            select(ActivityRow).where(ActivityRow.activity_key.like("evaluate:%"))
        )
        admission_activity = session.scalar(
            select(ActivityRow).where(ActivityRow.activity_key.like("admit:%"))
        )
        assert evaluation_activity is not None
        assert admission_activity is not None
        session.expunge(evaluation_activity)
        session.expunge(admission_activity)
    assert evaluation_handler.recover(evaluation_activity).disposition == (
        RecoveryDisposition.DURABLE_RESULT
    )
    assert admission_handler.recover(admission_activity).disposition == (
        RecoveryDisposition.DURABLE_RESULT
    )
    assert evaluation_handler.classify_failure(
        evaluation_activity, RuntimeError("retry")
    ) == FailureDisposition.RETRY
    assert admission_handler.classify_failure(
        admission_activity, RuntimeError("retry")
    ) == FailureDisposition.RETRY
    assert handler.classify_failure(
        evaluation_activity, RuntimeError("not-started")
    ) == FailureDisposition.RETRY
    untyped_handler = cast(Any, handler)
    untyped_handler._append_spool(
        untyped_handler._spool_path(f"harness:{activity_id}"), event
    )
    assert handler.classify_failure(
        variation, RuntimeError("ambiguous-provider-state")
    ) == FailureDisposition.RECONCILE
    with pytest.raises(ValueError, match="unique"):
        CandidateEvaluationActivityHandler(
            evidence=EvidenceService(database),
            activities=activities,
            budgets=budgets,
            evaluator_keys=(),
            runner=evaluate,
        )
    with pytest.raises(CampaignRuntimeError, match="invalid evaluate activity key"):
        evaluation_handler.recover(admission_activity)


@pytest.mark.parametrize(
    ("crash_before_settlement", "evaluation_reservation_fails"),
    [(False, False), (True, False), (False, True)],
)
def test_durable_over_budget_variation_settles_terminal_state_atomically(
    tmp_path: Path,
    crash_before_settlement: bool,
    evaluation_reservation_fails: bool,
) -> None:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    baseline.mkdir()
    candidate.mkdir()
    for root in (baseline, candidate):
        (root / "pyproject.toml").write_text(
            "[project]\nname='fixture'\n", encoding="utf-8"
        )
        (root / "target.py").write_text("VALUE = 1\n", encoding="utf-8")
    baseline_digest = source_tree_digest(baseline)

    database = Database(tmp_path / "state.db")
    database.initialize()
    original = experiment_spec()
    spec = original.model_copy(
        update={
            "workspace": original.workspace.model_copy(
                update={
                    "source_uri": f"file:{baseline}",
                    "source_tree_digest": baseline_digest,
                    "allowed_paths": ["pyproject.toml", "target.py"],
                    "required_paths": ["pyproject.toml", "target.py"],
                }
            ),
            "budget": original.budget.model_copy(
                update={
                    "model_input_tokens": 20 if evaluation_reservation_fails else 10,
                    "authoritative_evaluations": (
                        0 if evaluation_reservation_fails else 1
                    ),
                }
            ),
        }
    )
    runs = RunService(database)
    runs.create_experiment(spec)
    runs.create_run(spec.experiment_id, actor_id="operator", run_id="run-1", prepare=True)
    runs.transition("run-1", RunState.RUNNING, actor_id="operator")
    champion = runs.get_run("run-1").champion_id
    assert champion is not None

    budgets = (
        CrashOnceBudgetService(database)
        if crash_before_settlement
        else BudgetService(database)
    )
    estimate = UsageRecord.zero().model_copy(
        update={"model_input_tokens": 5, "model_output_tokens": 5, "variation_sessions": 1}
    )
    reservation_id = budgets.reserve(
        "run-1",
        activity_key="variation:session-1",
        estimated=estimate,
        actor_id="scheduler",
    )
    request = VariationSessionRequest(
        session_id="session-1",
        run_id="run-1",
        champion=CandidateRef(
            candidate_id=champion,
            source_tree_digest=baseline_digest,
            lineage_sequence=0,
        ),
        lineage_index_digest=canonical_digest([champion]),
        initial_context_digest=canonical_digest({"objective": spec.objective}),
        tool_capability_token="recorded-capability",
        development_evaluator_refs=[component("development")],
        budget_reservation_id=reservation_id,
        random_seed=7,
    )
    sessions = SessionService(database)
    sessions.enqueue(request)
    activities = ActivityService(database)
    activity_id = activities.enqueue(
        "run-1",
        activity_key="variation:session-1",
        input_digest=canonical_digest(request),
        actor_id="scheduler",
        session_id=request.session_id,
        budget_reservation_id=reservation_id,
    )
    event = RuntimeEvent(
        invocation_id="over-budget-event",
        sequence=1,
        event_type="usage",
        payload_digest=DIGEST_A,
        usage_delta={"input_tokens": 11, "output_tokens": 1},
        occurred_at=datetime.now(UTC),
    )
    runtime = MutatingRecordedRuntime(
        [
            RecordedRuntimeEntry(
                request_digest=canonical_digest(request),
                events=(event,),
                completion=AgentCompletion(
                    outcome="proposal", rationale="updated target", claimed_tests=["unit"]
                ),
            )
        ]
    )
    handler = CodingVariationActivityHandler(
        runtime=runtime,
        profile=_profile(),
        sessions=sessions,
        invocations=RuntimeService(database),
        budgets=budgets,
        terminal_budgets=TerminalBudgetService(database),
        evidence=EvidenceService(database),
        activities=activities,
        artifacts=ArtifactService(
            database, FilesystemArtifactStore(tmp_path / "artifacts")
        ),
        workspace_resolver=lambda _: CampaignWorkspace(
            baseline=baseline,
            candidate=candidate,
            git_metadata=tmp_path / "external-git",
        ),
        event_spool_root=tmp_path / "runtime-spool",
        evaluation_estimate=UsageRecord.zero().model_copy(
            update={"authoritative_evaluations": 1}
        ),
        harness_ref=component("recorded-runtime"),
        model_config_digest=spec.harness.model_config_digest,
        policy_bundle_digest=spec.policy_bundle_digest,
    )
    scheduler = Scheduler(activities, worker_id="worker-1", lease_seconds=30)
    scheduler.register("variation", handler)

    if crash_before_settlement:
        with pytest.raises(SimulatedProcessExit):
            asyncio.run(scheduler.run_once_async())
        with database.session() as session:
            session.execute(
                update(ActivityRow)
                .where(ActivityRow.activity_id == activity_id)
                .values(lease_expires_at=datetime.now(UTC) - timedelta(seconds=1))
            )
        assert asyncio.run(scheduler.run_once_async())
    else:
        assert asyncio.run(scheduler.run_once_async())
    assert runtime.turn_starts == 1
    assert runs.get_run("run-1").state == RunState.FAILED.value
    assert QueryService(database).session("session-1").state == "proposal_ready"

    with database.session() as session:
        variation = session.get(ActivityRow, activity_id)
        assert variation is not None
        assert variation.state == "completed"
        assert variation.result_digest is not None
        settled_result_digest = variation.result_digest
        evaluation = session.scalar(
            select(ActivityRow).where(ActivityRow.activity_key.like("evaluate:%"))
        )
        if evaluation_reservation_fails:
            assert evaluation is None
        else:
            assert evaluation is not None and evaluation.state == "cancelled"
        candidate_row = session.scalar(
            select(CandidateRow).where(CandidateRow.session_id == "session-1")
        )
        assert candidate_row is not None and candidate_row.state == "policy_blocked"
        variation_reservation = session.get(BudgetReservationRow, reservation_id)
        assert variation_reservation is not None
        assert variation_reservation.state == "exceeded"
        settled_actual = UsageRecord.model_validate_json(
            variation_reservation.actual_json or "{}"
        )
        assert settled_actual.model_input_tokens == 11
        if evaluation is not None:
            assert evaluation.budget_reservation_id is not None
            evaluation_reservation = session.get(
                BudgetReservationRow, evaluation.budget_reservation_id
            )
            assert evaluation_reservation is not None
            assert evaluation_reservation.state == "released"
        ledger = session.get(BudgetLedgerRow, "run-1")
        assert ledger is not None
        assert UsageRecord.model_validate_json(ledger.used_json).model_input_tokens == 11
        assert UsageRecord.model_validate_json(ledger.reserved_json) == UsageRecord.zero()
        policy = session.scalar(
            select(PolicyDecisionRow).where(
                PolicyDecisionRow.candidate_id == candidate_row.candidate_id
            )
        )
        assert policy is not None
        decision = PolicyDecision.model_validate_json(policy.decision_json)
        assert decision.outcome == "deny"
        assert decision.reason_codes == [
            (
                "authoritative_evaluations_budget_exceeded"
                if evaluation_reservation_fails
                else "model_input_token_budget_exceeded"
            )
        ]
        assert list(session.scalars(select(ReconciliationCaseRow))) == []

    provenance = ProvenanceService(database)
    exported = provenance.export_run("run-1")
    assert provenance.verify(exported).verified

    terminal = TerminalBudgetService(database)
    terminal.settle_exhausted_variation(
        run_id="run-1",
        activity_id=activity_id,
        reservation_id=reservation_id,
        result_digest=settled_result_digest,
        actual=settled_actual,
        required_evaluation=UsageRecord.zero().model_copy(
            update={"authoritative_evaluations": 1}
        ),
        policy_bundle_digest=spec.policy_bundle_digest,
        actor_id="recovery",
    )
    with pytest.raises(LookupError, match="context is incomplete"):
        terminal.settle_exhausted_variation(
            run_id="missing-run",
            activity_id=activity_id,
            reservation_id=reservation_id,
            result_digest=settled_result_digest,
            actual=settled_actual,
            required_evaluation=UsageRecord.zero(),
            policy_bundle_digest=spec.policy_bundle_digest,
            actor_id="recovery",
        )
    with pytest.raises(TerminalBudgetConflictError, match="another result"):
        terminal.settle_exhausted_variation(
            run_id="run-1",
            activity_id=activity_id,
            reservation_id=reservation_id,
            result_digest=DIGEST_A,
            actual=settled_actual,
            required_evaluation=UsageRecord.zero(),
            policy_bundle_digest=spec.policy_bundle_digest,
            actor_id="recovery",
        )
    with pytest.raises(TerminalBudgetConflictError, match="different actual usage"):
        terminal.settle_exhausted_variation(
            run_id="run-1",
            activity_id=activity_id,
            reservation_id=reservation_id,
            result_digest=settled_result_digest,
            actual=UsageRecord.zero(),
            required_evaluation=UsageRecord.zero(),
            policy_bundle_digest=spec.policy_bundle_digest,
            actor_id="recovery",
        )

    now = datetime.now(UTC)
    reconciliation = ReconciliationCaseRecord(
        reconciliation_id=str(uuid4()),
        run_id="run-1",
        activity_id=activity_id,
        session_id="session-1",
        reason="legacy_post_result_budget_failure",
        budget_reservation_id=reservation_id,
        state="open",
        opened_at=now,
    )
    with database.session() as session:
        session.add(
            ReconciliationCaseRow(
                reconciliation_id=reconciliation.reconciliation_id,
                run_id="run-1",
                activity_id=activity_id,
                session_id="session-1",
                state="open",
                record_digest=canonical_digest(reconciliation),
                record_json=reconciliation.model_dump_json(),
                created_at=now,
                updated_at=now,
            )
        )
    assert not provenance.verify(provenance.export_run("run-1")).verified
    terminal.settle_exhausted_variation(
        run_id="run-1",
        activity_id=activity_id,
        reservation_id=reservation_id,
        result_digest=settled_result_digest,
        actual=settled_actual,
        required_evaluation=UsageRecord.zero().model_copy(
            update={"authoritative_evaluations": 1}
        ),
        policy_bundle_digest=spec.policy_bundle_digest,
        actor_id="recovery",
    )
    with database.session() as session:
        recovered = session.get(
            ReconciliationCaseRow, reconciliation.reconciliation_id
        )
        assert recovered is not None and recovered.state == "resolved"
    assert provenance.verify(provenance.export_run("run-1")).verified


def test_stop_completion_finishes_without_freezing_partial_workspace(
    tmp_path: Path,
) -> None:
    class CapturingSessions:
        def __init__(self) -> None:
            self.attempts: list[object] = []
            self.results: list[VariationSessionResult] = []

        def record_attempt(self, record: object) -> int:
            self.attempts.append(record)
            return 1

        def finish(self, result: VariationSessionResult) -> None:
            self.results.append(result)

    sessions = CapturingSessions()
    handler = cast(Any, object.__new__(CodingVariationActivityHandler))
    handler._sessions = sessions
    request = VariationSessionRequest(
        session_id="session-stop",
        run_id="run-stop",
        champion=CandidateRef(
            candidate_id="seed-stop",
            source_tree_digest=DIGEST_A,
            lineage_sequence=0,
        ),
        lineage_index_digest=DIGEST_A,
        initial_context_digest=DIGEST_B,
        tool_capability_token="token",
        development_evaluator_refs=[component("development")],
        budget_reservation_id="reservation-stop",
        random_seed=1,
    )
    activity = ActivityRow(activity_id="activity-stop")
    workspace = CampaignWorkspace(
        baseline=tmp_path / "unused-baseline",
        candidate=tmp_path / "unused-candidate",
        git_metadata=tmp_path / "unused-git",
    )
    result_digest = asyncio.run(
        handler._finalize_completion(
            request=request,
            activity=activity,
            workspace=workspace,
            completion=AgentCompletion(outcome="stop", rationale="no safe improvement"),
            usage=UsageRecord.zero(),
            event_stream_digest=DIGEST_B,
            before_digest=DIGEST_A,
            after_digest=DIGEST_A,
        )
    )
    assert result_digest == canonical_digest(sessions.results[0])
    assert sessions.results[0].outcome == "exhausted"
    assert len(sessions.attempts) == 1
    with pytest.raises(CampaignRuntimeError, match="without workspace changes"):
        asyncio.run(
            handler._finalize_completion(
                request=request,
                activity=activity,
                workspace=workspace,
                completion=AgentCompletion(outcome="proposal", rationale="unchanged"),
                usage=UsageRecord.zero(),
                event_stream_digest=DIGEST_B,
                before_digest=DIGEST_A,
                after_digest=DIGEST_A,
            )
        )


def test_campaign_workspace_control_roots_must_be_disjoint(tmp_path: Path) -> None:
    baseline = tmp_path / "base"
    candidate = tmp_path / "candidate"
    baseline.mkdir()
    candidate.mkdir()
    binding = CampaignWorkspace(
        baseline=baseline,
        candidate=candidate,
        git_metadata=tmp_path / "git-metadata",
    )
    assert validate_campaign_workspace(binding, tmp_path / "spool") == (
        baseline.resolve(),
        candidate.resolve(),
    )
    with pytest.raises(CampaignRuntimeError, match="disjoint"):
        validate_campaign_workspace(
            CampaignWorkspace(baseline, baseline, tmp_path / "git"),
            tmp_path / "spool",
        )
    nested = baseline / "nested"
    nested.mkdir()
    with pytest.raises(CampaignRuntimeError, match="disjoint"):
        validate_campaign_workspace(
            CampaignWorkspace(baseline, nested, tmp_path / "git"),
            tmp_path / "spool",
        )
    with pytest.raises(CampaignRuntimeError, match="Git metadata"):
        validate_campaign_workspace(
            CampaignWorkspace(baseline, candidate, candidate / "git"),
            tmp_path / "spool",
        )
    with pytest.raises(CampaignRuntimeError, match="event spool"):
        validate_campaign_workspace(binding, candidate / "spool")

    nested_git_candidate = tmp_path / "nested-git-candidate"
    nested_git_candidate.mkdir()
    (nested_git_candidate / "sub" / ".git").mkdir(parents=True)
    with pytest.raises(CampaignRuntimeError, match="contains Git metadata"):
        validate_campaign_workspace(
            CampaignWorkspace(
                baseline, nested_git_candidate, tmp_path / "nested-git-metadata"
            ),
            tmp_path / "nested-spool",
        )

    ancestor_root = tmp_path / "ancestor-vcs"
    ancestor_candidate = ancestor_root / "candidate"
    ancestor_candidate.mkdir(parents=True)
    (ancestor_root / ".git").mkdir()
    with pytest.raises(CampaignRuntimeError, match="ancestors"):
        validate_campaign_workspace(
            CampaignWorkspace(
                baseline, ancestor_candidate, tmp_path / "ancestor-git-metadata"
            ),
            tmp_path / "ancestor-spool",
        )
