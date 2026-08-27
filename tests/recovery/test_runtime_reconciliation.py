from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from avo_correlate.adapters.persistence import Database
from avo_correlate.adapters.persistence.models import (
    ActivityRow,
    BudgetLedgerRow,
    BudgetReservationRow,
    ReconciliationCaseRow,
)
from avo_correlate.application.activity_service import ActivityConflictError, ActivityService
from avo_correlate.application.budget_service import BudgetService
from avo_correlate.application.query_service import QueryService
from avo_correlate.application.run_service import RunService
from avo_correlate.application.runtime_service import RuntimeConflictError, RuntimeService
from avo_correlate.application.scheduler import (
    ActivityRecovery,
    ActivityResult,
    FailureDisposition,
    RecoveryDisposition,
    Scheduler,
)
from avo_correlate.application.session_service import SessionService
from avo_correlate.contracts.budgets import UsageRecord
from avo_correlate.contracts.lifecycle import RunState
from avo_correlate.contracts.runtime import EconomicUsageRecord, HarnessInvocationRecord
from avo_correlate.contracts.variation import CandidateRef, VariationSessionRequest
from tests.conftest import DIGEST_A, DIGEST_B, component, experiment_spec


def running_services(
    tmp_path: Path,
) -> tuple[Database, RunService, ActivityService, SessionService]:
    database = Database(tmp_path / "state.db")
    database.initialize()
    runs = RunService(database)
    runs.create_experiment(experiment_spec())
    runs.create_run("experiment-1", actor_id="tester", run_id="run-1", prepare=True)
    runs.transition("run-1", RunState.RUNNING, actor_id="tester")
    return database, runs, ActivityService(database), SessionService(database)


def test_lease_epoch_fences_stale_completion_and_heartbeat(tmp_path: Path) -> None:
    database, _, activities, _ = running_services(tmp_path)
    activity_id = activities.enqueue(
        "run-1", activity_key="agent:one", input_digest=DIGEST_A, actor_id="scheduler"
    )
    started = datetime(2026, 1, 1, tzinfo=UTC)
    first = activities.claim_next(worker_id="same-worker", lease_seconds=2, now=started)
    assert first is not None
    second = activities.claim_next(
        worker_id="same-worker", lease_seconds=2, now=started + timedelta(seconds=3)
    )
    assert second is not None and second.lease_epoch == first.lease_epoch + 1
    with pytest.raises(ActivityConflictError, match="lease"):
        activities.complete(
            activity_id,
            worker_id="same-worker",
            lease_epoch=first.lease_epoch,
            result_digest=DIGEST_B,
        )
    with pytest.raises(ActivityConflictError, match="lease"):
        activities.heartbeat(
            activity_id,
            worker_id="same-worker",
            lease_epoch=first.lease_epoch,
            lease_seconds=2,
        )
    database.dispose()


class AmbiguousHandler:
    def recover(self, activity: ActivityRow) -> ActivityRecovery:
        del activity
        return ActivityRecovery(RecoveryDisposition.AMBIGUOUS)

    def execute(self, activity: ActivityRow, lease_epoch: int) -> ActivityResult:
        raise AssertionError((activity, lease_epoch))

    def classify_failure(
        self, activity: ActivityRow, error: Exception
    ) -> FailureDisposition:
        del activity, error
        return FailureDisposition.RECONCILE


def test_phase_aware_ambiguous_recovery_opens_operator_case(tmp_path: Path) -> None:
    database, runs, activities, _ = running_services(tmp_path)
    activity_id = activities.enqueue(
        "run-1", activity_key="agent:one", input_digest=DIGEST_A, actor_id="scheduler"
    )
    scheduler = Scheduler(activities, worker_id="worker")
    scheduler.register("agent", AmbiguousHandler())
    assert scheduler.run_once()
    with database.session() as session:
        activity = session.get(ActivityRow, activity_id)
        assert activity is not None and activity.state == "reconciliation_required"
    assert runs.get_run("run-1").state == RunState.BLOCKED_RECONCILIATION.value
    database.dispose()


def test_runtime_evidence_projection_and_operator_retry(tmp_path: Path) -> None:
    database, runs, activities, sessions = running_services(tmp_path)
    champion_id = runs.get_run("run-1").champion_id
    assert champion_id is not None
    reservation_id = BudgetService(database).reserve(
        "run-1",
        activity_key="agent-budget:session-1",
        estimated=UsageRecord.zero().model_copy(update={"tool_calls": 2}),
        actor_id="scheduler",
    )
    request = VariationSessionRequest(
        session_id="session-1",
        run_id="run-1",
        champion=CandidateRef(
            candidate_id=champion_id,
            source_tree_digest=DIGEST_A,
            lineage_sequence=0,
        ),
        lineage_index_digest=DIGEST_A,
        initial_context_digest=DIGEST_B,
        tool_capability_token="token",
        development_evaluator_refs=[component("development")],
        budget_reservation_id=reservation_id,
        random_seed=1,
    )
    sessions.enqueue(request)
    sessions.start(request.session_id)
    activity_id = activities.enqueue(
        "run-1",
        activity_key="agent:session-1",
        input_digest=DIGEST_A,
        actor_id="scheduler",
        session_id="session-1",
        budget_reservation_id=reservation_id,
    )
    runtime = RuntimeService(database)
    runtime.record_invocation(
        HarnessInvocationRecord(
            invocation_id="invocation-1",
            activity_id=activity_id,
            run_id="run-1",
            session_id="session-1",
            profile_digest=DIGEST_A,
            runtime_id="recorded-runtime-v1",
            state="running",
            adapter_version="1.0.0",
            runtime_version="1.0.0",
            requested_model="recorded",
            workspace_before_digest=DIGEST_A,
            economics=EconomicUsageRecord(
                billing_mode="local", cost_source="none"
            ),
            started_at=datetime.now(UTC),
        )
    )
    activities.mark_reconciliation_required(
        activity_id,
        actor_id="worker",
        error={"reason": "provider outcome is ambiguous"},
    )
    with database.session() as session:
        row = session.scalar(
            select(ReconciliationCaseRow).where(
                ReconciliationCaseRow.activity_id == activity_id
            )
        )
        assert row is not None
        case_id = row.reconciliation_id
        reservation = session.get(BudgetReservationRow, reservation_id)
        assert reservation is not None and reservation.state == "held"
    projection = QueryService(database).session_runtime("session-1")
    assert projection.invocations[0]["invocation_id"] == "invocation-1"
    assert projection.reconciliations[0]["state"] == "open"
    resolved = runtime.resolve_reconciliation(
        case_id,
        resolution="retry",
        note="provider confirms no turn was started",
        actor_id="operator",
    )
    assert resolved.resolution == "retry"
    assert runs.get_run("run-1").state == RunState.RUNNING.value
    assert QueryService(database).session("session-1").state == "running"
    with database.session() as session:
        reservation = session.get(BudgetReservationRow, reservation_id)
        assert reservation is not None and reservation.state == "reserved"
    database.dispose()


def test_invocation_transitions_are_idempotent_and_identity_fenced(
    tmp_path: Path,
) -> None:
    database, _, activities, _ = running_services(tmp_path)
    activity_id = activities.enqueue(
        "run-1", activity_key="agent:one", input_digest=DIGEST_A, actor_id="scheduler"
    )
    service = RuntimeService(database)
    started = HarnessInvocationRecord(
        invocation_id="invocation-1",
        activity_id=activity_id,
        run_id="run-1",
        profile_digest=DIGEST_A,
        runtime_id="recorded",
        state="started",
        adapter_version="1.0.0",
        runtime_version="1.0.0",
        requested_model="recorded",
        workspace_before_digest=DIGEST_A,
        economics=EconomicUsageRecord(billing_mode="local", cost_source="none"),
        started_at=datetime.now(UTC),
    )
    service.record_invocation(started)
    service.record_invocation(started)
    with pytest.raises(RuntimeConflictError, match="activity is missing"):
        service.record_invocation(started.model_copy(update={"activity_id": "missing"}))
    with pytest.raises(RuntimeConflictError, match="conflicting"):
        service.record_invocation(started.model_copy(update={"requested_model": "other"}))
    running = started.model_copy(update={"state": "running"})
    service.replace_invocation(running)
    with pytest.raises(RuntimeConflictError, match="identity fields"):
        service.replace_invocation(running.model_copy(update={"run_id": "another-run"}))
    completed = running.model_copy(
        update={
            "state": "completed",
            "workspace_after_digest": DIGEST_B,
            "completed_at": datetime.now(UTC),
        }
    )
    service.replace_invocation(completed)
    assert service.get_invocation("invocation-1").state == "completed"
    with pytest.raises(RuntimeConflictError, match="invalid invocation transition"):
        service.replace_invocation(started)
    with pytest.raises(LookupError, match="invocation not found"):
        service.get_invocation("missing")
    with pytest.raises(LookupError, match="invocation not found"):
        service.replace_invocation(started.model_copy(update={"invocation_id": "missing"}))
    database.dispose()


def test_accepting_reconciled_durable_result_requires_digest_and_is_idempotent(
    tmp_path: Path,
) -> None:
    database, runs, activities, _ = running_services(tmp_path)
    activity_id = activities.enqueue(
        "run-1", activity_key="agent:one", input_digest=DIGEST_A, actor_id="scheduler"
    )
    service = RuntimeService(database)
    case = service.open_reconciliation(
        run_id="run-1",
        activity_id=activity_id,
        reason="completion journal write was interrupted",
        actor_id="worker",
    )
    assert service.open_reconciliation(
        run_id="run-1",
        activity_id=activity_id,
        reason="same ambiguity",
        actor_id="worker",
    ) == case
    with pytest.raises(ValueError, match="result_digest"):
        service.resolve_reconciliation(
            case.reconciliation_id,
            resolution="accept_result",
            note="provider confirms completion",
            actor_id="operator",
        )
    resolved = service.resolve_reconciliation(
        case.reconciliation_id,
        resolution="accept_result",
        note="provider confirms completion",
        actor_id="operator",
        result_digest=DIGEST_B,
    )
    assert service.resolve_reconciliation(
        case.reconciliation_id,
        resolution="accept_result",
        note="same decision",
        actor_id="operator",
        result_digest=DIGEST_B,
    ) == resolved
    with pytest.raises(RuntimeConflictError, match="differently"):
        service.resolve_reconciliation(
            case.reconciliation_id,
            resolution="fail",
            note="conflicting decision",
            actor_id="operator",
        )
    assert runs.get_run("run-1").state == "running"
    with database.session() as session:
        activity = session.get(ActivityRow, activity_id)
        assert activity is not None and activity.result_digest == DIGEST_B
    with pytest.raises(RuntimeConflictError, match="target is missing"):
        service.open_reconciliation(
            run_id="run-1",
            activity_id="missing",
            reason="missing",
            actor_id="worker",
        )
    with pytest.raises(LookupError, match="reconciliation not found"):
        service.resolve_reconciliation(
            "missing", resolution="fail", note="missing", actor_id="operator"
        )
    with pytest.raises(ValueError, match="unknown"):
        service.resolve_reconciliation(
            case.reconciliation_id,
            resolution="invalid",
            note="invalid",
            actor_id="operator",
        )
    database.dispose()


def test_cancelling_reconciliation_releases_held_budget_atomically(
    tmp_path: Path,
) -> None:
    database, runs, activities, _ = running_services(tmp_path)
    budgets = BudgetService(database)
    estimate = UsageRecord.zero().model_copy(update={"tool_calls": 3})
    reservation_id = budgets.reserve(
        "run-1",
        activity_key="agent-budget:cancel",
        estimated=estimate,
        actor_id="scheduler",
    )
    activity_id = activities.enqueue(
        "run-1",
        activity_key="agent:cancel",
        input_digest=DIGEST_A,
        actor_id="scheduler",
        budget_reservation_id=reservation_id,
    )
    runtime = RuntimeService(database)
    case = runtime.open_reconciliation(
        run_id="run-1",
        activity_id=activity_id,
        reason="provider cannot determine outcome",
        actor_id="worker",
    )
    with database.session() as session:
        reservation = session.get(BudgetReservationRow, reservation_id)
        assert reservation is not None and reservation.state == "held"
    resolved = runtime.resolve_reconciliation(
        case.reconciliation_id,
        resolution="cancel",
        note="operator declines uncertain result",
        actor_id="operator",
    )
    assert resolved.resolution == "cancel"
    assert runs.get_run("run-1").state == "cancelled"
    with database.session() as session:
        reservation = session.get(BudgetReservationRow, reservation_id)
        assert reservation is not None and reservation.state == "released"
        ledger = session.get(BudgetLedgerRow, "run-1")
        assert ledger is not None
        assert UsageRecord.model_validate_json(ledger.reserved_json).tool_calls == 0
    database.dispose()
