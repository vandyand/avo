from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from avo_correlate.adapters.persistence import Database
from avo_correlate.adapters.persistence.models import ActivityRow
from avo_correlate.application.activity_service import ActivityService
from avo_correlate.application.run_service import RunService
from avo_correlate.application.scheduler import (
    ActivityRecovery,
    ActivityResult,
    FailureDisposition,
    InjectedWorkerCrash,
    RecoveryDisposition,
    Scheduler,
)
from avo_correlate.contracts.lifecycle import RunState
from tests.conftest import DIGEST_A, DIGEST_B, experiment_spec


class DurableFakeHandler:
    safely_retryable = True

    def __init__(self) -> None:
        self.execute_count = 0
        self.results: dict[str, ActivityResult] = {}

    def recover(self, activity: ActivityRow) -> ActivityRecovery:
        result = self.results.get(activity.activity_key)
        return ActivityRecovery(
            RecoveryDisposition.DURABLE_RESULT if result else RecoveryDisposition.NOT_STARTED,
            result,
        )

    def execute(self, activity: ActivityRow, lease_epoch: int) -> ActivityResult:
        assert lease_epoch > 0
        self.execute_count += 1
        result = ActivityResult(DIGEST_B)
        self.results[activity.activity_key] = result
        return result

    def classify_failure(
        self, activity: ActivityRow, error: Exception
    ) -> FailureDisposition:
        del activity, error
        return FailureDisposition.RETRY


class FailingHandler:
    def __init__(self, *, safely_retryable: bool) -> None:
        self.safely_retryable = safely_retryable

    def recover(self, activity: ActivityRow) -> ActivityRecovery:
        del activity
        return ActivityRecovery(RecoveryDisposition.NOT_STARTED)

    def execute(self, activity: ActivityRow, lease_epoch: int) -> ActivityResult:
        del activity, lease_epoch
        raise RuntimeError("external failure")

    def classify_failure(
        self, activity: ActivityRow, error: Exception
    ) -> FailureDisposition:
        del activity, error
        return (
            FailureDisposition.RETRY
            if self.safely_retryable
            else FailureDisposition.RECONCILE
        )


def scheduler_fixture(tmp_path: Path) -> tuple[Database, ActivityService]:
    database = Database(tmp_path / "state.db")
    database.initialize()
    runs = RunService(database)
    runs.create_experiment(experiment_spec())
    runs.create_run("experiment-1", actor_id="tester", run_id="run-1", prepare=True)
    runs.transition("run-1", RunState.RUNNING, actor_id="tester")
    return database, ActivityService(database)


def test_recovery_contract_and_scheduler_configuration_reject_ambiguity(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="only durable-result"):
        ActivityRecovery(RecoveryDisposition.DURABLE_RESULT)
    with pytest.raises(ValueError, match="only durable-result"):
        ActivityRecovery(RecoveryDisposition.NOT_STARTED, ActivityResult(DIGEST_A))
    _, activities = scheduler_fixture(tmp_path)
    with pytest.raises(ValueError, match="positive"):
        Scheduler(activities, worker_id="worker", lease_seconds=0)


def test_crash_after_external_result_recovers_without_reexecution(tmp_path: Path) -> None:
    database = Database(tmp_path / "state.db")
    database.initialize()
    runs = RunService(database)
    runs.create_experiment(experiment_spec())
    runs.create_run("experiment-1", actor_id="tester", run_id="run-1", prepare=True)
    runs.transition("run-1", RunState.RUNNING, actor_id="tester")
    activities = ActivityService(database)
    activity_id = activities.enqueue(
        "run-1", activity_key="evaluate:candidate-1", input_digest=DIGEST_A, actor_id="scheduler"
    )
    handler = DurableFakeHandler()
    first = Scheduler(activities, worker_id="worker-1", lease_seconds=1)
    first.register("evaluate", handler)
    with pytest.raises(InjectedWorkerCrash):
        first.run_once(crash_after_external_result=True)
    with database.session() as session:
        row = session.get(ActivityRow, activity_id)
        assert row is not None
        row.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    second = Scheduler(activities, worker_id="worker-2", lease_seconds=1)
    second.register("evaluate", handler)
    assert second.run_once()
    assert handler.execute_count == 1
    with database.session() as session:
        row = session.get(ActivityRow, activity_id)
        assert row is not None
        assert row.state == "completed"
        assert row.result_digest == DIGEST_B


def test_scheduler_handles_empty_queue_unknown_kind_and_registration_errors(
    tmp_path: Path,
) -> None:
    database, activities = scheduler_fixture(tmp_path)
    scheduler = Scheduler(activities, worker_id="worker")
    assert scheduler.run_once() is False
    with pytest.raises(ValueError, match="non-empty prefix"):
        scheduler.register("", DurableFakeHandler())
    with pytest.raises(ValueError, match="non-empty prefix"):
        scheduler.register("bad:kind", DurableFakeHandler())

    activity_id = activities.enqueue(
        "run-1", activity_key="unknown:item", input_digest=DIGEST_A, actor_id="scheduler"
    )
    assert scheduler.run_once() is True
    with database.session() as session:
        row = session.get(ActivityRow, activity_id)
        assert row is not None
        assert row.state == "reconciliation_required"


@pytest.mark.parametrize("retryable", [False, True])
def test_scheduler_marks_only_uncertain_nonretryable_failure_for_reconciliation(
    tmp_path: Path, retryable: bool
) -> None:
    database, activities = scheduler_fixture(tmp_path)
    activity_id = activities.enqueue(
        "run-1", activity_key="external:item", input_digest=DIGEST_A, actor_id="scheduler"
    )
    scheduler = Scheduler(activities, worker_id="worker")
    scheduler.register("external", FailingHandler(safely_retryable=retryable))
    with pytest.raises(RuntimeError, match="external failure"):
        scheduler.run_once()
    with database.session() as session:
        row = session.get(ActivityRow, activity_id)
        assert row is not None
        assert row.state == ("running" if retryable else "reconciliation_required")
