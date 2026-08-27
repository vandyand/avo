from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from avo_correlate.adapters.persistence import Database
from avo_correlate.application.activity_service import ActivityConflictError, ActivityService
from avo_correlate.application.run_service import RunService
from avo_correlate.contracts.lifecycle import RunState
from tests.conftest import DIGEST_A, DIGEST_B, experiment_spec


@pytest.fixture
def services(tmp_path: Path) -> tuple[Database, RunService, ActivityService]:
    database = Database(tmp_path / "state.db")
    database.initialize()
    runs = RunService(database)
    runs.create_experiment(experiment_spec())
    runs.create_run("experiment-1", actor_id="tester", run_id="run-1", prepare=True)
    runs.transition("run-1", RunState.RUNNING, actor_id="tester")
    return database, runs, ActivityService(database)


def test_expired_lease_is_recovered(
    services: tuple[Database, RunService, ActivityService],
) -> None:
    database, runs, activities = services
    activity_id = activities.enqueue(
        "run-1",
        activity_key="evaluate:candidate-1",
        input_digest=DIGEST_A,
        actor_id="scheduler",
    )
    start = datetime(2026, 1, 1, tzinfo=UTC)
    first = activities.claim_next(worker_id="worker-1", lease_seconds=10, now=start)
    assert first is not None
    assert first.activity_id == activity_id
    assert first.attempt_count == 1
    recovered = activities.claim_next(
        worker_id="worker-2",
        lease_seconds=10,
        now=start + timedelta(seconds=11),
    )
    assert recovered is not None
    assert recovered.activity_id == activity_id
    assert recovered.attempt_count == 2
    activities.complete(
        activity_id,
        worker_id="worker-2",
        lease_epoch=recovered.lease_epoch,
        result_digest=DIGEST_B,
    )
    activities.complete(
        activity_id,
        worker_id="worker-2",
        lease_epoch=recovered.lease_epoch,
        result_digest=DIGEST_B,
    )
    assert activities.claim_next(worker_id="worker-3", lease_seconds=10) is None
    assert [event.event_type for event in runs.list_events("run-1")] == [
        "run.created",
        "run.validating",
        "run.ready",
        "run.running",
        "activity.queued",
        "activity.claimed",
        "activity.claimed",
        "activity.completed",
    ]
    database.dispose()


def test_wrong_worker_cannot_complete(
    services: tuple[Database, RunService, ActivityService],
) -> None:
    database, _, activities = services
    activity_id = activities.enqueue(
        "run-1", activity_key="a", input_digest=DIGEST_A, actor_id="scheduler"
    )
    claimed = activities.claim_next(worker_id="owner", lease_seconds=10)
    assert claimed is not None
    with pytest.raises(ActivityConflictError):
        activities.complete(
            activity_id,
            worker_id="intruder",
            lease_epoch=claimed.lease_epoch,
            result_digest=DIGEST_B,
        )
    database.dispose()


def test_same_activity_key_cannot_change_input(
    services: tuple[Database, RunService, ActivityService],
) -> None:
    database, _, activities = services
    activities.enqueue("run-1", activity_key="a", input_digest=DIGEST_A, actor_id="scheduler")
    with pytest.raises(ActivityConflictError):
        activities.enqueue("run-1", activity_key="a", input_digest=DIGEST_B, actor_id="scheduler")
    with pytest.raises(ActivityConflictError, match="lifecycle context"):
        activities.enqueue(
            "run-1",
            activity_key="a",
            input_digest=DIGEST_A,
            actor_id="scheduler",
            session_id="another-session",
        )
    database.dispose()


def test_activity_idempotency_and_reconciliation_fail_closed(
    services: tuple[Database, RunService, ActivityService],
) -> None:
    database, _, activities = services
    activity_id = activities.enqueue(
        "run-1", activity_key="external:one", input_digest=DIGEST_A, actor_id="scheduler"
    )
    assert (
        activities.enqueue(
            "run-1", activity_key="external:one", input_digest=DIGEST_A, actor_id="scheduler"
        )
        == activity_id
    )
    activities.mark_reconciliation_required(
        activity_id, actor_id="worker", error={"reason": "uncertain"}
    )
    with pytest.raises(ActivityConflictError, match="cannot reconcile"):
        activities.mark_reconciliation_required(
            activity_id, actor_id="worker", error={"reason": "again"}
        )
    with pytest.raises(ActivityConflictError, match="does not hold"):
        activities.complete(
            activity_id, worker_id="worker", lease_epoch=0, result_digest=DIGEST_B
        )
    database.dispose()


def test_activity_missing_identifiers_are_explicit(
    services: tuple[Database, RunService, ActivityService],
) -> None:
    database, _, activities = services
    with pytest.raises(LookupError, match="run not found"):
        activities.enqueue(
            "missing", activity_key="external:one", input_digest=DIGEST_A, actor_id="scheduler"
        )
    with pytest.raises(LookupError, match="activity not found"):
        activities.complete(
            "missing", worker_id="worker", lease_epoch=0, result_digest=DIGEST_B
        )
    with pytest.raises(LookupError, match="activity not found"):
        activities.mark_reconciliation_required(
            "missing", actor_id="worker", error={"reason": "unknown"}
        )
    database.dispose()
