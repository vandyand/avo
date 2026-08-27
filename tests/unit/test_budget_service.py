from collections.abc import Generator
from pathlib import Path

import pytest

from avo_correlate.adapters.persistence import Database
from avo_correlate.adapters.persistence.models import BudgetLedgerRow
from avo_correlate.application.budget_service import BudgetService, ReservationConflictError
from avo_correlate.application.run_service import RunService
from avo_correlate.contracts.budgets import UsageRecord
from avo_correlate.domain.budgets import BudgetExceededError, reconcile_usage
from tests.conftest import experiment_spec


def usage(*, tool_calls: int = 0, cost: int = 0) -> UsageRecord:
    value = UsageRecord.zero().model_copy(
        update={"tool_calls": tool_calls, "model_cost_microusd": cost}
    )
    return UsageRecord.model_validate(value)


@pytest.fixture
def services(
    tmp_path: Path,
) -> Generator[tuple[Database, RunService, BudgetService], None, None]:
    database = Database(tmp_path / "state.db")
    database.initialize()
    runs = RunService(database)
    runs.create_experiment(experiment_spec())
    runs.create_run("experiment-1", actor_id="tester", run_id="run-1")
    yield database, runs, BudgetService(database)
    database.dispose()


def test_reservation_and_completion_are_idempotent(
    services: tuple[Database, RunService, BudgetService],
) -> None:
    database, runs, budgets = services
    reservation_id = budgets.reserve(
        "run-1", activity_key="tool:1", estimated=usage(tool_calls=2), actor_id="worker"
    )
    assert (
        budgets.reserve(
            "run-1", activity_key="tool:1", estimated=usage(tool_calls=2), actor_id="worker"
        )
        == reservation_id
    )
    budgets.complete(reservation_id, actual=usage(tool_calls=1), actor_id="worker")
    budgets.complete(reservation_id, actual=usage(tool_calls=1), actor_id="worker")
    with database.session() as session:
        ledger = session.get(BudgetLedgerRow, "run-1")
        assert ledger is not None
        assert UsageRecord.model_validate_json(ledger.used_json).tool_calls == 1
        assert UsageRecord.model_validate_json(ledger.reserved_json).tool_calls == 0
    assert [event.event_type for event in runs.list_events("run-1")] == [
        "run.created",
        "budget.reserved",
        "budget.completed",
    ]


def test_same_activity_cannot_change_estimate(
    services: tuple[Database, RunService, BudgetService],
) -> None:
    _, _, budgets = services
    budgets.reserve(
        "run-1", activity_key="tool:1", estimated=usage(tool_calls=1), actor_id="worker"
    )
    with pytest.raises(ReservationConflictError):
        budgets.reserve(
            "run-1", activity_key="tool:1", estimated=usage(tool_calls=2), actor_id="worker"
        )


def test_reservation_prevents_overshoot(
    services: tuple[Database, RunService, BudgetService],
) -> None:
    _, _, budgets = services
    with pytest.raises(BudgetExceededError, match="tool_calls"):
        budgets.reserve(
            "run-1", activity_key="too-large", estimated=usage(tool_calls=101), actor_id="worker"
        )


def test_reconciliation_holds_observed_usage_then_releases_reservation(
    services: tuple[Database, RunService, BudgetService],
) -> None:
    database, runs, budgets = services
    reservation_id = budgets.reserve(
        "run-1", activity_key="agent:1", estimated=usage(tool_calls=5), actor_id="worker"
    )
    budgets.observe(
        reservation_id, cumulative_actual=usage(tool_calls=2), actor_id="worker"
    )
    budgets.hold_for_reconciliation(reservation_id, actor_id="worker")
    budgets.release(reservation_id, actor_id="operator")
    with database.session() as session:
        ledger = session.get(BudgetLedgerRow, "run-1")
        assert ledger is not None
        assert UsageRecord.model_validate_json(ledger.used_json).tool_calls == 0
        assert UsageRecord.model_validate_json(ledger.reserved_json).tool_calls == 0
    assert [event.event_type for event in runs.list_events("run-1")][-4:] == [
        "budget.reserved",
        "budget.observed",
        "budget.held",
        "budget.released",
    ]


def test_observed_usage_is_monotonic_and_bounded(
    services: tuple[Database, RunService, BudgetService],
) -> None:
    _, _, budgets = services
    reservation_id = budgets.reserve(
        "run-1", activity_key="agent:1", estimated=usage(tool_calls=3), actor_id="worker"
    )
    budgets.observe(
        reservation_id, cumulative_actual=usage(tool_calls=2), actor_id="worker"
    )
    with pytest.raises(ReservationConflictError, match="monotonic"):
        budgets.observe(
            reservation_id, cumulative_actual=usage(tool_calls=1), actor_id="worker"
        )
    with pytest.raises(BudgetExceededError, match="reserved estimate"):
        budgets.observe(
            reservation_id, cumulative_actual=usage(tool_calls=4), actor_id="worker"
        )


def test_usage_reconciliation_rejects_reservation_underflow() -> None:
    with pytest.raises(ValueError, match="reservation underflow"):
        reconcile_usage(
            used=UsageRecord.zero(),
            already_reserved=UsageRecord.zero(),
            estimated=usage(tool_calls=1),
            actual=UsageRecord.zero(),
        )
