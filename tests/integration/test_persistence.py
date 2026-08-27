import json
from collections.abc import Generator
from pathlib import Path

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DatabaseError

from avo_correlate.adapters.persistence import Database
from avo_correlate.adapters.persistence.database import sqlite_foreign_keys_enabled
from avo_correlate.adapters.persistence.models import OutboxRow
from avo_correlate.application.run_service import RevisionConflictError, RunService
from avo_correlate.contracts.lifecycle import RunState
from tests.conftest import experiment_spec


@pytest.fixture
def database(tmp_path: Path) -> Generator[Database, None, None]:
    database = Database(tmp_path / "state.db")
    database.initialize()
    yield database
    database.dispose()


def test_create_and_transition_are_evented_atomically(database: Database) -> None:
    service = RunService(database)
    service.create_experiment(experiment_spec())
    run_id = service.create_run("experiment-1", actor_id="tester", run_id="run-1")
    run = service.transition(
        run_id,
        RunState.VALIDATING,
        actor_id="tester",
        expected_revision=1,
    )
    assert run.state == RunState.VALIDATING
    assert run.revision == 2
    events = service.list_events(run_id)
    assert [event.sequence for event in events] == [1, 2]
    assert [event.event_type for event in events] == ["run.created", "run.validating"]
    with database.session() as session:
        assert session.scalar(select(func.count()).select_from(OutboxRow)) == 2
        payload = json.loads(events[-1].payload_json)
        assert payload["from"] == "created"


def test_revision_conflict_is_visible(database: Database) -> None:
    service = RunService(database)
    service.create_experiment(experiment_spec())
    run_id = service.create_run("experiment-1", actor_id="tester")
    with pytest.raises(RevisionConflictError):
        service.transition(
            run_id,
            RunState.VALIDATING,
            actor_id="tester",
            expected_revision=99,
        )


def test_events_are_database_immutable(database: Database) -> None:
    service = RunService(database)
    service.create_experiment(experiment_spec())
    service.create_run("experiment-1", actor_id="tester", run_id="run-1")
    with pytest.raises(DatabaseError, match="events are immutable"), database.session() as session:
        session.execute(text("UPDATE events SET event_type='forged'"))
    with pytest.raises(DatabaseError, match="events are immutable"), database.session() as session:
        session.execute(text("DELETE FROM events"))


def test_sqlite_safety_pragmas_are_enabled(database: Database) -> None:
    assert sqlite_foreign_keys_enabled(database.engine)
    with database.engine.connect() as connection:
        assert connection.execute(text("PRAGMA journal_mode")).scalar_one().lower() == "wal"
        assert (
            connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
            == "0005_coding_agent_runtime"
        )
