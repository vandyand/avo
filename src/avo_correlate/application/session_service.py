"""Durable variation-session and private-attempt journal."""

from datetime import UTC, datetime

from sqlalchemy import func, select

from avo_correlate.adapters.persistence.database import Database
from avo_correlate.adapters.persistence.models import (
    AttemptRow,
    RunRow,
    VariationSessionRow,
)
from avo_correlate.contracts.lifecycle import RunState, VariationSessionState
from avo_correlate.contracts.variation import (
    VariationAttemptRecord,
    VariationSessionRequest,
    VariationSessionResult,
)
from avo_correlate.domain.canonical import canonical_digest
from avo_correlate.domain.lifecycle import require_transition


class SessionConflictError(RuntimeError):
    pass


class SessionService:
    def __init__(self, database: Database) -> None:
        self._database = database

    def enqueue(self, request: VariationSessionRequest) -> None:
        now = datetime.now(UTC)
        digest = canonical_digest(request)
        with self._database.session() as session:
            existing = session.get(VariationSessionRow, request.session_id)
            if existing is not None:
                if canonical_digest(request.model_validate_json(existing.request_json)) != digest:
                    raise SessionConflictError("session_id already has a different request")
                return
            run = session.get(RunRow, request.run_id)
            if run is None or run.champion_id != request.champion.candidate_id:
                raise SessionConflictError("session champion is stale or run is missing")
            next_number = int(
                session.scalar(
                    select(func.coalesce(func.max(VariationSessionRow.session_number), 0)).where(
                        VariationSessionRow.run_id == request.run_id
                    )
                )
                or 0
            ) + 1
            session.add(
                VariationSessionRow(
                    session_id=request.session_id,
                    run_id=request.run_id,
                    session_number=next_number,
                    state=VariationSessionState.QUEUED.value,
                    request_json=request.model_dump_json(),
                    result_json=None,
                    usage_json=None,
                    created_at=now,
                    updated_at=now,
                )
            )

    def start(self, session_id: str) -> None:
        now = datetime.now(UTC)
        with self._database.session() as session:
            row = session.get(VariationSessionRow, session_id)
            if row is None:
                raise SessionConflictError("session does not exist")
            if row.state == VariationSessionState.RUNNING.value:
                return
            run = session.get(RunRow, row.run_id)
            if run is None or run.state != RunState.RUNNING.value:
                raise SessionConflictError("run is not schedulable")
            other = session.scalar(
                select(VariationSessionRow).where(
                    VariationSessionRow.run_id == row.run_id,
                    VariationSessionRow.state == VariationSessionState.RUNNING.value,
                    VariationSessionRow.session_id != session_id,
                )
            )
            if other is not None:
                raise SessionConflictError("another variation session is running")
            require_transition(
                VariationSessionState(row.state), VariationSessionState.RUNNING
            )
            row.state = VariationSessionState.RUNNING.value
            row.updated_at = now

    def get_request(self, session_id: str) -> VariationSessionRequest:
        with self._database.session() as session:
            row = session.get(VariationSessionRow, session_id)
            if row is None:
                raise SessionConflictError("session does not exist")
            return VariationSessionRequest.model_validate_json(row.request_json)

    def get_state(self, session_id: str) -> VariationSessionState:
        with self._database.session() as session:
            row = session.get(VariationSessionRow, session_id)
            if row is None:
                raise SessionConflictError("session does not exist")
            return VariationSessionState(row.state)

    def get_result(self, session_id: str) -> VariationSessionResult | None:
        with self._database.session() as session:
            row = session.get(VariationSessionRow, session_id)
            if row is None:
                raise SessionConflictError("session does not exist")
            return (
                None
                if row.result_json is None
                else VariationSessionResult.model_validate_json(row.result_json)
            )

    def record_attempt(self, record: VariationAttemptRecord) -> int:
        digest = canonical_digest(record)
        with self._database.session() as session:
            row = session.get(VariationSessionRow, record.session_id)
            if row is None or row.state != VariationSessionState.RUNNING.value:
                raise SessionConflictError("attempt session is not running")
            existing = session.get(AttemptRow, record.attempt_id)
            if existing is not None:
                if existing.record_digest != digest:
                    raise SessionConflictError("attempt_id has conflicting evidence")
                return existing.attempt_number
            number = int(
                session.scalar(
                    select(func.coalesce(func.max(AttemptRow.attempt_number), 0)).where(
                        AttemptRow.session_id == record.session_id
                    )
                )
                or 0
            ) + 1
            session.add(
                AttemptRow(
                    attempt_id=record.attempt_id,
                    session_id=record.session_id,
                    attempt_number=number,
                    record_json=record.model_dump_json(),
                    record_digest=digest,
                    created_at=record.completed_at,
                )
            )
            return number

    def finish(self, result: VariationSessionResult) -> None:
        now = datetime.now(UTC)
        with self._database.session() as session:
            row = session.get(VariationSessionRow, result.session_id)
            if row is None:
                raise SessionConflictError("session does not exist")
            target = VariationSessionState(result.outcome)
            if row.result_json is not None:
                prior = VariationSessionResult.model_validate_json(row.result_json)
                if canonical_digest(prior) != canonical_digest(result):
                    raise SessionConflictError("session already has a different result")
                return
            require_transition(VariationSessionState(row.state), target)
            row.state = target.value
            row.result_json = result.model_dump_json()
            row.usage_json = result.usage.model_dump_json()
            row.updated_at = now
