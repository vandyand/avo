"""Durable external-activity journal with leases and idempotent completion."""

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from avo_correlate.adapters.persistence.database import Database
from avo_correlate.adapters.persistence.models import (
    ActivityRow,
    BudgetReservationRow,
    EventRow,
    OutboxRow,
    ReconciliationCaseRow,
    RunRow,
    VariationSessionRow,
)
from avo_correlate.contracts.lifecycle import RunState, VariationSessionState
from avo_correlate.contracts.runtime import ReconciliationCaseRecord
from avo_correlate.domain.canonical import canonical_digest
from avo_correlate.domain.lifecycle import require_transition


class ActivityConflictError(RuntimeError):
    pass


class ActivityService:
    def __init__(self, database: Database) -> None:
        self._database = database

    def enqueue(
        self,
        run_id: str,
        *,
        activity_key: str,
        input_digest: str,
        actor_id: str,
        session_id: str | None = None,
        budget_reservation_id: str | None = None,
    ) -> str:
        now = datetime.now(UTC)
        with self._database.session() as session:
            existing = session.scalar(
                select(ActivityRow).where(
                    ActivityRow.run_id == run_id,
                    ActivityRow.activity_key == activity_key,
                )
            )
            if existing:
                if existing.input_digest != input_digest:
                    raise ActivityConflictError("activity_key has a different input digest")
                if (
                    existing.session_id != session_id
                    or existing.budget_reservation_id != budget_reservation_id
                ):
                    raise ActivityConflictError("activity_key has different lifecycle context")
                return existing.activity_id
            run = session.get(RunRow, run_id)
            if run is None:
                raise LookupError(f"run not found: {run_id}")
            activity_id = str(uuid4())
            session.add(
                ActivityRow(
                    activity_id=activity_id,
                    run_id=run_id,
                    session_id=session_id,
                    budget_reservation_id=budget_reservation_id,
                    activity_key=activity_key,
                    state="queued",
                    attempt_count=0,
                    input_digest=input_digest,
                    created_at=now,
                    updated_at=now,
                )
            )
            self._append_event(
                session,
                run,
                "activity.queued",
                actor_id,
                {"activity_id": activity_id, "activity_key": activity_key},
                now,
            )
            return activity_id

    def claim_next(
        self,
        *,
        worker_id: str,
        lease_seconds: int,
        now: datetime | None = None,
    ) -> ActivityRow | None:
        claimed_at = now or datetime.now(UTC)
        expires_at = claimed_at + timedelta(seconds=lease_seconds)
        with self._database.session() as session:
            eligible = or_(
                ActivityRow.state == "queued",
                (
                    (ActivityRow.state == "running")
                    & (ActivityRow.lease_expires_at < claimed_at)
                    & (ActivityRow.result_digest.is_(None))
                ),
            )
            activity_id = session.scalar(
                select(ActivityRow.activity_id)
                .join(RunRow, RunRow.run_id == ActivityRow.run_id)
                .where(
                    eligible,
                    RunRow.state == "running",
                )
                .order_by(ActivityRow.created_at, ActivityRow.activity_id)
                .limit(1)
            )
            if activity_id is None:
                return None
            activity = session.scalar(
                update(ActivityRow)
                .where(ActivityRow.activity_id == activity_id, eligible)
                .values(
                    state="running",
                    attempt_count=ActivityRow.attempt_count + 1,
                    lease_epoch=ActivityRow.lease_epoch + 1,
                    lease_owner=worker_id,
                    lease_expires_at=expires_at,
                    updated_at=claimed_at,
                )
                .returning(ActivityRow)
            )
            if activity is None:
                return None
            run = session.get(RunRow, activity.run_id)
            if run is None:
                raise LookupError(f"run not found: {activity.run_id}")
            self._append_event(
                session,
                run,
                "activity.claimed",
                worker_id,
                {
                    "activity_id": activity.activity_id,
                    "attempt_count": activity.attempt_count,
                    "lease_epoch": activity.lease_epoch,
                },
                claimed_at,
            )
            session.flush()
            session.expunge(activity)
            return activity

    def complete(
        self,
        activity_id: str,
        *,
        worker_id: str,
        lease_epoch: int,
        result_digest: str,
    ) -> None:
        now = datetime.now(UTC)
        with self._database.session() as session:
            activity = session.get(ActivityRow, activity_id)
            if activity is None:
                raise LookupError(f"activity not found: {activity_id}")
            if activity.state == "completed":
                if activity.result_digest != result_digest:
                    raise ActivityConflictError("activity completed with another result")
                return
            if (
                activity.state != "running"
                or activity.lease_owner != worker_id
                or activity.lease_epoch != lease_epoch
            ):
                raise ActivityConflictError("worker does not hold the activity lease")
            run = session.get(RunRow, activity.run_id)
            if run is None:
                raise LookupError(f"run not found: {activity.run_id}")
            activity.state = "completed"
            activity.result_digest = result_digest
            activity.lease_owner = None
            activity.lease_expires_at = None
            activity.updated_at = now
            self._append_event(
                session,
                run,
                "activity.completed",
                worker_id,
                {
                    "activity_id": activity_id,
                    "result_digest": result_digest,
                    "lease_epoch": lease_epoch,
                },
                now,
            )

    def heartbeat(
        self,
        activity_id: str,
        *,
        worker_id: str,
        lease_epoch: int,
        lease_seconds: int,
        now: datetime | None = None,
    ) -> datetime:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        heartbeat_at = now or datetime.now(UTC)
        expires_at = heartbeat_at + timedelta(seconds=lease_seconds)
        with self._database.session() as session:
            activity = session.get(ActivityRow, activity_id)
            if activity is None:
                raise LookupError(f"activity not found: {activity_id}")
            if (
                activity.state != "running"
                or activity.lease_owner != worker_id
                or activity.lease_epoch != lease_epoch
                or (
                    activity.lease_expires_at is not None
                    and activity.lease_expires_at < heartbeat_at
                )
            ):
                raise ActivityConflictError("worker does not hold a live activity lease")
            activity.lease_expires_at = expires_at
            activity.updated_at = heartbeat_at
        return expires_at

    def mark_reconciliation_required(
        self,
        activity_id: str,
        *,
        actor_id: str,
        error: dict[str, object],
        lease_epoch: int | None = None,
    ) -> None:
        now = datetime.now(UTC)
        with self._database.session() as session:
            activity = session.get(ActivityRow, activity_id)
            if activity is None:
                raise LookupError(f"activity not found: {activity_id}")
            if activity.state not in {"running", "queued"}:
                raise ActivityConflictError(f"cannot reconcile activity in {activity.state}")
            if lease_epoch is not None and activity.lease_epoch != lease_epoch:
                raise ActivityConflictError("stale activity lease epoch")
            run = session.get(RunRow, activity.run_id)
            if run is None:
                raise LookupError(f"run not found: {activity.run_id}")
            activity.state = "reconciliation_required"
            activity.error_json = json.dumps(error, sort_keys=True, separators=(",", ":"))
            activity.lease_owner = None
            activity.lease_expires_at = None
            activity.updated_at = now
            if run.state != RunState.BLOCKED_RECONCILIATION.value:
                require_transition(RunState(run.state), RunState.BLOCKED_RECONCILIATION)
                run.state = RunState.BLOCKED_RECONCILIATION.value
            reconciliation = ReconciliationCaseRecord(
                reconciliation_id=str(uuid4()),
                run_id=run.run_id,
                activity_id=activity_id,
                reason=str(error.get("reason", "uncertain_external_state")),
                session_id=activity.session_id,
                budget_reservation_id=activity.budget_reservation_id,
                state="open",
                opened_at=now,
            )
            session.add(
                ReconciliationCaseRow(
                    reconciliation_id=reconciliation.reconciliation_id,
                    run_id=run.run_id,
                    activity_id=activity_id,
                    session_id=activity.session_id,
                    state="open",
                    record_digest=canonical_digest(reconciliation),
                    record_json=reconciliation.model_dump_json(),
                    created_at=now,
                    updated_at=now,
                )
            )
            if activity.session_id is not None:
                variation = session.get(VariationSessionRow, activity.session_id)
                if (
                    variation is not None
                    and variation.state == VariationSessionState.RUNNING.value
                ):
                    variation.state = VariationSessionState.RECONCILIATION_REQUIRED.value
                    variation.updated_at = now
            if activity.budget_reservation_id is not None:
                reservation = session.get(
                    BudgetReservationRow, activity.budget_reservation_id
                )
                if reservation is not None and reservation.state == "reserved":
                    reservation.state = "held"
            self._append_event(
                session,
                run,
                "activity.reconciliation_required",
                actor_id,
                {"activity_id": activity_id},
                now,
            )

    @staticmethod
    def _append_event(
        session: Session,
        run: RunRow,
        event_type: str,
        actor_id: str,
        payload: dict[str, object],
        now: datetime,
    ) -> None:
        event_id = str(uuid4())
        run.revision += 1
        run.event_sequence += 1
        run.updated_at = now
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        event = EventRow(
            event_id=event_id,
            run_id=run.run_id,
            sequence=run.event_sequence,
            event_type=event_type,
            actor_id=actor_id,
            payload_json=payload_json,
            created_at=now,
        )
        session.add(event)
        session.flush()
        session.add(
            OutboxRow(
                outbox_id=str(uuid4()),
                event_id=event_id,
                topic="run.events",
                payload_json=payload_json,
                created_at=now,
            )
        )
