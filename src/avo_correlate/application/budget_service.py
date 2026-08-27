"""Transactional budget reservation and reconciliation."""

import json
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy.orm import Session

from avo_correlate.adapters.persistence.database import Database
from avo_correlate.adapters.persistence.models import (
    BudgetLedgerRow,
    BudgetReservationRow,
    EventRow,
    OutboxRow,
    RunRow,
)
from avo_correlate.contracts.budgets import BudgetSpec, UsageRecord
from avo_correlate.domain.budgets import BudgetExceededError, reconcile_usage, reserve_usage


class ReservationConflictError(RuntimeError):
    pass


class BudgetService:
    def __init__(self, database: Database) -> None:
        self._database = database

    def reserve(
        self,
        run_id: str,
        *,
        activity_key: str,
        estimated: UsageRecord,
        actor_id: str,
    ) -> str:
        now = datetime.now(UTC)
        with self._database.session() as session:
            existing = session.query(BudgetReservationRow).filter_by(
                run_id=run_id, activity_key=activity_key
            ).one_or_none()
            if existing:
                prior = UsageRecord.model_validate_json(existing.estimated_json)
                if prior != estimated:
                    raise ReservationConflictError(
                        "activity_key already has a different estimate"
                    )
                return existing.reservation_id
            ledger = session.get(BudgetLedgerRow, run_id)
            run = session.get(RunRow, run_id)
            if ledger is None or run is None:
                raise LookupError(f"run not found: {run_id}")
            limit = BudgetSpec.model_validate_json(ledger.limit_json)
            used = UsageRecord.model_validate_json(ledger.used_json)
            reserved = UsageRecord.model_validate_json(ledger.reserved_json)
            new_reserved = reserve_usage(
                limit=limit,
                used=used,
                already_reserved=reserved,
                requested=estimated,
            )
            reservation_id = str(uuid4())
            session.add(
                BudgetReservationRow(
                    reservation_id=reservation_id,
                    run_id=run_id,
                    activity_key=activity_key,
                    state="reserved",
                    estimated_json=estimated.model_dump_json(),
                    created_at=now,
                )
            )
            ledger.reserved_json = new_reserved.model_dump_json()
            ledger.revision += 1
            self._append_run_event(
                session,
                run,
                "budget.reserved",
                actor_id,
                {"reservation_id": reservation_id, "activity_key": activity_key},
                now,
            )
            return reservation_id

    def complete(
        self,
        reservation_id: str,
        *,
        actual: UsageRecord,
        actor_id: str,
    ) -> None:
        now = datetime.now(UTC)
        with self._database.session() as session:
            reservation = session.get(BudgetReservationRow, reservation_id)
            if reservation is None:
                raise LookupError(f"reservation not found: {reservation_id}")
            if reservation.state == "completed":
                prior_actual = UsageRecord.model_validate_json(reservation.actual_json or "{}")
                if prior_actual != actual:
                    raise ReservationConflictError(
                        "completed reservation has different actual usage"
                    )
                return
            if reservation.state not in {"reserved", "held"}:
                raise ReservationConflictError(
                    f"cannot complete reservation in state {reservation.state}"
                )
            ledger = session.get(BudgetLedgerRow, reservation.run_id)
            run = session.get(RunRow, reservation.run_id)
            if ledger is None or run is None:
                raise LookupError(f"run not found: {reservation.run_id}")
            estimated = UsageRecord.model_validate_json(reservation.estimated_json)
            used, reserved = reconcile_usage(
                used=UsageRecord.model_validate_json(ledger.used_json),
                already_reserved=UsageRecord.model_validate_json(ledger.reserved_json),
                estimated=estimated,
                actual=actual,
            )
            limit = BudgetSpec.model_validate_json(ledger.limit_json)
            if not used.plus(reserved).fits_within(limit):
                raise BudgetExceededError("actual usage exceeds the run budget")
            ledger.used_json = used.model_dump_json()
            ledger.reserved_json = reserved.model_dump_json()
            ledger.revision += 1
            reservation.state = "completed"
            reservation.actual_json = actual.model_dump_json()
            reservation.reconciled_at = now
            self._append_run_event(
                session,
                run,
                "budget.completed",
                actor_id,
                {"reservation_id": reservation_id},
                now,
            )

    def observe(
        self,
        reservation_id: str,
        *,
        cumulative_actual: UsageRecord,
        actor_id: str,
    ) -> None:
        """Persist monotonic in-flight usage without releasing the reservation."""
        now = datetime.now(UTC)
        with self._database.session() as session:
            reservation = session.get(BudgetReservationRow, reservation_id)
            if reservation is None:
                raise LookupError(f"reservation not found: {reservation_id}")
            if reservation.state not in {"reserved", "held"}:
                raise ReservationConflictError(
                    "usage can only be observed on an active reservation"
                )
            prior = (
                UsageRecord.zero()
                if reservation.actual_json is None
                else UsageRecord.model_validate_json(reservation.actual_json)
            )
            if not cumulative_actual.plus(UsageRecord.zero()).fits_within(
                UsageRecord.model_validate_json(reservation.estimated_json)
            ):
                raise BudgetExceededError("observed usage exceeds the reserved estimate")
            for field in BudgetSpec.model_fields:
                if field != "schema_version" and getattr(cumulative_actual, field) < getattr(
                    prior, field
                ):
                    raise ReservationConflictError("observed usage must be monotonic")
            reservation.actual_json = cumulative_actual.model_dump_json()
            run = session.get(RunRow, reservation.run_id)
            if run is None:
                raise LookupError(f"run not found: {reservation.run_id}")
            self._append_run_event(
                session,
                run,
                "budget.observed",
                actor_id,
                {"reservation_id": reservation_id},
                now,
            )

    def hold_for_reconciliation(self, reservation_id: str, *, actor_id: str) -> None:
        now = datetime.now(UTC)
        with self._database.session() as session:
            reservation = session.get(BudgetReservationRow, reservation_id)
            if reservation is None:
                raise LookupError(f"reservation not found: {reservation_id}")
            if reservation.state == "held":
                return
            if reservation.state != "reserved":
                raise ReservationConflictError("only reserved usage can be held")
            reservation.state = "held"
            run = session.get(RunRow, reservation.run_id)
            if run is None:
                raise LookupError(f"run not found: {reservation.run_id}")
            self._append_run_event(
                session,
                run,
                "budget.held",
                actor_id,
                {"reservation_id": reservation_id},
                now,
            )

    def release(self, reservation_id: str, *, actor_id: str) -> None:
        now = datetime.now(UTC)
        with self._database.session() as session:
            reservation = session.get(BudgetReservationRow, reservation_id)
            if reservation is None:
                raise LookupError(f"reservation not found: {reservation_id}")
            if reservation.state == "released":
                return
            if reservation.state not in {"reserved", "held"}:
                raise ReservationConflictError("only active usage can be released")
            ledger = session.get(BudgetLedgerRow, reservation.run_id)
            run = session.get(RunRow, reservation.run_id)
            if ledger is None or run is None:
                raise LookupError(f"run not found: {reservation.run_id}")
            _, remaining = reconcile_usage(
                used=UsageRecord.model_validate_json(ledger.used_json),
                already_reserved=UsageRecord.model_validate_json(ledger.reserved_json),
                estimated=UsageRecord.model_validate_json(reservation.estimated_json),
                actual=UsageRecord.zero(),
            )
            ledger.reserved_json = remaining.model_dump_json()
            ledger.revision += 1
            reservation.state = "released"
            reservation.reconciled_at = now
            self._append_run_event(
                session,
                run,
                "budget.released",
                actor_id,
                {"reservation_id": reservation_id},
                now,
            )

    @staticmethod
    def _append_run_event(
        session: Session,
        run: RunRow,
        event_type: str,
        actor_id: str,
        payload: dict[str, str],
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
