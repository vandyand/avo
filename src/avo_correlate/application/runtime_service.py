"""Durable coding-agent invocation and operator reconciliation service."""

import json
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from avo_correlate.adapters.persistence.database import Database
from avo_correlate.adapters.persistence.models import (
    ActivityRow,
    BudgetLedgerRow,
    BudgetReservationRow,
    EventRow,
    HarnessInvocationRow,
    OutboxRow,
    ReconciliationCaseRow,
    RunRow,
    VariationSessionRow,
)
from avo_correlate.contracts.budgets import UsageRecord
from avo_correlate.contracts.lifecycle import RunState, VariationSessionState
from avo_correlate.contracts.runtime import (
    HarnessInvocationRecord,
    ReconciliationCaseRecord,
)
from avo_correlate.domain.budgets import reconcile_usage
from avo_correlate.domain.canonical import canonical_digest
from avo_correlate.domain.lifecycle import require_transition


class RuntimeConflictError(RuntimeError):
    pass


class RuntimeService:
    def __init__(self, database: Database) -> None:
        self._database = database

    def record_invocation(self, record: HarnessInvocationRecord) -> None:
        digest = canonical_digest(record)
        now = datetime.now(UTC)
        with self._database.session() as session:
            activity = session.get(ActivityRow, record.activity_id)
            if activity is None or activity.run_id != record.run_id:
                raise RuntimeConflictError(
                    "invocation activity is missing or belongs to another run"
                )
            existing = session.get(HarnessInvocationRow, record.invocation_id)
            if existing is not None:
                if existing.record_digest != digest:
                    raise RuntimeConflictError("invocation_id has conflicting evidence")
                return
            session.add(
                HarnessInvocationRow(
                    invocation_id=record.invocation_id,
                    run_id=record.run_id,
                    activity_id=record.activity_id,
                    session_id=record.session_id,
                    state=record.state,
                    record_digest=digest,
                    record_json=record.model_dump_json(),
                    created_at=now,
                    updated_at=now,
                )
            )

    def replace_invocation(self, record: HarnessInvocationRecord) -> None:
        """Advance a mutable invocation envelope while every event remains artifact-backed."""
        with self._database.session() as session:
            row = session.get(HarnessInvocationRow, record.invocation_id)
            if row is None:
                raise LookupError(f"invocation not found: {record.invocation_id}")
            if row.run_id != record.run_id or row.activity_id != record.activity_id:
                raise RuntimeConflictError("invocation identity fields cannot change")
            prior = HarnessInvocationRecord.model_validate_json(row.record_json)
            allowed: dict[str, set[str]] = {
                "started": {"running", "completed", "failed", "reconciliation_required"},
                "running": {"completed", "failed", "reconciliation_required"},
                "completed": set(),
                "failed": set(),
                "reconciliation_required": set(),
            }
            if record.state != prior.state and record.state not in allowed[prior.state]:
                raise RuntimeConflictError(
                    f"invalid invocation transition {prior.state}->{record.state}"
                )
            row.state = record.state
            row.record_json = record.model_dump_json()
            row.record_digest = canonical_digest(record)
            row.updated_at = datetime.now(UTC)

    def get_invocation(self, invocation_id: str) -> HarnessInvocationRecord:
        with self._database.session() as session:
            row = session.get(HarnessInvocationRow, invocation_id)
            if row is None:
                raise LookupError(f"invocation not found: {invocation_id}")
            return HarnessInvocationRecord.model_validate_json(row.record_json)

    def find_activity_invocation(
        self, activity_id: str
    ) -> HarnessInvocationRecord | None:
        with self._database.session() as session:
            row = session.scalar(
                select(HarnessInvocationRow).where(
                    HarnessInvocationRow.activity_id == activity_id
                )
            )
            if row is None:
                return None
            return HarnessInvocationRecord.model_validate_json(row.record_json)

    def open_reconciliation(
        self,
        *,
        run_id: str,
        activity_id: str,
        reason: str,
        actor_id: str,
        session_id: str | None = None,
        evidence_digests: list[str] | None = None,
        budget_reservation_id: str | None = None,
    ) -> ReconciliationCaseRecord:
        now = datetime.now(UTC)
        with self._database.session() as session:
            existing = session.scalar(
                select(ReconciliationCaseRow).where(
                    ReconciliationCaseRow.activity_id == activity_id,
                    ReconciliationCaseRow.state == "open",
                )
            )
            if existing is not None:
                return ReconciliationCaseRecord.model_validate_json(existing.record_json)
            activity = session.get(ActivityRow, activity_id)
            run = session.get(RunRow, run_id)
            if activity is None or activity.run_id != run_id or run is None:
                raise RuntimeConflictError("reconciliation target is missing")
            if activity.session_id is not None and activity.session_id != session_id:
                raise RuntimeConflictError("activity belongs to another session")
            effective_session_id = session_id or activity.session_id
            effective_reservation_id = (
                budget_reservation_id or activity.budget_reservation_id
            )
            if activity.state in {"queued", "running"}:
                activity.state = "reconciliation_required"
                activity.lease_owner = None
                activity.lease_expires_at = None
                activity.updated_at = now
            if run.state != RunState.BLOCKED_RECONCILIATION.value:
                require_transition(RunState(run.state), RunState.BLOCKED_RECONCILIATION)
                run.state = RunState.BLOCKED_RECONCILIATION.value
            if effective_session_id is not None:
                variation = session.get(VariationSessionRow, effective_session_id)
                if variation is None or variation.run_id != run_id:
                    raise RuntimeConflictError("reconciliation session is missing")
                if variation.state != VariationSessionState.RECONCILIATION_REQUIRED.value:
                    require_transition(
                        VariationSessionState(variation.state),
                        VariationSessionState.RECONCILIATION_REQUIRED,
                    )
                    variation.state = VariationSessionState.RECONCILIATION_REQUIRED.value
                    variation.updated_at = now
            if effective_reservation_id is not None:
                reservation = session.get(
                    BudgetReservationRow, effective_reservation_id
                )
                if reservation is None or reservation.run_id != run_id:
                    raise RuntimeConflictError("reconciliation budget reservation is missing")
                if reservation.state == "reserved":
                    reservation.state = "held"
                elif reservation.state != "held":
                    raise RuntimeConflictError("budget reservation is not active")
            record = ReconciliationCaseRecord(
                reconciliation_id=str(uuid4()),
                run_id=run_id,
                activity_id=activity_id,
                session_id=effective_session_id,
                reason=reason,
                evidence_digests=evidence_digests or [],
                budget_reservation_id=effective_reservation_id,
                state="open",
                opened_at=now,
            )
            session.add(
                ReconciliationCaseRow(
                    reconciliation_id=record.reconciliation_id,
                    run_id=run_id,
                    activity_id=activity_id,
                    session_id=effective_session_id,
                    state=record.state,
                    record_digest=canonical_digest(record),
                    record_json=record.model_dump_json(),
                    created_at=now,
                    updated_at=now,
                )
            )
            self._append_event(
                session,
                run,
                "reconciliation.opened",
                actor_id,
                {"reconciliation_id": record.reconciliation_id, "activity_id": activity_id},
                now,
            )
            return record

    def resolve_reconciliation(
        self,
        reconciliation_id: str,
        *,
        resolution: str,
        note: str,
        actor_id: str,
        result_digest: str | None = None,
    ) -> ReconciliationCaseRecord:
        if resolution not in {"retry", "accept_result", "cancel", "fail"}:
            raise ValueError("unknown reconciliation resolution")
        now = datetime.now(UTC)
        with self._database.session() as session:
            row = session.get(ReconciliationCaseRow, reconciliation_id)
            if row is None:
                raise LookupError(f"reconciliation not found: {reconciliation_id}")
            prior = ReconciliationCaseRecord.model_validate_json(row.record_json)
            if prior.state == "resolved":
                if prior.resolution != resolution:
                    raise RuntimeConflictError("reconciliation already resolved differently")
                return prior
            activity = session.get(ActivityRow, prior.activity_id)
            run = session.get(RunRow, prior.run_id)
            if activity is None or run is None:
                raise RuntimeConflictError("reconciliation target disappeared")
            if resolution == "retry":
                activity.state = "queued"
                run_target = RunState.RUNNING
                session_target = VariationSessionState.RUNNING
            elif resolution == "accept_result":
                if result_digest is None:
                    raise ValueError("accept_result requires result_digest")
                activity.state = "completed"
                activity.result_digest = result_digest
                run_target = RunState.RUNNING
                session_target = VariationSessionState.RUNNING
            elif resolution == "cancel":
                activity.state = "cancelled"
                run_target = RunState.CANCELLED
                session_target = VariationSessionState.CANCELLED
            else:
                activity.state = "failed"
                run_target = RunState.FAILED
                session_target = VariationSessionState.FAILED
            activity.error_json = None
            activity.updated_at = now
            require_transition(RunState(run.state), run_target)
            run.state = run_target.value
            if prior.session_id is not None:
                variation = session.get(VariationSessionRow, prior.session_id)
                if variation is None:
                    raise RuntimeConflictError("reconciliation session disappeared")
                require_transition(VariationSessionState(variation.state), session_target)
                variation.state = session_target.value
                variation.updated_at = now
            if prior.budget_reservation_id is not None:
                reservation = session.get(
                    BudgetReservationRow, prior.budget_reservation_id
                )
                if reservation is None:
                    raise RuntimeConflictError("reconciliation budget disappeared")
                if resolution == "retry":
                    reservation.state = "reserved"
                elif resolution in {"cancel", "fail"}:
                    ledger = session.get(BudgetLedgerRow, prior.run_id)
                    if ledger is None:
                        raise RuntimeConflictError("reconciliation budget ledger disappeared")
                    _, remaining = reconcile_usage(
                        used=UsageRecord.model_validate_json(ledger.used_json),
                        already_reserved=UsageRecord.model_validate_json(
                            ledger.reserved_json
                        ),
                        estimated=UsageRecord.model_validate_json(
                            reservation.estimated_json
                        ),
                        actual=UsageRecord.zero(),
                    )
                    ledger.reserved_json = remaining.model_dump_json()
                    ledger.revision += 1
                    reservation.state = "released"
                    reservation.reconciled_at = now
            record = prior.model_copy(
                update={
                    "state": "resolved",
                    "resolution": resolution,
                    "resolution_note": note,
                    "resolved_at": now,
                }
            )
            row.state = "resolved"
            row.record_json = record.model_dump_json()
            row.record_digest = canonical_digest(record)
            row.updated_at = now
            self._append_event(
                session,
                run,
                "reconciliation.resolved",
                actor_id,
                {"reconciliation_id": reconciliation_id, "resolution": resolution},
                now,
            )
            return record

    @staticmethod
    def _append_event(
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
        session.add(
            EventRow(
                event_id=event_id,
                run_id=run.run_id,
                sequence=run.event_sequence,
                event_type=event_type,
                actor_id=actor_id,
                payload_json=payload_json,
                created_at=now,
            )
        )
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
