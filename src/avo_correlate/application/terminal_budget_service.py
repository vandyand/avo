"""Atomic settlement for durable variation results that exhaust a run budget."""

import json
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, uuid4, uuid5

from sqlalchemy import select
from sqlalchemy.orm import Session

from avo_correlate.adapters.persistence.database import Database
from avo_correlate.adapters.persistence.models import (
    ActivityRow,
    BudgetLedgerRow,
    BudgetReservationRow,
    CandidateRow,
    EventRow,
    OutboxRow,
    PolicyDecisionRow,
    ReconciliationCaseRow,
    RunRow,
)
from avo_correlate.contracts.base import Sha256Digest
from avo_correlate.contracts.budgets import BudgetSpec, UsageRecord
from avo_correlate.contracts.lifecycle import CandidateState, RunState
from avo_correlate.contracts.policy import PolicyDecision
from avo_correlate.contracts.runtime import ReconciliationCaseRecord
from avo_correlate.domain.budgets import reconcile_usage
from avo_correlate.domain.canonical import canonical_digest
from avo_correlate.domain.lifecycle import require_transition


class TerminalBudgetConflictError(RuntimeError):
    """The durable result cannot be settled without contradicting recorded state."""


class TerminalBudgetService:
    """Commit every terminal consequence of post-result budget exhaustion together."""

    def __init__(self, database: Database) -> None:
        self._database = database

    def settle_exhausted_variation(
        self,
        *,
        run_id: str,
        activity_id: str,
        reservation_id: str,
        result_digest: Sha256Digest,
        actual: UsageRecord,
        required_evaluation: UsageRecord,
        policy_bundle_digest: Sha256Digest,
        actor_id: str,
        lease_epoch: int | None = None,
    ) -> None:
        """Persist an over-budget durable result and terminate its run atomically."""
        now = datetime.now(UTC)
        with self._database.session() as session:
            run = session.get(RunRow, run_id)
            activity = session.get(ActivityRow, activity_id)
            reservation = session.get(BudgetReservationRow, reservation_id)
            ledger = session.get(BudgetLedgerRow, run_id)
            if run is None or activity is None or reservation is None or ledger is None:
                raise LookupError("terminal budget settlement context is incomplete")
            if activity.run_id != run_id or reservation.run_id != run_id:
                raise TerminalBudgetConflictError("terminal budget context crosses run boundaries")
            if activity.budget_reservation_id != reservation_id:
                raise TerminalBudgetConflictError("activity has a different budget reservation")
            if activity.state == "running" and (
                lease_epoch is not None and activity.lease_epoch != lease_epoch
            ):
                raise TerminalBudgetConflictError("stale activity lease epoch")
            if activity.state not in {"running", "reconciliation_required", "completed"}:
                raise TerminalBudgetConflictError(
                    f"cannot terminally settle activity in state {activity.state}"
                )
            if activity.state == "completed" and activity.result_digest != result_digest:
                raise TerminalBudgetConflictError("activity completed with another result")

            open_reconciliations = list(
                session.scalars(
                    select(ReconciliationCaseRow).where(
                        ReconciliationCaseRow.run_id == run_id,
                        ReconciliationCaseRow.activity_id == activity_id,
                        ReconciliationCaseRow.state == "open",
                    )
                )
            )
            if reservation.state == "exceeded":
                prior_actual = UsageRecord.model_validate_json(reservation.actual_json or "{}")
                if prior_actual != actual:
                    raise TerminalBudgetConflictError(
                        "exceeded reservation has different actual usage"
                    )
                if run.state != RunState.FAILED.value or activity.state != "completed":
                    raise TerminalBudgetConflictError("terminal budget settlement is incomplete")
                if not open_reconciliations:
                    return
                for row in open_reconciliations:
                    self._resolve_reconciliation(row, now)
                self._append_event(
                    session,
                    run,
                    "reconciliation.resolved",
                    actor_id,
                    {"activity_id": activity_id, "resolution": "fail"},
                    now,
                )
                return
            if reservation.state not in {"reserved", "held"}:
                raise TerminalBudgetConflictError(
                    f"cannot terminally settle reservation in state {reservation.state}"
                )

            used = UsageRecord.model_validate_json(ledger.used_json)
            reserved = UsageRecord.model_validate_json(ledger.reserved_json)
            estimated = UsageRecord.model_validate_json(reservation.estimated_json)
            settled_used, remaining_reserved = reconcile_usage(
                used=used,
                already_reserved=reserved,
                estimated=estimated,
                actual=actual,
            )
            candidates = list(
                session.scalars(
                    select(CandidateRow).where(
                        CandidateRow.run_id == run_id,
                        CandidateRow.session_id == activity.session_id,
                    )
                )
            )
            if len(candidates) > 1:
                raise TerminalBudgetConflictError("variation session produced multiple candidates")
            candidate = candidates[0] if candidates else None
            evaluation_reservation = (
                None
                if candidate is None
                else session.scalar(
                    select(BudgetReservationRow).where(
                        BudgetReservationRow.run_id == run_id,
                        BudgetReservationRow.activity_key
                        == f"evaluate:{candidate.candidate_id}",
                    )
                )
            )
            unreserved_evaluation = (
                required_evaluation
                if candidate is not None
                and (
                    evaluation_reservation is None
                    or evaluation_reservation.state not in {"reserved", "held"}
                )
                else UsageRecord.zero()
            )
            limit = BudgetSpec.model_validate_json(ledger.limit_json)
            projected = settled_used.plus(remaining_reserved).plus(unreserved_evaluation)
            if projected.fits_within(limit):
                raise TerminalBudgetConflictError("usage does not exhaust the run budget")
            exceeded_dimensions = [
                name
                for name in BudgetSpec.model_fields
                if name != "schema_version" and getattr(projected, name) > getattr(limit, name)
            ]
            if candidate is not None:
                if candidate.state == CandidateState.STAGED.value:
                    require_transition(CandidateState.STAGED, CandidateState.POLICY_BLOCKED)
                    candidate.state = CandidateState.POLICY_BLOCKED.value
                elif candidate.state != CandidateState.POLICY_BLOCKED.value:
                    raise TerminalBudgetConflictError(
                        f"cannot budget-block candidate in state {candidate.state}"
                    )
                remaining_reserved = self._cancel_evaluation(
                    session,
                    candidate,
                    evaluation_reservation,
                    remaining_reserved,
                    now,
                )
                self._record_policy_denial(
                    session,
                    run_id=run_id,
                    candidate=candidate,
                    actual=actual,
                    limit=limit,
                    exceeded_dimensions=exceeded_dimensions,
                    policy_bundle_digest=policy_bundle_digest,
                    now=now,
                )

            ledger.used_json = settled_used.model_dump_json()
            ledger.reserved_json = remaining_reserved.model_dump_json()
            ledger.revision += 1
            reservation.state = "exceeded"
            reservation.actual_json = actual.model_dump_json()
            reservation.reconciled_at = now

            activity.state = "completed"
            activity.result_digest = result_digest
            activity.error_json = None
            activity.lease_owner = None
            activity.lease_expires_at = None
            activity.updated_at = now
            if run.state != RunState.FAILED.value:
                require_transition(RunState(run.state), RunState.FAILED)
                run.state = RunState.FAILED.value
            for row in open_reconciliations:
                self._resolve_reconciliation(row, now)
            self._append_event(
                session,
                run,
                "campaign.budget_exhausted",
                actor_id,
                {
                    "activity_id": activity_id,
                    "candidate_id": None if candidate is None else candidate.candidate_id,
                    "exceeded_dimensions": exceeded_dimensions,
                    "reservation_id": reservation_id,
                    "result_digest": result_digest,
                },
                now,
            )

    @staticmethod
    def _cancel_evaluation(
        session: Session,
        candidate: CandidateRow,
        evaluation_reservation: BudgetReservationRow | None,
        reserved: UsageRecord,
        now: datetime,
    ) -> UsageRecord:
        activity = session.scalar(
            select(ActivityRow).where(
                ActivityRow.run_id == candidate.run_id,
                ActivityRow.activity_key == f"evaluate:{candidate.candidate_id}",
            )
        )
        if activity is not None:
            if activity.state not in {"queued", "cancelled"}:
                raise TerminalBudgetConflictError(
                    f"cannot cancel evaluation activity in state {activity.state}"
                )
            if activity.state == "queued":
                activity.state = "cancelled"
                activity.error_json = json.dumps(
                    {"reason": "run_budget_exhausted"},
                    sort_keys=True,
                    separators=(",", ":"),
                )
                activity.updated_at = now
            if (
                evaluation_reservation is not None
                and activity.budget_reservation_id != evaluation_reservation.reservation_id
            ):
                raise TerminalBudgetConflictError(
                    "evaluation activity has a different budget reservation"
                )
        if evaluation_reservation is None:
            if activity is not None and activity.budget_reservation_id is not None:
                raise TerminalBudgetConflictError("evaluation budget reservation is missing")
            return reserved
        if evaluation_reservation.state == "released":
            return reserved
        if evaluation_reservation.state not in {"reserved", "held"}:
            raise TerminalBudgetConflictError(
                "evaluation budget reservation is not releasable"
            )
        _, remaining = reconcile_usage(
            used=UsageRecord.zero(),
            already_reserved=reserved,
            estimated=UsageRecord.model_validate_json(
                evaluation_reservation.estimated_json
            ),
            actual=UsageRecord.zero(),
        )
        evaluation_reservation.state = "released"
        evaluation_reservation.actual_json = UsageRecord.zero().model_dump_json()
        evaluation_reservation.reconciled_at = now
        return remaining

    @staticmethod
    def _record_policy_denial(
        session: Session,
        *,
        run_id: str,
        candidate: CandidateRow,
        actual: UsageRecord,
        limit: BudgetSpec,
        exceeded_dimensions: list[str],
        policy_bundle_digest: Sha256Digest,
        now: datetime,
    ) -> None:
        decision_id = str(
            uuid5(NAMESPACE_URL, f"avo:policy:budget-exhausted:{candidate.candidate_id}")
        )
        reason_codes = [
            {
                "model_input_tokens": "model_input_token_budget_exceeded",
                "model_output_tokens": "model_output_token_budget_exceeded",
            }.get(name, f"{name}_budget_exceeded")
            for name in exceeded_dimensions
        ]
        decision = PolicyDecision(
            decision_id=decision_id,
            policy_engine_id="avo-terminal-budget-v1",
            policy_bundle_digest=policy_bundle_digest,
            action="candidate.evaluate",
            resource=f"run/{run_id}/candidate/{candidate.candidate_id}",
            input_digest=canonical_digest(
                {
                    "actual": actual,
                    "candidate_manifest_digest": candidate.manifest_digest,
                    "limit": limit,
                }
            ),
            outcome="deny",
            reason_codes=reason_codes,
            decided_at=now,
        )
        digest = canonical_digest(decision)
        existing = session.get(PolicyDecisionRow, decision_id)
        if existing is not None:
            if existing.decision_digest != digest:
                raise TerminalBudgetConflictError("budget policy decision conflicts")
            return
        session.add(
            PolicyDecisionRow(
                decision_id=decision_id,
                run_id=run_id,
                candidate_id=candidate.candidate_id,
                decision_digest=digest,
                decision_json=decision.model_dump_json(),
                created_at=now,
            )
        )

    @staticmethod
    def _resolve_reconciliation(row: ReconciliationCaseRow, now: datetime) -> None:
        prior = ReconciliationCaseRecord.model_validate_json(row.record_json)
        record = prior.model_copy(
            update={
                "state": "resolved",
                "resolution": "fail",
                "resolution_note": "durable result exhausted the immutable run budget",
                "resolved_at": now,
            }
        )
        row.state = "resolved"
        row.record_json = record.model_dump_json()
        row.record_digest = canonical_digest(record)
        row.updated_at = now

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
