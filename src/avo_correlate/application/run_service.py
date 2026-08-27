"""Transactional experiment/run lifecycle service."""

import json
from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from avo_correlate.adapters.persistence.database import Database
from avo_correlate.adapters.persistence.models import (
    ActivityRow,
    BudgetLedgerRow,
    CandidateRow,
    EventRow,
    ExperimentRow,
    IdempotencyRow,
    LineageRow,
    OutboxRow,
    RunRow,
    VariationSessionRow,
)
from avo_correlate.contracts.budgets import BudgetSpec, UsageRecord
from avo_correlate.contracts.experiment import ExperimentSpec
from avo_correlate.contracts.lifecycle import RunState
from avo_correlate.domain.canonical import canonical_digest
from avo_correlate.domain.lifecycle import require_transition


class NotFoundError(LookupError):
    pass


class RevisionConflictError(RuntimeError):
    pass


class DuplicateExperimentError(ValueError):
    pass


class RunService:
    def __init__(self, database: Database) -> None:
        self._database = database

    def create_experiment(
        self,
        spec: ExperimentSpec,
        *,
        actor_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> str:
        digest = canonical_digest(spec)
        payload = json.dumps(spec.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
        now = datetime.now(UTC)
        with self._database.session() as session:
            if actor_id is not None and idempotency_key is not None:
                prior = self._check_idempotency(
                    session,
                    actor_id=actor_id,
                    endpoint_scope="experiments.create",
                    idempotency_key=idempotency_key,
                    request_digest=digest,
                )
                if prior is not None:
                    return digest
            existing = session.get(ExperimentRow, spec.experiment_id)
            if existing:
                if existing.spec_digest != digest:
                    raise DuplicateExperimentError(
                        "experiment_id already refers to a different immutable spec"
                    )
            else:
                session.add(
                    ExperimentRow(
                        experiment_id=spec.experiment_id,
                        spec_digest=digest,
                        spec_json=payload,
                        created_by=spec.created_by.actor_id,
                        created_at=now,
                    )
                )
            if actor_id is not None and idempotency_key is not None:
                self._record_idempotency(
                    session,
                    actor_id=actor_id,
                    endpoint_scope="experiments.create",
                    idempotency_key=idempotency_key,
                    request_digest=digest,
                    resource_id=spec.experiment_id,
                    now=now,
                )
        return digest

    def create_run(
        self,
        experiment_id: str,
        *,
        actor_id: str,
        run_id: str | None = None,
        prepare: bool = False,
        idempotency_key: str | None = None,
    ) -> str:
        run_id = run_id or str(uuid4())
        now = datetime.now(UTC)
        with self._database.session() as session:
            request_digest = canonical_digest(
                {"experiment_id": experiment_id, "prepare": prepare, "run_id": run_id}
            )
            if idempotency_key is not None:
                prior = self._check_idempotency(
                    session,
                    actor_id=actor_id,
                    endpoint_scope=f"experiments.{experiment_id}.runs.create",
                    idempotency_key=idempotency_key,
                    request_digest=request_digest,
                )
                if prior is not None:
                    return prior
            experiment = session.get(ExperimentRow, experiment_id)
            if experiment is None:
                raise NotFoundError(f"experiment not found: {experiment_id}")
            existing = session.get(RunRow, run_id)
            if existing:
                if existing.experiment_id != experiment_id:
                    raise RevisionConflictError("run_id belongs to another experiment")
                return run_id
            run = RunRow(
                run_id=run_id,
                experiment_id=experiment_id,
                state=RunState.CREATED.value,
                revision=1,
                event_sequence=1,
                created_at=now,
                updated_at=now,
            )
            session.add(run)
            session.flush()
            spec = ExperimentSpec.model_validate_json(experiment.spec_json)
            seed_id = f"seed-{run_id}"
            seed_manifest = {
                "schema_version": 1,
                "kind": "seed",
                "candidate_id": seed_id,
                "run_id": run_id,
                "source_tree_digest": spec.workspace.source_tree_digest,
                "source_revision": spec.workspace.source_revision,
            }
            seed_manifest_json = json.dumps(
                seed_manifest, sort_keys=True, separators=(",", ":")
            )
            session.add(
                CandidateRow(
                    candidate_id=seed_id,
                    run_id=run_id,
                    session_id=None,
                    state="seed",
                    source_tree_digest=spec.workspace.source_tree_digest,
                    manifest_digest=canonical_digest(seed_manifest),
                    manifest_json=seed_manifest_json,
                    created_at=now,
                )
            )
            session.add(
                LineageRow(
                    lineage_id=str(uuid4()),
                    run_id=run_id,
                    sequence=0,
                    candidate_id=seed_id,
                    source_tree_digest=spec.workspace.source_tree_digest,
                    admission_id=None,
                    committed_at=now,
                )
            )
            run.champion_id = seed_id
            zero = UsageRecord.zero().model_dump_json()
            session.add(
                BudgetLedgerRow(
                    run_id=run_id,
                    limit_json=spec.budget.model_dump_json(),
                    used_json=zero,
                    reserved_json=zero,
                    revision=1,
                )
            )
            self._append_event(
                session,
                run=run,
                sequence=1,
                event_type="run.created",
                actor_id=actor_id,
                payload={
                    "experiment_id": experiment_id,
                    "state": run.state,
                    "champion_id": seed_id,
                },
                now=now,
            )
            if prepare:
                run.state = RunState.READY.value
                run.revision = 3
                run.event_sequence = 3
                self._append_event(
                    session,
                    run=run,
                    sequence=2,
                    event_type="run.validating",
                    actor_id=actor_id,
                    payload={"from": "created", "to": "validating"},
                    now=now,
                )
                self._append_event(
                    session,
                    run=run,
                    sequence=3,
                    event_type="run.ready",
                    actor_id=actor_id,
                    payload={"from": "validating", "to": "ready"},
                    now=now,
                )
            if idempotency_key is not None:
                self._record_idempotency(
                    session,
                    actor_id=actor_id,
                    endpoint_scope=f"experiments.{experiment_id}.runs.create",
                    idempotency_key=idempotency_key,
                    request_digest=request_digest,
                    resource_id=run_id,
                    now=now,
                )
        return run_id

    def get_experiment(self, experiment_id: str) -> ExperimentSpec:
        with self._database.session() as session:
            row = session.get(ExperimentRow, experiment_id)
            if row is None:
                raise NotFoundError(f"experiment not found: {experiment_id}")
            return ExperimentSpec.model_validate_json(row.spec_json)

    def get_run(self, run_id: str) -> RunRow:
        with self._database.session() as session:
            run = session.get(RunRow, run_id)
            if run is None:
                raise NotFoundError(f"run not found: {run_id}")
            session.expunge(run)
            return run

    def get_budget(self, run_id: str) -> tuple[BudgetSpec, UsageRecord, UsageRecord]:
        with self._database.session() as session:
            ledger = session.get(BudgetLedgerRow, run_id)
            if ledger is None:
                raise NotFoundError(f"run not found: {run_id}")
            return (
                BudgetSpec.model_validate_json(ledger.limit_json),
                UsageRecord.model_validate_json(ledger.used_json),
                UsageRecord.model_validate_json(ledger.reserved_json),
            )

    def settle_control_request(self, run_id: str, *, actor_id: str) -> RunRow:
        """Commit pause/cancel once every active unit has reached a safe boundary."""
        run = self.get_run(run_id)
        state = RunState(run.state)
        if state not in {RunState.PAUSING, RunState.CANCELLING}:
            return run
        with self._database.session() as session:
            active_activity = session.scalar(
                select(ActivityRow.activity_id).where(
                    ActivityRow.run_id == run_id, ActivityRow.state == "running"
                )
            )
            active_session = session.scalar(
                select(VariationSessionRow.session_id).where(
                    VariationSessionRow.run_id == run_id,
                    VariationSessionRow.state == "running",
                )
            )
        if active_activity is not None or active_session is not None:
            return run
        target = RunState.PAUSED if state == RunState.PAUSING else RunState.CANCELLED
        return self.transition(
            run_id,
            target,
            actor_id=actor_id,
            expected_revision=run.revision,
            reason="safe_boundary_reached",
        )

    def transition(
        self,
        run_id: str,
        target: RunState,
        *,
        actor_id: str,
        expected_revision: int | None = None,
        reason: str | None = None,
        idempotency_key: str | None = None,
        endpoint_scope: str | None = None,
    ) -> RunRow:
        now = datetime.now(UTC)
        with self._database.session() as session:
            scope = endpoint_scope or f"runs.{run_id}.transition"
            request_digest = canonical_digest(
                {"run_id": run_id, "target": target.value, "reason": reason}
            )
            if idempotency_key is not None:
                prior = self._check_idempotency(
                    session,
                    actor_id=actor_id,
                    endpoint_scope=scope,
                    idempotency_key=idempotency_key,
                    request_digest=request_digest,
                )
                if prior is not None:
                    prior_run = session.get(RunRow, prior)
                    if prior_run is None:
                        raise NotFoundError(f"run not found: {prior}")
                    session.expunge(prior_run)
                    return prior_run
            current = session.scalar(select(RunRow).where(RunRow.run_id == run_id))
            if current is None:
                raise NotFoundError(f"run not found: {run_id}")
            current_state = RunState(current.state)
            require_transition(current_state, target)
            if expected_revision is not None and current.revision != expected_revision:
                raise RevisionConflictError(
                    f"expected revision {expected_revision}, current is {current.revision}"
                )
            next_revision = current.revision + 1
            next_sequence = current.event_sequence + 1
            changed = cast(
                CursorResult[Any],
                session.execute(
                    update(RunRow)
                    .where(RunRow.run_id == run_id, RunRow.revision == current.revision)
                    .values(
                        state=target.value,
                        revision=next_revision,
                        event_sequence=next_sequence,
                        updated_at=now,
                    )
                ),
            )
            if changed.rowcount != 1:
                raise RevisionConflictError("run changed concurrently")
            current.state = target.value
            current.revision = next_revision
            current.event_sequence = next_sequence
            current.updated_at = now
            self._append_event(
                session,
                run=current,
                sequence=next_sequence,
                event_type=f"run.{target.value}",
                actor_id=actor_id,
                payload={"from": current_state.value, "to": target.value, "reason": reason},
                now=now,
            )
            if idempotency_key is not None:
                self._record_idempotency(
                    session,
                    actor_id=actor_id,
                    endpoint_scope=scope,
                    idempotency_key=idempotency_key,
                    request_digest=request_digest,
                    resource_id=run_id,
                    now=now,
                )
            session.flush()
            session.expunge(current)
            return current

    def list_events(self, run_id: str, *, after: int = 0) -> list[EventRow]:
        with self._database.session() as session:
            events = list(
                session.scalars(
                    select(EventRow)
                    .where(EventRow.run_id == run_id, EventRow.sequence > after)
                    .order_by(EventRow.sequence)
                )
            )
            for item in events:
                session.expunge(item)
            return events

    @staticmethod
    def _check_idempotency(
        session: Session,
        *,
        actor_id: str,
        endpoint_scope: str,
        idempotency_key: str,
        request_digest: str,
    ) -> str | None:
        record = session.scalar(
            select(IdempotencyRow).where(
                IdempotencyRow.actor_id == actor_id,
                IdempotencyRow.endpoint_scope == endpoint_scope,
                IdempotencyRow.idempotency_key == idempotency_key,
            )
        )
        if record is None:
            return None
        if record.request_digest != request_digest:
            raise RevisionConflictError(
                "idempotency key was already used for a different request"
            )
        return record.resource_id

    @staticmethod
    def _record_idempotency(
        session: Session,
        *,
        actor_id: str,
        endpoint_scope: str,
        idempotency_key: str,
        request_digest: str,
        resource_id: str,
        now: datetime,
    ) -> None:
        session.add(
            IdempotencyRow(
                record_id=str(uuid4()),
                actor_id=actor_id,
                endpoint_scope=endpoint_scope,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                resource_id=resource_id,
                created_at=now,
            )
        )

    @staticmethod
    def _append_event(
        session: Session,
        *,
        run: RunRow,
        sequence: int,
        event_type: str,
        actor_id: str,
        payload: dict[str, object],
        now: datetime,
    ) -> None:
        event_id = str(uuid4())
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        event = EventRow(
            event_id=event_id,
            run_id=run.run_id,
            sequence=sequence,
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
