"""Candidate, evaluation, policy, admission, and lineage persistence."""

import json
from datetime import UTC, datetime
from typing import Any, cast
from uuid import uuid4

from sqlalchemy import func, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from avo_correlate.adapters.persistence.database import Database
from avo_correlate.adapters.persistence.models import (
    AdmissionRow,
    CandidateRow,
    EvaluationRow,
    EventRow,
    LineageRow,
    OutboxRow,
    PolicyDecisionRow,
    ReviewRequestRow,
    RunRow,
)
from avo_correlate.contracts.evaluation import AdmissionDecision, EvaluationRecord
from avo_correlate.contracts.lifecycle import CandidateState, RunState
from avo_correlate.contracts.policy import PolicyDecision
from avo_correlate.contracts.variation import CandidateManifest
from avo_correlate.domain.admission import evaluation_is_admissible
from avo_correlate.domain.canonical import canonical_digest


class EvidenceConflictError(RuntimeError):
    pass


class InvalidAdmissionError(ValueError):
    pass


class EvidenceService:
    def __init__(self, database: Database) -> None:
        self._database = database

    def stage_candidate(self, manifest: CandidateManifest) -> str:
        payload = manifest.model_dump_json()
        digest = canonical_digest(manifest)
        with self._database.session() as session:
            existing = session.get(CandidateRow, manifest.candidate_id)
            if existing is not None:
                if existing.manifest_digest != digest:
                    raise EvidenceConflictError("candidate_id already has different evidence")
                return digest
            run = session.get(RunRow, manifest.run_id)
            if run is None:
                raise InvalidAdmissionError("candidate run does not exist")
            if run.champion_id not in manifest.parent_candidate_ids:
                raise InvalidAdmissionError("candidate does not descend from current champion")
            session.add(
                CandidateRow(
                    candidate_id=manifest.candidate_id,
                    run_id=manifest.run_id,
                    session_id=manifest.session_id,
                    state=CandidateState.STAGED.value,
                    source_tree_digest=manifest.source_tree_digest,
                    manifest_digest=digest,
                    manifest_json=payload,
                    created_at=manifest.created_at,
                )
            )
        return digest

    def get_candidate(self, candidate_id: str) -> CandidateManifest:
        with self._database.session() as session:
            row = session.get(CandidateRow, candidate_id)
            if row is None:
                raise LookupError(f"candidate not found: {candidate_id}")
            return CandidateManifest.model_validate_json(row.manifest_json)

    def get_session_candidate(self, session_id: str) -> CandidateManifest | None:
        with self._database.session() as session:
            rows = list(
                session.scalars(
                    select(CandidateRow).where(CandidateRow.session_id == session_id)
                )
            )
            if len(rows) > 1:
                raise EvidenceConflictError("variation session has multiple candidates")
            return (
                None
                if not rows
                else CandidateManifest.model_validate_json(rows[0].manifest_json)
            )

    def list_evaluations(self, candidate_id: str) -> list[tuple[str, EvaluationRecord]]:
        with self._database.session() as session:
            rows = session.scalars(
                select(EvaluationRow)
                .where(EvaluationRow.candidate_id == candidate_id)
                .order_by(EvaluationRow.evaluator_key)
            )
            return [
                (row.evaluator_key, EvaluationRecord.model_validate_json(row.record_json))
                for row in rows
            ]

    def get_admission(self, candidate_id: str) -> AdmissionDecision | None:
        with self._database.session() as session:
            row = session.scalar(
                select(AdmissionRow).where(AdmissionRow.candidate_id == candidate_id)
            )
            return (
                None
                if row is None
                else AdmissionDecision.model_validate_json(row.decision_json)
            )

    def record_evaluation(self, record: EvaluationRecord, *, evaluator_key: str) -> str:
        payload = record.model_dump_json()
        digest = canonical_digest(record)
        with self._database.session() as session:
            candidate = session.get(CandidateRow, record.candidate_id)
            if candidate is None:
                raise InvalidAdmissionError("evaluation candidate does not exist")
            existing = session.scalar(
                select(EvaluationRow).where(
                    EvaluationRow.candidate_id == record.candidate_id,
                    EvaluationRow.evaluator_key == evaluator_key,
                )
            )
            if existing is not None:
                if existing.record_digest != digest:
                    raise EvidenceConflictError("evaluation activity returned different evidence")
                return digest
            session.add(
                EvaluationRow(
                    evaluation_id=record.evaluation_id,
                    candidate_id=record.candidate_id,
                    evaluator_key=evaluator_key,
                    tier=record.evaluator_tier,
                    state=record.outcome,
                    record_digest=digest,
                    record_json=payload,
                    created_at=record.completed_at,
                )
            )
            candidate.state = CandidateState.EVALUATING.value
        return digest

    def record_policy_decision(
        self, run_id: str, decision: PolicyDecision, *, candidate_id: str | None = None
    ) -> str:
        payload = decision.model_dump_json()
        digest = canonical_digest(decision)
        with self._database.session() as session:
            existing = session.get(PolicyDecisionRow, decision.decision_id)
            if existing is not None:
                if existing.decision_digest != digest:
                    raise EvidenceConflictError("policy decision ID has different evidence")
                return digest
            session.add(
                PolicyDecisionRow(
                    decision_id=decision.decision_id,
                    run_id=run_id,
                    candidate_id=candidate_id,
                    decision_digest=digest,
                    decision_json=payload,
                    created_at=decision.decided_at,
                )
            )
        return digest

    def commit_admission(self, run_id: str, decision: AdmissionDecision) -> int | None:
        """Persist one immutable decision and CAS-append admitted evidence to lineage."""
        now = datetime.now(UTC)
        try:
            with self._database.session() as session:
                existing = session.get(AdmissionRow, decision.admission_id)
                digest = canonical_digest(decision)
                if existing is not None:
                    if existing.decision_digest != digest:
                        raise EvidenceConflictError("admission ID has different evidence")
                    lineage = session.scalar(
                        select(LineageRow).where(LineageRow.admission_id == decision.admission_id)
                    )
                    return None if lineage is None else lineage.sequence
                run = session.get(RunRow, run_id)
                candidate = session.get(CandidateRow, decision.candidate_id)
                if run is None or candidate is None or candidate.run_id != run_id:
                    raise InvalidAdmissionError("run or candidate does not exist")
                self._validate_decision_evidence(session, decision)
                if run.state in {RunState.CANCELLING.value, RunState.CANCELLED.value}:
                    raise InvalidAdmissionError("cancellation fence prevents admission")
                if run.champion_id != decision.expected_champion_id:
                    raise EvidenceConflictError("champion changed before admission")
                session.add(
                    AdmissionRow(
                        admission_id=decision.admission_id,
                        run_id=run_id,
                        candidate_id=decision.candidate_id,
                        outcome=decision.outcome,
                        decision_digest=digest,
                        decision_json=decision.model_dump_json(),
                        created_at=decision.decided_at,
                    )
                )
                prior_candidate_state = candidate.state
                terminal_state = {
                    "admit": CandidateState.ADMITTED,
                    "reject": CandidateState.REJECTED,
                    "quarantine": CandidateState.QUARANTINED,
                    "review_required": CandidateState.REVIEW_REQUIRED,
                }[decision.outcome]
                candidate.state = terminal_state.value
                if decision.outcome != "admit":
                    return None
                if decision.comparison.conclusion != "improved":
                    raise InvalidAdmissionError("admission requires a proven improvement")
                if prior_candidate_state == CandidateState.REVIEW_REQUIRED.value:
                    approved_review = session.scalar(
                        select(ReviewRequestRow.review_id).where(
                            ReviewRequestRow.candidate_id == decision.candidate_id,
                            ReviewRequestRow.action == "candidate.admit",
                            ReviewRequestRow.state == "approved",
                        )
                    )
                    if approved_review is None:
                        raise InvalidAdmissionError("required human review is not approved")
                if run.state != RunState.RUNNING.value:
                    raise InvalidAdmissionError("only a running run may admit a candidate")
                next_lineage = cast(
                    int,
                    session.scalar(
                        select(func.coalesce(func.max(LineageRow.sequence), -1)).where(
                            LineageRow.run_id == run_id
                        )
                    ),
                ) + 1
                next_revision = run.revision + 1
                next_event = run.event_sequence + 1
                changed = cast(
                    CursorResult[Any],
                    session.execute(
                        update(RunRow)
                        .where(
                            RunRow.run_id == run_id,
                            RunRow.revision == run.revision,
                            RunRow.champion_id == decision.expected_champion_id,
                            RunRow.state == RunState.RUNNING.value,
                        )
                        .values(
                            champion_id=decision.candidate_id,
                            revision=next_revision,
                            event_sequence=next_event,
                            updated_at=now,
                        )
                    ),
                )
                if changed.rowcount != 1:
                    raise EvidenceConflictError("admission compare-and-swap failed")
                session.add(
                    LineageRow(
                        lineage_id=str(uuid4()),
                        run_id=run_id,
                        sequence=next_lineage,
                        candidate_id=decision.candidate_id,
                        source_tree_digest=candidate.source_tree_digest,
                        admission_id=decision.admission_id,
                        committed_at=now,
                    )
                )
                self._append_event(
                    session,
                    run_id=run_id,
                    sequence=next_event,
                    actor_id=decision.decided_by.actor_id,
                    candidate_id=decision.candidate_id,
                    admission_id=decision.admission_id,
                    lineage_sequence=next_lineage,
                    now=now,
                )
                return next_lineage
        except IntegrityError as exc:
            raise EvidenceConflictError("duplicate admission or lineage evidence") from exc

    @staticmethod
    def _validate_decision_evidence(session: Session, decision: AdmissionDecision) -> None:
        policy_ids = set(
            session.scalars(
                select(PolicyDecisionRow.decision_id).where(
                    PolicyDecisionRow.decision_id.in_(decision.policy_decision_ids)
                )
            )
        )
        if policy_ids != set(decision.policy_decision_ids):
            raise InvalidAdmissionError("admission references missing policy decisions")
        evaluations = list(
            session.scalars(
                select(EvaluationRow).where(
                    EvaluationRow.evaluation_id.in_(decision.evaluation_ids)
                )
            )
        )
        if {item.evaluation_id for item in evaluations} != set(decision.evaluation_ids):
            raise InvalidAdmissionError("admission references missing evaluations")
        if any(item.candidate_id != decision.candidate_id for item in evaluations):
            raise InvalidAdmissionError("evaluation belongs to another candidate")
        records = [EvaluationRecord.model_validate_json(item.record_json) for item in evaluations]
        if decision.outcome == "admit" and not any(
            evaluation_is_admissible(item) for item in records
        ):
            raise InvalidAdmissionError("admission lacks a passing authoritative evaluation")

    @staticmethod
    def _append_event(
        session: Session,
        *,
        run_id: str,
        sequence: int,
        actor_id: str,
        candidate_id: str,
        admission_id: str,
        lineage_sequence: int,
        now: datetime,
    ) -> None:
        event_id = str(uuid4())
        payload = json.dumps(
            {
                "candidate_id": candidate_id,
                "admission_id": admission_id,
                "lineage_sequence": lineage_sequence,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        session.add(
            EventRow(
                event_id=event_id,
                run_id=run_id,
                sequence=sequence,
                event_type="candidate.admitted",
                actor_id=actor_id,
                payload_json=payload,
                created_at=now,
            )
        )
        session.flush()
        session.add(
            OutboxRow(
                outbox_id=str(uuid4()),
                event_id=event_id,
                topic="run.events",
                payload_json=payload,
                created_at=now,
            )
        )
