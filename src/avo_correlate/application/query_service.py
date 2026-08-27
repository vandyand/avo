"""Read-only operator projections over authoritative records."""

import json
from typing import Any, cast

from sqlalchemy import select

from avo_correlate.adapters.persistence.database import Database
from avo_correlate.adapters.persistence.models import (
    AdmissionRow,
    ArtifactMetadataRow,
    AttemptRow,
    CandidateRow,
    EvaluationRow,
    HarnessInvocationRow,
    PolicyDecisionRow,
    ReconciliationCaseRow,
    ReviewDecisionRow,
    ReviewRequestRow,
    VariationSessionRow,
)
from avo_correlate.application.run_service import NotFoundError
from avo_correlate.contracts.projections import (
    ArtifactMetadataProjection,
    CandidateProjection,
    SessionProjection,
    SessionRuntimeProjection,
)


class QueryService:
    def __init__(self, database: Database) -> None:
        self._database = database

    def session(self, session_id: str) -> SessionProjection:
        with self._database.session() as session:
            row = session.get(VariationSessionRow, session_id)
            if row is None:
                raise NotFoundError(f"session not found: {session_id}")
            attempts = [
                _load(item.record_json)
                for item in session.scalars(
                    select(AttemptRow)
                    .where(AttemptRow.session_id == session_id)
                    .order_by(AttemptRow.attempt_number)
                )
            ]
            return SessionProjection(
                session_id=row.session_id,
                run_id=row.run_id,
                state=row.state,
                request=_load(row.request_json),
                result=None if row.result_json is None else _load(row.result_json),
                attempts=attempts,
            )

    def candidate(self, candidate_id: str) -> CandidateProjection:
        with self._database.session() as session:
            row = session.get(CandidateRow, candidate_id)
            if row is None:
                raise NotFoundError(f"candidate not found: {candidate_id}")
            evaluations = [
                _load(item.record_json)
                for item in session.scalars(
                    select(EvaluationRow).where(EvaluationRow.candidate_id == candidate_id)
                )
            ]
            admission_row = session.scalar(
                select(AdmissionRow).where(AdmissionRow.candidate_id == candidate_id)
            )
            policies = [
                _load(item.decision_json)
                for item in session.scalars(
                    select(PolicyDecisionRow).where(
                        PolicyDecisionRow.candidate_id == candidate_id
                    )
                )
            ]
            reviews = [
                {
                    "review_id": review.review_id,
                    "state": review.state,
                    "action": review.action,
                    "approvals_required": review.approvals_required,
                    "decisions": [
                        _load(item.decision_json)
                        for item in session.scalars(
                            select(ReviewDecisionRow).where(
                                ReviewDecisionRow.review_id == review.review_id
                            )
                        )
                    ],
                }
                for review in session.scalars(
                    select(ReviewRequestRow).where(
                        ReviewRequestRow.candidate_id == candidate_id
                    )
                )
            ]
            return CandidateProjection(
                candidate_id=row.candidate_id,
                run_id=row.run_id,
                state=row.state,
                manifest=_load(row.manifest_json),
                evaluations=evaluations,
                admission=(
                    None
                    if admission_row is None
                    else _load(admission_row.decision_json)
                ),
                policy_decisions=policies,
                reviews=reviews,
            )

    def session_runtime(self, session_id: str) -> SessionRuntimeProjection:
        with self._database.session() as session:
            row = session.get(VariationSessionRow, session_id)
            if row is None:
                raise NotFoundError(f"session not found: {session_id}")
            invocations = [
                _load(item.record_json)
                for item in session.scalars(
                    select(HarnessInvocationRow)
                    .where(HarnessInvocationRow.session_id == session_id)
                    .order_by(HarnessInvocationRow.created_at)
                )
            ]
            reconciliations = [
                _load(item.record_json)
                for item in session.scalars(
                    select(ReconciliationCaseRow)
                    .where(ReconciliationCaseRow.session_id == session_id)
                    .order_by(ReconciliationCaseRow.created_at)
                )
            ]
            return SessionRuntimeProjection(
                session_id=row.session_id,
                run_id=row.run_id,
                session_state=row.state,
                invocations=invocations,
                reconciliations=reconciliations,
            )

    def artifact(self, digest: str) -> ArtifactMetadataProjection:
        with self._database.session() as session:
            row = session.get(ArtifactMetadataRow, digest)
            if row is None:
                raise NotFoundError(f"artifact not found: {digest}")
            return ArtifactMetadataProjection(
                digest=cast(Any, row.digest),
                size_bytes=row.size_bytes,
                media_type=row.media_type,
                role=row.role,
                created_at=row.created_at,
                verified_at=row.verified_at,
            )


def _load(payload: str) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(payload))
