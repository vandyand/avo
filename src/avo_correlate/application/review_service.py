"""Role-gated, immutable human review workflow."""

import json
from datetime import UTC, datetime
from typing import cast
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from avo_correlate.adapters.persistence.database import Database
from avo_correlate.adapters.persistence.models import (
    CandidateRow,
    IdempotencyRow,
    ReviewDecisionRow,
    ReviewRequestRow,
)
from avo_correlate.contracts.lifecycle import CandidateState
from avo_correlate.contracts.review import ReviewDecision, ReviewRequest, ReviewStatus
from avo_correlate.domain.canonical import canonical_digest


class ReviewAuthorizationError(ValueError):
    pass


class ReviewConflictError(RuntimeError):
    pass


class ReviewService:
    def __init__(self, database: Database) -> None:
        self._database = database

    def create(self, request: ReviewRequest) -> None:
        with self._database.session() as session:
            prior = session.get(ReviewRequestRow, request.review_id)
            payload = request.model_dump_json()
            if prior is not None:
                prior_payload = self._request_from_row(prior).model_dump_json()
                if prior_payload != payload:
                    raise ReviewConflictError("review_id has another request")
                return
            candidate = session.get(CandidateRow, request.candidate_id)
            if candidate is None or candidate.run_id != request.run_id:
                raise ReviewAuthorizationError("review candidate does not exist")
            if candidate.state != CandidateState.REVIEW_REQUIRED.value:
                raise ReviewAuthorizationError("candidate is not awaiting review")
            session.add(
                ReviewRequestRow(
                    review_id=request.review_id,
                    run_id=request.run_id,
                    candidate_id=request.candidate_id,
                    action=request.action,
                    proposer_id=request.proposer_id,
                    eligible_roles_json=json.dumps(request.eligible_roles),
                    approvals_required=request.approvals_required,
                    proposer_may_review=request.proposer_may_review,
                    required_evidence_json=json.dumps(request.required_evidence_digests),
                    state="pending",
                    expires_at=request.expires_at,
                    created_at=request.created_at,
                )
            )

    def submit(
        self,
        decision: ReviewDecision,
        *,
        actor_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> ReviewStatus:
        now = datetime.now(UTC)
        try:
            with self._database.session() as session:
                request = session.get(ReviewRequestRow, decision.review_id)
                if request is None:
                    raise ReviewAuthorizationError("review request does not exist")
                digest = canonical_digest(decision)
                scope = f"reviews.{decision.review_id}.decisions"
                if actor_id is not None and idempotency_key is not None:
                    idempotent = session.scalar(
                        select(IdempotencyRow).where(
                            IdempotencyRow.actor_id == actor_id,
                            IdempotencyRow.endpoint_scope == scope,
                            IdempotencyRow.idempotency_key == idempotency_key,
                        )
                    )
                    if idempotent is not None:
                        if idempotent.request_digest != digest:
                            raise ReviewConflictError(
                                "idempotency key was already used for a different review decision"
                            )
                        return self._status(session, request)
                prior = session.get(ReviewDecisionRow, decision.decision_id)
                if prior is not None:
                    if prior.decision_digest != digest:
                        raise ReviewConflictError("review decision ID has other evidence")
                    self._record_idempotency(
                        session,
                        actor_id=actor_id,
                        idempotency_key=idempotency_key,
                        scope=scope,
                        digest=digest,
                        decision_id=decision.decision_id,
                        now=now,
                    )
                    return self._status(session, request)
                if request.state != "pending":
                    raise ReviewAuthorizationError(f"review is already {request.state}")
                if _as_utc(request.expires_at) <= now:
                    request.state = "expired"
                    raise ReviewAuthorizationError("review request expired")
                roles = set(cast(list[str], json.loads(request.eligible_roles_json)))
                if decision.reviewer_role not in roles:
                    raise ReviewAuthorizationError("reviewer role is not eligible")
                if (
                    decision.reviewer.actor_id == request.proposer_id
                    and not request.proposer_may_review
                ):
                    raise ReviewAuthorizationError("proposer cannot review this action")
                required = set(
                    cast(list[str], json.loads(request.required_evidence_json))
                )
                if not required.issubset(decision.evidence_digests):
                    raise ReviewAuthorizationError("required review evidence is missing")
                session.add(
                    ReviewDecisionRow(
                        decision_id=decision.decision_id,
                        review_id=decision.review_id,
                        reviewer_id=decision.reviewer.actor_id,
                        outcome=decision.outcome,
                        decision_digest=digest,
                        decision_json=decision.model_dump_json(),
                        created_at=decision.decided_at,
                    )
                )
                session.flush()
                if decision.outcome == "reject":
                    request.state = "rejected"
                else:
                    approvals = int(
                        session.scalar(
                            select(func.count())
                            .select_from(ReviewDecisionRow)
                            .where(
                                ReviewDecisionRow.review_id == request.review_id,
                                ReviewDecisionRow.outcome == "approve",
                            )
                        )
                        or 0
                    )
                    if approvals >= request.approvals_required:
                        request.state = "approved"
                self._record_idempotency(
                    session,
                    actor_id=actor_id,
                    idempotency_key=idempotency_key,
                    scope=scope,
                    digest=digest,
                    decision_id=decision.decision_id,
                    now=now,
                )
                return self._status(session, request)
        except IntegrityError as exc:
            raise ReviewConflictError("reviewer has already decided") from exc

    @staticmethod
    def _status(session: Session, request: ReviewRequestRow) -> ReviewStatus:
        approvals = int(
            session.scalar(
                select(func.count())
                .select_from(ReviewDecisionRow)
                .where(
                    ReviewDecisionRow.review_id == request.review_id,
                    ReviewDecisionRow.outcome == "approve",
                )
            )
            or 0
        )
        return ReviewStatus(
            review_id=request.review_id,
            state=request.state,  # type: ignore[arg-type]
            approvals=approvals,
            approvals_required=request.approvals_required,
        )

    @staticmethod
    def _request_from_row(row: ReviewRequestRow) -> ReviewRequest:
        return ReviewRequest(
            review_id=row.review_id,
            run_id=row.run_id,
            candidate_id=row.candidate_id,
            action=row.action,
            proposer_id=row.proposer_id,
            eligible_roles=cast(list[str], json.loads(row.eligible_roles_json)),
            approvals_required=row.approvals_required,
            proposer_may_review=row.proposer_may_review,
            required_evidence_digests=cast(
                list[str], json.loads(row.required_evidence_json)
            ),
            expires_at=_as_utc(row.expires_at),
            created_at=_as_utc(row.created_at),
        )

    @staticmethod
    def _record_idempotency(
        session: Session,
        *,
        actor_id: str | None,
        idempotency_key: str | None,
        scope: str,
        digest: str,
        decision_id: str,
        now: datetime,
    ) -> None:
        if actor_id is None or idempotency_key is None:
            return
        session.add(
            IdempotencyRow(
                record_id=str(uuid4()),
                actor_id=actor_id,
                endpoint_scope=scope,
                idempotency_key=idempotency_key,
                request_digest=digest,
                resource_id=decision_id,
                created_at=now,
            )
        )


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
