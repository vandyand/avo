from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from avo_correlate.application.review_service import (
    ReviewAuthorizationError,
    ReviewConflictError,
    ReviewService,
)
from avo_correlate.contracts.base import ActorRef
from avo_correlate.contracts.review import ReviewDecision, ReviewRequest
from tests.conftest import DIGEST_A
from tests.integration.test_admission import decision, setup_candidate


def review_decision(review_id: str, reviewer: str, role: str) -> ReviewDecision:
    return ReviewDecision(
        decision_id=f"decision-{reviewer}",
        review_id=review_id,
        reviewer=ActorRef(actor_type="human", actor_id=reviewer),
        reviewer_role=role,
        outcome="approve",
        evidence_digests=[DIGEST_A],
        rationale="evidence supports the already-defined admission action",
        signature_digest=DIGEST_A,
        decided_at=datetime.now(UTC),
    )


def test_two_person_review_authorizes_then_final_admission_commits(tmp_path: Path) -> None:
    database, runs, evidence, champion, _ = setup_candidate(tmp_path)
    preliminary = decision(champion).model_copy(
        update={
            "admission_id": "admission-review-required",
            "outcome": "review_required",
            "reason_codes": ["human_review_required"],
        }
    )
    assert evidence.commit_admission("run-1", preliminary) is None
    reviews = ReviewService(database)
    request = ReviewRequest(
        review_id="review-1",
        run_id="run-1",
        candidate_id="candidate-1",
        action="candidate.admit",
        proposer_id="tester",
        eligible_roles=["maintainer", "security"],
        approvals_required=2,
        proposer_may_review=False,
        required_evidence_digests=[DIGEST_A],
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        created_at=datetime.now(UTC),
    )
    reviews.create(request)
    first = review_decision("review-1", "reviewer-1", "maintainer")
    assert reviews.submit(
        first, actor_id="reviewer-1", idempotency_key="review-request-1"
    ).state == "pending"
    assert reviews.submit(
        first, actor_id="reviewer-1", idempotency_key="review-request-1"
    ).approvals == 1
    with pytest.raises(ReviewConflictError, match="idempotency key"):
        reviews.submit(
            first.model_copy(update={"rationale": "different evidence interpretation"}),
            actor_id="reviewer-1",
            idempotency_key="review-request-1",
        )
    assert reviews.submit(review_decision("review-1", "reviewer-2", "security")).state == (
        "approved"
    )
    final = decision(champion).model_copy(update={"admission_id": "admission-final"})
    assert evidence.commit_admission("run-1", final) == 1
    assert runs.get_run("run-1").champion_id == "candidate-1"


def test_proposer_and_ineligible_roles_cannot_approve(tmp_path: Path) -> None:
    database, _, evidence, champion, _ = setup_candidate(tmp_path)
    preliminary = decision(champion).model_copy(
        update={
            "admission_id": "admission-review-required",
            "outcome": "review_required",
        }
    )
    evidence.commit_admission("run-1", preliminary)
    reviews = ReviewService(database)
    reviews.create(
        ReviewRequest(
            review_id="review-1",
            run_id="run-1",
            candidate_id="candidate-1",
            action="candidate.admit",
            proposer_id="tester",
            eligible_roles=["maintainer"],
            approvals_required=1,
            required_evidence_digests=[DIGEST_A],
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            created_at=datetime.now(UTC),
        )
    )
    with pytest.raises(ReviewAuthorizationError, match="proposer"):
        reviews.submit(review_decision("review-1", "tester", "maintainer"))
    with pytest.raises(ReviewAuthorizationError, match="role"):
        reviews.submit(review_decision("review-1", "outsider", "viewer"))
