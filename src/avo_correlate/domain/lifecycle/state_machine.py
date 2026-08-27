"""Closed transition tables for every authoritative lifecycle."""

from avo_correlate.contracts.lifecycle import (
    CandidateState,
    EvaluationState,
    ReviewState,
    RunState,
    VariationSessionState,
)

LifecycleState = (
    RunState | VariationSessionState | CandidateState | EvaluationState | ReviewState
)

RUN_TRANSITIONS: dict[RunState, frozenset[RunState]] = {
    RunState.CREATED: frozenset({RunState.VALIDATING, RunState.CANCELLED}),
    RunState.VALIDATING: frozenset({RunState.READY, RunState.FAILED, RunState.CANCELLED}),
    RunState.READY: frozenset({RunState.RUNNING, RunState.CANCELLED}),
    RunState.RUNNING: frozenset(
        {
            RunState.PAUSING,
            RunState.CANCELLING,
            RunState.BLOCKED_REVIEW,
            RunState.BLOCKED_RECONCILIATION,
            RunState.COMPLETED,
            RunState.FAILED,
        }
    ),
    RunState.PAUSING: frozenset(
        {RunState.PAUSED, RunState.CANCELLING, RunState.BLOCKED_RECONCILIATION, RunState.FAILED}
    ),
    RunState.PAUSED: frozenset({RunState.READY, RunState.CANCELLED}),
    RunState.CANCELLING: frozenset(
        {RunState.CANCELLED, RunState.BLOCKED_RECONCILIATION, RunState.FAILED}
    ),
    RunState.BLOCKED_REVIEW: frozenset(
        {RunState.RUNNING, RunState.CANCELLING, RunState.FAILED}
    ),
    RunState.BLOCKED_RECONCILIATION: frozenset(
        {
            RunState.READY,
            RunState.RUNNING,
            RunState.PAUSED,
            RunState.CANCELLED,
            RunState.FAILED,
        }
    ),
    RunState.COMPLETED: frozenset[RunState](),
    RunState.CANCELLED: frozenset[RunState](),
    RunState.FAILED: frozenset[RunState](),
}
SESSION_TRANSITIONS: dict[VariationSessionState, frozenset[VariationSessionState]] = {
    VariationSessionState.QUEUED: frozenset(
        {VariationSessionState.RUNNING, VariationSessionState.CANCELLED}
    ),
    VariationSessionState.RUNNING: frozenset(
        {
            VariationSessionState.PROPOSAL_READY,
            VariationSessionState.EXHAUSTED,
            VariationSessionState.POLICY_BLOCKED,
            VariationSessionState.RECONCILIATION_REQUIRED,
            VariationSessionState.CANCELLED,
            VariationSessionState.FAILED,
        }
    ),
    VariationSessionState.PROPOSAL_READY: frozenset[VariationSessionState](),
    VariationSessionState.EXHAUSTED: frozenset[VariationSessionState](),
    VariationSessionState.POLICY_BLOCKED: frozenset[VariationSessionState](),
    VariationSessionState.RECONCILIATION_REQUIRED: frozenset(
        {
            VariationSessionState.RUNNING,
            VariationSessionState.CANCELLED,
            VariationSessionState.FAILED,
        }
    ),
    VariationSessionState.CANCELLED: frozenset[VariationSessionState](),
    VariationSessionState.FAILED: frozenset[VariationSessionState](),
}
CANDIDATE_TRANSITIONS: dict[CandidateState, frozenset[CandidateState]] = {
    CandidateState.STAGED: frozenset(
        {CandidateState.EVALUATING, CandidateState.POLICY_BLOCKED, CandidateState.CANCELLED}
    ),
    CandidateState.EVALUATING: frozenset(
        {
            CandidateState.REJECTED,
            CandidateState.QUARANTINED,
            CandidateState.REVIEW_REQUIRED,
            CandidateState.ADMITTED,
        }
    ),
    CandidateState.REVIEW_REQUIRED: frozenset(
        {CandidateState.ADMITTED, CandidateState.REJECTED, CandidateState.CANCELLED}
    ),
    CandidateState.ADMITTED: frozenset[CandidateState](),
    CandidateState.REJECTED: frozenset[CandidateState](),
    CandidateState.QUARANTINED: frozenset[CandidateState](),
    CandidateState.POLICY_BLOCKED: frozenset[CandidateState](),
    CandidateState.CANCELLED: frozenset[CandidateState](),
}
EVALUATION_TRANSITIONS: dict[EvaluationState, frozenset[EvaluationState]] = {
    EvaluationState.QUEUED: frozenset(
        {EvaluationState.RUNNING, EvaluationState.POLICY_BLOCKED}
    ),
    EvaluationState.RUNNING: frozenset(
        {
            EvaluationState.PASSED,
            EvaluationState.FAILED,
            EvaluationState.ERRORED,
            EvaluationState.TIMED_OUT,
            EvaluationState.POLICY_BLOCKED,
            EvaluationState.INVALID_REPORT,
        }
    ),
    EvaluationState.PASSED: frozenset[EvaluationState](),
    EvaluationState.FAILED: frozenset[EvaluationState](),
    EvaluationState.ERRORED: frozenset[EvaluationState](),
    EvaluationState.TIMED_OUT: frozenset[EvaluationState](),
    EvaluationState.POLICY_BLOCKED: frozenset[EvaluationState](),
    EvaluationState.INVALID_REPORT: frozenset[EvaluationState](),
}
REVIEW_TRANSITIONS: dict[ReviewState, frozenset[ReviewState]] = {
    ReviewState.PENDING: frozenset(
        {ReviewState.APPROVED, ReviewState.REJECTED, ReviewState.EXPIRED, ReviewState.WITHDRAWN}
    ),
    ReviewState.APPROVED: frozenset[ReviewState](),
    ReviewState.REJECTED: frozenset[ReviewState](),
    ReviewState.EXPIRED: frozenset[ReviewState](),
    ReviewState.WITHDRAWN: frozenset[ReviewState](),
}


class InvalidTransitionError(ValueError):
    """Raised when a transition is outside the closed table."""


def can_transition(current: LifecycleState, target: LifecycleState) -> bool:
    if type(current) is not type(target):
        return False
    if isinstance(current, RunState) and isinstance(target, RunState):
        return target in RUN_TRANSITIONS[current]
    if isinstance(current, VariationSessionState) and isinstance(
        target, VariationSessionState
    ):
        return target in SESSION_TRANSITIONS[current]
    if isinstance(current, CandidateState) and isinstance(target, CandidateState):
        return target in CANDIDATE_TRANSITIONS[current]
    if isinstance(current, EvaluationState) and isinstance(target, EvaluationState):
        return target in EVALUATION_TRANSITIONS[current]
    if isinstance(current, ReviewState) and isinstance(target, ReviewState):
        return target in REVIEW_TRANSITIONS[current]
    return False


def require_transition(current: LifecycleState, target: LifecycleState) -> None:
    if not can_transition(current, target):
        raise InvalidTransitionError(
            f"transition {type(current).__name__}:{current.value}->{target.value} is not allowed"
        )
