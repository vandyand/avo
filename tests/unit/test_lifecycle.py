import pytest

from avo_correlate.contracts.lifecycle import (
    CandidateState,
    EvaluationState,
    ReviewState,
    RunState,
    VariationSessionState,
)
from avo_correlate.domain.lifecycle import (
    InvalidTransitionError,
    can_transition,
    require_transition,
)
from avo_correlate.domain.lifecycle.state_machine import (
    CANDIDATE_TRANSITIONS,
    EVALUATION_TRANSITIONS,
    REVIEW_TRANSITIONS,
    RUN_TRANSITIONS,
    SESSION_TRANSITIONS,
)


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (RunState.CREATED, RunState.VALIDATING),
        (RunState.PAUSED, RunState.READY),
        (VariationSessionState.RUNNING, VariationSessionState.PROPOSAL_READY),
        (CandidateState.EVALUATING, CandidateState.ADMITTED),
        (EvaluationState.RUNNING, EvaluationState.INVALID_REPORT),
        (ReviewState.PENDING, ReviewState.EXPIRED),
    ],
)
def test_allowed_transitions(
    current: RunState
    | VariationSessionState
    | CandidateState
    | EvaluationState
    | ReviewState,
    target: RunState
    | VariationSessionState
    | CandidateState
    | EvaluationState
    | ReviewState,
) -> None:
    assert can_transition(current, target)
    require_transition(current, target)


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (RunState.COMPLETED, RunState.RUNNING),
        (RunState.CANCELLING, RunState.COMPLETED),
        (VariationSessionState.PROPOSAL_READY, VariationSessionState.RUNNING),
        (CandidateState.REJECTED, CandidateState.ADMITTED),
        (EvaluationState.PASSED, EvaluationState.RUNNING),
        (ReviewState.APPROVED, ReviewState.PENDING),
    ],
)
def test_forbidden_transitions(
    current: RunState
    | VariationSessionState
    | CandidateState
    | EvaluationState
    | ReviewState,
    target: RunState
    | VariationSessionState
    | CandidateState
    | EvaluationState
    | ReviewState,
) -> None:
    assert not can_transition(current, target)
    with pytest.raises(InvalidTransitionError):
        require_transition(current, target)


def test_every_state_is_present_in_transition_table() -> None:
    assert set(RUN_TRANSITIONS) == set(RunState)
    assert set(SESSION_TRANSITIONS) == set(VariationSessionState)
    assert set(CANDIDATE_TRANSITIONS) == set(CandidateState)
    assert set(EVALUATION_TRANSITIONS) == set(EvaluationState)
    assert set(REVIEW_TRANSITIONS) == set(ReviewState)


def test_cross_lifecycle_transition_is_forbidden() -> None:
    assert not can_transition(RunState.CREATED, CandidateState.STAGED)
