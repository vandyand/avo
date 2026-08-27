import pytest

from avo_correlate.contracts.supervisor import SupervisorObservation
from avo_correlate.domain.supervisor import DeterministicSupervisor


def observation(**changes: int | str) -> SupervisorObservation:
    values: dict[str, int | str] = {
        "run_id": "run-1",
        "run_state": "running",
        "sessions_without_admission": 0,
        "repeated_failure_count": 0,
        "quarantine_count": 0,
        "duplicate_patch_count": 0,
        "policy_denial_count": 0,
        "budget_fraction_micros": 100_000,
        "diversity_fraction_micros": 900_000,
    }
    values.update(changes)
    return SupervisorObservation.model_validate(values)


@pytest.mark.parametrize(
    "changes,expected",
    [
        ({"budget_fraction_micros": 950_000}, "pause"),
        ({"quarantine_count": 2}, "request_review"),
        ({"duplicate_patch_count": 2}, "change_hypothesis"),
        ({"repeated_failure_count": 3}, "reduce_scope"),
        ({"sessions_without_admission": 3}, "revisit_lineage"),
        ({"policy_denial_count": 3}, "pause"),
        ({"diversity_fraction_micros": 1}, "change_hypothesis"),
        ({"run_state": "cancelled"}, "terminate"),
        ({}, "continue"),
    ],
)
def test_supervisor_rules_are_deterministic(
    changes: dict[str, int | str], expected: str
) -> None:
    assert DeterministicSupervisor().decide(observation(**changes)).directive == expected
