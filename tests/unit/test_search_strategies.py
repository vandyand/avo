from decimal import Decimal

import pytest

from avo_correlate.application.search_strategies import (
    HybridArchiveStrategy,
    PopulationRoundRobinStrategy,
    SingleLineageStrategy,
    require_equal_methodology_budget,
)
from avo_correlate.contracts.budgets import UsageRecord
from avo_correlate.contracts.search import SearchCandidate, SearchState
from tests.conftest import DIGEST_A, DIGEST_B, experiment_spec


def state() -> SearchState:
    return SearchState(
        run_id="run-1",
        champion_id="champion",
        candidates=[
            SearchCandidate(
                candidate_id="champion",
                workspace_digest=DIGEST_A,
                lineage_sequence=2,
                quality=Decimal("10"),
                novelty=Decimal("0.1"),
                selection_count=3,
            ),
            SearchCandidate(
                candidate_id="novel",
                workspace_digest=DIGEST_B,
                lineage_sequence=1,
                quality=Decimal("9"),
                novelty=Decimal("3"),
                selection_count=0,
            ),
        ],
        budget_limit=experiment_spec().budget,
        budget_used=UsageRecord.zero(),
        next_session_number=4,
    )


def test_baseline_always_selects_committed_champion() -> None:
    assert SingleLineageStrategy().select_parent(state()).parent_candidate_id == "champion"


def test_experimental_strategies_add_breadth_deterministically() -> None:
    assert (
        HybridArchiveStrategy(
            novelty_weight=Decimal("1"), exploration_weight=Decimal("1")
        )
        .select_parent(state())
        .parent_candidate_id
        == "novel"
    )
    assert PopulationRoundRobinStrategy().select_parent(state()).parent_candidate_id == "novel"


def test_methodology_comparison_rejects_unequal_budget() -> None:
    left = state()
    require_equal_methodology_budget(left, left.model_copy())
    changed_budget = left.budget_limit.model_copy(update={"tool_calls": 99})
    with pytest.raises(ValueError, match="equal hard budgets"):
        require_equal_methodology_budget(
            left, left.model_copy(update={"budget_limit": changed_budget})
        )
