"""Deterministic parent selection behind the SearchStrategy port."""

from decimal import Decimal
from typing import Protocol

from avo_correlate.contracts.search import SearchCandidate, SearchDecision, SearchState


class SearchStrategy(Protocol):
    def select_parent(self, state: SearchState) -> SearchDecision: ...


class SingleLineageStrategy:
    version = "1.0.0"

    def select_parent(self, state: SearchState) -> SearchDecision:
        if not any(item.candidate_id == state.champion_id for item in state.candidates):
            raise ValueError("champion is absent from search state")
        return SearchDecision(
            method="single_lineage_agentic",
            method_version=self.version,
            parent_candidate_id=state.champion_id,
            reason_codes=["CURRENT_CHAMPION"],
        )


class HybridArchiveStrategy:
    """Experimental quality-diversity parent selection; not enabled in v1 runs."""

    version = "0.1.0-experimental"

    def __init__(self, *, novelty_weight: Decimal, exploration_weight: Decimal) -> None:
        if novelty_weight < 0 or exploration_weight < 0:
            raise ValueError("archive weights cannot be negative")
        self._novelty_weight = novelty_weight
        self._exploration_weight = exploration_weight

    def select_parent(self, state: SearchState) -> SearchDecision:
        parent = max(
            state.candidates,
            key=lambda item: (
                self._score(item),
                -item.lineage_sequence,
                item.candidate_id,
            ),
        )
        return SearchDecision(
            method="hybrid_archive_agentic",
            method_version=self.version,
            parent_candidate_id=parent.candidate_id,
            reason_codes=["QUALITY_DIVERSITY_SCORE"],
        )

    def _score(self, candidate: SearchCandidate) -> Decimal:
        exploration = Decimal(1) / Decimal(candidate.selection_count + 1)
        return (
            candidate.quality
            + self._novelty_weight * candidate.novelty
            + self._exploration_weight * exploration
        )


class PopulationRoundRobinStrategy:
    """Experimental breadth baseline for equal-budget methodology comparisons."""

    version = "0.1.0-experimental"

    def select_parent(self, state: SearchState) -> SearchDecision:
        parent = min(
            state.candidates,
            key=lambda item: (item.selection_count, item.lineage_sequence, item.candidate_id),
        )
        return SearchDecision(
            method="population_agentic",
            method_version=self.version,
            parent_candidate_id=parent.candidate_id,
            reason_codes=["LEAST_SELECTED_PARENT"],
        )


def require_equal_methodology_budget(left: SearchState, right: SearchState) -> None:
    if left.budget_limit != right.budget_limit:
        raise ValueError("methodology comparison requires equal hard budgets")
    if left.budget_used != right.budget_used:
        raise ValueError("methodology comparison must start from equal usage")
