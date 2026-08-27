"""Search-strategy extension records for controlled methodology experiments."""

from decimal import Decimal
from typing import Literal

from pydantic import Field

from avo_correlate.contracts.base import NonEmptyString, Sha256Digest, StrictModel
from avo_correlate.contracts.budgets import BudgetSpec, UsageRecord


class SearchCandidate(StrictModel):
    schema_version: Literal[1] = 1
    candidate_id: NonEmptyString
    workspace_digest: Sha256Digest
    lineage_sequence: int = Field(ge=0)
    quality: Decimal
    novelty: Decimal = Field(ge=0)
    selection_count: int = Field(ge=0)


class SearchState(StrictModel):
    schema_version: Literal[1] = 1
    run_id: NonEmptyString
    champion_id: NonEmptyString
    candidates: list[SearchCandidate] = Field(min_length=1)
    budget_limit: BudgetSpec
    budget_used: UsageRecord
    next_session_number: int = Field(ge=1)


class SearchDecision(StrictModel):
    schema_version: Literal[1] = 1
    method: Literal["single_lineage_agentic", "hybrid_archive_agentic", "population_agentic"]
    method_version: NonEmptyString
    parent_candidate_id: NonEmptyString
    reason_codes: list[NonEmptyString] = Field(min_length=1)
