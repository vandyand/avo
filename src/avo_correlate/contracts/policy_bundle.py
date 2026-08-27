"""Restricted v1 deny-by-default policy schema."""

from typing import Literal

from pydantic import Field

from avo_correlate.contracts.base import NonEmptyString, StrictModel
from avo_correlate.contracts.policy import PolicyObligation


class PolicyRule(StrictModel):
    schema_version: Literal[1] = 1
    rule_id: NonEmptyString
    effect: Literal["allow", "deny", "review"]
    actors: list[NonEmptyString] = Field(min_length=1)
    actions: list[NonEmptyString] = Field(min_length=1)
    resource_patterns: list[NonEmptyString] = Field(min_length=1)
    reason_code: NonEmptyString
    obligations: list[PolicyObligation] = Field(default_factory=list[PolicyObligation])


class PolicyBundle(StrictModel):
    schema_version: Literal[1] = 1
    policy_engine_id: NonEmptyString
    rules: list[PolicyRule]
