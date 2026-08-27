"""Budget specifications and usage accounting."""

from typing import Literal, Self

from avo_correlate.contracts.base import NonNegativeInt, StrictModel


class BudgetSpec(StrictModel):
    schema_version: Literal[1] = 1
    wall_clock_seconds: NonNegativeInt
    model_input_tokens: NonNegativeInt
    model_output_tokens: NonNegativeInt
    model_cost_microusd: NonNegativeInt
    tool_calls: NonNegativeInt
    sandbox_cpu_seconds: NonNegativeInt
    sandbox_gpu_seconds: NonNegativeInt
    authoritative_evaluations: NonNegativeInt
    variation_sessions: NonNegativeInt
    artifact_bytes: NonNegativeInt


class UsageRecord(BudgetSpec):
    @classmethod
    def zero(cls) -> Self:
        return cls(
            wall_clock_seconds=0,
            model_input_tokens=0,
            model_output_tokens=0,
            model_cost_microusd=0,
            tool_calls=0,
            sandbox_cpu_seconds=0,
            sandbox_gpu_seconds=0,
            authoritative_evaluations=0,
            variation_sessions=0,
            artifact_bytes=0,
        )

    def plus(self, other: "UsageRecord") -> "UsageRecord":
        values = {
            name: getattr(self, name) + getattr(other, name)
            for name in BudgetSpec.model_fields
            if name != "schema_version"
        }
        return UsageRecord(**values)

    def fits_within(self, limit: BudgetSpec) -> bool:
        return all(
            getattr(self, name) <= getattr(limit, name)
            for name in BudgetSpec.model_fields
            if name != "schema_version"
        )
