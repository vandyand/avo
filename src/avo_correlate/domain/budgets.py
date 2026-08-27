"""Pure budget arithmetic used by transactional adapters."""

from avo_correlate.contracts.budgets import BudgetSpec, UsageRecord


class BudgetExceededError(ValueError):
    pass


def reserve_usage(
    *,
    limit: BudgetSpec,
    used: UsageRecord,
    already_reserved: UsageRecord,
    requested: UsageRecord,
) -> UsageRecord:
    projected = used.plus(already_reserved).plus(requested)
    if not projected.fits_within(limit):
        exceeded = [
            name
            for name in BudgetSpec.model_fields
            if name != "schema_version" and getattr(projected, name) > getattr(limit, name)
        ]
        raise BudgetExceededError("budget exceeded: " + ", ".join(exceeded))
    return already_reserved.plus(requested)


def reconcile_usage(
    *,
    used: UsageRecord,
    already_reserved: UsageRecord,
    estimated: UsageRecord,
    actual: UsageRecord,
) -> tuple[UsageRecord, UsageRecord]:
    values = {
        "wall_clock_seconds": already_reserved.wall_clock_seconds
        - estimated.wall_clock_seconds,
        "model_input_tokens": already_reserved.model_input_tokens
        - estimated.model_input_tokens,
        "model_output_tokens": already_reserved.model_output_tokens
        - estimated.model_output_tokens,
        "model_cost_microusd": already_reserved.model_cost_microusd
        - estimated.model_cost_microusd,
        "tool_calls": already_reserved.tool_calls - estimated.tool_calls,
        "sandbox_cpu_seconds": already_reserved.sandbox_cpu_seconds
        - estimated.sandbox_cpu_seconds,
        "sandbox_gpu_seconds": already_reserved.sandbox_gpu_seconds
        - estimated.sandbox_gpu_seconds,
        "authoritative_evaluations": already_reserved.authoritative_evaluations
        - estimated.authoritative_evaluations,
        "variation_sessions": already_reserved.variation_sessions
        - estimated.variation_sessions,
        "artifact_bytes": already_reserved.artifact_bytes - estimated.artifact_bytes,
    }
    if any(value < 0 for value in values.values()):
        raise ValueError("reservation underflow")
    remaining = UsageRecord(
        wall_clock_seconds=values["wall_clock_seconds"],
        model_input_tokens=values["model_input_tokens"],
        model_output_tokens=values["model_output_tokens"],
        model_cost_microusd=values["model_cost_microusd"],
        tool_calls=values["tool_calls"],
        sandbox_cpu_seconds=values["sandbox_cpu_seconds"],
        sandbox_gpu_seconds=values["sandbox_gpu_seconds"],
        authoritative_evaluations=values["authoritative_evaluations"],
        variation_sessions=values["variation_sessions"],
        artifact_bytes=values["artifact_bytes"],
    )
    return used.plus(actual), remaining
