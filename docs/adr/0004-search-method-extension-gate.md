# ADR 0004: Gate alternative search methods behind equal-budget experiments

Status: accepted for experimental adapters; not enabled in v1 runs.

Single-lineage agentic variation remains the reference method because it gives the cleanest causal attribution and the smallest durable state surface. A hybrid quality-diversity archive is the most promising next method when local-optimum behavior is measured; a round-robin population adapter is retained as a breadth baseline.

Alternative methods implement the `SearchStrategy` port and identify their method and version in every decision. Comparative runs must start from identical workspace/evaluator inputs, hard budgets, model configuration, and zero-or-equal usage. The control plane rejects unequal-budget comparisons. Promotion requires statistically supported improvement in admitted outcomes per unit cost, plus recovery and policy contract parity.

The experimental adapters cannot be selected by the v1 `ExperimentSpec`; enabling one requires a new schema version and an architecture decision. This prevents optional archive state from leaking into the single-lineage source of truth.
