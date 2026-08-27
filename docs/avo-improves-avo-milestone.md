# Recursive milestone: AVO improves AVO

Status: full recursive admission achieved on 2026-08-26. The first Luna candidate passed all
technical gates and was correctly rejected for exceeding its immutable input-token budget; its
evidence later passed the corrected no-provider terminal replay. A second one-turn Luna candidate
passed every frozen gate, was admitted as the run champion, and reconstructed exactly. See the
[v1 result](avo-improves-avo-capstone-v1-result.md),
[terminal replay](avo-terminal-budget-replay-v1-result.md), and
[admitted v2 result](avo-improves-avo-capstone-v2-result.md).

## The insight

AVO has crossed the point where its own repository can become a candidate workspace governed by
AVO. Codex can propose an improvement to AVO, while AVO supplies the budget, isolation, immutable
base, independent tests, admission rules, lineage, and provenance. This closes the first recursive
loop: the improvement system becomes a subject of the improvement system.

This is constrained self-improvement, not self-governance. The candidate has no authority over the
rules that judge or apply it. Success demonstrates that AVO's abstractions work on a meaningful
self-referential target; it does not authorize autonomous merge, deployment, policy changes, or an
unbounded optimization loop.

## Invariants

- Materialize an immutable AVO base into a separate VCS-free candidate tree. Keep external Git
  metadata, AVO state, runtime spools, credentials, and private evaluators outside its read set.
- Give Codex only the signed workspace-write profile, denied network, denied ambient
  rules/skills/apps/MCP, deny-all approvals, and the isolated ChatGPT Pro identity.
- The candidate may change the scoped AVO source and public tests. It may not modify the frozen
  experiment, budget, permission contract, private evaluator, admission policy, provenance ledger,
  or worker that is running the campaign.
- Freeze the result before private evaluation. Admission must use independently produced evidence,
  policy decisions, compare-and-swap lineage, and complete provenance.
- Admission produces a review bundle. A human decides whether to apply it to the real repository;
  AVO and Codex do not merge or deploy it.

## First capstone

Choose one bounded, reviewable improvement whose private acceptance suite is authored and frozen
before the run. Prefer the already identified activation work around search-method versioning only
if it can be reduced to a single-candidate change; otherwise use a smaller lifecycle or recovery
improvement. Give the campaign one variation session and a fixed token/wall-time budget.

The capstone passes only when the candidate clears public and private evaluation, no boundary
canary fires, no hidden-evaluator reference appears in the patch, the admitted workspace can be
reconstructed exactly, provenance verification succeeds, and human review finds the change
appropriate. Rejection is still a useful valid result if all controls and evidence work correctly.

## What follows

The deterministic terminal budget-exhaustion path is complete, including pre-settlement crash
recovery, insufficient required-evaluation budget, atomic reservation cleanup, and provenance
enforcement. Next, add `ExperimentSpec` v2 for archive/population selection under a separate ADR
and equal-budget evaluation. Only then consider multi-generation AVO-on-AVO campaigns. Production
infrastructure and hostile-code claims remain independently gated.
