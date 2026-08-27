# AVO Coding-Agent Integration Plan v2

Planning authority: the [AVO roadmap](roadmap.md) supersedes this integration-specific sequence.
This document remains the durable design and result record for the coding-agent boundary.

Status: durable local lifecycle implemented, terminal-budget recovery replayed, and the first full
sanitized `AVO improves AVO` admission completed on 2026-08-26. Production approval and application
of the admitted patch to the real workspace remain deferred.

## Current position

The bounded comparison is complete. In one frozen eight-task repetition, the Codex arm admitted
8/8 candidates and the native OpenRouter/Luna arm admitted 6/8. This is useful architecture
evidence, not a statistical superiority finding. Codex is the primary high-value variation
runtime; the native interface remains the portable, inexpensive experimental baseline.

The second sanitized recursive campaign closed the first full self-improvement loop. One Luna turn
used 197,800 input tokens, passed public and frozen private evaluation, was policy-allowed, admitted
through lineage CAS, reconstructed exactly, and verified provenance with no reconciliation. See the
[admitted capstone result](avo-improves-avo-capstone-v2-result.md). The patch remains unapplied until
explicit human review.

The Python SDK is the primary Codex control client. It is a typed client for the local Codex
app-server and already exposes the thread, turn, streaming, steering, interruption, inspection,
account, and model operations required by AVO. AVO pins SDK and CLI versions independently and
selects the verified CLI by absolute path. Direct app-server JSON-RPC is reserved for a proven
SDK capability gap; `codex exec --json` remains a diagnostic canary, never an automatic fallback.

## Implemented lifecycle gate

The scheduler now drives the real single-lineage boundary:

```text
variation activity
  -> persist AVO invocation
  -> create and persist provider thread
  -> start Codex turn
  -> append runtime evidence outside the candidate tree
  -> freeze patch and candidate
  -> private evaluation activity
  -> policy and admission activity
  -> lineage CAS and verified provenance
```

Provider thread and turn identities are separate. Recovery inspects the persisted thread:

- no turn means it is safe to start once;
- a completed matching turn may be finalized without another prompt;
- running, missing, conflicting, externally advanced, or indeterminate work enters reconciliation;
- no session switches transport after it begins.

Variation, evaluation, and admission activities use deterministic keys and idempotent evidence.
A local worker can drain all three stages. Injected crashes after provider completion recover the
durable result without creating another turn, candidate, evaluation, budget charge, or admission.
The agent still cannot read admission fixtures, change policy, admit itself, or merge its output.

## Completed terminal-budget gate

The deterministic terminal budget-exhaustion path is implemented. After a durable provider result,
AVO atomically records actual over-budget usage, completes the variation activity, policy-blocks the
frozen candidate, cancels and releases queued evaluation work, fails the run, and resolves any open
reconciliation. A crash immediately before settlement is recovered from the durable session result
without another provider turn. The provenance verifier rejects every terminal run that retains an
open reconciliation. The [first recursive result](avo-improves-avo-capstone-v1-result.md) remains an
immutable historical regression fixture; its retained open case is intentionally documented rather
than silently rewriting the original evidence bundle. A deterministic replay of all 578 retained
events through a fresh control database passed every corrected terminal invariant without provider
contact; see the [replay result](avo-terminal-budget-replay-v1-result.md).

## Superseded next sequence

The following sequence captured the integration direction before the operator selected
human-on-exception autonomous promotion. Use the [authoritative roadmap](roadmap.md) for current
order, exit gates, and status.

1. Introduce a versioned `ExperimentSpec` v2 and ADR for the existing hybrid archive and
   population strategies; compare them under equal budgets before changing the default.
2. Run bounded multi-generation AVO-on-AVO campaigns with plateau detection, lineage limits,
   private regression promotion, and mandatory human review.
3. Improve the native/OpenRouter protocol only when portability, a model-selection experiment,
   or cost evidence makes that work higher priority.
4. Add production infrastructure only at its trigger: remote workers and PostgreSQL/object
   storage for multi-host load; centralized policy/secrets for multiple trust domains; backup and
   observability drills before a production claim; gVisor/Kata/VM isolation before untrusted code.

For current development campaigns, use `gpt-5.6-luna` for bounded implementation and routine work.
Use `gpt-5.6-terra` only after an explicit quality/reasoning escalation decision. Keep Sol disabled
while weekly subscription headroom is constrained; model escalation does not excuse a failed
budget, policy, or infrastructure gate.

## Promotion evidence

The lifecycle gate requires the contract, integration, recovery, parity, lint, and type suites to
pass; private evaluator material must remain outside the runtime read set; every admitted candidate
must reconstruct from provenance. The live WSL gate additionally requires the isolated
`vandyand@gmail.com` ChatGPT Pro login, no API-token variables, the signed runtime profile, exact
SDK/CLI checks, and all boundary canaries.

Official protocol references: [Codex SDK](https://learn.chatgpt.com/docs/codex-sdk) and
[Codex app-server](https://learn.chatgpt.com/docs/app-server).
