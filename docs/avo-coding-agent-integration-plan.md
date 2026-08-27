# AVO Coding-Agent Integration Plan

Status: historical v1 plan, implemented through the bounded development live gate and calibration.
The completed comparison and durable campaign sequence are maintained in
[the v2 integration plan](avo-coding-agent-integration-plan-v2.md).

## Objective

Add a provider-neutral coding-agent runtime to AVO while leaving AVO solely authoritative for budgets, workspace validation, candidate freezing, private evaluation, admission, lineage, and provenance. Codex is the first runtime adapter; the native structured-model harness remains the portable baseline. Claude Code and OpenCode remain evidence-gated follow-ons.

## Mandatory architecture gate

Before a coding-agent profile is enabled:

- Amend the threat model and tool contract to acknowledge sandboxed shell execution.
- Prove a pinned Codex SDK/runtime can enforce a workspace-only permission profile: root denied, minimal tool paths readable, candidate workspace writable, command network disabled, and AVO state, artifacts, private evaluators, authentication, unrelated home files, and spool data unreadable.
- Prove thread identity is available before mutation and that streaming, structured completion, interruption, inspection, and resume work.
- Keep the candidate tree VCS-free. Store Git metadata outside the tree and produce a normalized, round-trippable binary diff between immutable base and working trees.
- Fail closed if any proof is unavailable. Do not downgrade to ambient configuration, legacy broad sandboxing, or full access.

## Contracts and state

- Reuse signed plugin manifests and doctor reports for runtime compatibility.
- Add `HarnessRuntimeProfile`, `RuntimeSessionRef`, `RuntimeEvent`, `AgentCompletion`, `EconomicUsageRecord`, `HarnessInvocationRecord`, `ReconciliationCaseRecord`, and `SessionRuntimeProjection` schemas.
- Add a `CodingAgentRuntime` port with verify, start, run/resume, interrupt, and inspect operations. Provider checkpoints are opaque and equality-only to core code.
- Keep `BudgetSpec` and `UsageRecord` v1 unchanged. Economic observations live separately; only an actual metered charge maps into `model_cost_microusd`.
- Add `VariationSessionState.RECONCILIATION_REQUIRED` and `RunState.BLOCKED_RECONCILIATION`, plus operator-only cancellation or failure resolution.
- Persist harness invocations, reconciliation cases, and an activity lease epoch. Extend provenance with reachable invocation/event evidence.

## Runtime and recovery

- Replace static handler retryability with phase-aware recovery: durable result, not started, resumable, or ambiguous.
- Add CAS lease heartbeats and epoch fencing; completion requires the current epoch.
- Persist the provider thread ID before the mutating turn and append complete runtime events to a durable spool.
- Resume only a provably identical thread/workspace. Missing, externally advanced, conflicting, truncated, or indeterminate state enters reconciliation and is never automatically re-prompted.
- Cancellation interrupts, waits a bounded grace period, terminates if needed, fences the activity, and never freezes partial edits.
- A development-evaluator broker keeps capability tokens control-plane-side, remints them against the current workspace digest, enforces budget, and exposes no admission/audit evaluator.

## Adapters

- Add a real asynchronous OpenAI-compatible gateway with explicit Chat Completions or Responses wire profiles, strict structured output, tool-call mapping, provider usage/cost evidence, and mock-server contracts.
- Use the exactly pinned `openai-codex==0.147.0` Python SDK as the protocol client and an explicitly provisioned, absolute-path `codex-cli 0.149.1` executable. Verify both versions before every session; do not discover a CLI from ambient `PATH`. The 0.147.0 CLI bundled with the Python SDK is not the configured AVO runtime.
- Use an isolated `CODEX_HOME` authenticated only through `codex login` with the `vandyand@gmail.com` ChatGPT Pro subscription plus a separate private runtime `TMPDIR`. Reject API-key authentication, credential profiles, inherited key/token environment variables, a different email or plan, ambient rules/skills/MCP/web, and any unverified permission profile. Recompute strict completion-schema and permission-contract digests at preflight.
- Initial live support is Linux/WSL only. Native Windows reports an unsupported capability while deterministic adapter tests remain cross-platform.
- `ai-sessions` commit `bc9f40e` is a design and test reference, not a runtime dependency.

## Verification and rollout

- Build a shared runtime contract suite against a fake adapter before live Codex tests.
- Test lease expiry, fencing, all crash windows, resume, cancellation, malformed completion, ambiguous provider state, reconciliation, credential/private-evaluator canaries, filesystem/network denial, VCS-free binary patching, budget holds/releases, and provenance tampering.
- Run live Codex tests only when explicitly credential-enabled on Linux/WSL; CI uses recorded fixtures.
- Treat transport loss as ambiguous external state: detach the in-memory handle, clean only verified empty runtime scaffolds, and force explicit reconciliation instead of retrying.
- Benchmark eight hidden-admission tasks with three paired repetitions for Codex and one pinned OpenRouter/native profile. Store the shared task and each rendered prompt separately. Report admissions, normalized effect, regressions, reliability, time, attempts, tokens, evaluator calls, actual charge, counterfactual cost, and quota observations without collapsing them into one score.
- Codex remains experimental unless it has zero boundary violations, passes every injected recovery case without duplicate work, admits on at least six of eight tasks, and is not Pareto-dominated on the declared technical metrics. Default promotion requires a larger preregistered study with a strict measured advantage.
- After that gate, run a sanitized `AVO improves AVO` capstone with state/private evaluators outside the agent read set and require independent admission, provenance verification, canaries, and human review.

## Deferred production work

Remote workers, PostgreSQL/object-store parity, centralized secrets and signed policy distribution, backup/restore drills, hostile-code isolation, native Windows execution, multi-tenancy, and automatic harness selection require separate approval.
