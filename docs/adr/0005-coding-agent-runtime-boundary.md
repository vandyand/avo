# ADR 0005: Coding-agent runtimes are bounded variation adapters

Status: Accepted, 2026-08-25

## Decision

AVO may run a coding agent as an interchangeable `AgentHarness`, but the agent is never an admission or control-plane authority. It operates only on a disposable, VCS-free candidate tree. AVO validates and hashes the resulting tree, constructs the patch evidence, runs hidden evaluation, reconciles budgets, and controls lineage.

The first implementation uses the exact-pinned Python Codex SDK 0.147.0 as an app-server protocol client and an explicitly provisioned, absolute-path Codex CLI 0.149.1 runtime. Both versions and the signed executable digest are verified; no executable is discovered from ambient `PATH`. It uses isolated `CODEX_HOME` and private `TMPDIR` roots plus a recomputed permission-contract digest. The profile denies reads outside minimal runtime paths and the candidate workspace, disables command network access and ambient tools/configuration, rejects candidate-controlled Git/Codex/agent configuration, and fails closed when enforcement is unavailable. Authentication is restricted to the `vandyand@gmail.com` ChatGPT Pro subscription and independently verified through the app-server account response; API credential profiles and inherited token variables are rejected. Live operation is Linux/WSL-only for this phase.

Coding-agent shell execution deliberately supersedes the v1 default prohibition on `run_command` for this profile only. The compensating controls are filesystem read isolation, workspace-only writes, network denial, no ambient MCP/skills/rules, brokered development evaluation, immutable evidence, and independent admission. This remains a trusted-team experimental boundary, not hostile-code approval.

Provider threads are external durable state. AVO stores provider identity before mutation, uses opaque checkpoints, renews fenced activity leases, resumes only provably identical work, and enters an operator-resolved reconciliation state for ambiguity. Provider transport loss detaches the in-memory handle and forces this path. It never retries an uncertain mutating prompt or freezes partial cancelled work.

Economic reporting separates actual charges, provider API-equivalent estimates, AVO counterfactual estimates, and subscription quota observations. Existing budget schema remains authoritative and is not expanded with reporting-only dimensions.

## Consequences

- The scheduler, activity journal, session lifecycle, and provenance model gain generic recovery records before the Codex adapter is enabled.
- The current bespoke HTTP model gateway is not called OpenAI-compatible; a real compatible transport is a separate adapter.
- The native structured harness remains supported and harness choice stays explicit in the experiment specification.
- Codex is experimental after its first benchmark. Preferred/default status requires a larger preregistered comparison showing a strict measured advantage, not merely availability.
