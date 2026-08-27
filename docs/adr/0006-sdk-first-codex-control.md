# ADR 0006: Use the Codex Python SDK behind an AVO-owned control seam

Status: Accepted, 2026-08-26

## Decision

AVO uses the stable `openai-codex` Python SDK as its primary Codex control client. The SDK controls
the local app-server and accepts the absolute path of the separately pinned CLI runtime. AVO owns a
narrow `CodexControlClient` seam and keeps campaign code dependent only on `CodingAgentRuntime`.

Runtime startup is two-phase. AVO creates and journals the provider thread before it starts the
workspace-mutating turn. The durable reference stores separate thread and turn IDs plus the AVO
invocation ID. Recovery uses thread inspection: a thread without a turn is safe to continue, a
matching completed turn may be finalized, and any active or indeterminate turn that cannot be
reattached enters reconciliation.

Direct app-server JSON-RPC is not implemented preemptively. It may replace the SDK client behind the
same seam only when a required stable capability is unavailable through the SDK or measured SDK
behavior prevents correct recovery. `codex exec --json` is retained for diagnostics and canaries,
not campaign execution or automatic fallback.

## Consequences

- SDK and CLI versions remain exact, independent pins; CLI release-number differences do not imply
  that the SDK uses a different inference runtime.
- AVO avoids owning JSON-RPC framing, initialization, notification routing, generated schemas, and
  experimental capability negotiation until evidence justifies that cost.
- Transport choice cannot change budgets, candidate freezing, private evaluation, admission,
  lineage, or provenance.
- Mid-session transport fallback is forbidden because it would make external state ambiguous.

References: [Codex SDK](https://learn.chatgpt.com/docs/codex-sdk) and
[Codex app-server](https://learn.chatgpt.com/docs/app-server).
