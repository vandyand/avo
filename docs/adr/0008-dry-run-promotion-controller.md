# ADR 0008: Use a pinned, no-merge promotion controller

Status: Accepted for AVO-004.4, 2026-08-27

## Decision

AVO's first promotion controller is a dry-run boundary. It reads one exact protected Git ref,
compares it with a VCS-free candidate, reconstructs the promotion-policy request from trusted
evidence, and writes an immutable content-addressed promotion bundle. It does not check out,
stage, commit, update a ref, merge, deploy, or contact the remote.

The controller pins its policy configuration, repository root, and artifact root at construction.
Caller-provided policy cannot weaken the configured gate set, and the repository, candidate, and
artifact roots must be pairwise disjoint. Provenance and every external attestation are resolved by
trusted verifiers and bound to the candidate and base digests. The controller derives the base and
path attestations itself, closes the complete evidence manifest, and repeats the repository snapshot
compare-and-swap check immediately before the sole write.

The Git adapter verifies the exact repository root, sanitized remote identity, target ref, commit,
and tree. It materializes the base with `git archive`, rejects unsafe or non-portable entries,
symlinks, hardlinks, reparse points, unsupported file modes, path collisions, and files or trees
outside configured byte and entry limits. Descriptor-based candidate reads use no-follow behavior
where the platform supports it and compare metadata before, during, and after hashing. Source-tree
digests and comparisons include executable mode as well as path, size, and content.

Bundles use strict versioned schemas and RFC 8785 canonical JSON. Replay rejects duplicate or
non-canonical JSON, recomputes all internal digests and policy classification, re-verifies evidence,
and repeats the base snapshot precondition. Only an `allow` decision can produce `would_apply`;
deny, quarantine, and escalation produce `not_applicable`. Replay remains non-mutating.

## Consequences

- AVO-004.4 proves deterministic classification, evidence closure, provenance binding, and stale-base
  behavior without granting merge authority.
- A policy-denied or unresolved bundle remains useful audit evidence but cannot be confused with an
  applicable promotion.
- Filesystem storage remains a trusted local adapter. Distributed or hostile-code storage isolation
  is not claimed.
- Live branch protection retrieval, integration-branch mutation, soak, merge, and rollback authority
  remain AVO-004.5 and AVO-004.6 work.
