# AVO-004.7 protected-main graduation implementation plan

Status: implementation plan; C4 Phase A complete on 2026-08-30 at HEAD
`0cb20c50c43cd78f75b23da025e3bbe4e0f5ee78` with Terra approval; hosted `main` mutation blocked
pending organization-hosting/merge-queue (max-one-entry plus admission/hold) capability
and explicit isolated release-hold issuer authority.

This plan is subordinate to the [authoritative roadmap](roadmap.md) and
[ADR 0011](adr/0011-protected-main-graduation.md). It describes implementation-ready
work for the declared single-host, trusted-team boundary. It authorizes no repository
transfer, protection/queue mutation, deployment, or live `main` write.

## Outcome and non-goals

AVO-004.7 will graduate a trusted successful integration campaign result to protected
`main` by applying only its exact result delta to a fresh main base, with durable evidence,
recovery, and a separate main rollback authority. Completion requires the preregistered
12-of-12 eligible hosted threshold and both main-specific rollback evidence classes.

Out of scope are deployment, release promotion, secrets, production effects, hostile-code
containment, multi-host coordination, and any widening of integration-only contracts or
providers. Human authority remains available for exceptions and constitutional changes,
not routine approvals.

## C4 Phase A — contract-first coordinator boundary

Phase A is complete at the recorded HEAD; see the [Phase A result](avo-0047-c4-phase-a-result.md).
This closes only the contract/journal gate. The next ready gate is the live coordinator/provider
executor, including the required end-to-end on-disk recovery fixture as P2 coverage. It does not
establish live executor readiness or complete AVO-004.7.

Phase A freezes the coordinator and recovery contracts before any provider implementation.
It is documentation, schema, journal, and test-contract work only: it creates no candidate,
PR, queue entry, check run, hold, release transition, or other remote mutation. The
coordinator is deliberately orchestration-only and has no merge, ref-update, check-write,
or release-issuer capability. Capabilities are injected through narrow interfaces with
separate publication, PR, enqueue, admission-issuer, and release-issuer roles; a DTO or
caller-supplied observation cannot confer authority.

The Phase A journal defines one append-only chronology for every externally meaningful
boundary: attempt start, preparation authorization, each mutation intent, its provider
receipt or reconciliation, admission and hold observations, release claim, release
transition, authoritative post-state, cleanup, and completion. For every mutation, the
target-scoped unresolved-external-mutation slot/fence is durably reserved in the same
journal transaction as the mutation intent, before any provider capability is dispatched.
Thus there is no crash window in which a provider may have been called but the fence has
not yet been recorded. Successful or rejected authoritative observation, or later
reconciliation that conclusively establishes the outcome, resolves that reservation;
ambiguous or incomplete observation leaves it open. Receipts are create-once, and
conflicting duplicates remain unresolved rather than being overwritten. The journal also
exposes durable main-lease evidence (including owner, operation, target, policy epoch,
and expiry). While the fence is open, a new attempt cannot overlap or issue a new write;
recovery is read-only until the ambiguity is resolved.

The Phase A coordinator does not treat provider or lease evidence DTOs as authority.
Verifier capabilities are injected into the journal/coordinator boundary and must be
controller-owned, independently configured capabilities that authenticate and verify
those records. A caller-supplied DTO, serialized observation, lease snapshot, or claimed
issuer identity can be input to verification but cannot authorize a mutation by itself.
This rule applies to every mutation receipt, including both terminal and ambiguous
receipts: each remains a DTO until the mandatory controller-owned verifier authenticates
it at record, recovery, and use time. No receipt, regardless of its reported outcome, may
clear the target-scoped unresolved-mutation reservation or authorize a parent-stage
transition without that verifier result. A receipt that cannot be authenticated remains
unresolved and fail-closed.

The release boundary has an atomic, durable, create-once claim keyed by the exact
authorization digest, hold run/nonce, group, lease epoch, and issuer. Claiming is distinct
from dispatch: after dispatch may have begun, recovery must never issue a second release
transition, even when the receipt is lost. Release authorization expiry is bounded by the
lease expiry and configured maximum TTL.
The release-transition intent must be durably recorded before the release authorization or
one-use claim can expire. Any future live executor must use a trusted controller clock to
recheck authorization validity, lease validity, and issuer scope immediately before
dispatching the provider transition; a caller-supplied time or stale preflight check is
insufficient.

Admission and group-hold identities are deterministic and operation-bound (including the
exact PR/group, queue generation, source/head identity, and nonce derivation inputs), so a
success cannot transfer to a regenerated candidate, PR, or merge group. If an external
write may have happened but cannot be authoritatively observed, recovery only reads and
reconciles; it never retries admission, hold, release, enqueue, or publication by guessing.
Phase A does not add provider writes or grant the coordinator release authority.

## Dependency-ordered task graph

The IDs below are stable leaf IDs. A leaf may not be accepted until every dependency is
accepted and its write scope is reviewed.

| ID | Leaf | Depends on | Write scope | Acceptance checks |
| --- | --- | --- | --- | --- |
| AVO-004.7-C1 | Main contracts and journal | AVO-004.6 | New `main_graduation` contract models, canonical serializers, schema exports, and a dedicated journal/artifact namespace. No integration contract edits. | Strict models include `MainPreparationAuthorization`, `MainQueueAdmissionObservation`, `MainReleaseHoldObservation`, and one-use `MainReleaseAuthorization` with two SHA-specific states of the pinned `avo-main-release` context, exact hold/admission run ID/nonce, queue-generation identity, issuer/isolation contract, and App 15368 validation identity. Reject extras, mutable integration heads, wrong target, missing children, production/constitutional paths, `deploy=true`, duplicate evidence, and stale epochs. Plan/lease/intent/preparation-auth/admission/hold/release-auth/receipt/completion digests replay identically. |
| AVO-004.7-C2 | Deterministic composition adapter | AVO-004.7-C1 | New composition module and tests only. Reads the trusted package and a fresh main base; writes immutable candidate/tree/path-manifest artifacts. | Recomputes the exact sole-parent-to-result delta; applies it deterministically to a fresh base; proves exact tree and parent; rejects multi-parent, mutable-head, path-manifest drift, ordinary-risk drift, and disallowed paths. |
| AVO-004.7-C3 | Protected-main provider and attester | AVO-004.7-C1 | New provider/attester adapter and fixtures; no live provider configuration mutation. | Parses exact repository, main base, PR, queue, queue generation, merge-group, protection/ruleset, admission, hold, check, and receipt observations; accepts PR-head admission success only from the isolated issuer after verifying PR/base/head, active required queue, max entries per group=1, expected base/merge method, no bypass/direct merge, issuer identity, and all admission evidence; after enqueue accepts group evidence only for exact sole-PR membership and exact group tree/topology; accepts group release transition only from the isolated issuer; App 15368 is validation-only; rejects stale/reused PR-head status, head/group transfer, wrong-SHA/App, stale, incomplete, duplicate, queue-disabled, unrelated queued PR, tree/topology mismatch, retargeted, direct-merge/bypass, and protection-drift observations. |
| AVO-004.7-C4 | Coordinator and recovery | AVO-004.7-C2, AVO-004.7-C3 | Phase A freezes contracts, append-only journal records, durable lease/fence/claim indexes, deterministic external identities, injected verifier capabilities, and narrow mutation capability protocols; later phases add the coordinator/recovery adapter and focused tests. No provider writes in Phase A. | Phase A proves each mutation intent and target-scoped unresolved-mutation reservation are committed atomically before provider dispatch; create-once receipts and atomic one-use release claim; durable main-lease expiry and fencing; deterministic admission/hold identities; capability separation with no coordinator merge authority; and read-only reconciliation after ambiguous dispatch. Successful/rejected authoritative observations resolve a reservation, while ambiguity keeps it open. The completed C4 implementation must enforce preparation-auth → publish/PR → isolated PR-head admission observation + successful non-release check → enqueue → distinct group pending-hold observation → one-use release-auth → last-moment issuer revalidation → isolated hold-success chronology; no provider queue/merge request follows release-auth; duplicate callers lease-fence; crash/timeout around admission/enqueue/auth/hold success reconciles read-only; regeneration creates a new attempt/composition and never transfers auth; successful replay is read-only. |
| AVO-004.7-C5 | Main rollback authority | AVO-004.7-C1, AVO-004.7-C3, AVO-004.7-C4 | New `MainRollbackAuthority`, inverse-delta contracts, and tests. No reset, force update, or direct ref update. | Uses identical preparation-auth → PR-head admission success → enqueue → distinct group pending hold → final release-auth → last-moment issuer revalidation → group hold-success order; computes exact inverse on the current main tip; protected result has expected inverse tree and one parent; advanced/conflicting/non-invertible state fails closed; replay and cleanup are idempotent. |
| AVO-004.7-C6 | Campaign runner and eligibility ledger | AVO-004.7-C4, AVO-004.7-C5 | New runner, frozen activation record, eligibility ledger, threshold accumulator, and evidence package writer. | Begins only after the fresh hosted main rollback drill. Enforces a gap-free scheduler sequence after the watermark: every ordinary nonempty submission is eligible from submission, including upstream integration/package failures, and receives an attempt plus terminal durable failure/reset disposition; later submissions cannot count while an earlier sequence is open; only independently classified empty/non-ordinary inputs are exclusions; no starvation/withholding or silent exclusion. |
| AVO-004.7-C7 | Deterministic offline gate | AVO-004.7-C1 through AVO-004.7-C6 | Offline harness, fault matrix, and result artifact only. No hosted mutation. | Crash/adversarial matrix covers duplicate lease, stale base, package drift, composition mismatch, check/queue/protection failures, provider ambiguity, wrong topology, rollback conflicts, cleanup ambiguity, and replay. Main remains unchanged and no deployment occurs. |
| AVO-004.7-C8 | Hosted organization/queue/release gate | AVO-004.7-C7 | Hosted workflow/configuration and operator-controlled state root only after explicit organization-hosting and isolated-release-issuer authority. | Final protocol is organization-owned required merge queue with max entries per group=1, exact sole authorized PR membership, `pull_request` and `merge_group` checks, durable one-use `MainQueueAdmissionObservation` plus PR-head non-release admission, then distinct group pending `avo-main-release` hold, mandatory isolated release issuer, exact merge-group evidence, fresh main rollback drill before ledger activation, and 12 consecutive eligible successes with 0 failures/boundary violations. Until both hosting and release-hold authority exist this leaf is blocked and may not mutate current `main`. |

## Contract and evidence boundary

The main namespace should expose typed equivalents of these records, with canonical JSON
and content-addressed child artifacts:

* `MainGraduationPlan`, `MainGraduationEligibilityRecord`, and `MainGraduationAttempt`;
* `MainSourcePackageBinding` for the canonical integration package and every child;
* `MainDeltaManifest` for sole parent/result identities, changed paths, exact tree, and
  ordinary-risk recomputation;
* `MainCompositionArtifact` for fresh main base and deterministic output;
* `MainQueueAdmissionObservation`, `MainQueueObservation`, `MainProtectionManifest`,
  `MainMergeGroupChecks`, `MainReleaseHoldObservation`, and `MainAttestationManifest`;
* `MainGraduationIntent`, reversible `MainPreparationAuthorization`, durable one-use
  `MainQueueAdmissionObservation`, one-use `MainReleaseAuthorization` (exact release-check
  run ID/nonce and queue generation), release-transition receipt, provider receipt,
  reconciliation, and completion package; and
* `MainRollbackAuthorization`, `MainRollbackIntent`, inverse artifact, receipt, and
  completion package.

All records bind the fixed repository/target identity, package and policy digests, exact
base and result topology, issuer/attester identities, isolation contract, operation and
lease IDs, and `deploy_performed: false`. The candidate cannot provide any authority-bearing
field. App 15368 is validation-only; the release issuer is a distinct mandatory isolated
principal.

## Phase gates

### Gate P0 — boundary freeze

Accept ADR 0011, freeze the target/ref/provider configuration, define the final protocol
assumptions, and record that current user-owned hosting blocks live main mutation. No
repository transfer or protection change is part of P0.

### Gate P1 — contract and composition proof

Accept C1–C3 only after schema, canonicalization, path/risk, package-child, and exact
composition tests pass. A composition result is not eligible for a hosted attempt until
provider and attester evidence can bind the exact merge group.

### Gate P2 — coordinator/recovery proof

Accept the live C4–C6 implementation after each durable boundary has crash/restart tests,
including the required end-to-end on-disk recovery fixture, duplicate-runner tests,
stale-base tests, and immutable artifact replay. The runner must emit a durable eligibility
ledger before counting any attempt toward the threshold.

### Gate P3 — offline rollback gate

Accept C7 only when the deterministic adversarial matrix passes, including a distinct
main-specific inverse-delta rollback authority. The completed AVO-004.6 integration
rollback package is a prerequisite input, never a substitute.

### Gate P4 — hosting and release-hold activation

P4 is blocked on two independent prerequisites. It requires an explicit operator decision
and authority to use an organization-owned repository with a required merge queue configured
for max one entry per group and exact PR-head admission/group-hold behavior, or a separately
reviewed exact-CAS writer design, **and** a dedicated least-privilege isolated release-check
issuer that can read only matching release authorization and transition only the exact
pending group-specific `avo-main-release` run. The activation record must pin repository
identity, protections/rulesets, queue generation, workflow/event configuration, App 15368
validation identity, release issuer/isolation contract, hold check, and rollback authority.
No current-host mutation or App 15368 action may be used to work around either blocker.

### Gate P5 — rollback drill, hosted threshold, and audit

After P4, run and pass the fresh hosted main rollback drill under the final protocol before
freezing ledger activation. Then freeze the campaign and enforce a gap-free scheduler
sequence: every post-watermark submission receives an eligible attempt or a terminal,
durable disposition. Count every eligible ordinary nonempty candidate; require 12
consecutive successes, 0 failures, and 0 boundary violations, complete per-attempt
evidence, final audit, and idempotent replay before declaring AVO-004.7 complete.

## Cross-cutting acceptance rules

* Any changed base, package, result, path manifest, policy/configuration, protection,
  queue, workflow, check identity, or attestation invalidates the current attempt.
  Regeneration, reorder, rerun, stale success, duplicate delivery, lost release receipt,
  or wrong release issuer invalidates the old release authorization; create a new pending
  hold and new attempt/composition. Never rerun release success. A stale/reused PR-head
  admission success cannot satisfy or transfer to a regenerated group.
* Any eligible failure, including failure before canonical integration package creation,
  timeout, quarantine, ambiguity, operator intervention, reset condition, or boundary
  violation resets the threshold streak to zero while preserving all evidence. Material
  protocol/configuration changes begin a new campaign.
* No result is complete from a provider success alone: exact main commit/tree/topology,
  queue/PR/check/protection receipts, cleanup, and replay must be durable.
* No ordinary path may include deployment or constitutional scope. Human intervention is
  recorded as an exception and prevents counting that attempt as a success.
* AVO-004.7 documentation and offline work can proceed while C8 is blocked; the current
  repository must remain unchanged by this gate.

## Required offline fault matrix

The deterministic gate must exercise, with durable expected outcomes, a crash immediately
before/after enqueue, immediately before/after preparation authorization, immediately
before/after release authorization, and immediately after isolated hold success. It must
also cover all other checks green before release authorization; merge-group regeneration,
queue reorder, check rerun, stale successful hold, duplicate delivery, lost release
receipt, wrong issuer, candidate-controlled fake hold/check, admission success, stale or
reused PR-head status, direct-merge/bypass refusal, exact PR-head/group separation,
unrelated queued PR, singleton violation, group-tree/topology mismatch, issuer last-moment
drift/expiry, rollback chronology, and upstream integration failure/reset/gap blocking.
The expected result is fail-closed reconciliation or a read-only completed replay; no test
may call release success twice or use App 15368 as the release issuer.

## Verification artifacts

Each accepted leaf supplies immutable links in the aggregate plan/result. The final audit
must be able to reconstruct the source package, exact delta, composition, queue/check
observation, lease/intent/authorization sequence, main result, rollback result, cleanup,
threshold ledger, resets/exclusions, and replay from the journal root without mutable
integration state.

See the [AVO-004.7 runbook](avo-0047-main-graduation-runbook.md) for the operator protocol.
