# AVO-004.7 protected-main graduation runbook

Status: activation and evidence runbook; C4 Phase A contract/journal gate complete on
2026-08-30 at HEAD `0cb20c50c43cd78f75b23da025e3bbe4e0f5ee78` with Terra approval; live `main`
mutation is blocked until both
organization-hosting/merge-queue capability and isolated release-hold authority are
explicitly authorized.

This runbook operationalizes [ADR 0011](adr/0011-protected-main-graduation.md) and the
[implementation plan](avo-0047-main-graduation-plan.md). It is limited to the declared
single-host, trusted-team boundary. It does not authorize deployment, production effects,
repository transfer, branch-protection mutation, or direct ref writes.

Phase A completion is contract/journal evidence only. The next ready gate is implementation
of the live coordinator/provider executor and its required end-to-end on-disk recovery fixture
for P2 coverage; no provider or `main` mutation is authorized by this status.

## 1. Activation prerequisites

Before any activation, the controller owner records a signed/content-addressed activation
record containing:

* the fixed repository identity and `refs/heads/main` target;
* the accepted ADR/plan digests and protocol/configuration epoch;
* the final provider, protected-main, queue, workflow, App 15368 validation identity,
  isolated release issuer, hold check, reviewer, evaluator, and rollback-authority
  identities;
* the release issuer's isolation contract: it may read only a matching
  `MainReleaseAuthorization` and transition only its exact pending `avo-main-release`
  check run; it cannot publish, enqueue, approve evidence, alter protections, or write a
  ref;
* the state/artifact root outside the checkout and credential-handling boundary;
* `deploy_performed: false` and an explicit production/constitutional path deny list; and
* the preregistered threshold: 12 consecutive eligible attempts, 12 successes, 0
  failures, and 0 boundary violations.

The current user-owned public repository cannot satisfy the preferred required merge-queue
protocol, and no isolated release-hold issuer has been authorized. Stop activation at this
point and mark the hosted leaf blocked on both prerequisites. An operator must explicitly
authorize organization-hosting authority or a separately reviewed exact-CAS writer design,
and separately authorize the dedicated least-privilege release issuer. Do not transfer the
repository, alter protections, enable a queue, create a main PR, or write `main` as an
implied implementation step. App 15368 is validation-only and cannot satisfy the release
issuer requirement. The isolated issuer is a bounded AVO-004.7 dependency under this
trusted-team boundary, not an automatic AVO-008 escalation.

After that authority exists, independently capture the organization-owned repository
identity, protected-main rules, required merge queue, and workflows triggered by both
`pull_request` and `merge_group`. GitHub's [merge queue documentation](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/incorporating-changes-from-a-pull-request/merging-a-pull-request-with-a-merge-queue)
describes availability for organization-owned public repositories. The [merge_group event](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#merge_group)
must report checks for the exact merge-group SHA.

## 2. Hosted rollback prerequisite (before ledger activation)

After both hosting prerequisites are authorized, run a fresh main rollback drill under the
final live protocol before freezing ledger activation. This drill is separate from the
AVO-004.6 integration rollback evidence and must use the final organization-owned queue,
exact PR-head admission success, a distinct group-specific pending `avo-main-release` hold,
exact merge-group checks, and isolated release issuer. It must use the complete chronology:
preparation authorization, PR-head admission success, enqueue, distinct group pending hold,
final release authorization, last-moment issuer revalidation, and group hold success. It
must pass current-tip-only inverse composition, protected queue mutation, exact result
tree/one-parent topology, cleanup, `deploy_performed=false`, and read-only replay. Any
advanced, conflicting, ambiguous, or non-invertible main state fails closed. A failed drill
blocks ledger activation and does not count toward the 12-run streak.

## 3. Freeze the eligibility ledger

At frozen activation, persist `EligibilityLedgerStarted` with the activation digest,
controller configuration digest, scheduler sequence watermark, and empty streak. For every
scheduler-submitted candidate after that watermark:

1. Record the submission and scheduler sequence before reading candidate content.
2. Classify it using controller-owned policy and trusted path/risk computation.
3. Mark every ordinary, nonempty candidate eligible at submission, including one that
   later fails or is quarantined before a canonical integration package exists. An
   operator may not skip a difficult, slow, or inconvenient candidate.
4. Record controller-derived exclusions with a reason and evidence digest. Only an
   independently classified empty or non-ordinary input may be excluded. Exclusions are
   not silent and cannot be manually backfilled later.
5. Bind the candidate to its canonical successful integration package when available.
   An upstream integration/package failure receives an immutable terminal failure/reset
   disposition for that eligible attempt; it is not reclassified as an exclusion.

The ledger is append-only and its scheduler sequence must be gap-free. The controller must
continuously reconcile the next sequence after the watermark: every ordinary nonempty
submission receives an eligible attempt from submission and a terminal durable disposition
(success, failed, quarantined, or reconciliation-required). Later submissions cannot count
while an earlier scheduler sequence remains open. Starvation, withholding, or silent
exclusion is a boundary violation and resets the streak. The threshold streak counts only
eligible full attempts. The controller, not the operator, derives eligibility, exclusions,
and resets.

## 4. Per-attempt preparation

Use a fresh controller-owned attempt ID and retain one state root. Verify and persist:

* canonical package digest and every child digest, issuer, completion state, and exact
  successful integration result;
* integration result sole parent, result tree, complete trusted changed-path manifest,
  ordinary risk recomputation, and exact deterministic delta;
* fresh current main commit/tree and protected-main, queue, repository, workflow, and
  check configuration manifests;
* immutable composed candidate commit/tree and parent identity; and
* reviewer/evaluator attestations bound to the package, composition, main base, and policy
  epoch. Exact merge-group evidence is collected only after enqueue.

Reject and retain evidence if the integration head is read as the source, if the package
is mutable/incomplete, if there is more than one integration-result parent, if the delta
cannot be inverted, if path/risk recomputation differs, or if any production or
constitutional path appears. Never repair the package by rereading a moving integration
branch.

## 5. Staged authorization and invariant checklist

Before candidate publication, PR creation, or enqueue, the coordinator must durably journal
the plan, claim the lease, record intent, and obtain a `MainPreparationAuthorization`.
Preparation authorization is reversible and permits only candidate publication, PR
preparation, and enqueue. It cannot authorize main mutation. Before enqueue, the active
required-merge-queue rule must be pinned, have maximum entries per group equal to 1,
forbid bypass/direct merge, and identify the isolated issuer. No merge-group evidence is
expected yet.

The attester must answer yes to these preparation checks:

| Check | Required observation |
| --- | --- |
| Source | Canonical successful integration package and all children; exact applied result |
| Composition | Sole-parent-to-result delta; exact tree/parent; deterministic composition digest |
| Scope | Complete trusted path manifest; ordinary risk; no production/constitutional paths; `deploy_performed=false` |
| Main | Current exact commit/tree and configured protected `main` ref |
| Candidate | Immutable candidate ref/commit/tree and package binding |
| Queue | Required merge queue enabled and same repository/target; current queue policy digest |
| Admission | After immutable PR-head verification, isolated issuer writes `MainQueueAdmissionObservation` and a successful non-release `avo-main-release` check on that exact PR-head SHA; it permits queue admission only |
| Queue rule | Required merge queue active; maximum entries per group=1; exact sole PR membership is required after enqueue; no bypass/direct merge; expected base and merge method |
| Checks before enqueue | No merge-group evidence is required or inferred before enqueue; PR-head success is never group evidence |
| Attestations | Independent reviewer and evaluator evidence bound to the same attempt |
| Durability | Plan, lease, intent, preparation authorization and all child digests durable before write |

Any no, unknown, stale, mismatched, duplicate, retargeted, or missing observation stops the
attempt and opens reconciliation. It does not create a new attempt to hide the condition.

After enqueue returns an exact group, the isolated issuer creates a NEW group-specific
pending hold run with a unique nonce. Persist `MainReleaseHoldObservation` with the exact
group SHA/tree/complete parents/base, queue-generation identity, exact sole authorized PR
membership, max-entries-per-group=1, hold run ID/nonce and pending status, all other
required checks, protection/ruleset evidence, and reviewer/evaluator attestations. All
other required checks must be complete, successful, fresh, and bound to that exact group
SHA. The PR-head non-release success never satisfies or transfers to the group. Only then
may the coordinator durably write a one-use `MainReleaseAuthorization` bound to that group,
queue generation, hold run ID/nonce, policy/configuration epoch, lease, and evidence
digests. The hold remains pending.

Only the isolated release issuer may read that exact authorization and transition that exact
hold run to success. The transition is the sole irreversible main-mutation trigger. App
15368 only validates; it cannot transition the hold. The coordinator performs no provider
queue/merge request after release authorization.

## 6. Hosted execution (only after activation is unblocked)

1. Publish the immutable candidate to the controller-owned ref and record the publication
   receipt. Reconcile an exact existing ref; quarantine a wrong or preseeded ref.
2. Create or reconcile exactly one same-repository PR targeting protected `main`. Verify
   repository, number, base ref/SHA, head ref/SHA, state, and draft status.
3. Verify active required-merge-queue rule, max entries per group=1, no bypass/direct
   merge, expected base/merge method, and isolated issuer identity. The isolated issuer
   verifies immutable PR/base/head and all admission evidence, then writes one durable
   `MainQueueAdmissionObservation` plus a successful NON-RELEASE `avo-main-release` check
   on the exact PR-head SHA. This one-use admission success permits queue admission only;
   it cannot mutate main or transfer to a group. A crash around admission success is
   read-only reconciliation.
4. Use `MainPreparationAuthorization` to enqueue exactly that authorized PR. Enqueue is
   reversible preparation. Capture queue admission receipt; reject any unrelated queued
   PR, group-size violation, unexpected base, merge-method drift, bypass, or direct merge.
5. Once GitHub creates a distinct merge-group SHA, the isolated issuer creates a NEW
   group-specific pending hold run with a unique run ID/nonce. The workflow executes for
   `merge_group`, checks out the event SHA, and reports validation contexts from App 15368.
   Record exact group SHA/tree/complete parents/base, singleton membership, and
   queue-generation identity. PR-head success never satisfies or transfers to this hold.
6. Read and persist the pending `MainReleaseHoldObservation`, all other required checks,
   protection/rulesets, reviewer/evaluator attestations, package, and composition evidence.
   All checks must be exact-group, complete, successful, fresh, and unique; head-SHA checks
   alone are insufficient. The exact group tree must equal deterministic composition.
7. Re-read main, PR, merge group, singleton membership, queue generation, protections,
   hold, and all checks. If any identity changed, regenerate composition and create a new
   pending hold under a new attempt; the old attempt gets terminal failure/reset and any
   final authorization cannot transfer.
8. After the final lease fence, persist one-use `MainReleaseAuthorization` bound to the
   exact hold run ID/nonce and group. Immediately before release, the isolated issuer must
   re-read the pending hold, group SHA/tree/membership, main base, queue/protection identity,
   all non-release checks, authorization expiry, and nonce. Only that issuer may transition
   the hold to success; persist a one-use transition receipt. Do not call a provider
   queue/merge endpoint after release authorization.
9. Observe main and record the resulting commit, tree, complete parent list, PR/queue
   state, check/protection receipts, cleanup, and `deploy_performed=false`.
10. Mark success only if the observed result is the exact deterministic tree with expected
   one-parent topology and all completion artifacts are durable. A provider response
   without observation is not success.

## 7. Live stop conditions

Stop immediately, preserve the state root, and open reconciliation on any of the following:

* current repository, target, protection, or queue identity differs from activation;
* package/child/result digest, sole parent, tree, path manifest, risk, or policy changes;
* candidate ref is wrong, preseeded, mutable, retargeted, or not same-repository;
* merge queue is missing, disabled, bypassed, permits direct merge, exceeds max entries
  per group=1, contains an unrelated PR, or produces no exact merge-group SHA;
* PR/base/head, expected base/merge method, admission evidence, admission issuer, or
  durable one-use `MainQueueAdmissionObservation` is stale, reused, duplicated, or wrong;
* workflow does not run on `merge_group`, checks attach only to a PR head, or App 15368's
  validation identity, SHA, name, status, conclusion, freshness, or uniqueness is wrong;
* the group tree/topology/base/membership differs from deterministic composition, or the
  group-specific `avo-main-release` hold is absent, already successful before final auth,
  rerun, stale, duplicated, reordered, controlled by a candidate, or issued by the wrong
  release issuer;
* reviewer/evaluator attestation is missing, stale, duplicated, or conflicted;
* main advances unexpectedly, topology is not exactly one parent, or the result tree is
  not the composed tree;
* provider response is timed out, ambiguous, unauthorized, partially persisted, or would
  require a retry; or
* cleanup, deployment state, credentials, lease, preparation/release authorization, or
  replay is ambiguous.

Do not delete evidence or rotate the operation identity to make a failed attempt disappear.

## 8. Recovery and idempotent replay

Recovery always loads the durable plan, package binding, lease epoch, intent, preparation
authorization, PR-head `MainQueueAdmissionObservation`, group hold observation, release
authorization, admission/transition receipts, provider attempt, and completion package
before any new preflight. It uses the same operation and state root.

* Before preparation authorization, no preparation or main mutation is presumed. A missing
  or stale prerequisite closes the attempt without a provider write.
* Preparation authorization permits only reversible publication/PR/enqueue. If enqueue is
  ambiguous, reconcile the same ref/PR/queue and never issue a second preparation write
  blindly.
* A crash before or after PR-head admission success reads the exact PR/base/head,
  admission check run, issuer, and queue configuration. If the durable one-use admission
  transition is observed, return its receipt or reconcile it read-only; never replay the
  admission success. Admission success permits queue admission only and cannot transfer
  to a later merge group.
* After release authorization, a crash or lost release receipt is an ambiguous mutation
  boundary. Read the exact hold, queue, merge group, PR, and main state. If the exact result
  is observed, record the receipt and completion; otherwise retain reconciliation-required
  state. Never rerun release success and never issue a post-auth queue/merge request.
* Regeneration, reorder, rerun, stale success, duplicate delivery, changed base/group,
  changed checks/configuration, singleton violation, or wrong issuer terminally fails/resets
  the old attempt and requires a new composition, new PR-head admission, new pending group
  hold, and new attempt. An old admission or final authorization never transfers.
* A duplicate runner must fail closed on the lease or return the durable result. A stale
  lease holder cannot heartbeat, authorize, or complete.
* A wrong existing ref/PR/queue object is quarantined. An exact existing object is adopted
  only when its durable authorization and all bindings match.
* Cleanup is a separate durable action. Unknown cleanup remains reconciliation-required;
  it is not treated as absent.

Replay of a completed operation must return the same plan, attempt, completion, and result
digests, issue no provider mutation, and leave `main` unchanged from the recorded result.

## 9. Main rollback drill

Rollback requires a separately issued main-specific rollback authorization. It must bind the
completed graduation package, failed/current main head, exact original delta, inverse
delta/tree, and final protocol epoch.

1. Observe current protected main and require the failed graduation result to be the current
   main tip. Rollback is current-tip-only; any advanced, conflicting, ambiguous, or
   non-invertible state fails closed.
2. Compute and persist the exact inverse delta. Reject a changed, conflicting, multi-parent,
   or non-invertible state.
3. Compose an immutable rollback candidate parented by the current main head.
4. Write `MainPreparationAuthorization`, create/reconcile one protected rollback PR, and
   verify its exact immutable PR/base/head. The isolated issuer writes the durable
   `MainQueueAdmissionObservation` and successful NON-RELEASE `avo-main-release` check on
   that exact PR-head SHA after admission evidence passes.
5. Enqueue exactly that authorized rollback PR. Once a distinct group exists, the isolated
   issuer creates a NEW group-specific pending hold; verify singleton membership, exact
   group SHA/tree/parents/base, queue generation, protections, and all other checks.
6. Write one-use rollback release authorization bound to that exact hold/group; immediately
   before release the isolated issuer revalidates pending hold, group, membership, main tip,
   queue/protection identity, non-release checks, expiry, and nonce. Only it may transition
   the hold. Make no post-authorization queue/merge request and recover ambiguity by
   observation.
7. Verify the inverse tree, exact one-parent topology, queue/PR/check/protection receipts,
   cleanup, and `deploy_performed=false`.

The offline rollback matrix is one required evidence class. This fresh hosted main rollback
drill must pass before frozen ledger activation. AVO-004.6's integration rollback evidence
is prerequisite lifecycle evidence, not a substitute for this drill.

## 10. Threshold, reset, and completion audit

For each eligible attempt append one immutable ledger outcome. Increment the streak only
after exact post-mutation observation, cleanup, replay, and evidence review succeed. A
failure, timeout, quarantine, ambiguity, operator intervention, reset condition, or
boundary violation resets the streak to zero; preserve all prior records and reason codes.
Any material protocol/configuration change also starts a new activation and campaign.

Completion requires:

* 12 consecutive eligible full attempts, 12 successes, 0 failures, and 0 boundary
  violations, with a gap-free scheduler sequence and every post-watermark submission
  accounted for by an eligible attempt or terminal durable disposition;
* deterministic offline crash/adversarial rollback matrix passed;
* one fresh hosted main rollback drill under the final queue protocol passed;
* final audit reconstructs every package, delta, composition, exact check/queue/protection
  observation, journal boundary, result, rollback, cleanup, reset/exclusion, and replay;
* no deployment or irreversible effect occurred; and
* independent reviewer/evaluator attestations approve the aggregate without relying on a
  proposing candidate's own claim.

If any completion condition is missing, leave AVO-004.7 in progress or blocked at the
specific gate. Do not mark AVO-004 complete.

## 11. Required deterministic fault tests

The offline matrix must exercise queue-admission behavior, stale/reused PR-head status,
wrong issuer, direct-merge/bypass refusal, exact PR-head versus group separation, unrelated
queued PR, singleton violation, and group-tree mismatch. It must crash immediately before
and after preparation authorization, admission success, enqueue, release authorization,
and hold success. It must also cover all other checks green before release authorization;
merge-group regeneration, queue reorder, check rerun, stale successful hold, duplicate
delivery, lost admission/release receipt, issuer last-moment drift/expiry, and a
candidate-controlled hold/check. Rollback must exercise the identical chronology. An
ordinary nonempty upstream integration failure must receive terminal failure/reset and
block later sequence counting until its disposition is durable. Each case must produce
durable fail-closed reconciliation or read-only replay. No case may transition release
success twice, allow App 15368 to release, or issue a provider queue/merge request after
release authorization.
