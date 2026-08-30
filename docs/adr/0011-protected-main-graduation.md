# ADR 0011: Protected-main graduation boundary

Status: accepted for the AVO-004.7 architecture; implementation and hosted gate in progress.
Live `main` mutation is blocked by current GitHub hosting capability and missing isolated
release-hold authority.

## Context

AVO-004.5 established a protected, PR-native promotion lifecycle for the `integration`
branch. AVO-004.6 established durable leases, staged authorization, reconciliation,
exact-SHA attestation, and a separately authorized integration rollback. Those mechanics
are reusable, but they do not authorize onward promotion to `main`. The main boundary
needs a narrower authority surface and a stronger statement about the exact base being
validated and merged.

The declared boundary is the single-host, trusted-team repository. Deployment, secrets,
production effects, and irreversible external effects remain outside this ADR. A human
operator remains the exception and constitutional authority; the ordinary path must not
turn the operator into a routine approver.

GitHub's synchronous pull-request merge endpoint accepts a `sha` precondition, but the
documented precondition is that the pull-request **head** must match. It does not document
an exact-base compare-and-swap (CAS) at the merge call. See the official [merge a pull
request API documentation](https://docs.github.com/en/rest/pulls/pulls#merge-a-pull-request).
Strict required checks and an up-to-date branch reduce races, as described in GitHub's
[required status checks branch-protection rule](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-branch-protection-rules#require-status-checks-before-merging),
but are not an API-level exact-base CAS. Treating them as one would make the main gate
claim stronger atomicity than the provider documents.

The preferred hosted protocol is an organization-owned repository with required merge
queue protection. GitHub documents that merge queues are available for public repositories
owned by an organization (and for eligible private organization repositories) in [merging
a pull request with a merge queue](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/incorporating-changes-from-a-pull-request/merging-a-pull-request-with-a-merge-queue).
The current public repository is user-owned, and its current hosting capability does not
make that queue available. GitHub also requires workflows used by queue checks to listen
for `merge_group`; the [workflow events documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#merge_group)
defines the merge-group SHA and trigger, and the [required-status-check guidance](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks#status-checks-with-github-actions-and-a-merge-queue)
explains why omitting that event prevents a required check from being reported.

## Decision

### Main-specific authority boundary

Introduce a narrow `MainGraduationCoordinator` and a dedicated protected-main provider
and evidence namespace. They may consume a trusted canonical successful
`IntegrationCampaignEvidencePackage`, derive a main candidate, and prepare one protected
main release when all gates pass. Only the isolated release issuer may trigger the merge.
They may not widen integration-only provider contracts,
target selection, credentials, or integration schemas to include `main`.

The coordinator reuses the existing promotion engine's durable lease, intent, staged
authorization, provider-receipt, and reconciliation mechanics through adapters.
The adapter is main-specific and the target is controller-configured; candidate input
cannot select a provider, repository, branch, policy, evaluator, or authority.

Main evidence has its own media types, artifact roles, operation IDs, and journal index.
An integration package is an input and provenance anchor, never a main completion record.
Every main artifact binds the repository, `refs/heads/main`, the integration package
digest, exact main base commit/tree, candidate/result commit/tree/topology, protection
and queue manifests, attester identities, lease/intent/preparation-authorization/release-
authorization digests, and
`deploy_performed: false`.

### C4 Phase A contract freeze

The first coordinator increment is contract-only. It must not publish a candidate, create
or modify a pull request, enqueue, create or update a check/hold, transition a release
check, update a ref, or otherwise write to a provider. The coordinator has no provider
merge, ref-update, check-write, or release-issuer capability. Separate narrow capability
interfaces govern publication, PR preparation, enqueue, isolated admission issuance,
and isolated release issuance; typed evidence supplied by a caller is data for
verification, never authority.

Every externally meaningful action has an append-only intent-before-dispatch record and a
create-once receipt or reconciliation record. The journal is the source of truth for
attempt start, preparation, publication, PR, admission, enqueue, merge-group hold,
release, post-state, cleanup, and completion. It must expose durable main-lease evidence
with owner, operation, target, policy epoch, and expiry, plus a target-scoped unresolved
external-mutation fence. An open fence blocks overlapping attempts and all new writes;
recovery may only read and reconcile the provider until the ambiguity is closed.

Release authorization includes an atomic, durable, create-once claim bound to its exact
authorization digest, hold run/nonce, merge group, lease epoch, and isolated issuer.
Claiming is separate from dispatch, but once dispatch may have begun no recovery path may
issue a second release transition after a lost or delayed receipt. Authorization expiry
cannot exceed the lease expiry or configured maximum TTL. Admission and group-hold run
IDs/nonces are deterministic from the operation and exact external identities, including
the queue generation, so evidence cannot transfer across regenerated PRs or groups.
These Phase A rules make ambiguous external writes fail closed without guessing or
replaying a mutation.

### Canonical input and deterministic composition

The only eligible input is a trusted, immutable, canonical successful
`IntegrationCampaignEvidencePackage` with every child present and valid. The coordinator
must verify the package digest, child digests, issuer/domain policy, completion state,
integration result, and ordinary-risk classification before deriving any main candidate.

It derives exactly the integration result's sole-parent-to-result delta. It must never
promote the mutable integration head wholesale, copy an integration branch ref, or infer
a patch from a mutable working tree. The derived delta must have exactly one expected
parent (the recorded integration result parent), an exact result tree, a complete trusted
path manifest, and an ordinary risk recomputation. Constitutional, production, or
otherwise disallowed paths fail closed. Composition applies the delta deterministically
to a freshly observed main base and records the resulting tree and parent identity.

The main candidate is immutable after composition. A changed main base, source package,
delta, path manifest, policy, workflow, protection, queue, or check observation invalidates
the operation and requires a new package-bound attempt. No mutable integration head is
read as an implicit source after the canonical package has been accepted.

### Staged authorization and required invariants

Before candidate-ref publication, PR creation, or enqueue, the coordinator must durably
write a `MainPreparationAuthorization` bound to the package, composition, current main
base, lease, policy epoch, and reversible preparation scope. This authorization permits
only candidate publication, PR preparation, and queue admission. It cannot authorize,
trigger, or be read as permission for a main mutation.

Before preparation begins, the coordinator must have durable evidence for the following:

1. The canonical source package and all children are trusted, complete, immutable, and
   successful; the exact applied integration result is recorded. A scheduler-submitted
   ordinary nonempty candidate that fails before obtaining this package is still an
   eligible attempt and receives a terminal durable failure/reset disposition.
2. The sole-parent-to-result delta, exact tree, complete trusted path manifest, ordinary
   risk recomputation, and deterministic composition digest agree. No production or
   constitutional path is present, and `deploy_performed` is `false`.
3. The fresh main base commit/tree, protected-main manifest, required queue manifest,
   repository identity, and target ref are current and controller-pinned.
4. The candidate and its derived patch are immutable. The active required-merge-queue
   rule is pinned, has maximum entries per group equal to 1, forbids bypass/direct merge,
   and names the isolated issuer. No merge-group evidence is required or inferred before
   enqueue.
5. Independent reviewer and evaluator attestations are present for the declared ordinary
   trusted-team boundary. A human is not a routine approver and cannot replace missing
   machine evidence.
6. A durable plan, lease, intent, and preparation authorization exist in that order,
   each binding the same operation, package, base, candidate, evidence digests, and policy
   epoch. No `MainReleaseAuthorization` exists yet.

Missing, conflicting, stale, substituted, or ambiguous evidence is a fail-closed
reconciliation state, not a reason to retry with a new identity or relax a gate.

After `MainPreparationAuthorization` is durable, the PR is created and its immutable head
is observed, the isolated issuer first writes a durable `MainQueueAdmissionObservation` and
a successful **non-release**
`avo-main-release` check run on that exact PR-head SHA. The observation binds the PR/base/
head, active required-merge-queue rule, no-bypass/direct-merge decision, expected base and
merge method, issuer/isolation contract, preparation authorization, and all admission
evidence. The active queue rule also pins maximum entries per group to 1. This one-use
success transition and observation are durable and reconciled; it
permits queue admission only and can never authorize or trigger a main mutation. A crash
around admission success is read-only reconciliation.

The provider then enqueues the exact authorized PR. Once GitHub creates a distinct
merge-group SHA, the isolated issuer creates a **new** group-specific pending
`avo-main-release` hold run with a new run ID/nonce. The PR-head non-release success never
satisfies, transfers to, or is reused as group evidence. `MainReleaseHoldObservation`
binds the new pending run to the exact group SHA/tree/complete parent list, base SHA,
singleton membership (exactly the authorized PR and no unrelated entry), expected merge
method, queue-generation identity, all other required checks,
protection/ruleset manifest, and reviewer/evaluator attestations. The hold remains
pending/non-successful. The group tree must equal deterministic composition and its
topology must match the expected one-parent result. Only then may the coordinator durably write a single-use
`MainReleaseAuthorization` bound to the exact group, queue generation, hold run ID/nonce,
all evidence digests, and lease epoch.

Only the isolated release issuer may read that authorization and transition that exact
hold check to success. The transition is the sole irreversible main-mutation trigger;
the queue may merge as a consequence. App 15368 remains the validation identity only and
is not the release issuer. The coordinator performs no provider queue/merge request after
writing release authorization. A release authorization is one-use, cannot be transferred
to a regenerated group, and is invalid if the hold is rerun, reordered, stale, duplicated,
or issued by the wrong identity.

Any base, group, check, queue, protection, workflow, or configuration regeneration
terminally marks the old eligible attempt as failed/reset (while retaining its evidence),
requires a new composition and new pending hold, and issues a new attempt identity. No
old final authorization may transfer, and the release issuer must never rerun a prior
release-success transition.

Immediately before that transition, the isolated issuer must re-read and compare the exact
pending hold run, group SHA/tree/membership, current main base, queue-generation identity,
protection/ruleset and queue configuration, all required non-release checks, authorization
expiry, lease epoch, and release nonce. Drift, regeneration, expiry, duplicate delivery,
wrong issuer, or any changed identity rejects the transition and resets the attempt. The
issuer persists a one-use release-transition receipt. A lost receipt is read-only
reconciliation and never a second hold-success call.

### Preferred hosted mutation protocol and current blocker

The preferred live protocol is:

1. An organization-owned repository enables required merge queue protection on `main`,
   sets maximum entries per group to 1, forbids bypass/direct merge, and pins the
   `avo-main-release` context to the isolated release issuer.
2. The trusted validation workflow runs for both pull requests and `merge_group` events,
   checks out the exact merge-group SHA, and reports allowlisted validation checks for that
   SHA from App 15368. The isolated issuer verifies the PR/base/head and admission
   evidence, then writes the successful non-release PR-head admission observation/check.
3. The provider creates or reconciles one same-repository PR and enqueues that exact
   authorized PR. Enqueue yields a distinct group; the isolated issuer creates a new
   pending hold run with a unique nonce on that group. The coordinator verifies singleton
   membership (exactly that PR), group SHA/tree/complete parents/base, expected merge
   method, queue generation, all other checks, protections, and attestations, while the
   hold remains pending. The group tree must equal deterministic composition.
4. The coordinator writes the one-use release authorization. Only the isolated release
   issuer reads it and transitions that exact hold run to success. That transition is the
   sole irreversible trigger; no post-authorization queue/merge request is made.
5. The coordinator observes the resulting `main` commit, tree, and complete parent list,
   then records queue/PR/check/protection receipts and cleanup evidence.

The current public repository is user-owned and does not expose the required merge queue
under its present hosting capability. Therefore live main mutation is blocked. No transfer
of repository ownership, branch-protection mutation, queue enablement, or main write is
authorized by this ADR. An operator must explicitly authorize a move to an organization
that meets the hosting requirement, or authorize a separately reviewed exact-CAS writer
design. Until then, offline implementation and evidence work may proceed, but no hosted
AVO-004.7 attempt may mutate `main`.

The isolated release-check issuer is mandatory for AVO-004.7, not an optional future
hardening step. It must be a dedicated least-privilege GitHub App or equivalent isolated
principal whose only relevant authority is to read a matching durable
`MainReleaseAuthorization` and transition the one pinned `avo-main-release` check run.
It may not publish candidates, alter protections, enqueue, approve its own evidence, or
write a ref. This is a bounded AVO-004.7 hosting dependency under the current trusted-team
boundary, not an automatic AVO-008 escalation. App 15368 remains validation-only.

### Post-mutation and replay obligations

After the isolated issuer transitions the hold to success, recovery must treat the boundary
as an ambiguous mutation until authoritative state is observed. The coordinator must
observe and durably bind:

* the exact resulting main commit, tree, and one-parent topology;
* queue, PR, merge-group, check, repository, and protection receipts;
* queue-admission observation and both SHA-specific `avo-main-release` check receipts;
* `deploy_performed: false` and unchanged deployment state;
* candidate-ref/PR cleanup, with cleanup ambiguity retained for reconciliation; and
* a content-addressed completion package whose replay is read-only and returns the same
  result.

A reported provider success without exact post-mutation observation is incomplete. A
timeout or lost acknowledgement is unknown; recovery reads authoritative state and never
blindly repeats the write.

Recovery loads and reconciles the durable preparation authorization, queue-admission
observation/check, group hold observation, release authorization, and transition receipts
in order. A crash before or after admission success reads the exact PR-head SHA and
admission run without replaying its success; a crash after hold success is an ambiguous
mutation boundary resolved by read-only observation. Admission, hold, and release
transitions are never rerun or transferred to another SHA.

### Main rollback authority

Rollback is not an integration promotion with a different target. A separate
`MainRollbackAuthority` consumes a completed main-graduation package and an explicit
rollback authorization, computes the exact inverse of the recorded delta, and applies it
through a protected PR/merge-queue operation to the current main. It never resets,
force-pushes, directly updates a ref, or assumes that the old main head remains current.
The rollback PR is parented by the current main head and its result must have the expected
inverse tree and one-parent topology. Rollback is current-tip-only: any advanced,
conflicting, ambiguous, or non-invertible main state fails closed and requires exception
handling.

AVO-004.6 integration rollback is prerequisite evidence for lifecycle and recovery
mechanics, not evidence of this main-specific rollback authority. AVO-004.7 requires both
a deterministic offline crash/adversarial rollback matrix and at least one fresh hosted
main rollback drill under the final live protocol before completion.

The rollback authority uses the identical chronology: preparation authorization, exact
PR-head admission observation and successful non-release admission check, enqueue, distinct
group-specific pending hold, final release authorization, last-moment isolated-issuer
revalidation, and group-hold success. It is current-tip-only and never uses a direct ref
update, reset, force push, or post-authorization merge request.

### Preregistered completion threshold

Before frozen activation, complete and record the deterministic rollback matrix and at
least one fresh hosted main rollback drill under the final live protocol, then record a
campaign plan and eligibility rule. The hosted gate
requires 12 consecutive eligible full integration-to-main graduation attempts, 12
successes, 0 failures, and 0 boundary violations. Every scheduler-submitted ordinary,
nonempty candidate after activation is eligible from submission, including one that fails
before a canonical integration package exists; that upstream failure receives terminal
durable failure/reset evidence. Exclusions are only independently classified empty or
non-ordinary inputs, durable, and auditable; operators may not select only easy candidates.
Later submissions cannot count while an earlier scheduler sequence lacks a terminal
disposition. Any eligible failure, timeout, quarantine, ambiguity, operator intervention,
reset condition, or boundary violation resets the streak to zero without deleting evidence.
Any material protocol or configuration change starts a new campaign and threshold.

## Alternatives considered and rejected

* **Call the synchronous PR merge endpoint with head-SHA and strict checks.** Rejected as
  the formal main atomicity guarantee: the documented SHA binds the PR head, not an exact
  base CAS. It remains suitable only for a separately reviewed weaker boundary.
* **Promote the integration branch head wholesale.** Rejected because the integration
  ref is mutable and can contain unrelated or later results. The canonical package's
  sole-parent delta is the only source.
* **Widen the integration provider/contracts to target `main`.** Rejected because it
  couples two authority domains and makes accidental main writes possible. Main gets
  dedicated contracts, provider, attesters, and rollback authority.
* **Direct ref update, force push, reset, or local fast-forward.** Rejected because it
  bypasses protected review, queue, exact merge-group checks, and topology receipts.
* **Treat branch protection alone as an exact-base CAS.** Rejected: strict required checks
  reduce stale-base risk but do not supply a documented atomic API precondition.
* **Transfer the repository or mutate protections automatically.** Rejected for this
  gate because no such operator authority was supplied. Hosting transfer is a prerequisite
  decision, not an implementation side effect.
* **Use a custom exact-CAS writer immediately.** Deferred. It may be considered only as a
  separately reviewed provider design with equivalent protection, attestation, recovery,
  and rollback evidence.

## Consequences

The architecture is conservative about the boundary that can mutate `main`: the source is
immutable, composition is reproducible, every write is durable and single-writer fenced,
and ambiguous remote state is observable rather than guessed. The cost is a new contract
namespace, provider and rollback implementation, queue-aware hosted CI, and a hosting
decision before any live main write. The 12-run threshold intentionally measures ordinary
traffic rather than curated examples. Deployment and irreversible effects remain out of
scope.

## Related evidence

* [AVO roadmap](../roadmap.md)
* [PR-native integration promotion ADR](0009-pr-native-integration-promotion.md)
* [Exact-SHA attestation ADR](0010-exact-sha-attestation-and-failure-drills.md)
* [AVO-004.7 implementation plan](../avo-0047-main-graduation-plan.md)
* [AVO-004.7 runbook](../avo-0047-main-graduation-runbook.md)
* [AVO-004.6 live failure-drill result](../avo-0046-live-failure-drill-result.md)
