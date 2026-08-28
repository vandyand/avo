# ADR 0009: PR-native protected integration promotion

Status: Proposed for AVO-004.5 (boundary freeze; does not complete AVO-004.5)

## Context

AVO-004.4 produces an immutable, content-addressed dry-run bundle. AVO-004.5 adds one
bounded mutation: promoting an ordinary candidate to a protected integration branch.
The mutation must retain the evidence, provenance, reviewer-independence, and
compare-and-swap assumptions established by ADR 0007 and ADR 0008 without granting
the controller direct `main`, deployment, or production authority.

## Decision

Promotion is PR-native. For each allowed bundle, a trusted apply service creates or
uses a temporary candidate ref and one pull request targeting the one configured,
protected integration branch. The candidate cannot choose the target ref, provider,
policy configuration, evaluator, or credentials. The apply service does not update
the integration ref directly, force-update any ref, merge to `main`, deploy, or
perform onward promotion after the integration merge.

Apply is controller-exclusive and single-writer. A durable lease, identified by a
lease identity and digest, serializes AVO apply operations for the repository and
integration branch. The lease and its expiry are included in the durable intent and
completion evidence. This serializes AVO's own applies; native protected-branch
rules remain authoritative for races with other actors.

The ordering is mandatory. Because the provider does not expose a synthetic merge
until a PR exists, PR preparation precedes the immutable AVO-004.4 bundle:

1. Verify and durably journal the controller-published candidate, pinned repository
   identity, temporary candidate ref, exact integration base/head, and candidate tree.
2. Create or reconcile exactly one same-repository PR targeting the configured
   integration branch. Re-read its repository, number, base ref/SHA, head ref/SHA,
   open state, and draft state. A PR that fails a later prerequisite remains an
   observable, non-mergeable preparation artifact; it is never evidence of approval.
3. Discover the provider's exact synthetic merge SHA/tree, semantic branch-protection
   configuration, allowlisted required checks, App IDs, and freshness. Persist the
   provider-produced canonical check and protection manifests by content digest.
4. Verify that frozen private regression evaluation, provenance reconstruction,
   independent reviewer quorum, rollback evidence, and the bounded pre-merge
   integration soak are all present, trusted, current, and bound to the exact
   candidate, integration base, and discovered synthetic merge. The soak evaluates
   the synthetic integration result; it is not a post-merge onward-promotion gate.
   Reconstruct and verify the resulting exact AVO-004.4 bundle and canonical digest.
   A base/head change, PR retarget, head rerun, or other evidence-invalidating change
   requires a fresh discovery, evaluation, and bundle.
5. Bind the immutable bundle marker to that same PR, re-read it, and require the
   complete repository/ref/commit, check, review, protection, and marker identity to
   remain unchanged.
6. Immediately before the single merge request, re-read the exact integration head,
   protection configuration/evidence, PR head/base, strict required-status result,
   bundle bindings, and the pinned `main` branch protection. The `main` protection
   must require at least one approving review and enforce administrators (no
   administrator bypass). Any mismatch stops without a merge; the canonical main
   protection digest is carried into the durable promotion receipt.
7. Durably record a completion plan and operation intent, including bundle digest,
   publication and PR identity, all evidence refs, the pre-campaign `main` head,
   lease identity and
   digest, PR identity, exact base/head, synthetic merge SHA/tree, and the intended
   squash operation. After the final lease fence succeeds, durably record a mutation
   authorization bound to the intent and lease immediately before entering the one
   provider PUT. The authorization record is the irreversible local commit point:
   before it exists, recovery must not infer success from remote state; after it
   exists, the already-validated one-shot operation remains authorized even if its
   acknowledgement is lost or the lease later expires. No unbounded provider read
   occurs between that local commit point and the PUT. Only after the intent and
   mutation authorization are durable may the service submit one merge request for
   that PR. A timeout or transport ambiguity after authorization is an unknown
   outcome: observe the PR and integration ref before any retry. If observation
   proves that no merge occurred, discard the old eligibility/intent cycle and
   create a fresh one; the persisted intent is never blindly replayed.
8. After a reported merge, observe the integration ref and record the resulting
   commit, PR state, checks, and evidence-manifest digest. Merge using squash only:
   the resulting integration commit is expected to differ from the PR head, while
   its tree must equal the candidate/synthetic tree and its first parent must equal
   the expected protected integration base. The complete observed parent list must
   contain exactly that one parent; an external second parent is a reconciliation
   failure, never a successful promotion. Observation repairs a missing
   acknowledgement; it does not authorize a second merge.

The GitHub pull-request merge API's `sha` precondition protects the PR head SHA; it
does not compare-and-swap the base SHA. The immediate full observation and protected
branch checks narrow that race but cannot eliminate a malicious retarget between the
last read and the merge request. During this gate, `main` therefore requires an
independent approving review, so the campaign identity cannot turn a retargeted PR
into an autonomous `main` merge. Any target change observed before or after the call
is a boundary violation and reconciliation condition.

GitHub's reference-update behavior is not an expected-old-SHA CAS. Its `force=false`
mode requests a fast-forward update and rejects overwriting work; therefore this ADR
does not treat a refs PATCH as the mutation primitive. The hosted guard is the exact
PR head/base recheck together with protected-branch required-status enforcement and
the single PR merge request. GitHub documents that required checks must pass before
a protected branch can be merged, and that status checks apply to the latest commit.
See [Git references](https://docs.github.com/en/rest/git/refs), [status checks](https://docs.github.com/en/pull-requests/reference/status-checks),
and [protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches).

## Authority and evidence boundaries

The proposing agent owns neither the policy inputs nor trusted attestations. Trusted
CI, private evaluation, provenance, review, rollback, branch-protection, and soak
verifiers produce evidence; the apply service reconstructs and binds it to the
bundle. The private evaluator package, cases, credentials, and raw secret-bearing
logs never enter the candidate ref, PR body, comments, bundle, or persistent apply
logs. Only digests and approved metadata are retained.

The authoritative completion record is immutable and content-addressed. It includes
the bundle digest; repository and integration ref identity; pre- and post-merge
heads; candidate ref and PR identity; protection and required-check evidence;
controller/config/decision/provenance digests; all gate and reviewer evidence;
rollback evidence; synthetic merge SHA/tree; allowlisted check names, App IDs, and
freshness; soak telemetry; operation idempotency key; lease identity/digest; and the
observed merge/reconciliation result. A successful merge is not complete until the
resulting integration head is observed and this record is durable.

The apply state is one of `ready`, `intent_recorded`, `applied`, `already_applied`,
`stale_base`, `not_applicable`, `invalid`, or `reconciliation_required`.
Missing, stale, malformed, conflicting,
untrusted, or protection-drift evidence is reconciliation, not approval. A remote
timeout, lost acknowledgement, or partial persistence is also reconciliation; the
service must never blindly repeat the merge. A known stale base has no mutation.

## Consequences

Ordinary changes receive one hosted, protected integration mutation while retaining
the dry-run bundle as the decision and evidence boundary. PR status checks and exact
head/base observations provide the hosted mutation guard, but do not claim an
arbitrary API-level CAS. Duplicate delivery is idempotent by publication and
operation keys. Publication, completion-plan, lease, intent, mutation-authorization, receipt,
provider-final-evidence, and package records are durable before the next irreversible
boundary. Ambiguous publication or merge delivery is resolved by observing
authoritative remote state, never by blindly repeating the write.

The controller remains unable to change `main`, deployment, production, policy,
credentials, private evaluators, or other constitutional scope. Branch-protection
drift fails closed. The integration branch may contain an applied candidate while a
completion record is being reconciled; that condition is observable and cannot be
treated as onward promotion.

## Deferred work

AVO-004.6 owns injected stale-base, flaky-check, failed-soak, timeout/partial-success,
and rollback/revert drills with immutable evidence. AVO-004.5 does not authorize
post-merge promotion to `main`, deployment, or production; that remains outside this
boundary until the roadmap activates the applicable later gate.
