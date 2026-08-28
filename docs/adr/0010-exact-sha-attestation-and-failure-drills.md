# ADR 0010: Base-controlled exact-SHA attestation and failure drills

Status: accepted for the architecture and deterministic offline proof; AVO-004.6
gate remains incomplete pending hosted canary and protected rollback.

## Context

The AVO-004.5 live campaign proved the protected integration promotion lifecycle, but
it also exposed a boundary mismatch: ordinary pull-request checks were attached to the
PR head while the promotion invariant is defined over the provider's exact synthetic
merge commit. The temporary validation-ref/workflow-dispatch bridge recovered that
campaign, but it is not a sufficient production attester. AVO-004.6 must make the
identity boundary repeatable and exercise the failure modes around it without allowing
an injected failure to become an approval.

The design is for the current trusted-team, single-repository boundary. It is not a
claim that arbitrary hostile code, repository administrators, or a compromised CI
control plane can be contained by the reference implementation. The production
triggers and escalation boundary are explicit below.

## Decision

### Exact-SHA attestation

The attester validates one immutable observation assembled from the provider:

* the pinned repository identity and target `refs/heads/integration`;
* the exact base ref/commit/tree, PR head ref/commit/tree, and synthetic merge
  commit/tree;
* every required check context, including its exact check-run `head_sha`, App ID,
  completion status, successful conclusion, and controller-derived freshness; and
* the semantic target-branch protection manifest, including strict required checks,
  review and administrator rules, linear history, and disabled force-push/delete
  capabilities.

The check allowlist is controller-owned and currently pins the two required contexts
to App 15368:

* `avo synthetic validate (ubuntu-latest)` / App 15368
* `avo synthetic validate (windows-latest)` / App 15368

The names, App ID, repository, target ref, and one-hour freshness window are not
request-selectable. A check attached only to the PR head, a different synthetic SHA,
an unexpected App, a stale or incomplete run, a duplicate context, or a protection
drift is rejected or quarantined for reconciliation. The attester never substitutes
head-SHA evidence for synthetic-SHA evidence.

### Base-controlled workflow and immutable external pin

The trusted workflow runs only on the deterministic ref
`refs/heads/avo/validation/<operation-digest>`. It checks out `github.sha`, verifies
that the checked-out commit is exactly the event SHA, and runs the full Ubuntu and
Windows validation surface. The workflow itself is treated as a trusted input only
when its blob digest equals the administrator-set repository variable
`AVO_TRUSTED_WORKFLOW_SHA256`. That external digest is lowercase SHA-256 over the
workflow blob on the controlling base and is checked before validation work begins.

The external digest complements, rather than replaces, the pinned controller
configuration, candidate-authority guard, branch protection, and exact provider
observation. A workflow change requires an explicitly authorized maintenance update
of the external variable followed by a fresh hosted verification. A candidate cannot
alter the variable or use a non-deterministic branch to select trusted workflow code.
The workflow uses immutable action SHAs and does not persist checkout credentials.

The current workflow is [synthetic-validation.yml](../../.github/workflows/synthetic-validation.yml).
Its exact check names and App identity remain a deployment/configuration invariant and
must be captured in the durable check manifest for every operation.

### Durable create authorization and recovery

The validation operation is provider-neutral and content-addressed by the complete
request. The service in
[synthetic_validation_service.py](../../src/avo_correlate/application/synthetic_validation_service.py)
must follow this order:

1. Validate the observation and derive the deterministic operation ID and validation
   ref.
2. Durably record an immutable plan before any provider mutation.
3. Read the validation ref and reconcile an exact or wrong existing object.
4. Atomically claim the durable `SyntheticValidationCreateAuthorization` index. Only
   the claimant may issue the one create request.
5. Record the attempt and perform one provider create. A timeout or transport error
   is unknown; the service reads and reconciles and never blindly retries the POST.
6. Persist the typed outcome, including the observed commit/tree and artifact links.

The authorization is the local single-writer fence, not evidence that the remote POST
succeeded. A crash after authorization is therefore read-only recovery. An exact
existing ref can reconcile; a wrong ref is invalid/quarantined; an absent ref remains
`reconciliation_required`. A pre-existing exact ref without the durable authorization
is quarantined as preseeded and is never adopted as trusted evidence. Cleanup is a
separate operation and requires a durable completion proof bound to the operation,
plan, and package artifact. Cleanup ambiguity is retained for later reconciliation.

The validation contracts are defined in
[synthetic_validation.py](../../src/avo_correlate/contracts/synthetic_validation.py),
with filesystem durability in
[synthetic_validation_journal.py](../../src/avo_correlate/adapters/artifacts/synthetic_validation_journal.py).

### Early authority guard

Before candidate publication, PR creation, validation-ref creation, or any other
hosted mutation, the controller derives risk from the trusted changed-path manifest.
Constitutional and production scope is denied or escalated before remote writes. This
includes policy, admission/lifecycle/budget/provenance controls, schemas, CI and
workflow rules, dependencies, evaluators, credentials, sandboxing, migrations, and
promotion-controller code. A candidate cannot self-authorize an ordinary path by
omitting or changing the manifest. The live runner's preflight applies the same guard.

### Failure-drill evidence

Cases 1--8 are represented by strict, versioned contracts and content-addressed
artifacts. Each case binds the repository, integration target, operation, main before
and after identity, target result identity/topology, attester identity, and
`deploy_performed: false`. The aggregate result must contain each case exactly once,
reconstruct from its plan and artifacts, and prove that `main` did not change.

The deterministic offline harness uses the real promotion, policy, provider-parser,
synthetic-validation, rollback, and journal boundaries with controlled transports and
faults. It is evidence of state-machine behavior and idempotence, not proof that a
hosted GitHub account, workflow, branch-protection configuration, or network boundary
behaves correctly. A live hosted canary and a live protected rollback remain required
before this ADR can support an AVO-004.6 completion decision.

### Trusted-team boundary and escalation

This ADR is valid for a trusted team that controls the repository, branch protections,
the `AVO_TRUSTED_WORKFLOW_SHA256` variable, App 15368, and the attester credentials.
The boundary must be escalated to a dedicated least-privilege GitHub App, with
independent installation/configuration ownership and check-run authority, when any of
the following becomes true:

* repository or CI writers are not all trusted operators;
* multiple autonomous writers can race the validation namespace or mutate workflow,
  protection, or repository variables;
* AVO must attest untrusted candidate code in a shared repository;
* the current personal/account-scoped provider credentials or App 15368 cannot be
  isolated to the attester's exact repository and checks;
* the project requires multi-host concurrency, durable remote coordination, or an
  auditable key/installation rotation boundary; or
* production deployment, secrets, irreversible external effects, or a hostile-code
  threat model is activated.

Until that escalation is implemented and independently verified, the temporary bridge
must not be reclassified as production attestation and exact-SHA evidence must remain
fail-closed.

## Consequences

The exact synthetic commit becomes the sole trusted validation subject. This prevents
head-versus-synthetic evidence substitution and makes duplicate delivery, lost
acknowledgements, preseeded refs, and cleanup ambiguity reconstructable. The cost is
additional provider reads, durable records, strict configuration maintenance, and a
required hosted verification step. A base-controlled workflow can be operated without
granting candidate code authority over the workflow or repository variable, but it
still depends on trusted repository administration; the dedicated-App escalation is
therefore a boundary change, not an optional implementation detail.

The failure drills make no claim of production completion. They provide a repeatable
offline gate, while the live canary must verify the workflow digest, exact App/check
identity, branch protection, ref lifecycle, and real recovery behavior.

## Alternatives considered

* **Keep the workflow-dispatch bridge.** It is useful as a historical recovery aid but
  leaves a mutable, separately-triggered ref as the source of trusted checks and does
  not establish a durable production attester.
* **Trust checks on the PR head.** This is cheaper, but it does not attest the exact
  synthetic merge tree that the protected merge operation evaluates.
* **Use only a local controller digest.** A local pin is insufficient if a remote
  workflow can be changed independently; the external base-controlled digest gives the
  hosted boundary an immutable comparison point.
* **Use a direct ref update for validation or rollback.** Direct ref mutation bypasses
  the PR-native protected operation and weakens topology, review, and branch-protection
  evidence. Both validation publication and rollback remain narrowly scoped and
  provider-appropriate; rollback uses the normal protected PR/squash path.
* **Adopt a dedicated GitHub App immediately.** This is the stronger hostile or
  multi-writer architecture, but it adds key management and installation operations
  not required for the current trusted-team gate. The escalation triggers above make
  the migration decision explicit.

## Related evidence and implementation

* [PR-native integration promotion ADR](0009-pr-native-integration-promotion.md)
* [AVO-004.5 live campaign result](../avo-0045-sanitized-live-result.md)
* [AVO-004.6 failure-drill runbook](../avo-0046-failure-drill-runbook.md)
* [AVO-004.6 offline drill result](../avo-0046-offline-drill-result.md)
* [integration drill service](../../src/avo_correlate/application/integration_drill_service.py)
* [rollback drill service](../../src/avo_correlate/application/integration_rollback_service.py)
* [case-8 attester drill service](../../src/avo_correlate/application/integration_attester_drill_service.py)
* [drill contracts](../../src/avo_correlate/contracts/integration_drill.py)
