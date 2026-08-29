# AVO-004.6 failure-drill runbook

Status: completed runbook and decision record for the AVO-004.6 gate.

This runbook turns the [AVO roadmap's AVO-004.6 sequence](roadmap.md#avo-0046-failure-drill-sequence)
into an evidence protocol. It deliberately separates deterministic offline proof from
the hosted proof collected by the completed live drill. The offline result remains a
separate evidence class rather than a substitute for the real GitHub canary, protected
integration promotion, and authorized rollback recorded in the
[live result](avo-0046-live-failure-drill-result.md).

## Scope and invariants

The v1 drill target is the pinned repository identity and exactly
`refs/heads/integration`. The harness must start from a clean trusted base, use a
controller-owned state/artifact root, and retain the immutable plan, per-case records,
aggregate result, and replay output. Every case must prove:

* `main_before_commit == main_after_commit`;
* `deploy_performed == false`;
* exact repository, target-ref, operation, and attester identity bindings;
* successful outcomes have content-addressed evidence; and
* a second invocation is read-only and returns the durable result or a durable
  reconciliation state.

The implementation entrypoint is
[`scripts/run_avo0046_drills.py`](../scripts/run_avo0046_drills.py), backed by the
[integration drill service](../src/avo_correlate/application/integration_drill_service.py),
[rollback drill service](../src/avo_correlate/application/integration_rollback_service.py),
and [case-8 attester drill](../src/avo_correlate/application/integration_attester_drill_service.py).

## Evidence classes

### Offline deterministic proof (available from the local harness)

This proves contract validation, state-machine ordering, single-writer fences,
content-addressed journaling, parser strictness, replay idempotence, and the
no-deploy/main-unchanged invariant under controlled provider transports and clocks.
It does not prove hosted GitHub behavior.

Required records are the typed `IntegrationDrillPlan`, one
`IntegrationDrillCaseResult` for each case 1--8, linked soak/rollback/attestation
artifacts where applicable, and a typed `IntegrationDrillResult` with a recomputed
`result_digest`. The runner's compact JSON is a pointer; the journal/artifact root is
the evidence authority.

### Live hosted proof (completed)

A trusted operator ran a sanitized canary against the public repository and
protected `integration` branch after the implementation/workflow is published. The
live package must capture the controlling-base workflow blob digest and repository
variable match, exact synthetic commit/tree, both check sets and their enforcement
authority, freshness, protection manifest, PR/base/head identities, provider receipts,
and ref cleanup. The protection manifest must show the normal App 15368 PR-head
contexts `validate (ubuntu-latest)` and `validate (windows-latest)` as its required
checks. Separately, the base-controlled workflow must produce the trusted App 15368
contexts `avo synthetic validate (ubuntu-latest)` and `avo synthetic validate
(windows-latest)` on the exact synthetic merge SHA for strict controller validation;
these exact contexts are not branch-protection-required contexts.
It must then exercise one real integration soak failure and an explicitly authorized
rollback through the normal protected PR/squash promotion path. The live package must
prove the rollback result has exactly one parent equal to the failed integration head,
the authorized restore tree, and no change to `main`.

Both evidence classes were independently reviewed, the exact-ref mechanism is bounded by
the pinned GitHub Actions App 15368 check identity executing the base-controlled workflow,
and replay produced no additional provider mutations. The exact identities are retained in
the live result.

## Case matrix

| Case | Injected condition and expected behavior | Offline evidence | Live hosted evidence / disposition |
| --- | --- | --- | --- |
| 1. Duplicate runners | Two concurrent callers race one durable lease. Exactly one applies; the other fails closed or returns the durable completed result. | Barrier-controlled concurrent `IntegrationPromotionService` calls; lease artifacts, one provider mutation, two typed outcomes, aggregate binding, and read-only replay. | Two independent live invocations using one state/operation identity; provider PR/merge history must show one mutation and the duplicate must reconcile without a second merge. |
| 2. Stale base/head CAS | Protected integration moves after the planned base. Promotion refuses without merge or target mutation. | Controlled stale-head provider response through the real promotion service; `stale_base` report, no mutation receipt, durable error, main/target identity. | Move or arrange a harmless protected-branch head race in a disposable canary; capture provider rejection, unchanged target/main, and replayable intent. |
| 3. Check identity/freshness | A protection-required PR-head check is missing or unsuccessful, or a trusted exact check is stale, incomplete, duplicated, attached to the PR head only, or from the wrong App/SHA. GitHub's protection gate and AVO's controller gate each reject their respective failures. | Real `GitHubIntegrationProvider` parser against controlled transports; normal PR-head protection checks plus exact synthetic success and head-only, wrong SHA/App, stale, incomplete, and duplicate-context trusted-check rejection scenarios. | Protection manifest must require normal App 15368 `validate (ubuntu-latest)` and `validate (windows-latest)` contexts on the PR head. Separately, the base-controlled workflow must post App 15368 `avo synthetic validate (ubuntu-latest)` and `avo synthetic validate (windows-latest)` contexts on the exact synthetic SHA; controller evidence must show success and freshness. Repeat at least one rejected identity condition without weakening either gate. |
| 4. Reviewer/quorum/private evaluation | Reviewer disagreement/insufficient independent quorum or failed private evaluation cannot approve. | Typed quality adapter and `PromotionPolicy.classify` denial; durable case record with issuer/domain/reason evidence. | Candidate PR with real independent review/evaluation inputs; capture no-merge rejection and immutable evidence, then a separate valid canary only if the operation is authorized to continue. |
| 5. Provider/auth interruption | Mutation acknowledgement is lost or provider/auth boundary is interrupted. Recovery observes state and never blindly repeats. | Controlled ambiguous provider mutation through `IntegrationPromotionService`; durable intent/authorization, reconciliation read, one mutation count, `already_applied`/reconciliation result, replay. | Interrupt or induce a bounded transport/auth ambiguity around a disposable PR operation; reconcile the real PR/ref and prove no duplicate merge or lost receipt. Preserve credentials outside artifacts. |
| 6. Wrong topology | External two-parent result, wrong parent, or wrong tree is not accepted. Target remains safe. | Controlled provider result through the real promotion service; topology reconciliation record and unchanged target/main. | Inspect a real protected result's complete parent list and tree after canary promotion; any mismatch must halt and reconcile, not be interpreted as success. |
| 7. Failed soak and rollback | Integration soak fails; a separately authorized restore is promoted through protected PR-native flow; main remains unchanged. | `DeterministicFailedIntegrationSoak`, rollback authorization/intent/receipt contracts, exact failed-head parent, restore tree, receipt, replay, and main-before/after binding. | Real failed integration soak artifact, explicit rollback authorization, new rollback commit parented by failed integration head, protected PR/squash merge, exact result tree/one-parent topology, unchanged main, and durable provider receipt. |
| 8. Production-boundary attester | Temporary exact-ref/workflow-dispatch bridge is replaced or bounded by base-controlled exact-SHA attestation. | `IntegrationAttesterDrillService` joins synthetic-ref service and provider parser; one create, exact accepted scenario, head-only/wrong App/SHA/stale/incomplete/duplicate rejection, attester identity, and replay. | Published base-controlled workflow plus external workflow digest variable; live exact-SHA canary and cleanup, exact App 15368 check evidence, protected configuration, workflow/action SHAs, and independent re-audit. Dedicated App proof is required if an escalation trigger applies. |

## Offline procedure

1. Select a fresh controller-owned journal root and record the trusted base identities.
2. Run the harness twice with the same root:

   ```text
   uv run python scripts/run_avo0046_drills.py --root <controller-state>/avo0046-drills
   uv run python scripts/run_avo0046_drills.py --root <controller-state>/avo0046-drills
   ```

3. Validate that the first run reports all eight case IDs and a non-null aggregate
   result digest. The second run must report the same operation/plan/result digest and
   zero additional provider mutations.
4. Independently load the journal and recompute every plan, artifact, case, and result
   digest. Check that the case IDs are exactly 1 through 8 and that `main` and deploy
   invariants hold.
5. Run the focused unit/security tests for the synthetic-validation, integration-drill,
   rollback, attester, hosted-provider, and campaign boundaries, followed by Ruff and
   strict Pyright. Retain command versions and the test report digest with the package.

The offline package should be marked `deterministic-offline-proof`, never `live` or
`production-attestation`.

The current recorded package is the [AVO-004.6 offline drill result](avo-0046-offline-drill-result.md).
It records operation `sha256:b0309f521a56f4a2fabf438d7f203deea8d00d49ecb35cbc5adfb3bad24996c8`,
plan `sha256:e09ae69810ef096eff316ce4f8749d46f6933315f4dfe35628816e3c82d782a5`,
and result `sha256:a7176851aa1cdc1a7d615439b8e4dc23aa39fb2e493ddbe0b89dce6e6498ac7e`.
Fresh A, replay A, and fresh B are identical; cases 1--8 completed, with the
`111...` main invariant unchanged and no deployment. This is local evidence
under controlled transports; the hosted canary and protected rollback below
remain required.

## Live procedure and stop conditions

The live procedure is authorized only after the implementation is published through
normal repository controls and the base-controlled workflow variable is set from the
workflow blob on that controlling base. Use a harmless ordinary candidate and a fresh
state root. Capture, before cleanup:

* repository, branch-protection, PR, base/head, synthetic commit/tree, and result
  identities;
* exact workflow blob digest and external variable comparison;
* both check sets, their App IDs, status/conclusion, completion timestamps, and
  freshness decision: GitHub-required normal `validate (...)` contexts on the PR
  head, plus controller-validated `avo synthetic validate (...)` contexts on the
  exact synthetic SHA;
* durable validation plan, create authorization, attempt/outcome, package, promotion
  intent/authorization/receipt, soak, rollback, and final observation artifacts; and
* the final validation-ref cleanup response and a read-back proving no wrong ref was
  deleted.

Stop and preserve the state root on any stale base, retarget, missing or unsuccessful
PR-head protection check, missing/mismatched exact trusted check, workflow digest
mismatch, unexpected exact context in branch protection, protection drift, ambiguous
provider mutation, unexpected parent/tree, duplicate mutation, main change, cleanup
ambiguity, or credential-boundary failure. Recovery uses the same state root and
durable identities; it does not mint a new operation to hide ambiguity.

## Gate decision record

Decision: pass on 2026-08-29. The [offline package](avo-0046-offline-drill-result.md) and
[live hosted result](avo-0046-live-failure-drill-result.md) are linked from the roadmap
and were independently reviewed. The live result records:

* exact implementation, workflow, protected-base, and repository-variable bindings;
* offline operation, plan, result, and replay digests;
* hosted canary and rollback PR, commit, check, protection, and cleanup identities;
* independent adversarial approval with no P0/P1 residual; and
* explicit proof that `main` was unchanged and `deploy_performed=false`.

AVO-004.6 is complete. AVO-004.7 may begin under its own preregistered exit gate.
