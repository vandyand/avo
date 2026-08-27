# AVO Roadmap

Status date: 2026-08-27.

Review date: 2026-08-27.

Authority: This file is AVO's sole authority for outcomes, priority, sequencing, milestone status, and decision gates.

## Authority and maintenance

This roadmap governs what AVO should do next and what “complete” means. Implementation packets,
integration plans, ADRs, release records, and experiment results provide durable evidence but do not
override this file's current priority or status. GitHub Issues may later track execution and a GitHub
Project may visualize it; both remain derived views.

Every material roadmap update must preserve stable milestone IDs, link its evidence, update the
status date, and pass the project-local `avo-roadmap` validator. Review date records a deliberate
evidence audit and must be refreshed at least every 45 days. A candidate cannot mark its own
milestone complete: completion follows independent verification and the applicable promotion gate.

## North star

Make AVO a robust, reliable, performant, and capable evaluator-grounded system for sustained
autonomous software improvement. AVO should maximize useful improvement per unit of time, model
budget, and operator attention while keeping evaluation, policy, provenance, promotion, and
production authority outside the proposing agent's control.

## Current position

- Draft 3 phases 0–3 are complete for the declared single-host, trusted-team reference boundary;
  production hardening is selective and explicitly not a hostile-code security claim.
- Codex is the primary high-value variation runtime. The frozen one-repetition comparison admitted
  8/8 Codex candidates and 6/8 native/OpenRouter candidates; this is architecture evidence, not a
  statistical superiority result.
- The first full sanitized AVO-on-AVO candidate passed public and private evaluation, admission,
  exact reconstruction, and provenance verification. Its historical patch remains unapplied.
- Strict-JSON Luna advisory inference passed one bounded live canary and a ten-case offline gate;
  repeated live reliability remains unproven.
- The Windows workspace is now the controlling repository and has a public authenticated remote,
  a tagged clean baseline, a successful disposable-clone recovery rehearsal, and enforced
  server-side protection on `main`. Candidate workspaces remain intentionally VCS-free.
- Trusted hosted CI is green on Ubuntu and Windows. The canonical Linux gate passes all 373 tests
  at 85.40% branch coverage, and the native Windows portability gate passes 365 tests with one
  expected platform skip.

## Milestone register

| ID | Horizon | Status | Risk | Outcome | Exit gate | Depends on | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| AVO-001 | done | complete | protected | Deliver the evaluator-grounded local reference architecture through bounded agentic variation. | Draft 3 phases 0–3 pass their contract, security, recovery, parity, and end-to-end acceptance evidence. | — | [Implementation status](implementation-status.md), [Draft 3 packet](avo-correlate-implementation-packet-v3.md) |
| AVO-002 | done | complete | protected | Integrate Codex as a durable, subscription-authenticated coding-agent variation runtime. | The lifecycle, comparison, terminal-budget replay, recursive admission, reconstruction, and provenance gates pass. | AVO-001 | [Integration plan and result](avo-coding-agent-integration-plan-v2.md), [Recursive capstone](avo-improves-avo-capstone-v2-result.md) |
| AVO-003 | done | complete | standard | Establish a bounded strict-JSON inference boundary for inexpensive typed advisory operations. | The live canary and frozen offline corpus pass without granting policy, admission, mutation, or lifecycle authority. | AVO-001 | [Structured inference](structured-inference.md), [Offline evaluation result](structured-inference-evaluation-v2-result.md) |
| AVO-004 | now | in_progress | protected | Establish authoritative roadmap governance and human-on-exception autonomous source promotion. | Ordinary changes can progress from a clean Git base through protected deterministic and adversarial gates, integration soak, verified merge, and rollback evidence without routine operator approval. | AVO-002 | [Threat model](threat-model.md), [Git baseline v1](avo-004-git-baseline-v1-result.md), [Promotion policy ADR](adr/0007-promotion-policy.md), [Dry-run result](avo-004-promotion-dry-run-v1-result.md) |
| AVO-005 | next | ready | standard | Version the existing hybrid archive and population strategies and compare them under equal budgets. | ExperimentSpec v2 and an ADR freeze both methods, and a preregistered comparison determines whether either should change the default. | AVO-004 | [Search extension ADR](adr/0004-search-method-extension-gate.md), [Draft 3 roadmap](avo-correlate-implementation-packet-v3.md) |
| AVO-006 | next | planned | protected | Run bounded multi-generation AVO-on-AVO campaigns without making the operator the routine merge bottleneck. | Plateau detection, lineage limits, private regression promotion, autonomous ordinary-change promotion, and exception escalation pass a frozen campaign. | AVO-004, AVO-005 | [Recursive milestone](avo-improves-avo-milestone.md), [Integration plan](avo-coding-agent-integration-plan-v2.md) |
| AVO-007 | later | deferred | standard | Improve the native/OpenRouter coding loop only when portability, cost, or model-selection evidence justifies it. | A frozen trigger and targeted protocol evaluation show that the work resolves an observed decision-relevant limitation. | AVO-002 | [Comparison results](comparison-v2-results.md), [OpenRouter interface](openrouter-interface.md) |
| AVO-008 | gated | gated | production | Add distributed storage, orchestration, observability, policy distribution, and stronger isolation only at their production triggers. | Load, multi-host, trust-domain, recovery, observability, or hostile-code requirements activate the adapter-specific promotion criteria and all production release blockers pass. | AVO-004, AVO-006 | [Production boundary](implementation-status.md), [Threat model](threat-model.md) |

## Active milestone: AVO-004

### Objective

Replace routine human approval of AVO-on-AVO source improvements with a fail-closed, auditable,
risk-tiered promotion path. The operator handles exceptions and constitutional changes rather than
approving every ordinary patch.

### Delivery gates

| Gate | Status | Deliverable | Verification |
| --- | --- | --- | --- |
| AVO-004.1 | complete | Canonical `docs/roadmap.md`, project-local `avo-roadmap` skill, deterministic validation, and CI freshness enforcement. | Skill validation, roadmap validator tests, link audit, Ruff, and strict Pyright. |
| AVO-004.2 | complete | Green trusted CI baseline plus a controlling Git repository and remote, with candidate workspaces still VCS-free. | Hosted Linux/Windows CI, public repository, tagged commit/tree baseline, disposable-clone recovery, and enforced server-side `main` protection pass. |
| AVO-004.3 | complete | ADR defining risk classes, constitutional paths, reviewer independence, exception policy, and rollback limits. | ADR 0007, exported strict schemas, 85 focused policy tests, independent adversarial review, and the full trusted suite pass. |
| AVO-004.4 | in_progress | Dry-run promotion controller producing a content-addressed promotion bundle without merging. | [ADR 0008](adr/0008-dry-run-promotion-controller.md) and the [v1 result](avo-004-promotion-dry-run-v1-result.md) must pass deterministic replay, trusted-base evaluation, provenance, adversarial review, coverage, and compare-and-swap checks. |
| AVO-004.5 | planned | Automatic ordinary-change promotion to a protected integration branch. | Required trusted checks, independent review quorum, private regression evaluation, and integration soak all pass. |
| AVO-004.6 | planned | Rollback and failure drills with immutable evidence. | Injected stale-base, flaky-check, reviewer-disagreement, failed-soak, and revert scenarios fail closed and reconstruct. |
| AVO-004.7 | planned | Graduation of ordinary changes from integration to automatic protected-main promotion. | A preregistered clean-run threshold is met with zero boundary violations and successful rollback drills. |

The roadmap gate was completed first because the operator explicitly authorized it. The green test
and coverage baseline, controlling repository, public remote, baseline tag, recovery rehearsal, and
server-side `main` protection now pass. AVO-004.4 is implementing the first no-merge controller gate
on a protected feature-branch and pull-request path.

### Promotion policy target

- Low-risk documentation, tests, and internal refactors may promote automatically after their
  declared deterministic gates and an independent review.
- Ordinary behavioral changes require the complete trusted CI suite, frozen private evaluation,
  provenance reconstruction, two independent reviews, integration soak, and base-head
  compare-and-swap.
- Constitutional changes—including admission, policy, lifecycle, budgets, provenance, private
  evaluators, schemas, CI rules, dependencies, migrations, sandboxing, credentials, or the
  promotion controller—cannot approve themselves. They enter a separately authorized maintenance
  path and notify the operator only when the independent policy cannot resolve them safely.
- Production deployment and irreversible external effects remain outside autonomous source
  promotion until AVO-008 is activated and completed.

### Exit criteria

AVO-004 completes only when a clean controlling Git repository exists; roadmap drift fails CI;
ordinary changes can be classified, independently evaluated, reviewed, promoted, soaked, and
reverted through immutable evidence; protected changes fail closed into exception handling; and a
frozen evidence set demonstrates that the proposing agent cannot modify or bypass its own judge.

## Decision gates

- Start AVO-005 after the Git foundation and promotion-policy ADR make generated experimental
  changes recoverable and reviewable.
- Start AVO-006 only after AVO-004 and AVO-005 complete; multi-generation search magnifies weak
  promotion rules and should not precede them.
- Activate AVO-007 only for a concrete portability, model-choice, or cost decision.
- Activate AVO-008 only when its documented production trigger exists. Standard Docker remains a
  trusted-team isolation aid, not hostile-code containment.
