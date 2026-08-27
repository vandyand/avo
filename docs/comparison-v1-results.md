# AVO + Codex comparison-v1 results

Date: 2026-08-25

## Outcome

The frozen, paired Luna/high experiment completed all 48 first-attempt runs without replacement
runs. Codex admitted 21 of 24 attempts (87.5%). The AVO native OpenRouter interface admitted 15
of 24 (62.5%). Both arms used the same requested base model and reasoning effort, so the observed
difference is primarily evidence about the complete interfaces around the model—not a comparison
of different base-model intelligence.

| Result | Codex | OpenRouter native |
| --- | ---: | ---: |
| Hidden-evaluator admissions | 21/24 | 15/24 |
| Public evaluator successes | 24/24 | 22/24 |
| Runtime errors | 0 | 3 |
| Mean wall time | 78.69 s | 173.58 s |
| Median wall time | 69.76 s | 132.01 s |
| Nearest-rank p95 | 118.33 s | 440.99 s |
| Total sequential task time | 31.47 min | 69.43 min |
| Metered provider cost | Subscription; not assigned | $0.551825 |

OpenRouter remained well funded. The post-run balance was $10.8717, above the locked $2 floor.
The account-level usage increase was $0.610509, while request-level provider records attributed
$0.551825 to the formal runs. The $0.058684 difference is deliberately left unallocated because
the account balance is not a request-attribution ledger.

## Paired results

Across the 24 task/repetition pairs:

- both admitted: 15;
- Codex only: 6;
- OpenRouter native only: 0;
- neither admitted: 3.

The attempt-level exact McNemar value is 0.03125. It must not be read as a general superiority
claim: repetitions are clustered within only eight tasks. At task level, Codex was better on two
tasks, OpenRouter was better on none, and six tied. The suite is diagnostic, not large enough for
a broad population claim.

| Task | Codex | OpenRouter native | Audit interpretation |
| --- | ---: | ---: | --- |
| rolling-window | 3/3 | 3/3 | Both stable |
| identifier-boundary | 3/3 | 0/3 | Native schema/transport interface failed |
| integer-allocation | 3/3 | 0/3 | Native edit/test loop failed or exhausted |
| bounded-backoff | 3/3 | 3/3 | Both stable |
| interval-union | 3/3 | 3/3 | Both stable |
| dependency-order | 3/3 | 3/3 | Both stable |
| event-reconciliation | 3/3 | 3/3 | Both stable; native latency was high |
| configuration-overlay | 0/3 | 0/3 | Hidden evaluator is under-specified |

## What failed and why

### Native `identifier-boundary`

All three attempts ended in a model-gateway validation error after several successful turns. The
provider returned a structured turn whose `arguments_json` string contained source-code quoting
and escaping that was not valid inner JSON. AVO therefore rejected the turn before executing the
edit. The provider responses and their billed usage were preserved, and the analysis recovered
their request-level cost from the response artifacts.

This is an AVO interface weakness. Encoding a tool argument object as a JSON string inside the
outer strict-JSON response makes complex code edits unnecessarily fragile.

### Native `integer-allocation`

Two attempts exhausted all 20 turns without landing an edit. One landed a candidate that passed
public tests but failed hidden evaluation, then ended without a valid proposal. The trajectories
were dominated by failed `replace_text` and `apply_patch` calls, especially exact-match,
hand-authored diff, and trailing-blank-line failures. The native evaluator also returned only
pass/fail and exit code, giving the agent less debugging information than Codex receives from its
shell and test output.

This is principally tool ergonomics and observability overhead, not evidence that Luna could not
reason about the task.

### `configuration-overlay` benchmark defect

All six arm/repetition candidates implemented recursive merge, deletion, isolation, and nested-key
validation. They raised `TypeError` for a non-string key. The hidden evaluator requires
`ValueError`, but neither the task prompt nor the public API docstring specifies the exception
class. Penalizing those candidates is not justified by the stated contract.

The raw preregistered score remains unchanged. As a sensitivity check, removing this ambiguous
task yields Codex 21/21 and OpenRouter native 15/21, so it does not create the six-attempt gap.

## Usage interpretation

Codex reported 2,151,807 input tokens and 84,278 output tokens through its runtime events.
OpenRouter reported 351,811 input tokens and 388,463 output tokens across 219 invocations. These
figures are not apples-to-apples: the two runtimes account for cached context and reasoning tokens
differently. Wall time, admission, and actual OpenRouter provider cost are safer cross-interface
measures.

The most defensible conclusion is that Codex's mature coding-agent interface made the same Luna
model substantially more reliable and about 2.2 times faster on this suite. The native interface
already matched Codex on five well-specified tasks, so its basic architecture is viable; its
remaining gap is concentrated in structured tool transport, editing ergonomics, and diagnostic
feedback.

## Recommended comparison-v2 work

1. Replace `arguments_json: string` with a real typed argument object or provider-native tool
   calls. Validate the outer turn and tool-specific argument schema separately.
2. Promote exact replacement into `WorkspaceToolBroker` as an atomic, policy-checked operation.
   Preserve the original newline convention and roll back on post-write policy failure.
3. Return bounded, sanitized public-evaluator stdout/stderr to the native agent, not only status
   and exit code. Public test output is development evidence, not hidden-evaluator leakage.
4. Preserve provider request ID, usage, cost, and the underlying parse error before validating the
   agent turn. Partial failed sessions should expose accumulated usage directly.
5. Correct `configuration-overlay`: either specify `ValueError` in the contract or accept both
   conventional exception types. Freeze a new task/suite digest; never rewrite comparison-v1.
6. Add adversarial adapter tests for nested quotes, backslashes, multiline code, trailing newlines,
   tool-schema errors, and partial provider responses.
7. Run comparison-v2 on the corrected interface and a larger task set. Keep the same-model pairing,
   then add the deferred raw strict-JSON baseline as a separate arm once its OpenRouter model is
   selected.

Production-only orchestration should remain deferred until comparison-v2 shows that the native
editing and evaluator loop is reliable. Security boundaries, evidence retention, credit floors,
and account isolation are already appropriate to keep; autoscaling, remote scheduling, durable
queues, multi-tenant controls, and operational dashboards should come after interface correctness.

## Evidence

- Frozen suite digest: `sha256:19e60770f7741ec8dfad5cba7f1caf3bbc552ae0d48a946e0d714d097aceff04`
- Frozen run-lock digest: `sha256:22c8bef379acccf2953d32f99befdd6121d700a4a781937091dd9b2ce5ac6beb`
- Codex run IDs:
  - `comparison-v1-codex-comparison-r1-20260825T191105Z-580a20b7`
  - `comparison-v1-codex-comparison-r2-20260825T200913Z-a4ee7331`
  - `comparison-v1-codex-comparison-r3-20260825T202127Z-66616dd2`
- OpenRouter run IDs:
  - `comparison-v1-openrouter-comparison-r1-20260825T192116Z-08001663`
  - `comparison-v1-openrouter-comparison-r2-20260825T194358Z-13032524`
  - `comparison-v1-openrouter-comparison-r3-20260825T203239Z-2756fef8`
- Machine-readable aggregate: `pilots/comparison-v1/analysis.json`
- Reproducible analyzer: `scripts/analyze_comparison.py`
