# Codex v1 calibration pilot

Status: completed on 2026-08-25. This is a small Codex-only calibration, not the preregistered provider comparison and not evidence of superiority.

## Design

- Run ID: `codex-v1-20260825T171313Z-7ebb0471`.
- Frozen three-task suite digest: `sha256:3ef992192adcf47a6bc1ab4021b236c585f2047a13394481c862e12f3ca601c2`.
- Runtime: signed `codex-live-wsl-v6` profile, `openai-codex==0.147.0`, exact `codex-cli 0.149.1`, model `gpt-5.6-sol`, ChatGPT Pro subscription.
- Tasks: rolling-window correctness, path-like identifier security boundaries, and exact proportional integer allocation.
- Repetitions: one per task.
- Candidate input: byte-stable seed tree, stored prompt, public tests, and documented API only.
- Hidden evaluation: stored outside the candidate workspace, mounted read-only into a separate networkless Docker evaluator after completion.
- Evidence: normalized runtime events, strict completion, source-tree digests, external-Git binary patch, public/hidden sandbox outcomes, usage observations, and wall time.
- OpenRouter/API credentials: not used.

The manifest, fixture digests, and frozen calibration fixtures are under `pilots/codex-v1`. The reusable runner verifies the lock before execution and is stored at `scripts/run_codex_pilot.py`.

## Result

| Task | Seed public | Seed hidden | Candidate public | Candidate hidden | Admitted | Codex wall time |
|---|---:|---:|---:|---:|---:|---:|
| rolling-window | pass | fail | pass | pass | yes | 40.06 s |
| identifier-boundary | pass | fail | pass | pass | yes | 86.57 s |
| integer-allocation | fail | fail | pass | pass | yes | 58.54 s |

Aggregate:

- 3/3 first-attempt admissions.
- 185.17 seconds of Codex turn wall time.
- 933 normalized runtime events.
- 225,211 reported total input tokens, including 166,912 cached input tokens.
- 5,599 output tokens, including 818 reasoning output tokens.
- 230,810 reported total tokens.
- Actual metered charge: none observed; billing mode was subscription.
- No transport failures, cancellations, reconciliation cases, boundary violations, or hidden-evaluator references appeared in the candidates.

The semantic patches were independently inspected and matched the documented contracts. Candidate test claims were not treated as admission evidence; the public and hidden networkless evaluators were authoritative for this calibration.

## Calibration finding and correction

The raw first-run patches include six generated `__pycache__/*.pyc` files because Codex ran tests and `compileall`. This did not affect correctness or hidden evaluation, but it inflated raw patch sizes and result-tree digests. The raw artifacts remain unchanged for auditability.

The runner now deterministically removes only regular `.pyc` files contained in `__pycache__` directories before hashing and diffing, and fails closed on symlinks or unexpected content. The Codex child also receives `PYTHONDONTWRITEBYTECODE=1` to prevent implicit cache creation. Future comparison arms will use this corrected normalization.

## Docker Desktop behavior

AVO evaluator containers are intentionally short-lived `docker run --rm` processes named `avo-<20-hex-digest>`. A reference scenario or pilot launches several in rapid succession for seed, development, admission, and adversarial checks.

The 48-hour Docker event review found 33 AVO container exits:

- 21 successful development/admission/benchmark evaluations.
- 12 exit-code-1 base-image runs corresponding to tests that intentionally verify hidden reads, host writes, or network access fail.
- No recurring background retry loop and no surviving `avo-*` container.

New evaluator containers carry:

- `dev.avo-correlate.component=evaluator-sandbox`
- `dev.avo-correlate.execution-id=<AVO execution ID>`

These labels make each brief container attributable in Docker Desktop and Docker event logs.

Concurrent native-Windows and WSL suites initially exposed a real shared-daemon race: the same logical execution ID produced the same deterministic container name. One run could therefore fail immediately while the other held the name. Container names now retain a stable execution hash but add a unique per-attempt suffix; the stable logical ID remains in the label. The exact conflicting test and both complete suites pass concurrently after the correction.

## Interpretation and next gate

The 3/3 result establishes that the live adapter is useful enough to justify a larger study. It does not estimate reliability: the tasks are small, synthetic, and each has only one repetition. Token overhead is material despite heavy cache reuse.

Before any provider comparison, freeze five additional tasks without tuning them against these results, define the full eight-task analysis and failure policy, and take immutable task/evaluator digests. When the OpenRouter model and account are selected, reuse the same frozen materials and equal limits for the native arm.
