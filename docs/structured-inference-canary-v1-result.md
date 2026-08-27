# Structured inference advisory canary v1

Status date: 2026-08-27. Result: passed.

This was one sanitized, preregistered OpenRouter call using `openai/gpt-5.6-luna` at medium reasoning effort. There was no retry, fallback, Terra inference, Sol usage, policy decision, candidate mutation, or campaign state transition.

## Subject and result

The advisory operation reviewed retained candidate `fdf17fa5-e0e0-5b79-8d70-6abc6a0db7c7`, the two-file RuntimeInspection invariant patch previously admitted by the recursive campaign. The frozen patch digest was `sha256:fc3ad61cf2f72ea37732664586e1c9c03207489a80bceee7d33a8d66cbfe1c73`.

Luna returned `accept_with_follow_up` at 930,000 micros confidence. It recognized the centralized invariant as a valid bounded improvement and identified the preregistered test gap: the patch tests invalid combinations but lacks direct positive coverage for completed-with-completion and representative non-completed states. It made one low-severity testing finding and no unsupported high or critical finding.

The result therefore met the preregistered quality rule: at least two distinct themes, including a limitation/test-gap theme. It did not surface the two optional secondary themes—the pre-existing downstream campaign guard or the JSON Schema cross-field limitation—so this is evidence of useful bounded review, not comprehensive review.

## Mechanical and provenance gates

- The raw provider JSON validated against the exact compiled strict wire schema before Pydantic defaults could be applied.
- Candidate, changed-path, and evidence references passed local semantic validation.
- Exactly one invocation record was retained; provider `openrouter`, requested and resolved model `openai/gpt-5.6-luna`, finish reason `stop`, and no error.
- Usage was 1,836 input tokens, 479 output tokens, and 1,034 microusd provider-reported cost.
- No `OPENROUTER_API_KEY` marker was present anywhere in the retained run evidence.
- All checked content-addressed files existed and independently matched their SHA-256 names.

Evidence identifiers:

- input: `sha256:e59f3e0468802aebe6898466449f025c3835f24fc8a0ba5439ac4560322737c9`
- validated review bundle: `sha256:d310c190a4a1cbee0777b01566c6a2633a083c8ed73173676fcd5a61d4cd8ecc`
- invocation record: `sha256:8a0c5df1c5bdc5c4ec92af60b1338b4cfdd6f4c4113d87bc3bfba4d98fc3ca90`
- result manifest: `sha256:615d201255bd92bc978284ce64015b78f701a8b16ac0ca6dbe1111eaf38814f3`
- invocation ID: `3b9dfbf1-3d06-4a13-8caf-d74005e407b3`

The retained WSL evidence root is `/var/lib/avo/structured-inference-runs/20260827-runtime-inspection-luna-advisory-v1`. The checked-in rubric and evidence catalog are under `pilots/structured-inference-v1/`.

## Interpretation

This validates the first intended division of labor: Codex handles stateful implementation work, while a simple strict-JSON Luna call can cheaply produce a typed, evidence-bound advisory judgment. One favorable sample does not establish reliability, superiority, or production readiness. The next evidence milestone should evaluate several qualitatively different advisory tasks and measure theme recall, unsupported-claim rate, latency, and token cost without granting the advisory path any admission authority.
