# AVO + Codex comparison v2 results

Date: 2026-08-25

## Outcome

The one-repetition diagnostic favors the Codex interface on this frozen suite:

| Arm | Hidden admissions | Public tests | Mean task time | Total task time |
| --- | ---: | ---: | ---: | ---: |
| Codex coding-agent runtime | 8/8 (100%) | 8/8 | 75.9 s | 607.4 s |
| AVO native / OpenRouter | 6/8 (75%) | 8/8 | 155.6 s | 1,245.1 s |

Six pairs admitted in both arms. Two admitted only in Codex. None admitted only in the native arm. The paired exact McNemar p-value is 0.5; with eight tasks and one repetition, this is descriptive evidence, not a superiority finding.

## Per-task results

| Task | Codex | Native | Codex time | Native time | Native cost |
| --- | ---: | ---: | ---: | ---: | ---: |
| rolling-window | pass | pass | 55.44 s | 54.40 s | $0.007078 |
| identifier-boundary | pass | fail | 88.73 s | 274.82 s | $0.043167 |
| integer-allocation | pass | pass | 74.56 s | 116.48 s | $0.017100 |
| bounded-backoff | pass | pass | 40.09 s | 64.73 s | $0.008430 |
| interval-union | pass | fail | 51.68 s | 304.00 s | $0.049187 |
| dependency-order | pass | pass | 98.19 s | 107.38 s | $0.014558 |
| event-reconciliation | pass | pass | 89.65 s | 166.95 s | $0.021161 |
| configuration-overlay | pass | pass | 109.08 s | 156.28 s | $0.020646 |

OpenRouter's actual provider-reported cost was $0.181327 for 80 model invocations, 130,215 input tokens, and 124,605 output tokens. The post-run account balance was $10.602051. Codex used the `vandyand@gmail.com` Pro subscription with no API token; its runtime events reported 646,050 input tokens and 27,467 output tokens, but no directly attributable dollar cost. These token counters are interface-specific and are not a clean billable-token comparison.

## What v2 fixed

The v2 run was frozen only after both interfaces passed end-to-end canaries. It changed the native harness in four material ways:

- Replaced the nested `arguments_json` string with typed tool arguments.
- Added a broker-owned, atomic `replace_text` operation that preserves newline convention and rolls back on policy failure.
- Returned bounded evaluator stdout and stderr to the agent while retaining their content-addressed artifacts.
- Captured provider identity, usage, and cost before validating the assistant turn, preserving billing evidence for malformed responses.

The configuration-overlay prompt and docstring now explicitly require `ValueError` for non-string keys. Both arms passed that corrected task.

## Native-arm failure analysis

### identifier-boundary

The session exhausted all 20 turns without changing the workspace. Luna repeatedly requested `read_file` with corrupted path suffixes such as `?`, `.json?`, or other stray characters. The broker correctly rejected those paths. This is an interface-generation failure rather than a benchmark or evaluator failure.

### interval-union

The candidate patch itself was correct: public and hidden evaluation both succeeded. The session was still not admitted because it never produced a valid terminal proposal. After making the successful edit, Luna continued issuing malformed paths and failed exact replacements. Its final response filled the path field with a long sequence of NUL characters, hit the 4,096-token output limit, and omitted required turn fields. The gateway recorded the response and its provider usage before rejecting it.

These failures show that the remaining native bottleneck is not primarily code generation. It is reliable tool selection, argument emission, and terminal-state control.

## Interpretation

Using the same Luna base model does create a useful interface comparison. Here, Codex's agent runtime was both more reliable and about twice as fast end to end. The native loop was nevertheless capable: it solved six of eight tasks for eighteen cents, with strict workspace boundaries and independently verified outcomes.

One run cannot estimate stochastic variance. The v2 outcome should therefore guide architecture, not serve as a model leaderboard. It also compares complete interfaces: Codex has richer orchestration and coding utilities, while the native arm deliberately exposes a small structured tool vocabulary.

## Recommended next implementation

Keep both interfaces, but give them different roles:

1. Use Codex as the primary implementation/search agent for high-value variations.
2. Retain the native OpenAI-compatible adapter for inexpensive bounded variations, provider portability, and controlled experiments.
3. Replace the single union-shaped strict JSON turn with provider-native function/tool calling, where each tool has its own argument schema. Luna officially supports both function calling and structured outputs, and this should remove the awkward requirement for every unused argument field to be present as null: <https://developers.openai.com/api/docs/models/gpt-5.6-luna>
4. Add broker-side argument repair only for unambiguous syntax noise: exact known-path canonicalization and rejection of control characters. Record both raw and normalized values. Do not silently guess among multiple files.
5. Add a deterministic terminal controller: after a successful evaluator run, request only a proposal/stop response; if a candidate already passes and a later model turn is malformed, preserve the failure in research mode but allow an explicitly configured production recovery policy.
6. Add a compact workspace inventory with stable file IDs so tool calls can reference an enum-like identifier rather than regenerate paths.

Before adding broader production features, implement items 3–6 and run a small targeted protocol evaluation. A later multi-repetition benchmark should be reserved for a genuinely changed adapter or a model-selection decision; repeating this exact v2 run immediately would add cost without resolving the observed protocol defects.

## Evidence

- Frozen suite: `pilots/comparison-v2/manifest.json`
- Content lock: `pilots/comparison-v2/digests.json`
- Preregistered execution lock: `pilots/comparison-v2/run-lock.json`
- Machine-readable analysis: `pilots/comparison-v2/analysis.json`
- Reproducible analyzer: `scripts/analyze_comparison.py`
- OpenRouter run: `comparison-v2-openrouter-comparison-r1-20260825T213922Z-8d966859`
- Codex run: `comparison-v2-codex-comparison-r1-20260825T220053Z-cde26e35`
