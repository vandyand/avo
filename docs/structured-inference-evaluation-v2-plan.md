# Structured inference evaluation v2 plan

Status date: 2026-08-27. This plan defines an offline evidence milestone. It authorizes no provider call, campaign mutation, admission decision, or production infrastructure change.

## Objective and stopping condition

Build a deterministic advisory-review corpus and scoring harness that exercises successful reviews and every important rejection boundary without contacting a model provider. The milestone is complete only when the frozen corpus contains at least six qualitatively different cases, at least three substantive review categories, all required failure modes, a reproducible aggregate report, content-addressed result evidence, and clean focused plus full canonical WSL gates.

## Architecture

1. Add versioned strict contracts for a corpus case, theme expectation, forbidden claim, severity expectation, per-case score, aggregate score, and result manifest. These are evaluation records only and must expose no policy, admission, mutation, or lifecycle authority.
2. Store each sanitized case as JSON under `pilots/structured-inference-v2/cases/`. A case contains the bounded `AdvisoryPatchReviewInput`, a recorded provider observation, its expected processing stage, and its private deterministic rubric.
3. Represent recorded observations explicitly as one of: JSON review text, malformed JSON text, refusal, or truncated response. JSON review text is parsed with duplicate-key rejection, checked against the same compiled strict wire schema used by live inference, then Pydantic-validated and semantically bound to the case input.
4. Score themes using frozen, case-insensitive literal marker groups over canonical review text plus any required finding category and evidence references. Score forbidden claims the same way. This deliberately measures rubric recall on recorded outputs; it does not pretend to perform semantic grading.
5. Treat severity calibration as a bounded rule over matched findings: an expectation declares a target category/evidence binding and an allowed severity range. Missing or out-of-range findings are reported deterministically.
6. Aggregate expected-stage accuracy, strict-schema validity, semantic validity, theme recall, unsupported-claim rate, and severity-calibration accuracy using integer micros. Preserve all case results and source digests.
7. Add an offline CLI that verifies a frozen corpus lock, evaluates every case in stable order, writes the canonical report through the filesystem content-addressed store, and emits a small manifest linking the corpus, report, and case digests. It must contain no network or provider adapter path.

## Corpus matrix

The v2 corpus will contain ten cases so each concern is independently attributable:

| Case | Category or boundary | Expected result |
|---|---|---|
| correctness invariant | correctness | accepted review with required correctness theme |
| missing positive tests | testing | accepted review with test-gap theme |
| path traversal guard | security | accepted review with evidence-bound security finding |
| compatibility break | compatibility | accepted review with bounded compatibility finding |
| insufficient evidence | evidence quality | valid `no_conclusion` review without invented claims |
| fabricated evidence reference | semantic boundary | semantic rejection |
| omitted required strict fields | wire boundary | strict-schema rejection before defaults |
| malformed JSON | parse boundary | parse rejection |
| provider refusal | provider boundary | refusal recorded as expected unavailability |
| truncated output | provider boundary | truncation recorded as expected unavailability |

All patches and identifiers are synthetic and sanitized. Existing frozen pilot fixtures and locks remain untouched.

## Verification and evidence

- Unit tests cover contract bounds, corpus parsing, duplicate keys, exact wire validation, semantic binding, marker matching, forbidden claims, severity rules, aggregation, lock drift, stable ordering, and CAS linkage.
- A corpus integrity test proves the declared matrix, stable IDs, content lock, and absence of authority fields and credential markers.
- The standalone CLI generates the checked-in offline report and independently verifiable digests without network access.
- The released suite digest is a CLI trust anchor; a self-consistent replacement lock requires an explicit separately trusted digest. Credential-bearing JSON fields and credential-like recorded text are rejected before scoring or persistence.
- The report records the evaluator identity/version and the exact compiled advisory wire-schema digest so a scorer or schema change is machine-visible.
- Ruff, strict Pyright, schema regeneration parity, existing AgentTurn/OpenRouter gateway regression tests, and the complete LF-normalized ext4 WSL suite must pass.
- Native Windows may retain only the four established CRLF-sensitive frozen-fixture failures; their locks must not be rewritten.

## Delegation boundaries

Luna agents may independently own contracts/scoring, corpus fixtures/lock, and CLI/report/tests/docs. Shared export or documentation files are integrated after the core interfaces stabilize. At most one read-only Terra review may be used if cross-layer provenance or scoring risks remain. No Sol subagent is permitted.
