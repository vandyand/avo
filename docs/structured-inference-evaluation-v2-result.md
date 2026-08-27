# Structured inference advisory evaluation v2

Status date: 2026-08-27. Result: passed offline evidence gate.

This milestone evaluates AVO's advisory-review validation and scoring boundaries against a frozen, sanitized corpus. It made no provider request, read no API token, changed no campaign state, and exercised no policy, admission, or lifecycle authority.

## Corpus and result

The frozen corpus contains ten qualitatively different cases: four accepted substantive reviews (correctness, testing, security, and compatibility), a valid insufficient-evidence `no_conclusion`, a fabricated evidence reference, omitted strict fields, malformed JSON, a provider refusal, and a truncated response. Inputs and recorded observations live under `pilots/structured-inference-v2/cases/`; `manifest.json` fixes their order and `digests.json` locks their exact bytes.

| Metric | Result | Interpretation |
|---|---:|---|
| Expected-stage accuracy | 10/10 | Every recorded success or rejection reached its preregistered boundary. |
| Strict-schema validity | 6/10 | The five accepted reviews and the syntactically valid fabricated-reference review passed the exact wire schema. |
| Semantic validity | 5/10 | The five accepted reviews also passed candidate, path, and evidence binding. The denominator includes all ten cases. |
| Theme recall | 5/5 | Every literal rubric theme was found with its required category/evidence binding. |
| Unsupported-claim rate | 0/5 | None of the five frozen forbidden-claim expressions matched. |
| Severity calibration | 4/4 | All substantive finding severities fell within their frozen evidence-bound ranges. |

The 60% strict-validity and 50% semantic-validity figures are expected corpus composition, not model quality rates: four cases intentionally fail before semantic acceptance, and one intentionally fails semantic evidence binding.

## Reproduction and evidence

Run the evaluator without provider credentials:

```text
python scripts/evaluate_advisory_corpus.py \
  --corpus-root pilots/structured-inference-v2 \
  --output-dir pilots/structured-inference-v2/results/v1
```

The command verifies the frozen lock against the released suite digest before parsing cases, rejects duplicate JSON keys, non-standard numeric constants, credential-bearing fields, and credential-like text, applies the same compiled strict wire schema used by live advisory inference, validates Pydantic and input/evidence binding, and writes canonical report, per-case score, and result-manifest objects through the filesystem content-addressed store. Evaluating a separately trusted corpus requires an explicit `--expected-suite-digest`; a merely self-consistent replacement lock is not accepted by default.

- Corpus suite: `sha256:6138214c26c2f9eef8fba74d97978bb757d08e7e0a3d33c4f8c505d5acc412bd`
- Evaluator: `avo-advisory-evaluation` version `1`
- Advisory wire schema: `sha256:0b545c7e447cfa1f60ce395beb08614e4887330dff8f1ddf245169f44f080d96`
- Aggregate report: `sha256:50bdb147e3ba77931daca5a76f231d75ae4ad44f16a09c63fddbe390c7b394a9`
- Result manifest: `sha256:e6a675d4f5bce4d7dd6244b210c0caedb1495357ff165269ba63ac18d95cb4ed`

Human-readable copies are in `pilots/structured-inference-v2/results/v1/report.json` and `result.json`; the latter links all ten input and score digests. The corresponding canonical bytes are retained below `results/v1/artifacts/objects/sha256/` and independently match their content addresses.

## Scope and limitations

This result establishes deterministic offline evaluation infrastructure and coverage of the intended failure boundaries. It does not estimate Luna reliability, compare models, measure latency or cost, or validate free-form semantic understanding. Theme and forbidden-claim scoring uses frozen case-insensitive literal AND-of-OR marker groups; category and evidence bindings reduce ambiguity, but the metric can still produce lexical false positives or false negatives. Future live samples can be recorded into a separately versioned corpus and scored by this harness, but changing a rubric or observation requires a new frozen lock.
