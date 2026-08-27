# Structured inference

Status date: 2026-08-27. The generic structured-inference boundary is implemented as an experimental, one-call capability. Its first bounded OpenRouter Luna advisory canary and its ten-case deterministic offline evidence gate passed; neither is a production or model-superiority claim.

## Purpose and boundary

AVO uses a bounded strict-JSON call for operations that need classification, review, extraction, or a compact recommendation. These operations do not edit files, invoke tools, admit candidates, spend campaign budget, change lineage, or alter lifecycle state. Deterministic AVO services remain the authority for policy, evaluation, admission, budgets, provenance, and state transitions.

`OpenAICompatibleStructuredInference[InputT, OutputT]` accepts a strict Pydantic input model and output model. A call is made with `infer(StructuredInferenceContext, input)` and returns a validated `StructuredInferenceResult[OutputT]`. The context records the run, session, activity, operation, and operation version. The output includes usage, provider identity, finish reason, and the digest of the validated output artifact.

Before a request, AVO compiles the output model schema into a strict wire schema: object properties are all required, objects set `additionalProperties: false`, nullable unions remain nullable, and local schemas are validated. Open-ended mappings, unsupported external references, malformed schema nodes, and non-object roots fail before network access. The source and wire schema digests are retained separately.

The current implementation uses the OpenAI Chat Completions-compatible protocol with `response_format.type = json_schema` and `strict = true`. Before Pydantic normalization can apply local defaults, AVO validates the raw provider document against the exact compiled wire schema. It makes exactly one provider request: there is no automatic retry, transparent cache, or model fallback in this milestone. Refusals, incomplete responses, malformed JSON, output validation failures, and transport errors are recorded as unavailable inference and do not mutate campaign state.

## Advisory patch review

`AdvisoryPatchReviewInput` is a bounded, deterministic package containing a candidate identifier, objective, patch, changed paths, evaluator summaries, and an evidence catalog. `AdvisoryPatchReview` contains an enum recommendation, bounded findings, missing tests, limitations, and confidence. Findings may cite only evidence identifiers supplied in the input; local validation rejects fabricated references and unsafe paths.

The advisory result is a review artifact, not an admission decision. A caller may display or persist it for human consideration, but must not treat the recommendation as permission to apply a patch or alter a run. The first bounded canary passed its preregistered schema, semantic, provenance, and quality rubric; see the [v1 result](structured-inference-canary-v1-result.md).

The [v2 offline evaluation](structured-inference-evaluation-v2-result.md) adds a frozen ten-case corpus and deterministic scoring for exact-stage behavior, strict-schema validity, semantic/evidence binding, literal theme recall, forbidden claims, and severity calibration. Its standalone CLI verifies the input lock and writes content-addressed per-case and aggregate evidence without importing a provider adapter or reading credentials. The operation remains experimental pending repeated live samples and broader task distributions.

## OpenRouter and model defaults

`OpenRouterStructuredInference` uses the OpenRouter Chat Completions endpoint, reads `OPENROUTER_API_KEY` only at invocation time, and defaults provider preferences to `require_parameters: true` and `data_collection: deny`. The first intended model is `openai/gpt-5.6-luna`, selected for inexpensive, high-volume bounded work. GPT-5.6 Luna supports Structured Outputs and Chat Completions; see the [official model documentation](https://developers.openai.com/api/docs/models/gpt-5.6-luna). Terra is reserved for an explicitly approved adversarial review or later quality comparison, not automatic escalation.

The adapter records redacted prompt, request, response, schema, and validated-output artifacts through AVO’s artifact sink. Invocation provenance records operation identity/version, requested and resolved model identity, token usage, provider-reported or table-derived cost, finish status, and validation errors. Credentials are never included in these artifacts.

See [the OpenRouter interface guide](openrouter-interface.md) for endpoint and routing details. The existing native `AgentTurn` gateway remains a separate compatibility path; this generic interface does not change its tool vocabulary or authority semantics.
