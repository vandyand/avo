# OpenAI-compatible and OpenRouter inference

Status date: 2026-08-27. The generic Chat Completions adapter and the OpenRouter specialization are implemented. Both the existing native `AgentTurn` probe and the generic advisory operation have passed bounded live canaries. This is an inference boundary, not a production promotion. See the [structured-inference guide](structured-inference.md) and [advisory canary result](structured-inference-canary-v1-result.md).

## Interface

`OpenAICompatibleModelGateway` accepts any server exposing the OpenAI Chat Completions response shape. Remote endpoints must use HTTPS; loopback development servers may use HTTP. Callers supply the endpoint, model, prompts, request parameters, an API-key callback, and AVO artifact/invocation sinks.

The native `AgentTurn` compatibility mode requests `response_format.type = json_schema` with `strict: true`. Its provider wire schema makes every property required and sets `additionalProperties: false`; its bounded `arguments` field is a nullable typed object, not an `arguments_json` string. AVO parses the response with duplicate-key rejection and then validates the resulting `AgentTurn` locally. The generic typed-input/typed-output operation is documented separately. The older `json_object` mode remains available for servers without strict schema support, but it provides weaker enforcement.

Protocol fields (`model`, `messages`, `response_format`, `stream`, and `n`) cannot be overridden through the free-form parameters map. Extra headers cannot replace authorization, content type, or host. Usage parsing accepts current OpenAI/OpenRouter token detail objects, preserves integer counters with dotted names, and uses a provider-reported decimal cost when present.

## OpenRouter profile

`OpenRouterModelGateway` fixes the endpoint to `https://openrouter.ai/api/v1/chat/completions`, reads `OPENROUTER_API_KEY` only when a call is made, adds the application title, and defaults provider routing to:

~~~json
{
  "require_parameters": true,
  "data_collection": "deny"
}
~~~

This prevents silent routing to a backend that ignores strict output parameters and excludes providers OpenRouter marks as collecting request data. These preferences can be made stricter in a frozen runtime profile when production data policy is defined.

Run the bounded connectivity probe with the key present only in the child process:

~~~text
python scripts/probe_openrouter.py --model openai/gpt-5.6-luna --max-tokens 512
~~~

The probe emits only non-sensitive routing, completion, token, and cost metadata. It does not print prompts, response bodies, or credentials.

## Live result and model decision

The live AVO probe succeeded on 2026-08-25 with `openai/gpt-5.6-luna`:

- strict schema-valid `stop` action;
- resolved model matched the requested model;
- provider request ID and finish reason captured;
- 289 input tokens and 61 output tokens;
- OpenRouter-reported charge of 131 micro-USD.

The first attempted profile also sent `seed` and `temperature`. Under `provider.require_parameters = true`, OpenRouter found no eligible route and returned HTTP 404. Removing those nonessential sampling controls produced a valid call while retaining strict schema enforcement. This is why supported model-level parameters are not assumed to be simultaneously available on every eligible provider route.

As checked immediately after the probes, the account had 655 total purchased credits, 653.440501152 used, and 1.559498848 remaining. That balance is ample for smoke testing and probably a small Luna pilot, but it is not enough headroom for the preregistered 24 OpenRouter repetitions (48 total repetitions across both arms) with a frontier model.

Two model choices serve different questions:

- Use `openai/gpt-5.6-luna` for inexpensive integration, regression, and operational tests.
- Use `openai/gpt-5.6-sol` for the formal Codex-versus-native comparison. Matching the Codex pilot's model family and exact model ID reduces model-quality confounding and better isolates the agentic interface/harness effect.

Before the formal run, top up the OpenRouter account and freeze the exact model IDs, parameters, prices, provider policy, profiles, and credit snapshot. A minimum $10 available balance should cover a conservative first pass based on the calibration token volume; $25 provides safer retry-free headroom. Configure a bounded key spend limit before production or a larger benchmark.

## Frozen comparison suite

The preregistered eight-task suite is under `pilots/comparison-v1`. It references the original three `codex-v1` fixtures directly and adds five tasks without changing or tuning the completed calibration artifacts. Its suite digest is `sha256:19e60770f7741ec8dfad5cba7f1caf3bbc552ae0d48a946e0d714d097aceff04`.

The manifest fixes three repetitions per task, pairing rules, primary and secondary outcomes, infrastructure-failure handling, and analysis language. Exact runtime/model profiles are intentionally a separate pre-run lock: they must be frozen after credit sufficiency is established and before either arm sees any new task.
