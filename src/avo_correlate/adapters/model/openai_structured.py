"""Generic strict-JSON Chat Completions inference adapter."""

import asyncio
import re
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any, Literal, cast
from urllib.parse import urlparse
from uuid import uuid4

from jsonschema import Draft202012Validator, SchemaError, ValidationError

from avo_correlate.adapters.model.http import (
    ArtifactSink,
    InvocationSink,
    ModelGatewayError,
    Transport,
    https_post,
    load_unique_json,
    optional_string,
)
from avo_correlate.contracts.base import StrictModel
from avo_correlate.contracts.budgets import UsageRecord
from avo_correlate.contracts.inference import (
    StructuredInferenceContext,
    StructuredInferenceResult,
)
from avo_correlate.contracts.model import ModelInvocationRecord
from avo_correlate.domain.canonical import canonical_bytes

_RESERVED_PARAMETERS = {"messages", "model", "n", "response_format", "stream"}
_RESERVED_HEADERS = {"authorization", "content-type", "host"}
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


class OpenAICompatibleStructuredInference[InputT: StrictModel, OutputT: StrictModel]:
    """Run one bounded strict-JSON operation against a compatible endpoint."""

    def __init__(
        self,
        *,
        endpoint: str,
        api_key: Callable[[], str],
        provider: str,
        model: str,
        system_prompt: str,
        developer_prompt: str,
        parameters: dict[str, Any],
        input_model: type[InputT],
        output_model: type[OutputT],
        schema_name: str,
        artifact_sink: ArtifactSink,
        invocation_sink: InvocationSink,
        input_microusd_per_million: int = 0,
        output_microusd_per_million: int = 0,
        developer_role: Literal["developer", "system"] = "developer",
        extra_headers: dict[str, str] | None = None,
        timeout_seconds: int = 120,
        max_response_bytes: int = 2_000_000,
        transport: Transport | None = None,
    ) -> None:
        parsed = urlparse(endpoint)
        local_http = parsed.scheme == "http" and parsed.hostname in {
            "localhost", "127.0.0.1", "::1"
        }
        if not parsed.hostname or (parsed.scheme != "https" and not local_http):
            raise ValueError("endpoint must use HTTPS, except for loopback development servers")
        if not schema_name or len(schema_name) > 64 or not schema_name[0].isalpha():
            raise ValueError("schema_name must start with a letter and be at most 64 characters")
        if not all(character.isascii() and (character.isalnum() or character in "_-")
                   for character in schema_name):
            raise ValueError("schema_name must contain only ASCII letters, digits, '_' or '-'")
        if min(input_microusd_per_million, output_microusd_per_million) < 0:
            raise ValueError("model prices cannot be negative")
        forbidden = sorted(_RESERVED_PARAMETERS.intersection(parameters))
        if forbidden:
            raise ValueError("parameters cannot override protocol fields: " + ", ".join(forbidden))
        headers: dict[str, str] = {}
        for name, value in (extra_headers or {}).items():
            if name.lower() in _RESERVED_HEADERS:
                raise ValueError(f"extra header cannot override {name}")
            if not _HEADER_NAME.fullmatch(name) or not value or "\r" in value or "\n" in value:
                raise ValueError("extra headers must contain valid non-empty HTTP values")
            headers[name] = value
        from avo_correlate.domain.structured_schema import compile_strict_output_schema

        compiled = compile_strict_output_schema(output_model)
        self._endpoint = endpoint
        self._api_key = api_key
        self._provider = provider
        self._model = model
        self._system_prompt = system_prompt
        self._developer_prompt = developer_prompt
        self._parameters = dict(parameters)
        self._input_model = input_model
        self._output_model = output_model
        self._schema_name = schema_name
        self._source_schema = compiled.source_schema
        self._source_schema_digest = compiled.source_digest
        self._wire_schema = compiled.wire_schema
        self._wire_schema_digest = compiled.wire_digest
        try:
            Draft202012Validator.check_schema(self._wire_schema)
            self._wire_validator = Draft202012Validator(self._wire_schema)
        except SchemaError as exc:
            raise ValueError(f"compiled strict output schema is invalid: {exc.message}") from exc
        self._artifact_sink = artifact_sink
        self._invocation_sink = invocation_sink
        self._input_price = input_microusd_per_million
        self._output_price = output_microusd_per_million
        self._developer_role = developer_role
        self._extra_headers = headers
        self._timeout = timeout_seconds
        self._max_response = max_response_bytes
        self._transport = transport or https_post

    async def infer(
        self, context: StructuredInferenceContext, input: InputT
    ) -> StructuredInferenceResult[OutputT]:
        invocation_id = str(uuid4())
        started = datetime.now(UTC)
        validated_input = self._input_model.model_validate(input)
        user_payload = canonical_bytes(validated_input)
        system_digest = self._artifact_sink(self._system_prompt.encode(), "model-system")
        developer_digest = self._artifact_sink(
            self._developer_prompt.encode(), "model-developer"
        )
        user_digest = self._artifact_sink(user_payload, "model-user")
        schema_digest = self._artifact_sink(
            canonical_bytes(self._wire_schema), "model-response-schema"
        )
        body = canonical_bytes({
            "model": self._model,
            "messages": [
                {"role": "system", "content": self._system_prompt},
                {"role": self._developer_role, "content": self._developer_prompt},
                {"role": "user", "content": user_payload.decode()},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": self._schema_name,
                    "strict": True,
                    "schema": self._wire_schema,
                },
            },
            **self._parameters,
        })
        request_digest = self._artifact_sink(body, "model-request-redacted")
        response_digest: str | None = None
        output_digest: str | None = None
        error_class: str | None = None
        finish_reason: str | None = None
        provider_request_id: str | None = None
        provider_revision: str | None = None
        usage = UsageRecord.zero()
        provider_usage: dict[str, int] = {}
        cost_source: Literal["provider", "price_table"] = "price_table"
        try:
            token = self._api_key()
            headers = {"Content-Type": "application/json", **self._extra_headers}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            response = await asyncio.to_thread(
                self._transport, self._endpoint, headers, body, self._timeout, self._max_response
            )
            response_digest = self._artifact_sink(response, "model-response-redacted")
            document = load_unique_json(response)
            raw_choices = document.get("choices")
            if not isinstance(raw_choices, list):
                raise ModelGatewayError("response must contain exactly one choice")
            choices = cast(list[object], raw_choices)
            if len(choices) != 1:
                raise ModelGatewayError("response must contain exactly one choice")
            choice = choices[0]
            if not isinstance(choice, dict):
                raise ModelGatewayError("choice must be an object")
            typed_choice = cast(dict[str, Any], choice)
            finish_reason = optional_string(typed_choice.get("finish_reason")) or "completed"
            provider_request_id = optional_string(document.get("id"))
            provider_revision = optional_string(document.get("model"))
            raw_usage = document.get("usage", {})
            if not isinstance(raw_usage, dict):
                raise ModelGatewayError("usage must be an object")
            typed_usage = cast(dict[str, object], raw_usage)
            provider_usage = _integer_usage(typed_usage)
            input_tokens = provider_usage.get(
                "prompt_tokens", provider_usage.get("input_tokens", 0)
            )
            output_tokens = provider_usage.get(
                "completion_tokens", provider_usage.get("output_tokens", 0)
            )
            provider_cost = _provider_cost_microusd(typed_usage.get("cost"))
            if provider_cost is not None:
                cost, cost_source = provider_cost, "provider"
            else:
                cost = (
                    input_tokens * self._input_price
                    + output_tokens * self._output_price
                    + 999_999
                ) // 1_000_000
            usage = UsageRecord.zero().model_copy(update={
                "model_input_tokens": input_tokens,
                "model_output_tokens": output_tokens,
                "model_cost_microusd": cost,
            })
            if finish_reason in {"length", "max_tokens", "content_filter", "tool_calls"}:
                raise ModelGatewayError(f"structured response is incomplete: {finish_reason}")
            message = typed_choice.get("message")
            if not isinstance(message, dict):
                raise ModelGatewayError("choice message must be an object")
            typed_message = cast(dict[str, Any], message)
            refusal = typed_message.get("refusal")
            if refusal is not None and (not isinstance(refusal, str) or refusal):
                raise ModelGatewayError("model refused structured output")
            content = typed_message.get("content")
            if not isinstance(content, str) or not content:
                raise ModelGatewayError("choice message must contain JSON text")
            raw_output = load_unique_json(content.encode())
            try:
                cast(Any, self._wire_validator).validate(raw_output)
            except ValidationError as exc:
                raise ModelGatewayError(
                    f"structured output does not match wire schema: {exc.message}"
                ) from exc
            output = self._output_model.model_validate(raw_output)
            output_digest = self._artifact_sink(
                canonical_bytes(output), "model-output-validated"
            )
            return StructuredInferenceResult(
                output=output,
                usage=usage,
                invocation_id=invocation_id,
                provider_request_id=provider_request_id,
                provider_model_revision=provider_revision,
                finish_reason=finish_reason,
                output_artifact_digest=output_digest,
            )
        except Exception as exc:
            error_class = type(exc).__name__
            raise ModelGatewayError(
                f"OpenAI-compatible structured inference failed: {error_class}: {str(exc)[:500]}"
            ) from exc
        finally:
            self._invocation_sink(context.run_id, ModelInvocationRecord(
                invocation_id=invocation_id,
                activity_id=context.activity_id,
                session_id=context.session_id,
                provider=self._provider,
                endpoint_class="openai_chat_completions_structured",
                requested_model=self._model,
                provider_model_revision=provider_revision,
                system_artifact_digest=system_digest,
                developer_artifact_digest=developer_digest,
                user_artifact_digest=user_digest,
                tool_schema_digest=schema_digest,
                parameters={
                    **self._parameters,
                    "response_format": "json_schema",
                    "schema_name": self._schema_name,
                    "operation_id": context.operation_id,
                    "operation_version": context.operation_version,
                    "source_schema_digest": self._source_schema_digest,
                    "wire_schema_digest": self._wire_schema_digest,
                },
                provider_request_id=provider_request_id,
                usage=usage,
                provider_usage=provider_usage,
                retry_parent_invocation_id=None,
                finish_reason=finish_reason,
                error_class=error_class,
                request_artifact_digest=request_digest,
                response_artifact_digest=response_digest,
                cost_source=cost_source,
                started_at=started,
                completed_at=datetime.now(UTC),
            ))


def _integer_usage(document: dict[str, object]) -> dict[str, int]:
    usage: dict[str, int] = {}

    def visit(prefix: str, value: object) -> None:
        if isinstance(value, bool):
            return
        if isinstance(value, int):
            if value < 0:
                raise ModelGatewayError("provider usage must contain nonnegative integers")
            usage[prefix] = value
            return
        if isinstance(value, dict):
            for child_key, child_value in cast(dict[str, object], value).items():
                visit(f"{prefix}.{child_key}" if prefix else child_key, child_value)

    for key, value in document.items():
        if key != "cost":
            visit(key, value)
    return usage


def _provider_cost_microusd(value: object) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        decimal_value = Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise ModelGatewayError("provider cost must be a nonnegative decimal") from None
    if not decimal_value.is_finite() or decimal_value < 0:
        raise ModelGatewayError("provider cost must be a nonnegative decimal")
    return int((decimal_value * 1_000_000).quantize(Decimal("1"), ROUND_HALF_UP))
