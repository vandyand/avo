"""Strict-JSON gateway for OpenAI Chat Completions compatible servers."""

import asyncio
import re
from collections.abc import Callable
from datetime import UTC, datetime
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any, Literal, cast
from urllib.parse import urlparse
from uuid import uuid4

from avo_correlate.adapters.model.http import (
    ArtifactSink,
    InvocationSink,
    ModelGatewayError,
    Transport,
    https_post,
    load_unique_json,
    nonnegative_int,
    optional_string,
)
from avo_correlate.contracts.agent import AgentContext, AgentTurn
from avo_correlate.contracts.budgets import UsageRecord
from avo_correlate.contracts.model import ModelInvocationRecord
from avo_correlate.domain.canonical import canonical_bytes

_RESERVED_PARAMETERS = {"messages", "model", "n", "response_format", "stream"}
_RESERVED_HEADERS = {"authorization", "content-type", "host"}
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def strict_agent_turn_schema() -> dict[str, Any]:
    """Return the provider wire schema used to construct an ``AgentTurn``.

    Strict Structured Outputs requires every object property to be required and
    forbids open-ended objects. The bounded native tool vocabulary therefore uses
    one typed argument object with nullable fields; unused fields are removed
    locally before dispatch.
    """

    nullable_string: dict[str, Any] = {
        "anyOf": [{"type": "string"}, {"type": "null"}]
    }
    nullable_digest: dict[str, Any] = {
        "anyOf": [
            {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            {"type": "null"},
        ]
    }
    argument_properties = {
        name: nullable_string
        for name in ("path", "pattern", "old", "new", "patch")
    }
    nullable_arguments: dict[str, Any] = {
        "anyOf": [
            {
                "type": "object",
                "additionalProperties": False,
                "properties": argument_properties,
                "required": list(argument_properties),
            },
            {"type": "null"},
        ]
    }
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "schema_version": {"type": "integer", "const": 1},
            "action": {"type": "string", "enum": ["tool", "propose", "stop"]},
            "rationale": {"type": "string", "minLength": 1},
            "tool_id": nullable_string,
            "arguments": nullable_arguments,
            "proposed_workspace_digest": nullable_digest,
            "proposed_patch_digest": nullable_digest,
            "stop_reason": {
                "anyOf": [
                    {
                        "type": "string",
                        "enum": ["exhausted", "policy_blocked", "cancelled", "failed"],
                    },
                    {"type": "null"},
                ]
            },
        },
        "required": [
            "schema_version",
            "action",
            "rationale",
            "tool_id",
            "arguments",
            "proposed_workspace_digest",
            "proposed_patch_digest",
            "stop_reason",
        ],
    }


class OpenAICompatibleModelGateway:
    """Map a standard Chat Completions response into AVO's strict ``AgentTurn``."""

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
        artifact_sink: ArtifactSink,
        invocation_sink: InvocationSink,
        input_microusd_per_million: int = 0,
        output_microusd_per_million: int = 0,
        response_format: Literal["json_schema", "json_object"] = "json_schema",
        developer_role: Literal["developer", "system"] = "developer",
        extra_headers: dict[str, str] | None = None,
        timeout_seconds: int = 120,
        max_response_bytes: int = 2_000_000,
        transport: Transport | None = None,
    ) -> None:
        parsed = urlparse(endpoint)
        local_http = parsed.scheme == "http" and parsed.hostname in {
            "localhost",
            "127.0.0.1",
            "::1",
        }
        if not parsed.hostname or (parsed.scheme != "https" and not local_http):
            raise ValueError("endpoint must use HTTPS, except for loopback development servers")
        if min(input_microusd_per_million, output_microusd_per_million) < 0:
            raise ValueError("model prices cannot be negative")
        forbidden_parameters = sorted(_RESERVED_PARAMETERS.intersection(parameters))
        if forbidden_parameters:
            raise ValueError(
                "parameters cannot override protocol fields: "
                + ", ".join(forbidden_parameters)
            )


        checked_headers: dict[str, str] = {}
        for name, value in (extra_headers or {}).items():
            if name.lower() in _RESERVED_HEADERS:
                raise ValueError(f"extra header cannot override {name}")
            if not _HEADER_NAME.fullmatch(name) or not value or "\r" in value or "\n" in value:
                raise ValueError("extra headers must contain valid non-empty HTTP values")
            checked_headers[name] = value
        self._endpoint = endpoint
        self._api_key = api_key
        self._provider = provider
        self._model = model
        self._system_prompt = system_prompt
        self._developer_prompt = developer_prompt
        self._parameters = dict(parameters)
        self._extra_headers = checked_headers
        self._artifact_sink = artifact_sink
        self._invocation_sink = invocation_sink
        self._input_price = input_microusd_per_million
        self._output_price = output_microusd_per_million
        self._response_format = response_format
        self._developer_role = developer_role
        self._timeout = timeout_seconds
        self._max_response = max_response_bytes
        self._transport = transport or https_post

    async def next_turn(self, context: AgentContext) -> AgentTurn:
        invocation_id = str(uuid4())
        activity_id = f"model:{invocation_id}"
        started = datetime.now(UTC)
        user_payload = canonical_bytes(context)
        system_digest = self._artifact_sink(self._system_prompt.encode(), "model-system")
        developer_digest = self._artifact_sink(
            self._developer_prompt.encode(), "model-developer"
        )
        user_digest = self._artifact_sink(user_payload, "model-user")
        schema = (
            strict_agent_turn_schema()
            if self._response_format == "json_schema"
            else AgentTurn.model_json_schema()
        )
        schema_digest = self._artifact_sink(canonical_bytes(schema), "model-response-schema")
        format_document: dict[str, Any]
        if self._response_format == "json_schema":
            format_document = {
                "type": "json_schema",
                "json_schema": {"name": "avo_agent_turn", "strict": True, "schema": schema},
            }
        else:
            format_document = {"type": "json_object"}
        body_document = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": self._system_prompt},
                {"role": self._developer_role, "content": self._developer_prompt},
                {"role": "user", "content": user_payload.decode()},
            ],
            "response_format": format_document,
            **self._parameters,
        }
        body = canonical_bytes(body_document)
        request_digest = self._artifact_sink(body, "model-request-redacted")
        response_digest: str | None = None
        error_class: str | None = None
        finish_reason: str | None = None
        provider_request_id: str | None = None
        resolved_model: str | None = None
        usage = UsageRecord.zero()
        provider_usage: dict[str, int] = {}
        cost_source: Literal["provider", "price_table"] = "price_table"
        try:
            token = self._api_key()
            headers = {"Content-Type": "application/json", **self._extra_headers}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            response = await asyncio.to_thread(
                self._transport,
                self._endpoint,
                headers,
                body,
                self._timeout,
                self._max_response,
            )
            response_digest = self._artifact_sink(response, "model-response-redacted")
            document = load_unique_json(response)
            raw_choices = document.get("choices")
            if not isinstance(raw_choices, list):
                raise ModelGatewayError("response must contain exactly one choice")
            choices = cast(list[object], raw_choices)
            if len(choices) != 1:
                raise ModelGatewayError("response must contain exactly one choice")
            if not isinstance(choices[0], dict):
                raise ModelGatewayError("choice must be an object")
            choice = cast(dict[str, Any], choices[0])
            message = choice.get("message")
            if not isinstance(message, dict):
                raise ModelGatewayError("choice message must be an object")
            typed_message = cast(dict[str, Any], message)
            finish_reason = optional_string(choice.get("finish_reason")) or "completed"
            provider_request_id = optional_string(document.get("id"))
            resolved_model = optional_string(document.get("model"))
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
                cost = provider_cost
                cost_source = "provider"
            else:
                cost = (
                    input_tokens * self._input_price
                    + output_tokens * self._output_price
                    + 999_999
                ) // 1_000_000
                cost_source = "price_table"
            usage = UsageRecord.zero().model_copy(
                update={
                    "model_input_tokens": input_tokens,
                    "model_output_tokens": output_tokens,
                    "model_cost_microusd": cost,
                }
            )
            if not isinstance(typed_message.get("content"), str):
                raise ModelGatewayError("choice message must contain JSON text")
            content = load_unique_json(cast(str, typed_message["content"]).encode())
            turn = (
                _turn_from_strict_wire(content)
                if self._response_format == "json_schema"
                else AgentTurn.model_validate(content)
            )
            return turn.model_copy(update={"usage": usage})
        except Exception as exc:
            error_class = type(exc).__name__
            raise ModelGatewayError(
                f"OpenAI-compatible invocation failed: {error_class}: {str(exc)[:500]}"
            ) from exc
        finally:
            self._invocation_sink(
                context.run_id,
                ModelInvocationRecord(
                    invocation_id=invocation_id,
                    activity_id=activity_id,
                    session_id=context.session_id,
                    provider=self._provider,
                    endpoint_class="openai_chat_completions",
                    requested_model=self._model,
                    provider_model_revision=resolved_model,
                    system_artifact_digest=system_digest,
                    developer_artifact_digest=developer_digest,
                    user_artifact_digest=user_digest,
                    tool_schema_digest=schema_digest,
                    parameters={
                        **self._parameters,
                        "response_format": self._response_format,
                        "developer_role": self._developer_role,
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
                ),
            )


def _turn_from_strict_wire(document: dict[str, Any]) -> AgentTurn:
    arguments_wire = document.get("arguments")
    arguments: dict[str, Any] | None = None
    if arguments_wire is not None:
        if not isinstance(arguments_wire, dict):
            raise ModelGatewayError("arguments must be an object or null")
        arguments = {
            key: value
            for key, value in cast(dict[str, Any], arguments_wire).items()
            if value is not None
        }
    elif document.get("action") == "tool":
        # Structured-output providers commonly choose the nullable branch for
        # tools with no parameters. The internal contract represents those as
        # an empty object.
        arguments = {}
    return AgentTurn.model_validate(
        {
            "schema_version": document.get("schema_version"),
            "action": document.get("action"),
            "rationale": document.get("rationale"),
            "tool_id": document.get("tool_id"),
            "arguments": arguments,
            "proposed_workspace_digest": document.get("proposed_workspace_digest"),
            "proposed_patch_digest": document.get("proposed_patch_digest"),
            "stop_reason": document.get("stop_reason"),
            "usage": UsageRecord.zero().model_dump(mode="json"),
        }
    )


def _integer_usage(document: dict[str, object]) -> dict[str, int]:
    usage: dict[str, int] = {}

    def visit(prefix: str, value: object) -> None:
        if isinstance(value, bool):
            return
        if isinstance(value, int):
            usage[prefix] = nonnegative_int(value)
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


def __getattr__(name: str) -> Any:
    """Lazily expose the generic implementation without an import cycle."""

    if name == "OpenAICompatibleStructuredInference":
        from avo_correlate.adapters.model.openai_structured import (
            OpenAICompatibleStructuredInference,
        )

        return OpenAICompatibleStructuredInference
    raise AttributeError(name)
