"""Remote-capable structured model gateway with complete invocation evidence."""

import json
import ssl
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import urlparse
from uuid import uuid4

from avo_correlate.contracts.agent import AgentContext, AgentTurn
from avo_correlate.contracts.budgets import UsageRecord
from avo_correlate.contracts.model import ModelInvocationRecord
from avo_correlate.domain.canonical import canonical_bytes

Transport = Callable[[str, dict[str, str], bytes, int, int], bytes]
ArtifactSink = Callable[[bytes, str], str]
InvocationSink = Callable[[str, ModelInvocationRecord], None]


class ModelGatewayError(RuntimeError):
    pass


class StructuredHttpModelGateway:
    """Call a versioned HTTPS endpoint that returns one validated ``AgentTurn``."""

    def __init__(
        self,
        *,
        endpoint: str,
        bearer_token: Callable[[], str],
        provider: str,
        model: str,
        system_prompt: str,
        developer_prompt: str,
        tool_schema: dict[str, Any],
        parameters: dict[str, Any],
        artifact_sink: ArtifactSink,
        invocation_sink: InvocationSink,
        input_microusd_per_million: int,
        output_microusd_per_million: int,
        timeout_seconds: int = 120,
        max_response_bytes: int = 2_000_000,
        transport: Transport | None = None,
    ) -> None:
        parsed = urlparse(endpoint)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("model gateway endpoint must be an absolute HTTPS URL")
        if min(input_microusd_per_million, output_microusd_per_million) < 0:
            raise ValueError("model prices cannot be negative")
        self._endpoint = endpoint
        self._bearer_token = bearer_token
        self._provider = provider
        self._model = model
        self._system_prompt = system_prompt
        self._developer_prompt = developer_prompt
        self._tool_schema = tool_schema
        self._parameters = parameters
        self._artifact_sink = artifact_sink
        self._invocation_sink = invocation_sink
        self._input_price = input_microusd_per_million
        self._output_price = output_microusd_per_million
        self._timeout = timeout_seconds
        self._max_response = max_response_bytes
        self._transport = transport or _https_post

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
        tool_digest = self._artifact_sink(
            canonical_bytes(self._tool_schema), "model-tool-schema"
        )
        body = canonical_bytes(
            {
                "schema_version": 1,
                "invocation_id": invocation_id,
                "model": self._model,
                "messages": [
                    {"role": "system", "content": self._system_prompt},
                    {"role": "developer", "content": self._developer_prompt},
                    {"role": "user", "content": user_payload.decode()},
                ],
                "tool_schema": self._tool_schema,
                "parameters": self._parameters,
                "response_schema": AgentTurn.model_json_schema(),
            }
        )
        request_digest = self._artifact_sink(body, "model-request-redacted")
        response_digest: str | None = None
        error_class: str | None = None
        finish_reason: str | None = None
        provider_request_id: str | None = None
        provider_revision: str | None = None
        usage = UsageRecord.zero()
        provider_usage: dict[str, int] = {}
        cost_source = "price_table"
        try:
            response = self._transport(
                self._endpoint,
                {
                    "Authorization": f"Bearer {self._bearer_token()}",
                    "Content-Type": "application/json",
                },
                body,
                self._timeout,
                self._max_response,
            )
            response_digest = self._artifact_sink(response, "model-response-redacted")
            document = _load_unique_json(response)
            turn = AgentTurn.model_validate(document.get("turn"))
            provider_request_id = _optional_string(document.get("provider_request_id"))
            provider_revision = _optional_string(document.get("provider_model_revision"))
            finish_reason = _optional_string(document.get("finish_reason")) or "completed"
            raw_usage = cast(dict[str, Any], document.get("usage", {}))
            provider_usage = {
                key: _nonnegative_int(value) for key, value in raw_usage.items()
            }
            input_tokens = provider_usage.get("input_tokens", 0)
            output_tokens = provider_usage.get("output_tokens", 0)
            if "cost_microusd" in provider_usage:
                cost = provider_usage["cost_microusd"]
                cost_source = "provider"
            else:
                cost = (
                    input_tokens * self._input_price
                    + output_tokens * self._output_price
                    + 999_999
                ) // 1_000_000
            usage = UsageRecord.zero().model_copy(
                update={
                    "model_input_tokens": input_tokens,
                    "model_output_tokens": output_tokens,
                    "model_cost_microusd": cost,
                }
            )
            return turn.model_copy(update={"usage": usage})
        except Exception as exc:
            error_class = type(exc).__name__
            raise ModelGatewayError(f"structured model invocation failed: {error_class}") from exc
        finally:
            record = ModelInvocationRecord(
                invocation_id=invocation_id,
                activity_id=activity_id,
                session_id=context.session_id,
                provider=self._provider,
                endpoint_class="structured_https",
                requested_model=self._model,
                provider_model_revision=provider_revision,
                system_artifact_digest=system_digest,
                developer_artifact_digest=developer_digest,
                user_artifact_digest=user_digest,
                tool_schema_digest=tool_digest,
                parameters=self._parameters,
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
            )
            self._invocation_sink(context.run_id, record)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


def _https_post(
    endpoint: str,
    headers: dict[str, str],
    body: bytes,
    timeout_seconds: int,
    max_response_bytes: int,
) -> bytes:
    request = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()), _NoRedirect()
    )
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            payload = response.read(max_response_bytes + 1)
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ModelGatewayError("model endpoint request failed") from exc
    if len(payload) > max_response_bytes:
        raise ModelGatewayError("model response exceeds byte limit")
    return payload


def _load_unique_json(payload: bytes) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ModelGatewayError(f"duplicate response key: {key}")
            result[key] = value
        return result

    try:
        return cast(dict[str, Any], json.loads(payload, object_pairs_hook=unique))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ModelGatewayError("model response is not valid JSON") from exc


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _nonnegative_int(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ModelGatewayError("provider usage must contain nonnegative integers")
    return value


# Public transport primitives shared by compatible protocol adapters.
https_post = _https_post
load_unique_json = _load_unique_json
optional_string = _optional_string
nonnegative_int = _nonnegative_int
