"""OpenRouter defaults for the OpenAI-compatible model gateway."""

import os
from collections.abc import Callable
from typing import Any, cast

from avo_correlate.adapters.model.http import (
    ArtifactSink,
    InvocationSink,
    ModelGatewayError,
    Transport,
)
from avo_correlate.adapters.model.openai_compatible import (
    OpenAICompatibleModelGateway,
    OpenAICompatibleStructuredInference,
)
from avo_correlate.contracts.base import StrictModel

OPENROUTER_CHAT_COMPLETIONS_ENDPOINT = (
    "https://openrouter.ai/api/v1/chat/completions"
)


class OpenRouterStructuredInference(OpenAICompatibleStructuredInference[StrictModel, StrictModel]):
    """Strict inference with OpenRouter's safe routing defaults."""

    def __init__(
        self,
        *,
        model: str,
        system_prompt: str,
        developer_prompt: str,
        parameters: dict[str, Any],
        input_model: type[StrictModel],
        output_model: type[StrictModel],
        schema_name: str,
        artifact_sink: ArtifactSink,
        invocation_sink: InvocationSink,
        api_key: Callable[[], str] | None = None,
        input_microusd_per_million: int = 0,
        output_microusd_per_million: int = 0,
        app_title: str = "AVO Correlate",
        app_url: str | None = None,
        timeout_seconds: int = 120,
        max_response_bytes: int = 2_000_000,
        transport: Transport | None = None,
    ) -> None:
        routed_parameters = dict(parameters)
        raw_provider = routed_parameters.get("provider", {})
        if not isinstance(raw_provider, dict):
            raise ValueError("OpenRouter provider preferences must be an object")
        provider_preferences = dict(cast(dict[str, Any], raw_provider))
        provider_preferences.setdefault("require_parameters", True)
        provider_preferences.setdefault("data_collection", "deny")
        routed_parameters["provider"] = provider_preferences
        headers = {"X-Title": app_title}
        if app_url is not None:
            headers["HTTP-Referer"] = app_url
        super().__init__(  # pyright: ignore[reportUnknownMemberType]
            endpoint=OPENROUTER_CHAT_COMPLETIONS_ENDPOINT,
            api_key=api_key or openrouter_api_key_from_environment,
            provider="openrouter",
            model=model,
            system_prompt=system_prompt,
            developer_prompt=developer_prompt,
            parameters=routed_parameters,
            input_model=input_model,
            output_model=output_model,
            schema_name=schema_name,
            artifact_sink=artifact_sink,
            invocation_sink=invocation_sink,
            input_microusd_per_million=input_microusd_per_million,
            output_microusd_per_million=output_microusd_per_million,
            developer_role="developer",
            extra_headers=headers,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
            transport=transport,
        )


def openrouter_api_key_from_environment() -> str:
    """Read the OpenRouter key at invocation time without retaining it in configuration."""

    token = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not token:
        raise ModelGatewayError("OPENROUTER_API_KEY is not set")
    return token


class OpenRouterModelGateway(OpenAICompatibleModelGateway):
    """AVO gateway with privacy-conscious OpenRouter routing defaults."""

    def __init__(
        self,
        *,
        model: str,
        system_prompt: str,
        developer_prompt: str,
        parameters: dict[str, Any],
        artifact_sink: ArtifactSink,
        invocation_sink: InvocationSink,
        api_key: Callable[[], str] = openrouter_api_key_from_environment,
        input_microusd_per_million: int = 0,
        output_microusd_per_million: int = 0,
        app_title: str = "AVO Correlate",
        app_url: str | None = None,
        timeout_seconds: int = 120,
        max_response_bytes: int = 2_000_000,
        transport: Transport | None = None,
    ) -> None:
        routed_parameters = dict(parameters)
        raw_provider = routed_parameters.get("provider", {})
        if not isinstance(raw_provider, dict):
            raise ValueError("OpenRouter provider preferences must be an object")
        provider_preferences = dict(cast(dict[str, Any], raw_provider))
        provider_preferences.setdefault("require_parameters", True)
        provider_preferences.setdefault("data_collection", "deny")
        routed_parameters["provider"] = provider_preferences
        headers = {"X-Title": app_title}
        if app_url is not None:
            headers["HTTP-Referer"] = app_url
        super().__init__(
            endpoint=OPENROUTER_CHAT_COMPLETIONS_ENDPOINT,
            api_key=api_key,
            provider="openrouter",
            model=model,
            system_prompt=system_prompt,
            developer_prompt=developer_prompt,
            parameters=routed_parameters,
            artifact_sink=artifact_sink,
            invocation_sink=invocation_sink,
            input_microusd_per_million=input_microusd_per_million,
            output_microusd_per_million=output_microusd_per_million,
            response_format="json_schema",
            developer_role="developer",
            extra_headers=headers,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
            transport=transport,
        )
