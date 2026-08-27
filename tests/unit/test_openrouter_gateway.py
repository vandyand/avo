import asyncio
import hashlib
import json

import pytest

from avo_correlate.adapters.model.http import ModelGatewayError
from avo_correlate.adapters.model.openrouter import (
    OPENROUTER_CHAT_COMPLETIONS_ENDPOINT,
    OpenRouterModelGateway,
    openrouter_api_key_from_environment,
)
from avo_correlate.contracts.agent import AgentContext
from avo_correlate.contracts.model import ModelInvocationRecord
from tests.conftest import DIGEST_A, DIGEST_B


def test_openrouter_gateway_applies_strict_routing_and_cost_accounting() -> None:
    records: list[ModelInvocationRecord] = []

    def transport(
        endpoint: str,
        headers: dict[str, str],
        body: bytes,
        timeout: int,
        maximum: int,
    ) -> bytes:
        del timeout, maximum
        assert endpoint == OPENROUTER_CHAT_COMPLETIONS_ENDPOINT
        assert headers["Authorization"] == "Bearer test-key"
        assert headers["X-Title"] == "AVO test"
        assert headers["HTTP-Referer"] == "https://example.test/avo"
        request = json.loads(body)
        assert request["provider"] == {
            "require_parameters": True,
            "data_collection": "deny",
        }
        assert request["response_format"]["json_schema"]["strict"] is True
        content = {
            "schema_version": 1,
            "action": "tool",
            "rationale": "run the evaluator",
            "tool_id": "run_development_evaluator",
            "arguments": None,
            "proposed_workspace_digest": None,
            "proposed_patch_digest": None,
            "stop_reason": None,
        }
        return json.dumps(
            {
                "id": "generation-1",
                "model": "openai/gpt-test",
                "choices": [
                    {
                        "message": {"role": "assistant", "content": json.dumps(content)},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 20,
                    "completion_tokens": 5,
                    "total_tokens": 25,
                    "cost": 0.000042,
                    "completion_tokens_details": {"reasoning_tokens": 2},
                },
            }
        ).encode()

    gateway = OpenRouterModelGateway(
        model="openai/gpt-test",
        system_prompt="system",
        developer_prompt="developer",
        parameters={"max_tokens": 100},
        artifact_sink=lambda payload, role: "sha256:" + hashlib.sha256(payload).hexdigest(),
        invocation_sink=lambda run_id, record: records.append(record),
        api_key=lambda: "test-key",
        app_title="AVO test",
        app_url="https://example.test/avo",
        transport=transport,
    )
    turn = asyncio.run(
        gateway.next_turn(
            AgentContext(
                run_id="run-1",
                session_id="session-1",
                champion_workspace_digest=DIGEST_A,
                initial_context_digest=DIGEST_B,
                observations=[],
                turn_number=1,
                turns_remaining=0,
            )
        )
    )

    assert turn.action == "tool"
    assert turn.tool_id == "run_development_evaluator"
    assert turn.arguments == {}
    assert turn.usage.model_cost_microusd == 42
    assert records[0].provider_usage["completion_tokens_details.reasoning_tokens"] == 2
    assert records[0].cost_source == "provider"


def test_openrouter_key_is_read_at_call_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    with pytest.raises(ModelGatewayError, match="is not set"):
        openrouter_api_key_from_environment()
    monkeypatch.setenv("OPENROUTER_API_KEY", " runtime-key ")
    assert openrouter_api_key_from_environment() == "runtime-key"


def test_openrouter_gateway_rejects_non_object_provider_preferences() -> None:
    with pytest.raises(ValueError, match="must be an object"):
        OpenRouterModelGateway(
            model="openai/gpt-test",
            system_prompt="system",
            developer_prompt="developer",
            parameters={"provider": "invalid"},
            artifact_sink=lambda payload, role: DIGEST_A,
            invocation_sink=lambda run_id, record: None,
            api_key=lambda: "test-key",
        )


def test_openrouter_gateway_records_usage_before_turn_validation() -> None:
    records: list[ModelInvocationRecord] = []

    def transport(
        endpoint: str,
        headers: dict[str, str],
        body: bytes,
        timeout: int,
        maximum: int,
    ) -> bytes:
        del endpoint, headers, body, timeout, maximum
        invalid_turn = {
            "schema_version": 1,
            "action": "tool",
            "rationale": "edit",
            "tool_id": "replace_text",
            "arguments": "nested JSON is forbidden",
            "proposed_workspace_digest": None,
            "proposed_patch_digest": None,
            "stop_reason": None,
        }
        return json.dumps(
            {
                "id": "generation-invalid",
                "model": "openai/gpt-test",
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(invalid_turn),
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 30,
                    "completion_tokens": 7,
                    "cost": 0.000321,
                },
            }
        ).encode()

    gateway = OpenRouterModelGateway(
        model="openai/gpt-test",
        system_prompt="system",
        developer_prompt="developer",
        parameters={},
        artifact_sink=lambda payload, role: (
            "sha256:" + hashlib.sha256(payload).hexdigest()
        ),
        invocation_sink=lambda run_id, record: records.append(record),
        api_key=lambda: "test-key",
        transport=transport,
    )

    with pytest.raises(ModelGatewayError, match="arguments must be an object"):
        asyncio.run(
            gateway.next_turn(
                AgentContext(
                    run_id="run-1",
                    session_id="session-1",
                    champion_workspace_digest=DIGEST_A,
                    initial_context_digest=DIGEST_B,
                    observations=[],
                    turn_number=1,
                    turns_remaining=0,
                )
            )
        )

    assert records[0].provider_request_id == "generation-invalid"
    assert records[0].usage.model_input_tokens == 30
    assert records[0].usage.model_output_tokens == 7
    assert records[0].usage.model_cost_microusd == 321
