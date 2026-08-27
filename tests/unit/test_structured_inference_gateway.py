"""Contract tests for bounded OpenAI-compatible structured inference."""

import asyncio
import hashlib
import json
from typing import Any

import pytest

from avo_correlate.adapters.model.http import ModelGatewayError
from avo_correlate.adapters.model.openai_compatible import (
    OpenAICompatibleStructuredInference,
)
from avo_correlate.contracts.base import StrictModel
from avo_correlate.contracts.inference import (
    StructuredInferenceContext,
    StructuredInferenceResult,
)
from avo_correlate.contracts.model import ModelInvocationRecord


class Input(StrictModel):
    question: str


class Output(StrictModel):
    answer: str


class DefaultNested(StrictModel):
    label: str = "default-label"
    note: str | None = None


class DefaultOutput(StrictModel):
    answer: str = "default-answer"
    nested: DefaultNested


def _context() -> StructuredInferenceContext:
    return StructuredInferenceContext(
        run_id="run-1",
        session_id="session-1",
        activity_id="activity-1",
        operation_id="review",
        operation_version="1.0",
    )


def _gateway(
    response: dict[str, Any],
    records: list[ModelInvocationRecord],
    seen: list[dict[str, Any]],
    *,
    output_model: type[StrictModel] = Output,
    schema_name: str = "review_v1",
) -> OpenAICompatibleStructuredInference[Input, Output]:
    def transport(
        endpoint: str,
        headers: dict[str, str],
        body: bytes,
        timeout: int,
        maximum: int,
    ) -> bytes:
        del endpoint, headers, timeout, maximum
        seen.append(json.loads(body))
        return json.dumps(response).encode()

    def artifact_sink(payload: bytes, role: str) -> str:
        del role
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    def invocation_sink(run_id: str, record: ModelInvocationRecord) -> None:
        del run_id
        records.append(record)

    return OpenAICompatibleStructuredInference(
        endpoint="https://models.example.test/v1/chat/completions",
        api_key=lambda: "secret",
        provider="test-provider",
        model="openai/gpt-test",
        system_prompt="system",
        developer_prompt="developer",
        parameters={"temperature": 0},
        input_model=Input,
        output_model=output_model,
        schema_name=schema_name,
        artifact_sink=artifact_sink,
        invocation_sink=invocation_sink,
        input_microusd_per_million=2,
        output_microusd_per_million=4,
        transport=transport,
    )


def _response(content: object, *, finish_reason: str = "stop") -> dict[str, Any]:
    return {
        "id": "generation-1",
        "model": "openai/gpt-test-2026-01-01",
        "choices": [
            {
                "message": {"role": "assistant", "content": content},
                "finish_reason": finish_reason,
            }
        ],
        "usage": {"prompt_tokens": 20, "completion_tokens": 5, "cost": 0.000042},
    }


def test_structured_inference_returns_typed_output_and_provider_usage() -> None:
    records: list[ModelInvocationRecord] = []
    requests: list[dict[str, Any]] = []
    gateway = _gateway(_response(json.dumps({"answer": "42"})), records, requests)

    result: StructuredInferenceResult[Output] = asyncio.run(
        gateway.infer(_context(), Input(question="meaning"))
    )

    assert isinstance(result, StructuredInferenceResult)
    assert isinstance(result.output, Output)
    assert result.output.answer == "42"
    assert result.usage.model_input_tokens == 20
    assert result.usage.model_output_tokens == 5
    assert result.usage.model_cost_microusd == 42
    assert requests[0]["response_format"]["json_schema"]["strict"] is True
    assert requests[0]["response_format"]["json_schema"]["schema"]["required"] == ["answer"]
    assert records[0].activity_id == "activity-1"
    assert records[0].parameters["operation_id"] == "review"
    assert records[0].error_class is None


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (_response('{"answer":"ok","answer":"duplicate"}'), "duplicate response key"),
        (_response(None), "JSON text"),
        (_response("{}", finish_reason="length"), "incomplete"),
        (
            {
                **_response("{}"),
                "choices": [
                    {"message": {"refusal": "unsafe"}, "finish_reason": "stop"}
                ],
            },
            "refused",
        ),
    ],
)
def test_structured_inference_failures_record_evidence(
    response: dict[str, Any], message: str
) -> None:
    records: list[ModelInvocationRecord] = []
    gateway = _gateway(response, records, [])

    with pytest.raises(ModelGatewayError, match=message):
        asyncio.run(gateway.infer(_context(), Input(question="meaning")))

    assert records[0].provider_request_id == "generation-1"
    assert records[0].usage.model_input_tokens == 20
    assert records[0].usage.model_output_tokens == 5
    assert records[0].error_class is not None


def test_wire_schema_rejects_omitted_defaulted_top_level_field() -> None:
    records: list[ModelInvocationRecord] = []
    gateway = _gateway(
        _response(json.dumps({"nested": {"label": "provided"}})),
        records,
        [],
        output_model=DefaultOutput,
        schema_name="defaults_v1",
    )

    with pytest.raises(ModelGatewayError, match="does not match wire schema"):
        asyncio.run(gateway.infer(_context(), Input(question="meaning")))

    assert records[0].error_class == "ModelGatewayError"


def test_wire_schema_rejects_omitted_defaulted_nested_field() -> None:
    records: list[ModelInvocationRecord] = []
    gateway = _gateway(
        _response(json.dumps({"answer": "provided", "nested": {}})),
        records,
        [],
        output_model=DefaultOutput,
        schema_name="defaults_v1",
    )

    with pytest.raises(ModelGatewayError, match="does not match wire schema"):
        asyncio.run(gateway.infer(_context(), Input(question="meaning")))

    assert records[0].error_class == "ModelGatewayError"


def test_wire_schema_accepts_explicit_default_and_nullable_values() -> None:
    records: list[ModelInvocationRecord] = []
    gateway = _gateway(
        _response(
            json.dumps(
                {
                    "answer": "provided",
                    "nested": {"label": "provided", "note": None},
                }
            )
        ),
        records,
        [],
        output_model=DefaultOutput,
        schema_name="defaults_v1",
    )

    result = asyncio.run(gateway.infer(_context(), Input(question="meaning")))

    assert result.output.answer == "provided"
    assert result.output.nested.note is None
    assert records[0].error_class is None
