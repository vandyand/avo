import asyncio
import hashlib
import json

from avo_correlate.adapters.model.http import StructuredHttpModelGateway
from avo_correlate.contracts.agent import AgentContext
from avo_correlate.contracts.model import ModelInvocationRecord
from tests.conftest import DIGEST_A, DIGEST_B


def test_structured_gateway_records_artifacts_usage_and_integer_cost() -> None:
    artifacts: dict[str, bytes] = {}
    records: list[tuple[str, ModelInvocationRecord]] = []

    def artifact_sink(payload: bytes, role: str) -> str:
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        artifacts[f"{role}:{digest}"] = payload
        return digest

    def transport(
        endpoint: str,
        headers: dict[str, str],
        body: bytes,
        timeout: int,
        max_bytes: int,
    ) -> bytes:
        assert endpoint == "https://models.example.test/v1/turn"
        assert headers["Authorization"] == "Bearer top-secret"
        assert timeout == 30
        assert len(body) < max_bytes
        return json.dumps(
            {
                "turn": {
                    "schema_version": 1,
                    "action": "propose",
                    "rationale": "bounded repair is ready",
                    "proposed_workspace_digest": DIGEST_B,
                    "proposed_patch_digest": DIGEST_A,
                    "usage": {
                        "schema_version": 1,
                        "wall_clock_seconds": 0,
                        "model_input_tokens": 0,
                        "model_output_tokens": 0,
                        "model_cost_microusd": 0,
                        "tool_calls": 0,
                        "sandbox_cpu_seconds": 0,
                        "sandbox_gpu_seconds": 0,
                        "authoritative_evaluations": 0,
                        "variation_sessions": 0,
                        "artifact_bytes": 0,
                    },
                },
                "provider_request_id": "provider-1",
                "provider_model_revision": "revision-7",
                "finish_reason": "stop",
                "usage": {
                    "input_tokens": 1_500_000,
                    "output_tokens": 500_000,
                    "cached_tokens": 250_000,
                },
            }
        ).encode()

    gateway = StructuredHttpModelGateway(
        endpoint="https://models.example.test/v1/turn",
        bearer_token=lambda: "top-secret",
        provider="test-provider",
        model="test-model",
        system_prompt="system",
        developer_prompt="developer",
        tool_schema={"read_file": {}},
        parameters={"temperature": 0},
        artifact_sink=artifact_sink,
        invocation_sink=lambda run_id, record: records.append((run_id, record)),
        input_microusd_per_million=2,
        output_microusd_per_million=4,
        timeout_seconds=30,
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
                turns_remaining=2,
            )
        )
    )
    assert turn.action == "propose"
    assert turn.usage.model_input_tokens == 1_500_000
    assert turn.usage.model_output_tokens == 500_000
    assert turn.usage.model_cost_microusd == 5
    assert records[0][0] == "run-1"
    record = records[0][1]
    assert record.provider_usage["cached_tokens"] == 250_000
    assert record.cost_source == "price_table"
    assert record.error_class is None
    assert all(b"top-secret" not in payload for payload in artifacts.values())
