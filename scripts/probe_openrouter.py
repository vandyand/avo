"""Make one secret-safe structured AVO inference through OpenRouter."""

import argparse
import asyncio
import hashlib
import json

from avo_correlate.adapters.model.openrouter import OpenRouterModelGateway
from avo_correlate.contracts.agent import AgentContext
from avo_correlate.contracts.model import ModelInvocationRecord

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="openai/gpt-5.6-luna")
    parser.add_argument("--max-tokens", type=int, default=512)
    parser.add_argument(
        "--reasoning-effort",
        choices=("none", "low", "medium", "high", "xhigh", "max"),
        default="high",
    )
    return parser.parse_args()


def _digest(payload: bytes, role: str) -> str:
    del role
    return "sha256:" + hashlib.sha256(payload).hexdigest()


async def _run(
    model: str, max_tokens: int, reasoning_effort: str
) -> dict[str, object]:
    if max_tokens <= 0:
        raise ValueError("max tokens must be positive")
    records: list[ModelInvocationRecord] = []
    gateway = OpenRouterModelGateway(
        model=model,
        system_prompt="You are the structured decision component of AVO Correlate.",
        developer_prompt=(
            "Return a stop action for this connectivity probe. Set stop_reason to "
            "exhausted and every inapplicable nullable field to null."
        ),
        parameters={
            "max_tokens": max_tokens,
            "reasoning": {"effort": reasoning_effort},
        },
        artifact_sink=_digest,
        invocation_sink=lambda run_id, record: records.append(record),
    )
    turn = await gateway.next_turn(
        AgentContext(
            run_id="openrouter-smoke",
            session_id="openrouter-smoke-session",
            champion_workspace_digest=DIGEST_A,
            initial_context_digest=DIGEST_B,
            observations=[],
            turn_number=1,
            turns_remaining=0,
        )
    )
    record = records[0]
    return {
        "schema_version": 1,
        "provider": record.provider,
        "requested_model": record.requested_model,
        "resolved_model": record.provider_model_revision,
        "reasoning_effort": reasoning_effort,
        "request_id_present": record.provider_request_id is not None,
        "finish_reason": record.finish_reason,
        "action": turn.action,
        "stop_reason": turn.stop_reason,
        "input_tokens": turn.usage.model_input_tokens,
        "output_tokens": turn.usage.model_output_tokens,
        "cost_microusd": turn.usage.model_cost_microusd,
        "cost_source": record.cost_source,
    }


def main() -> None:
    arguments = _arguments()
    result = asyncio.run(
        _run(arguments.model, arguments.max_tokens, arguments.reasoning_effort)
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
