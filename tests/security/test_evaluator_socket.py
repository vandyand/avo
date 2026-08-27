import asyncio
import json
import os
from pathlib import Path
from typing import Any, cast

import pytest

from avo_correlate.adapters.tools.evaluator_socket import (
    DevelopmentEvaluatorSocketBroker,
)
from avo_correlate.contracts.agent import AgentObservation
from tests.conftest import DIGEST_A


@pytest.mark.skipif(os.name == "nt", reason="initial live broker is Linux/WSL-only")
def test_evaluator_socket_keeps_capability_token_control_plane_side(
    tmp_path: Path,
) -> None:
    calls: list[tuple[dict[str, object], str]] = []

    async def evaluator(
        arguments: dict[str, object], token: str
    ) -> AgentObservation:
        calls.append((arguments, token))
        return AgentObservation(
            tool_id="run_development_evaluator",
            outcome="succeeded",
            result_digest=DIGEST_A,
            summary="passed",
        )

    async def scenario() -> None:
        socket_path = tmp_path / "evaluator.sock"
        broker = DevelopmentEvaluatorSocketBroker(
            socket_path,
            capability_token="control-plane-secret",
            evaluator=evaluator,
        )
        async with broker:
            connect = cast(Any, getattr(asyncio, "open_unix_connection", None))
            reader, writer = await connect(str(socket_path))
            writer.write(b'{"operation":"evaluate","arguments":{"suite":"dev"}}\n')
            await writer.drain()
            response = json.loads(await reader.readline())
            writer.close()
            await writer.wait_closed()
            assert response["ok"] is True
            assert "control-plane-secret" not in json.dumps(response)
        assert not socket_path.exists()

    asyncio.run(scenario())
    assert calls == [({"suite": "dev"}, "control-plane-secret")]
