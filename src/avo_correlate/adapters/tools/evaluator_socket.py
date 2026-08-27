"""One-session Unix-socket broker for the development evaluator."""

import asyncio
import json
import os
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, cast

from avo_correlate.contracts.agent import AgentObservation

EvaluatorCall = Callable[[dict[str, Any], str], Awaitable[AgentObservation]]


class EvaluatorSocketError(RuntimeError):
    pass


class DevelopmentEvaluatorSocketBroker:
    """Keep evaluator credentials control-plane-side; socket access is the capability."""

    def __init__(
        self,
        socket_path: Path,
        *,
        capability_token: str,
        evaluator: EvaluatorCall,
        max_request_bytes: int = 65_536,
        request_timeout_seconds: int = 120,
    ) -> None:
        self.socket_path = socket_path.resolve()
        if not capability_token:
            raise ValueError("capability token cannot be empty")
        self._token = capability_token
        self._evaluator = evaluator
        self._max_request_bytes = max_request_bytes
        self._timeout = request_timeout_seconds
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        if self._server is not None:
            return
        if os.name == "nt":
            raise EvaluatorSocketError("the v1 evaluator socket broker requires Linux/WSL")
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.exists():
            raise EvaluatorSocketError("evaluator socket path already exists")
        start_unix_server = cast(Any, getattr(asyncio, "start_unix_server", None))
        if start_unix_server is None:
            raise EvaluatorSocketError("Unix sockets are unavailable")
        self._server = await start_unix_server(
            self._handle, path=str(self.socket_path)
        )
        self.socket_path.chmod(0o600)

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        if self.socket_path.is_socket():
            self.socket_path.unlink()

    async def __aenter__(self) -> "DevelopmentEvaluatorSocketBroker":
        await self.start()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        response: dict[str, Any]
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=self._timeout)
            if len(line) > self._max_request_bytes or not line.endswith(b"\n"):
                raise EvaluatorSocketError("invalid evaluator request framing")
            document = _unique_json(line)
            if document.get("operation") != "evaluate":
                raise EvaluatorSocketError("unsupported evaluator operation")
            arguments = document.get("arguments")
            if not isinstance(arguments, dict):
                raise EvaluatorSocketError("evaluator arguments must be an object")
            observation = await asyncio.wait_for(
                self._evaluator(cast(dict[str, Any], arguments), self._token),
                timeout=self._timeout,
            )
            response = {"ok": True, "observation": observation.model_dump(mode="json")}
        except Exception as exc:
            response = {
                "ok": False,
                "error": type(exc).__name__,
                "detail": "development evaluator request failed",
            }
        writer.write(
            json.dumps(response, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        )
        try:
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()


def _unique_json(payload: bytes) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        document: dict[str, Any] = {}
        for key, value in pairs:
            if key in document:
                raise EvaluatorSocketError(f"duplicate request key: {key}")
            document[key] = value
        return document

    try:
        value = json.loads(payload, object_pairs_hook=unique)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise EvaluatorSocketError("request is not unique-key JSON") from exc
    if not isinstance(value, dict):
        raise EvaluatorSocketError("request must be a JSON object")
    return cast(dict[str, Any], value)
