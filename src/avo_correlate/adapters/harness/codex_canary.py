"""Live, non-inference Codex permission-profile boundary canaries."""

import asyncio
import inspect
import shlex
import subprocess
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from typing import Any, cast

from avo_correlate.contracts.runtime import HarnessRuntimeProfile

CanaryCommandResult = tuple[int, str, str]
CanaryCommandExecutor = Callable[[tuple[str, ...], Path], Awaitable[CanaryCommandResult]]
AuthenticationProbe = Callable[
    [HarnessRuntimeProfile], bool | Awaitable[bool]
]


class CodexLiveCanaryRunner:
    """Exercise the configured Codex sandbox without asking a model to run commands."""

    def __init__(
        self,
        *,
        command_executor: CanaryCommandExecutor | None = None,
        authentication_probe: AuthenticationProbe | None = None,
    ) -> None:
        self._command_executor = command_executor
        self._authentication_probe = authentication_probe or self._probe_authentication

    async def __call__(
        self,
        profile: HarnessRuntimeProfile,
        overrides: tuple[str, ...],
    ) -> Mapping[str, bool]:
        root = self.validate_canary_root(profile)
        workspace = root / "workspace"
        avo_state = root / "avo-state"
        private_evaluator = root / "private-evaluator"
        for directory in (workspace, avo_state, private_evaluator):
            directory.mkdir(parents=True, exist_ok=True)
        workspace_marker = workspace / "workspace-readable.txt"
        workspace_write = workspace / "workspace-written.txt"
        root_marker = root / "outside-workspace.txt"
        avo_marker = avo_state / "state-secret.txt"
        evaluator_marker = private_evaluator / "private-secret.txt"
        workspace_marker.write_text("workspace-canary\n", encoding="utf-8")
        root_marker.write_text("outside-canary\n", encoding="utf-8")
        avo_marker.write_text("avo-state-canary\n", encoding="utf-8")
        evaluator_marker.write_text("private-evaluator-canary\n", encoding="utf-8")

        unix_socket = root / "undeclared.sock"
        if unix_socket.exists() and unix_socket.is_socket():
            unix_socket.unlink()
        start_unix_server = cast(
            Callable[..., Awaitable[asyncio.AbstractServer]],
            asyncio.__dict__["start_unix_server"],
        )
        unix_server = await start_unix_server(self._accept, path=str(unix_socket))
        tcp_server = await asyncio.start_server(self._accept, host="127.0.0.1", port=0)
        tcp_port = cast(Any, tcp_server.sockets[0]).getsockname()[1]
        client: Any | None = None
        try:
            executor = self._command_executor
            if executor is None:
                client, executor = await self._sdk_executor(profile, overrides, workspace)
            results = {
                "workspace_read": await self._succeeds(
                    executor,
                    self._shell_test(f'cat -- {shlex.quote(str(workspace_marker))}'),
                    workspace,
                ),
                "workspace_write": await self._succeeds(
                    executor,
                    self._shell_test(
                        f'printf workspace-write > {shlex.quote(str(workspace_write))}'
                    ),
                    workspace,
                ),
                "root_denied": await self._denied(executor, root_marker, workspace),
                "avo_state_denied": await self._denied(executor, avo_marker, workspace),
                "private_evaluator_denied": await self._denied(
                    executor, evaluator_marker, workspace
                ),
                "external_network_denied": not await self._succeeds(
                    executor,
                    (
                        "python3",
                        "-c",
                        (
                            "import socket,sys; "
                            "s=socket.create_connection(('127.0.0.1',int(sys.argv[1])),2); "
                            "s.close()"
                        ),
                        str(tcp_port),
                    ),
                    workspace,
                ),
                "undeclared_socket_denied": not await self._succeeds(
                    executor,
                    (
                        "python3",
                        "-c",
                        (
                            "import socket,sys; s=socket.socket(socket.AF_UNIX); "
                            "s.settimeout(2); s.connect(sys.argv[1]); s.close()"
                        ),
                        str(unix_socket),
                    ),
                    workspace,
                ),
            }
            authentication = self._authentication_probe(profile)
            results["authentication_available"] = (
                await authentication if inspect.isawaitable(authentication) else authentication
            )
            return results
        finally:
            tcp_server.close()
            unix_server.close()
            await tcp_server.wait_closed()
            await unix_server.wait_closed()
            if client is not None:
                await client.close()
            if unix_socket.exists() and unix_socket.is_socket():
                unix_socket.unlink()

    @staticmethod
    async def _accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        del reader
        writer.write(b"ok")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    @staticmethod
    def validate_canary_root(profile: HarnessRuntimeProfile) -> Path:
        value = profile.configuration.get("canary_root")
        if not isinstance(value, str):
            raise ValueError("canary_root must be configured")
        root = Path(value)
        if not root.is_absolute() or root == Path(root.anchor) or root == Path.home():
            raise ValueError("canary_root must be a narrow absolute directory")
        codex_home = Path(cast(str, profile.configuration["isolated_codex_home"]))
        if root == codex_home or root.is_relative_to(codex_home):
            raise ValueError("canary_root must be outside CODEX_HOME")
        return root

    @staticmethod
    def _shell_test(command: str) -> tuple[str, ...]:
        return ("/bin/sh", "-c", command)

    @classmethod
    async def _denied(
        cls,
        executor: CanaryCommandExecutor,
        marker: Path,
        workspace: Path,
    ) -> bool:
        return not await cls._succeeds(
            executor,
            cls._shell_test(f'cat -- {shlex.quote(str(marker))}'),
            workspace,
        )

    @staticmethod
    async def _succeeds(
        executor: CanaryCommandExecutor,
        command: tuple[str, ...],
        workspace: Path,
    ) -> bool:
        try:
            exit_code, _, _ = await executor(command, workspace)
        except Exception:
            return False
        return exit_code == 0

    @staticmethod
    async def _sdk_executor(
        profile: HarnessRuntimeProfile,
        overrides: tuple[str, ...],
        workspace: Path,
    ) -> tuple[Any, CanaryCommandExecutor]:
        from openai_codex import CodexConfig
        from openai_codex.async_client import AsyncCodexClient
        from openai_codex.generated.v2_all import CommandExecResponse

        from avo_correlate.adapters.harness.codex import CodexCodingAgentRuntime

        client = AsyncCodexClient(
            CodexConfig(
                codex_bin=cast(str, profile.configuration["codex_executable"]),
                config_overrides=overrides,
                cwd=str(workspace),
                env=CodexCodingAgentRuntime.codex_environment(profile),
            )
        )
        await client.start()
        await client.initialize()

        async def execute(command: tuple[str, ...], cwd: Path) -> CanaryCommandResult:
            response = await client.request(
                "command/exec",
                {
                    "command": list(command),
                    "cwd": str(cwd),
                    "permissionProfile": "avo-workspace-only",
                    "timeoutMs": 5_000,
                    "outputBytesCap": 16_384,
                    "env": {
                        "OPENAI_API_KEY": None,
                        "CODEX_API_KEY": None,
                        "CODEX_ACCESS_TOKEN": None,
                    },
                },
                response_model=CommandExecResponse,
            )
            return response.exit_code, response.stdout, response.stderr

        return client, execute

    @staticmethod
    def _probe_authentication(profile: HarnessRuntimeProfile) -> bool:
        from avo_correlate.adapters.harness.codex import CodexCodingAgentRuntime

        completed = subprocess.run(
            [
                cast(str, profile.configuration["codex_executable"]),
                "login",
                "status",
            ],
            check=False,
            capture_output=True,
            env=CodexCodingAgentRuntime.codex_environment(profile),
            text=True,
            timeout=10,
        )
        output = completed.stdout + completed.stderr
        return completed.returncode == 0 and "Logged in using ChatGPT" in output
