import asyncio
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from avo_correlate.adapters.harness.codex import (
    CodexAccountIdentity,
    CodexCodingAgentRuntime,
    CodexRuntimeError,
    candidate_workspace_is_config_free,
    candidate_workspace_is_vcs_free,
    codex_permission_contract,
    probe_cli_version,
    remove_empty_codex_scaffolds,
    strict_agent_completion_schema,
)
from avo_correlate.adapters.harness.codex_canary import CodexLiveCanaryRunner
from avo_correlate.adapters.harness.recorded_runtime import (
    RecordedCodingAgentRuntime,
    RecordedRuntimeEntry,
)
from avo_correlate.adapters.model.openai_compatible import OpenAICompatibleModelGateway
from avo_correlate.application.plugin_registry import sign_plugin_manifest
from avo_correlate.contracts.agent import AgentContext
from avo_correlate.contracts.model import ModelInvocationRecord
from avo_correlate.contracts.plugins import PluginCapabilityManifest, SignedPluginManifest
from avo_correlate.contracts.runtime import (
    AgentCompletion,
    HarnessRuntimeProfile,
    RuntimeEvent,
    RuntimeSessionRef,
)
from avo_correlate.contracts.variation import CandidateRef, VariationSessionRequest
from avo_correlate.domain.canonical import canonical_digest
from tests.conftest import DIGEST_A, DIGEST_B, component


def request() -> VariationSessionRequest:
    return VariationSessionRequest(
        session_id="session-1",
        run_id="run-1",
        champion=CandidateRef(
            candidate_id="seed-1", source_tree_digest=DIGEST_A, lineage_sequence=0
        ),
        lineage_index_digest=DIGEST_A,
        initial_context_digest=DIGEST_B,
        tool_capability_token="signed-token",
        development_evaluator_refs=[component("development")],
        budget_reservation_id="reservation-1",
        random_seed=1,
    )


def profile(tmp_path: Path, *, signing_key: bytes | None = None) -> HarnessRuntimeProfile:
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir(exist_ok=True)
    private_tmpdir = tmp_path / "codex-tmp"
    private_tmpdir.mkdir(exist_ok=True)
    codex_executable = tmp_path / "codex"
    codex_executable.write_text("test executable", encoding="utf-8")
    manifest = PluginCapabilityManifest(
        plugin_id="openai-codex",
        plugin_version="0.147.0",
        package_digest=(
            "sha256:" + hashlib.sha256(codex_executable.read_bytes()).hexdigest()
        ),
        source_digest=DIGEST_B,
        supported_contract_versions=["HarnessRuntimeProfile.v1"],
        supported_schema_versions=[1],
        operating_systems=["linux"],
        architectures=["x86_64"],
        required_executables=[],
        network_access="brokered",
        configuration_schema={},
        side_effects=["workspace_write"],
        security_classification="sandboxed-coding-agent",
        health_check=["permission-canaries"],
        license="Proprietary",
    )
    signed = (
        SignedPluginManifest(
            manifest=manifest,
            signature_algorithm="hmac-sha256",
            signer_key_id="test",
            signature_hex="00",
        )
        if signing_key is None
        else sign_plugin_manifest(manifest, key_id="test", signing_key=signing_key)
    )
    return HarnessRuntimeProfile(
        profile_id="codex-test",
        plugin=signed,
        transport="sdk",
        requested_model="gpt-5.6-codex",
        authentication_class="subscription",
        permission_profile_digest=canonical_digest(codex_permission_contract()),
        development_evaluator_id="development",
        max_wall_time_seconds=60,
        max_turns=5,
        completion_schema_digest=canonical_digest(strict_agent_completion_schema()),
        configuration={
            "isolated_codex_home": str(codex_home.resolve()),
            "private_tmpdir": str(private_tmpdir.resolve()),
            "codex_executable": str(codex_executable.resolve()),
        },
    )


def test_recorded_runtime_satisfies_full_lifecycle(tmp_path: Path) -> None:
    invocation_id = "recorded:session-1"
    event = RuntimeEvent(
        invocation_id=invocation_id,
        sequence=1,
        event_type="completion",
        payload_digest=DIGEST_A,
        occurred_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    runtime = RecordedCodingAgentRuntime(
        [
            RecordedRuntimeEntry(
                request_digest=canonical_digest(request()),
                events=(event,),
                completion=AgentCompletion(outcome="proposal", rationale="ready"),
            )
        ]
    )

    async def scenario() -> None:
        report = await runtime.preflight(profile(tmp_path))
        assert report.compatible
        session = await runtime.prepare(
            profile(tmp_path),
            request(),
            str(tmp_path),
            invocation_id=invocation_id,
        )
        assert (await runtime.inspect(profile(tmp_path), session, str(tmp_path))).state == (
            "not_started"
        )
        session = await runtime.start_turn(profile(tmp_path), request(), session)
        assert (await runtime.inspect(profile(tmp_path), session, str(tmp_path))).state == (
            "running"
        )
        assert [item async for item in runtime.events(session)] == [event]
        assert (await runtime.wait(session)).outcome == "proposal"
        assert (await runtime.inspect(profile(tmp_path), session, str(tmp_path))).state == (
            "completed"
        )
        assert await runtime.recover(session.native_session_id) == session

    asyncio.run(scenario())


def test_codex_permission_profile_is_fail_closed_and_canary_gated(tmp_path: Path) -> None:
    configured = profile(tmp_path)
    overrides = CodexCodingAgentRuntime.permission_overrides(configured)
    permission_table = next(item for item in overrides if item.startswith("permissions="))
    assert '":root" = "deny"' in permission_table
    assert '":minimal" = "read"' in permission_table
    assert '":tmpdir" = "write"' in permission_table
    assert '":slash_tmp" = "deny"' in permission_table
    assert '":workspace_roots" = { "." = "write" }' in permission_table
    assert 'extends = ":workspace"' not in permission_table
    assert "project_doc_max_bytes=0" in overrides
    assert "features.hooks=false" in overrides
    assert "features.apps=false" in overrides
    assert "features.plugins=false" in overrides
    assert "network = { enabled = false }" in permission_table
    runtime = CodexCodingAgentRuntime(
        artifact_sink=lambda payload, role: canonical_digest(
            {"role": role, "payload": payload.hex()}
        )
    )
    report = asyncio.run(runtime.preflight(configured))
    assert not report.compatible
    canary = next(check for check in report.checks if check.name == "permission_canaries")
    assert canary.status == "fail"


def test_codex_preflight_rejects_permission_contract_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signing_key = b"trusted-plugin-key-material-123456"
    configured = profile(tmp_path, signing_key=signing_key).model_copy(
        update={"permission_profile_digest": DIGEST_A}
    )
    monkeypatch.setattr(
        "avo_correlate.adapters.harness.codex.platform.system", lambda: "Linux"
    )
    runtime = CodexCodingAgentRuntime(
        artifact_sink=lambda payload, role: DIGEST_A,
        canary_runner=lambda runtime_profile, overrides: {
            name: True
            for name in (
                "workspace_read",
                "workspace_write",
                "root_denied",
                "avo_state_denied",
                "private_evaluator_denied",
                "external_network_denied",
                "undeclared_socket_denied",
                "authentication_available",
            )
        },
        account_probe=lambda runtime_profile: CodexAccountIdentity(
            "chatgpt", "vandyand@gmail.com", "pro"
        ),
        cli_version_probe=lambda executable: "codex-cli 0.149.1",
        trusted_plugin_keys={"test": signing_key},
    )
    report = asyncio.run(runtime.preflight(configured))
    digest_check = next(
        check for check in report.checks if check.name == "permission_profile_digest"
    )
    assert not report.compatible
    assert digest_check.status == "fail"


def test_openai_compatible_gateway_uses_strict_json_schema() -> None:
    records: list[ModelInvocationRecord] = []

    def sink(payload: bytes, role: str) -> str:
        del role
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    def transport(
        endpoint: str,
        headers: dict[str, str],
        body: bytes,
        timeout: int,
        maximum: int,
    ) -> bytes:
        del timeout, maximum
        assert endpoint == "http://127.0.0.1:8000/v1/chat/completions"
        assert headers["Authorization"] == "Bearer local-key"
        assert headers["X-Title"] == "AVO Correlate tests"
        request_body = json.loads(body)
        assert request_body["response_format"]["type"] == "json_schema"
        assert request_body["response_format"]["json_schema"]["strict"] is True
        schema = request_body["response_format"]["json_schema"]["schema"]
        assert set(schema["required"]) == set(schema["properties"])
        argument_schema = schema["properties"]["arguments"]["anyOf"][0]
        assert argument_schema["type"] == "object"
        assert argument_schema["additionalProperties"] is False
        assert set(argument_schema["required"]) == set(argument_schema["properties"])
        turn = {
            "schema_version": 1,
            "action": "stop",
            "rationale": "done",
            "tool_id": None,
            "arguments": None,
            "proposed_workspace_digest": None,
            "proposed_patch_digest": None,
            "stop_reason": "exhausted",
        }
        return json.dumps(
            {
                "id": "request-1",
                "model": "local-model-revision",
                "choices": [
                    {
                        "message": {"role": "assistant", "content": json.dumps(turn)},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 10,
                    "completion_tokens": 3,
                    "total_tokens": 13,
                    "cost": 0.000123,
                    "prompt_tokens_details": {"cached_tokens": 4},
                },
            }
        ).encode()

    gateway = OpenAICompatibleModelGateway(
        endpoint="http://127.0.0.1:8000/v1/chat/completions",
        api_key=lambda: "local-key",
        provider="local",
        model="local-model",
        system_prompt="system",
        developer_prompt="developer",
        parameters={"temperature": 0},
        extra_headers={"X-Title": "AVO Correlate tests"},
        artifact_sink=sink,
        invocation_sink=lambda run_id, record: records.append(record),
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
                turns_remaining=1,
            )
        )
    )
    assert turn.action == "stop"
    assert turn.usage.model_input_tokens == 10
    assert turn.usage.model_cost_microusd == 123
    assert records[0].endpoint_class == "openai_chat_completions"
    assert records[0].provider_usage["prompt_tokens_details.cached_tokens"] == 4
    assert records[0].cost_source == "provider"


@pytest.mark.parametrize("field", ["model", "messages", "response_format", "stream", "n"])
def test_openai_compatible_gateway_rejects_protocol_parameter_overrides(field: str) -> None:
    with pytest.raises(ValueError, match="cannot override protocol fields"):
        OpenAICompatibleModelGateway(
            endpoint="https://models.example.test/v1/chat/completions",
            api_key=lambda: "key",
            provider="test",
            model="test-model",
            system_prompt="system",
            developer_prompt="developer",
            parameters={field: "unsafe"},
            artifact_sink=lambda payload, role: DIGEST_A,
            invocation_sink=lambda run_id, record: None,
        )


def test_openai_compatible_gateway_rejects_sensitive_extra_headers() -> None:
    with pytest.raises(ValueError, match="cannot override"):
        OpenAICompatibleModelGateway(
            endpoint="https://models.example.test/v1/chat/completions",
            api_key=lambda: "key",
            provider="test",
            model="test-model",
            system_prompt="system",
            developer_prompt="developer",
            parameters={},
            extra_headers={"Authorization": "replacement"},
            artifact_sink=lambda payload, role: DIGEST_A,
            invocation_sink=lambda run_id, record: None,
        )


class FakeTokenUsage:
    def model_dump(self, **_: object) -> dict[str, object]:
        return {"input_tokens": 4, "details": {"cached_tokens": 2}}


class FakeCodexHandle:
    def __init__(self, result: Any, final_text: str = "") -> None:
        self.id = "turn-1"
        self.result = result
        self.final_text = final_text
        self.interrupted = False

    async def stream(self) -> Any:
        yield SimpleNamespace(method="turn/started", payload=SimpleNamespace())
        yield SimpleNamespace(
            method="item/completed",
            payload=SimpleNamespace(
                item=SimpleNamespace(
                    root=SimpleNamespace(
                        text=self.final_text,
                        phase=SimpleNamespace(value="final_answer"),
                    )
                )
            ),
        )
        yield SimpleNamespace(
            method="thread/tokenUsage/updated",
            payload=SimpleNamespace(token_usage=FakeTokenUsage()),
        )
        yield SimpleNamespace(
            method="turn/completed", payload=SimpleNamespace(turn=self.result)
        )

    async def run(self) -> Any:
        return self.result

    async def interrupt(self) -> None:
        self.interrupted = True


class ExplodingCodexHandle(FakeCodexHandle):
    async def stream(self) -> Any:
        yield SimpleNamespace(method="turn/started", payload=SimpleNamespace())
        raise ConnectionError("provider process exited")


class ExplodingWaitCodexHandle(FakeCodexHandle):
    async def run(self) -> Any:
        raise ConnectionError("provider process exited while waiting")


class FakeCodexThread:
    id = "thread-1"

    def __init__(self, handle: FakeCodexHandle) -> None:
        self.handle = handle
        self.turn_arguments: dict[str, Any] = {}
        self.read_response: object = SimpleNamespace(
            thread=SimpleNamespace(turns=[])
        )

    async def turn(self, prompt: str, **arguments: Any) -> FakeCodexHandle:
        self.turn_arguments = {"prompt": prompt, **arguments}
        return self.handle

    async def read(self, *, include_turns: bool = False) -> object:
        assert include_turns
        return self.read_response


class FakeCodexClient:
    def __init__(self, configuration: Any, handle: FakeCodexHandle) -> None:
        self.configuration = configuration
        self.thread = FakeCodexThread(handle)
        self.start_arguments: dict[str, Any] = {}
        self.closed = False

    async def thread_start(self, **arguments: Any) -> FakeCodexThread:
        self.start_arguments = arguments
        return self.thread

    async def thread_resume(
        self, thread_id: str, **arguments: Any
    ) -> FakeCodexThread:
        del arguments
        if thread_id != self.thread.id:
            raise LookupError(thread_id)
        return self.thread

    async def close(self) -> None:
        self.closed = True


def test_codex_sdk_adapter_streams_normalized_events_and_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("openai_codex")
    signing_key = b"trusted-plugin-key-material-123456"
    configured = profile(tmp_path, signing_key=signing_key)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    completion = AgentCompletion(outcome="proposal", rationale="candidate is ready")
    result = SimpleNamespace(final_response=None)
    handle = FakeCodexHandle(result, completion.model_dump_json())
    clients: list[FakeCodexClient] = []

    def factory(configuration: Any) -> FakeCodexClient:
        client = FakeCodexClient(configuration, handle)
        clients.append(client)
        return client

    canaries = {
        "workspace_read": True,
        "workspace_write": True,
        "root_denied": True,
        "avo_state_denied": True,
        "private_evaluator_denied": True,
        "external_network_denied": True,
        "undeclared_socket_denied": True,
        "authentication_available": True,
    }
    monkeypatch.setattr(
        "avo_correlate.adapters.harness.codex.platform.system", lambda: "Linux"
    )
    runtime = CodexCodingAgentRuntime(
        artifact_sink=lambda payload, role: "sha256:"
        + hashlib.sha256(role.encode() + payload).hexdigest(),
        canary_runner=lambda runtime_profile, overrides: canaries,
        client_factory=factory,
        account_probe=lambda runtime_profile: CodexAccountIdentity(
            authentication_type="chatgpt",
            email="vandyand@gmail.com",
            plan="pro",
        ),
        cli_version_probe=lambda executable: "codex-cli 0.149.1",
        trusted_plugin_keys={"test": signing_key},
    )

    async def scenario() -> None:
        report = await runtime.preflight(configured)
        assert report.compatible
        session = await runtime.prepare(
            configured,
            request(),
            str(workspace),
            invocation_id="invocation-1",
        )
        assert clients[0].thread.turn_arguments == {}
        assert (await runtime.inspect(configured, session, str(workspace))).state == (
            "not_started"
        )
        session = await runtime.start_turn(configured, request(), session)
        events = [event async for event in runtime.events(session)]
        assert [event.event_type for event in events] == [
            "session_started",
            "message",
            "usage",
            "completion",
        ]
        assert events[2].usage_delta == {
            "input_tokens": 4,
            "details.cached_tokens": 2,
        }
        assert await runtime.wait(session) == completion
        assert await runtime.recover(session.native_session_id) == session.model_copy(
            update={"checkpoint": 4}
        )
        await runtime.cancel(session)
        assert handle.interrupted
        assert await runtime.recover("unknown") is None

    asyncio.run(scenario())
    assert clients[0].closed
    assert clients[0].configuration.codex_bin == configured.configuration["codex_executable"]
    assert clients[0].configuration.env.get("OPENAI_API_KEY") is None
    assert clients[0].configuration.env.get("CODEX_ACCESS_TOKEN") is None
    assert clients[0].configuration.env["TMPDIR"] == configured.configuration[
        "private_tmpdir"
    ]
    assert clients[0].configuration.env["PYTHONDONTWRITEBYTECODE"] == "1"
    assert 'forced_login_method="chatgpt"' in clients[0].configuration.config_overrides
    assert clients[0].start_arguments.get("sandbox") is None
    assert clients[0].thread.turn_arguments.get("sandbox") is None
    output_schema = clients[0].thread.turn_arguments["output_schema"]
    assert output_schema["required"] == [
        "schema_version",
        "outcome",
        "rationale",
        "claimed_tests",
    ]


def test_codex_detached_thread_inspection_classifies_provider_state(
    tmp_path: Path,
) -> None:
    pytest.importorskip("openai_codex")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    completion = AgentCompletion(outcome="proposal", rationale="recovered")
    result = SimpleNamespace(final_response=completion.model_dump_json())
    handle = FakeCodexHandle(result)
    client = FakeCodexClient(SimpleNamespace(), handle)
    runtime = CodexCodingAgentRuntime(
        artifact_sink=lambda payload, role: DIGEST_A,
        client_factory=lambda configuration: client,
    )

    async def inspect_turns(turns: list[object], turn_id: str | None = "turn-1") -> str:
        client.thread.read_response = SimpleNamespace(
            thread=SimpleNamespace(turns=turns)
        )
        reference = RuntimeSessionRef(
            adapter_id=runtime.adapter_id,
            native_session_id="thread-1",
            native_operation_id=turn_id,
            invocation_id="invocation-1",
            storage_class="provider",
        )
        return (await runtime.inspect(profile(tmp_path), reference, str(workspace))).state

    assert asyncio.run(inspect_turns([])) == "not_started"
    completed = SimpleNamespace(
        id="turn-1",
        status=SimpleNamespace(value="completed"),
        final_response=completion.model_dump_json(),
    )
    assert asyncio.run(inspect_turns([completed])) == "completed"
    running = SimpleNamespace(id="turn-1", status=SimpleNamespace(value="running"))
    assert asyncio.run(inspect_turns([running])) == "running"
    interrupted = SimpleNamespace(
        id="turn-1", status=SimpleNamespace(value="interrupted")
    )
    assert asyncio.run(inspect_turns([interrupted])) == "interrupted"
    unknown = SimpleNamespace(id="turn-1", status=SimpleNamespace(value="new-status"))
    assert asyncio.run(inspect_turns([unknown])) == "unknown"
    assert asyncio.run(inspect_turns([completed], turn_id="other")) == "unknown"
    assert asyncio.run(inspect_turns([completed, unknown], turn_id=None)) == "unknown"
    assert asyncio.run(inspect_turns([completed], turn_id=None)) == "completed"

    missing = RuntimeSessionRef(
        adapter_id=runtime.adapter_id,
        native_session_id="missing-thread",
        storage_class="provider",
    )
    assert asyncio.run(runtime.inspect(profile(tmp_path), missing, str(workspace))).state == (
        "missing"
    )


def test_codex_transport_failure_detaches_and_forces_reconciliation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("openai_codex")
    signing_key = b"trusted-plugin-key-material-123456"
    configured = profile(tmp_path, signing_key=signing_key)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    handle = ExplodingCodexHandle(SimpleNamespace(final_response=None))
    client = FakeCodexClient(SimpleNamespace(), handle)
    canaries = {
        "workspace_read": True,
        "workspace_write": True,
        "root_denied": True,
        "avo_state_denied": True,
        "private_evaluator_denied": True,
        "external_network_denied": True,
        "undeclared_socket_denied": True,
        "authentication_available": True,
    }
    monkeypatch.setattr(
        "avo_correlate.adapters.harness.codex.platform.system", lambda: "Linux"
    )
    runtime = CodexCodingAgentRuntime(
        artifact_sink=lambda payload, role: DIGEST_A,
        canary_runner=lambda runtime_profile, overrides: canaries,
        client_factory=lambda configuration: client,
        account_probe=lambda runtime_profile: CodexAccountIdentity(
            "chatgpt", "vandyand@gmail.com", "pro"
        ),
        cli_version_probe=lambda executable: "codex-cli 0.149.1",
        trusted_plugin_keys={"test": signing_key},
    )

    async def scenario() -> None:
        session = await runtime.start(configured, request(), str(workspace))
        for name in (".git", ".codex", ".agents"):
            (workspace / name).mkdir()
        with pytest.raises(ConnectionError, match="provider process exited"):
            _ = [event async for event in runtime.events(session)]
        assert client.closed
        assert await runtime.recover(session.native_session_id) is None
        assert not any(
            (workspace / name).exists() for name in (".git", ".codex", ".agents")
        )

    asyncio.run(scenario())


def test_codex_wait_transport_failure_detaches_and_forces_reconciliation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("openai_codex")
    signing_key = b"trusted-plugin-key-material-123456"
    configured = profile(tmp_path, signing_key=signing_key)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    handle = ExplodingWaitCodexHandle(SimpleNamespace(final_response=None))
    client = FakeCodexClient(SimpleNamespace(), handle)
    canaries = {
        "workspace_read": True,
        "workspace_write": True,
        "root_denied": True,
        "avo_state_denied": True,
        "private_evaluator_denied": True,
        "external_network_denied": True,
        "undeclared_socket_denied": True,
        "authentication_available": True,
    }
    monkeypatch.setattr(
        "avo_correlate.adapters.harness.codex.platform.system", lambda: "Linux"
    )
    runtime = CodexCodingAgentRuntime(
        artifact_sink=lambda payload, role: DIGEST_A,
        canary_runner=lambda runtime_profile, overrides: canaries,
        client_factory=lambda configuration: client,
        account_probe=lambda runtime_profile: CodexAccountIdentity(
            "chatgpt", "vandyand@gmail.com", "pro"
        ),
        cli_version_probe=lambda executable: "codex-cli 0.149.1",
        trusted_plugin_keys={"test": signing_key},
    )

    async def scenario() -> None:
        session = await runtime.start(configured, request(), str(workspace))
        with pytest.raises(ConnectionError, match="while waiting"):
            await runtime.wait(session)
        assert client.closed
        assert await runtime.recover(session.native_session_id) is None

    asyncio.run(scenario())


def test_codex_profile_supports_only_one_declared_evaluator_socket(tmp_path: Path) -> None:
    base_profile = profile(tmp_path)
    configured = base_profile.model_copy(
        update={
            "configuration": {
                **base_profile.configuration,
                "isolated_codex_home": str((tmp_path / "home").resolve()),
                "development_evaluator_socket": "/run/avo/evaluator.sock",
            }
        }
    )
    overrides = CodexCodingAgentRuntime.permission_overrides(configured)
    assert "features.network_proxy=true" in overrides
    assert any("/run/avo/evaluator.sock" in item for item in overrides)
    invalid = configured.model_copy(
        update={"configuration": {"development_evaluator_socket": "relative.sock"}}
    )
    with pytest.raises(ValueError, match="absolute Unix"):
        CodexCodingAgentRuntime.permission_overrides(invalid)


def test_codex_profile_pins_reasoning_effort(tmp_path: Path) -> None:
    base_profile = profile(tmp_path)
    configured = base_profile.model_copy(
        update={
            "configuration": {
                **base_profile.configuration,
                "reasoning_effort": "high",
            }
        }
    )
    overrides = CodexCodingAgentRuntime.permission_overrides(configured)
    assert 'model_reasoning_effort="high"' in overrides

    invalid = configured.model_copy(
        update={"configuration": {**configured.configuration, "reasoning_effort": "ultra"}}
    )
    with pytest.raises(ValueError, match="reasoning_effort"):
        CodexCodingAgentRuntime.permission_overrides(invalid)


def test_codex_candidate_workspace_rejects_parent_vcs_metadata(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    workspace = repository / "candidate"
    workspace.mkdir(parents=True)
    assert candidate_workspace_is_vcs_free(workspace)
    (repository / ".git").mkdir()
    assert not candidate_workspace_is_vcs_free(workspace)


def test_codex_candidate_workspace_rejects_agent_config_and_cleans_scaffolds(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "candidate"
    workspace.mkdir()
    assert candidate_workspace_is_config_free(workspace)
    for name in (".git", ".codex", ".agents"):
        (workspace / name).mkdir()
    remove_empty_codex_scaffolds(workspace)
    assert not any((workspace / name).exists() for name in (".git", ".codex", ".agents"))
    (workspace / ".codex").mkdir()
    (workspace / ".codex" / "config.toml").write_text("unsafe", encoding="utf-8")
    assert not candidate_workspace_is_config_free(workspace)
    with pytest.raises(CodexRuntimeError, match="not empty"):
        remove_empty_codex_scaffolds(workspace)


def test_codex_scaffold_cleanup_rejects_unsafe_and_nested_metadata(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "candidate"
    workspace.mkdir()
    (workspace / ".git").write_text("not a directory", encoding="utf-8")
    with pytest.raises(CodexRuntimeError, match="unsafe"):
        remove_empty_codex_scaffolds(workspace)
    (workspace / ".git").unlink()
    nested = workspace / "nested"
    nested.mkdir()
    (nested / ".git").mkdir()
    with pytest.raises(CodexRuntimeError, match="VCS metadata"):
        remove_empty_codex_scaffolds(workspace)
    (nested / ".git").rmdir()
    (nested / ".codex").mkdir()
    with pytest.raises(CodexRuntimeError, match="agent configuration"):
        remove_empty_codex_scaffolds(workspace)


def test_strict_completion_schema_rejects_missing_properties(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def empty_schema() -> dict[str, Any]:
        return {}

    monkeypatch.setattr(AgentCompletion, "model_json_schema", empty_schema)
    with pytest.raises(RuntimeError, match="no properties"):
        strict_agent_completion_schema()


def test_codex_preflight_requires_exact_chatgpt_pro_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signing_key = b"trusted-plugin-key-material-123456"
    configured = profile(tmp_path, signing_key=signing_key)
    canaries = {
        "workspace_read": True,
        "workspace_write": True,
        "root_denied": True,
        "avo_state_denied": True,
        "private_evaluator_denied": True,
        "external_network_denied": True,
        "undeclared_socket_denied": True,
        "authentication_available": True,
    }
    monkeypatch.setattr(
        "avo_correlate.adapters.harness.codex.platform.system", lambda: "Linux"
    )

    def report_for(
        identity: CodexAccountIdentity,
        runtime_profile: HarnessRuntimeProfile = configured,
    ) -> Any:
        runtime = CodexCodingAgentRuntime(
            artifact_sink=lambda payload, role: DIGEST_A,
            canary_runner=lambda profile, overrides: canaries,
            account_probe=lambda profile: identity,
            cli_version_probe=lambda executable: "codex-cli 0.149.1",
            trusted_plugin_keys={"test": signing_key},
        )
        return asyncio.run(runtime.preflight(runtime_profile))

    valid = report_for(CodexAccountIdentity("chatgpt", "vandyand@gmail.com", "pro"))
    assert valid.compatible
    account_check = next(
        check for check in valid.checks if check.name == "required_chatgpt_account"
    )
    assert account_check.status == "pass"

    api_profile = configured.model_copy(update={"authentication_class": "api_key"})
    api_report = report_for(
        CodexAccountIdentity("apiKey", None, None),
        api_profile,
    )
    assert not api_report.compatible
    subscription_check = next(
        check for check in api_report.checks if check.name == "chatgpt_subscription_only"
    )
    assert subscription_check.status == "fail"

    wrong_email = report_for(CodexAccountIdentity("chatgpt", "other@example.com", "pro"))
    assert not wrong_email.compatible
    wrong_plan = report_for(
        CodexAccountIdentity("chatgpt", "vandyand@gmail.com", "plus")
    )
    assert not wrong_plan.compatible


def test_codex_preflight_surfaces_account_probe_and_declared_socket_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signing_key = b"trusted-plugin-key-material-123456"
    socket = "/run/avo/evaluator.sock"
    base = profile(tmp_path, signing_key=signing_key)
    configured = base.model_copy(
        update={
            "permission_profile_digest": canonical_digest(
                codex_permission_contract(socket)
            ),
            "configuration": {
                **base.configuration,
                "development_evaluator_socket": socket,
                "canary_root": str((tmp_path / "canary").resolve()),
            },
        }
    )
    canaries = {
        "workspace_read": True,
        "workspace_write": True,
        "root_denied": True,
        "avo_state_denied": True,
        "private_evaluator_denied": True,
        "external_network_denied": True,
        "undeclared_socket_denied": True,
        "authentication_available": True,
    }
    monkeypatch.setattr(
        "avo_correlate.adapters.harness.codex.platform.system", lambda: "Linux"
    )

    def fail_account(runtime_profile: HarnessRuntimeProfile) -> CodexAccountIdentity:
        raise RuntimeError("account transport failed")

    runtime = CodexCodingAgentRuntime(
        artifact_sink=lambda payload, role: DIGEST_A,
        canary_runner=lambda runtime_profile, overrides: canaries,
        account_probe=fail_account,
        cli_version_probe=lambda executable: "codex-cli 0.149.1",
        trusted_plugin_keys={"test": signing_key},
    )
    report = asyncio.run(runtime.preflight(configured))
    account = next(
        check for check in report.checks if check.name == "required_chatgpt_account"
    )
    permission = next(
        check for check in report.checks if check.name == "permission_canaries"
    )
    assert "RuntimeError: account transport failed" in account.detail
    assert "declared_evaluator_socket_allowed" in permission.detail


def test_live_codex_canary_runner_maps_boundary_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeUnixServer:
        def close(self) -> None:
            pass

        async def wait_closed(self) -> None:
            pass

    async def start_unix_server(*args: object, **kwargs: object) -> FakeUnixServer:
        del args, kwargs
        return FakeUnixServer()

    async def execute(command: tuple[str, ...], workspace: Path) -> tuple[int, str, str]:
        del workspace
        rendered = " ".join(command)
        allowed = "workspace-readable.txt" in rendered or "workspace-written.txt" in rendered
        return (0 if allowed else 1), "", ""

    monkeypatch.setitem(asyncio.__dict__, "start_unix_server", start_unix_server)
    configured = profile(tmp_path).model_copy(
        update={
            "configuration": {
                **profile(tmp_path).configuration,
                "canary_root": str((tmp_path / "boundary-canary").resolve()),
            }
        }
    )
    runner = CodexLiveCanaryRunner(
        command_executor=execute,
        authentication_probe=lambda runtime_profile: True,
    )
    results = asyncio.run(runner(configured, ()))
    assert results == {
        "workspace_read": True,
        "workspace_write": True,
        "root_denied": True,
        "avo_state_denied": True,
        "private_evaluator_denied": True,
        "external_network_denied": True,
        "undeclared_socket_denied": True,
        "authentication_available": True,
    }


def test_live_codex_canary_root_is_narrow_and_outside_auth_home(tmp_path: Path) -> None:
    configured = profile(tmp_path)
    with pytest.raises(ValueError, match="canary_root"):
        CodexLiveCanaryRunner.validate_canary_root(configured)
    inside_auth = configured.model_copy(
        update={
            "configuration": {
                **configured.configuration,
                "canary_root": str(
                    Path(configured.configuration["isolated_codex_home"]) / "canary"
                ),
            }
        }
    )
    with pytest.raises(ValueError, match="outside CODEX_HOME"):
        CodexLiveCanaryRunner.validate_canary_root(inside_auth)


def test_codex_preflight_reports_canary_errors_and_signed_cli_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signing_key = b"trusted-plugin-key-material-123456"
    configured = profile(tmp_path, signing_key=signing_key)
    executable = Path(configured.configuration["codex_executable"])
    executable.write_text("changed executable", encoding="utf-8")
    monkeypatch.setattr(
        "avo_correlate.adapters.harness.codex.platform.system", lambda: "Linux"
    )

    def broken_canaries(
        runtime_profile: HarnessRuntimeProfile, overrides: tuple[str, ...]
    ) -> dict[str, bool]:
        del runtime_profile, overrides
        raise RuntimeError("canary transport failed")

    runtime = CodexCodingAgentRuntime(
        artifact_sink=lambda payload, role: DIGEST_A,
        canary_runner=broken_canaries,
        account_probe=lambda runtime_profile: CodexAccountIdentity(
            "chatgpt", "vandyand@gmail.com", "pro"
        ),
        cli_version_probe=lambda path: "codex-cli 0.149.1",
        trusted_plugin_keys={"test": signing_key},
    )
    report = asyncio.run(runtime.preflight(configured))
    assert not report.compatible
    digest_check = next(check for check in report.checks if check.name == "signed_cli_digest")
    assert digest_check.status == "fail"
    canary_check = next(check for check in report.checks if check.name == "permission_canaries")
    assert "RuntimeError: canary transport failed" in canary_check.detail


def test_codex_cli_version_probe_uses_an_allowlisted_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed: dict[str, object] = {}

    def run(command: list[str], **arguments: object) -> Any:
        observed.update(arguments)
        observed["command"] = command
        return SimpleNamespace(stdout="codex-cli 0.149.1\n")

    monkeypatch.setenv("OPENAI_API_KEY", "must-not-be-inherited")
    monkeypatch.setattr(
        "avo_correlate.adapters.harness.codex.subprocess.run",
        run,
    )
    executable = tmp_path / "codex"
    assert probe_cli_version(executable) == "codex-cli 0.149.1"
    assert observed["command"] == [str(executable), "--version"]
    environment = observed["env"]
    assert isinstance(environment, dict)
    assert "OPENAI_API_KEY" not in environment


def test_codex_authentication_probe_accepts_status_on_stderr(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    configured = profile(tmp_path)

    def run(*args: object, **kwargs: object) -> Any:
        del args, kwargs
        return SimpleNamespace(
            returncode=0,
            stdout="",
            stderr="Logged in using ChatGPT\n",
        )

    monkeypatch.setattr(
        "avo_correlate.adapters.harness.codex_canary.subprocess.run",
        run,
    )
    assert CodexLiveCanaryRunner._probe_authentication(  # pyright: ignore[reportPrivateUsage]
        configured
    )
