"""Pinned Codex SDK adapter with fail-closed permission-profile preflight."""

import hashlib
import inspect
import json
import os
import platform
import subprocess
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast

from avo_correlate.application.plugin_registry import (
    PluginCompatibilityError,
    verify_plugin_manifest,
)
from avo_correlate.contracts.operations import CheckStatus, DoctorCheck
from avo_correlate.contracts.runtime import (
    AgentCompletion,
    HarnessRuntimeProfile,
    RuntimeCapabilityReport,
    RuntimeEvent,
    RuntimeInspection,
    RuntimeSessionRef,
)
from avo_correlate.contracts.variation import VariationSessionRequest
from avo_correlate.domain.canonical import canonical_digest

CODEX_SDK_VERSION = "0.147.0"
CODEX_CLI_VERSION = "0.149.1"
CODEX_REASONING_EFFORTS = {"none", "low", "medium", "high", "xhigh", "max"}
REQUIRED_CODEX_ACCOUNT_EMAIL = "vandyand@gmail.com"
REQUIRED_CODEX_ACCOUNT_PLAN = "pro"
_CANARIES = frozenset(
    {
        "workspace_read",
        "workspace_write",
        "root_denied",
        "avo_state_denied",
        "private_evaluator_denied",
        "external_network_denied",
        "undeclared_socket_denied",
        "authentication_available",
    }
)

ArtifactSink = Callable[[bytes, str], str]
CanaryRunner = Callable[
    [HarnessRuntimeProfile, tuple[str, ...]],
    Mapping[str, bool] | Awaitable[Mapping[str, bool]],
]
CliVersionProbe = Callable[[Path], str]


class CodexControlClient(Protocol):
    """Narrow SDK surface owned by AVO rather than by campaign code."""

    async def thread_start(self, **arguments: Any) -> Any: ...

    async def thread_resume(self, thread_id: str, **arguments: Any) -> Any: ...

    async def close(self) -> None: ...


ClientFactory = Callable[[Any], CodexControlClient]


@dataclass(frozen=True)
class CodexAccountIdentity:
    authentication_type: str
    email: str | None
    plan: str | None


AccountProbe = Callable[
    [HarnessRuntimeProfile],
    CodexAccountIdentity | Awaitable[CodexAccountIdentity],
]


def probe_cli_version(executable: Path) -> str:
    environment = {
        key: value
        for key in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "LANG", "LC_ALL")
        if (value := os.environ.get(key)) is not None
    }
    completed = subprocess.run(
        [str(executable), "--version"],
        check=True,
        capture_output=True,
        env=environment,
        text=True,
        timeout=10,
    )
    return completed.stdout.strip()


def strict_agent_completion_schema() -> dict[str, Any]:
    """Return the provider schema with every declared property required."""
    schema = AgentCompletion.model_json_schema()
    properties = schema.get("properties")
    if not isinstance(properties, dict) or not properties:
        raise RuntimeError("AgentCompletion schema has no properties")
    typed_properties = cast(dict[str, Any], properties)
    schema["required"] = list(typed_properties)
    schema["additionalProperties"] = False
    return schema


def codex_permission_contract(
    development_evaluator_socket: object = None,
) -> dict[str, object]:
    """Return the canonical contract enforced by the Codex permission overrides."""
    if development_evaluator_socket is None:
        network: dict[str, str] = {"mode": "deny"}
    elif (
        isinstance(development_evaluator_socket, str)
        and development_evaluator_socket.startswith("/")
    ):
        network = {
            "mode": "declared-unix-socket-only",
            "path": development_evaluator_socket,
        }
    else:
        raise ValueError("development evaluator socket must be an absolute Unix path")
    return {
        "profile": "avo-workspace-only",
        "root": "deny",
        "minimal": "read",
        "workspace": "write",
        "project_instructions": "disabled",
        "ambient_capabilities": "disabled",
        "tmpdir": "private-write",
        "slash_tmp": "deny",
        "network": network,
        "web_search": "disabled",
    }


def candidate_workspace_is_vcs_free(workspace: Path) -> bool:
    """Reject VCS metadata in the candidate or any ancestor directory."""
    if any((ancestor / ".git").exists() for ancestor in (workspace, *workspace.parents)):
        return False
    return not any(workspace.rglob(".git"))


def candidate_workspace_is_config_free(workspace: Path) -> bool:
    """Reject candidate-controlled Codex and agent configuration directories."""
    return not any(
        path.name in {".codex", ".agents"} for path in workspace.rglob("*")
    )


class CodexRuntimeError(RuntimeError):
    pass


def remove_empty_codex_scaffolds(workspace: Path) -> None:
    """Remove only the empty mount targets created by Codex around a live turn."""
    for name in (".git", ".codex", ".agents"):
        target = workspace / name
        if not target.exists() and not target.is_symlink():
            continue
        if target.is_symlink() or not target.is_dir():
            raise CodexRuntimeError(f"Codex runtime scaffold is unsafe: {target}")
        try:
            target.rmdir()
        except OSError as exc:
            raise CodexRuntimeError(
                f"Codex runtime scaffold is not empty: {target}"
            ) from exc
    if not candidate_workspace_is_vcs_free(workspace):
        raise CodexRuntimeError("VCS metadata appeared in the candidate workspace")
    if not candidate_workspace_is_config_free(workspace):
        raise CodexRuntimeError("agent configuration appeared in the candidate workspace")


class CodexCodingAgentRuntime:
    adapter_id = f"openai-codex-sdk-{CODEX_SDK_VERSION}-cli-{CODEX_CLI_VERSION}"
    adapter_version = CODEX_SDK_VERSION
    runtime_version = CODEX_CLI_VERSION

    def __init__(
        self,
        *,
        artifact_sink: ArtifactSink,
        canary_runner: CanaryRunner | None = None,
        client_factory: ClientFactory | None = None,
        account_probe: AccountProbe | None = None,
        cli_version_probe: CliVersionProbe | None = None,
        trusted_plugin_keys: Mapping[str, bytes] | None = None,
    ) -> None:
        self._artifact_sink = artifact_sink
        self._canary_runner = canary_runner
        self._client_factory = client_factory
        self._account_probe = account_probe or self._probe_account
        self._cli_version_probe = cli_version_probe or probe_cli_version
        self._trusted_plugin_keys = trusted_plugin_keys or {}
        self._sessions: dict[str, tuple[Any, Any, Any | None]] = {}
        self._session_refs: dict[str, RuntimeSessionRef] = {}
        self._results: dict[str, Any] = {}
        self._final_responses: dict[str, str] = {}
        self._sequences: dict[str, int] = {}
        self._workspaces: dict[str, Path] = {}

    async def preflight(self, profile: HarnessRuntimeProfile) -> RuntimeCapabilityReport:
        checks: list[DoctorCheck] = []
        linux = platform.system().lower() == "linux"
        checks.append(
            DoctorCheck(
                name="linux_wsl_boundary",
                status=CheckStatus.PASS if linux else CheckStatus.FAIL,
                detail=(
                    "Linux/WSL permission enforcement is available"
                    if linux
                    else "live Codex operation is Linux/WSL-only in this release"
                ),
                next_action=None if linux else "Run the worker inside Linux or WSL 2.",
            )
        )
        subscription_only = (
            profile.authentication_class == "subscription"
            and profile.credential_profile_ref is None
        )
        checks.append(
            DoctorCheck(
                name="chatgpt_subscription_only",
                status=CheckStatus.PASS if subscription_only else CheckStatus.FAIL,
                detail=(
                    "profile uses cached ChatGPT subscription authentication"
                    if subscription_only
                    else "Codex requires subscription auth with no API credential profile"
                ),
                next_action=(
                    None
                    if subscription_only
                    else "Set authentication_class=subscription and omit credential_profile_ref."
                ),
            )
        )
        verified_manifest = None
        try:
            verified_manifest = verify_plugin_manifest(
                profile.plugin,
                trusted_keys=self._trusted_plugin_keys,
                required_contract="HarnessRuntimeProfile.v1",
                required_schema_version=1,
                operating_system="linux",
                architecture="x86_64",
            )
            plugin_ok = verified_manifest.plugin_version == CODEX_SDK_VERSION
            plugin_detail = (
                f"trusted plugin manifest pins {verified_manifest.plugin_version}"
                if plugin_ok
                else (
                    f"plugin pins {verified_manifest.plugin_version}; "
                    f"required {CODEX_SDK_VERSION}"
                )
            )
        except PluginCompatibilityError as exc:
            plugin_ok = False
            plugin_detail = str(exc)
        checks.append(
            DoctorCheck(
                name="signed_plugin_manifest",
                status=CheckStatus.PASS if plugin_ok else CheckStatus.FAIL,
                detail=plugin_detail,
                next_action=(
                    None
                    if plugin_ok
                    else "Install a trusted, exact-version Codex plugin manifest."
                ),
            )
        )
        try:
            import openai_codex

            actual_version = openai_codex.__version__
        except ImportError:
            actual_version = "not-installed"
        version_ok = actual_version == CODEX_SDK_VERSION
        checks.append(
            DoctorCheck(
                name="pinned_sdk",
                status=CheckStatus.PASS if version_ok else CheckStatus.FAIL,
                detail=f"openai-codex {actual_version}; required {CODEX_SDK_VERSION}",
                next_action=None if version_ok else "Install the avo-correlate[codex] extra.",
            )
        )
        required_completion_schema_digest = canonical_digest(
            strict_agent_completion_schema()
        )
        completion_schema_ok = (
            profile.completion_schema_digest == required_completion_schema_digest
        )
        checks.append(
            DoctorCheck(
                name="strict_completion_schema",
                status=(
                    CheckStatus.PASS if completion_schema_ok else CheckStatus.FAIL
                ),
                detail=(
                    "profile pins the provider-valid strict completion schema"
                    if completion_schema_ok
                    else "profile completion schema digest is stale or incompatible"
                ),
                next_action=(
                    None
                    if completion_schema_ok
                    else "Re-provision the profile with the current strict schema digest."
                ),
            )
        )
        permission_contract_error: str | None = None
        try:
            required_permission_profile_digest = canonical_digest(
                codex_permission_contract(
                    profile.configuration.get("development_evaluator_socket")
                )
            )
            permission_profile_ok = (
                profile.permission_profile_digest
                == required_permission_profile_digest
            )
        except ValueError as exc:
            permission_profile_ok = False
            permission_contract_error = str(exc)
        checks.append(
            DoctorCheck(
                name="permission_profile_digest",
                status=(
                    CheckStatus.PASS if permission_profile_ok else CheckStatus.FAIL
                ),
                detail=(
                    "profile pins the current fail-closed permission contract"
                    if permission_profile_ok
                    else (
                        permission_contract_error
                        or "profile permission digest is stale or incompatible"
                    )
                ),
                next_action=(
                    None
                    if permission_profile_ok
                    else "Re-provision the profile with the current permission contract."
                ),
            )
        )
        executable_value = profile.configuration.get("codex_executable")
        executable = (
            Path(executable_value)
            if isinstance(executable_value, str) and Path(executable_value).is_absolute()
            else None
        )
        executable_exists = executable is not None and executable.is_file()
        actual_cli = "not-configured"
        if executable_exists and executable is not None:
            try:
                actual_cli = self._cli_version_probe(executable)
            except (OSError, subprocess.SubprocessError) as exc:
                actual_cli = f"unavailable: {exc}"
        required_cli = f"codex-cli {CODEX_CLI_VERSION}"
        cli_ok = executable_exists and actual_cli == required_cli
        checks.append(
            DoctorCheck(
                name="pinned_cli",
                status=CheckStatus.PASS if cli_ok else CheckStatus.FAIL,
                detail=f"{actual_cli}; required {required_cli}",
                next_action=(
                    None
                    if cli_ok
                    else (
                        "Configure an absolute codex_executable for exact CLI "
                        f"{CODEX_CLI_VERSION}."
                    )
                ),
            )
        )
        actual_executable_digest = None
        if executable_exists and executable is not None:
            with executable.open("rb") as source:
                actual_executable_digest = (
                    "sha256:" + hashlib.file_digest(source, "sha256").hexdigest()
                )
        executable_digest_ok = (
            verified_manifest is not None
            and actual_executable_digest == verified_manifest.package_digest
        )
        checks.append(
            DoctorCheck(
                name="signed_cli_digest",
                status=CheckStatus.PASS if executable_digest_ok else CheckStatus.FAIL,
                detail=(
                    "configured CLI matches the signed package digest"
                    if executable_digest_ok
                    else "configured CLI does not match the signed package digest"
                ),
                next_action=(
                    None
                    if executable_digest_ok
                    else "Re-sign the profile for the reviewed Codex executable."
                ),
            )
        )
        home_value = profile.configuration.get("isolated_codex_home")
        isolated_home = (
            isinstance(home_value, str)
            and Path(home_value).is_absolute()
            and Path(home_value).is_dir()
        )
        checks.append(
            DoctorCheck(
                name="isolated_codex_home",
                status=CheckStatus.PASS if isolated_home else CheckStatus.FAIL,
                detail=(
                    "an absolute isolated CODEX_HOME is configured"
                    if isolated_home
                    else "isolated_codex_home is absent, not absolute, or not a directory"
                ),
                next_action=(
                    None
                    if isolated_home
                    else "Create and configure a dedicated absolute CODEX_HOME."
                ),
            )
        )
        private_tmpdir_value = profile.configuration.get("private_tmpdir")
        private_tmpdir = (
            Path(private_tmpdir_value)
            if isinstance(private_tmpdir_value, str)
            and Path(private_tmpdir_value).is_absolute()
            else None
        )
        isolated_home_path = Path(home_value) if isinstance(home_value, str) else None
        private_tmpdir_ok = (
            private_tmpdir is not None
            and private_tmpdir.is_dir()
            and private_tmpdir != Path(private_tmpdir.anchor)
            and private_tmpdir != Path.home()
            and isolated_home_path is not None
            and private_tmpdir != isolated_home_path
            and not private_tmpdir.is_relative_to(isolated_home_path)
        )
        checks.append(
            DoctorCheck(
                name="private_tmpdir",
                status=CheckStatus.PASS if private_tmpdir_ok else CheckStatus.FAIL,
                detail=(
                    "a narrow private TMPDIR outside CODEX_HOME is configured"
                    if private_tmpdir_ok
                    else (
                        "private_tmpdir is absent, broad, inside CODEX_HOME, "
                        "or not an existing directory"
                    )
                ),
                next_action=(
                    None
                    if private_tmpdir_ok
                    else "Create and configure a private runtime TMPDIR with mode 0700."
                ),
            )
        )
        identity: CodexAccountIdentity | None = None
        identity_error: str | None = None
        if (
            subscription_only
            and version_ok
            and cli_ok
            and isolated_home
            and private_tmpdir_ok
        ):
            try:
                account_outcome = self._account_probe(profile)
                identity = (
                    await account_outcome
                    if inspect.isawaitable(account_outcome)
                    else account_outcome
                )
            except Exception as exc:  # provider errors are reported, never downgraded
                identity_error = f"{type(exc).__name__}: {exc}"
        account_ok = (
            identity is not None
            and identity.authentication_type == "chatgpt"
            and identity.email is not None
            and identity.email.casefold() == REQUIRED_CODEX_ACCOUNT_EMAIL.casefold()
            and identity.plan == REQUIRED_CODEX_ACCOUNT_PLAN
        )
        if identity is None:
            identity_detail = identity_error or "account probe prerequisites failed"
        else:
            identity_detail = (
                f"type={identity.authentication_type}; email={identity.email}; plan={identity.plan}"
            )
        checks.append(
            DoctorCheck(
                name="required_chatgpt_account",
                status=CheckStatus.PASS if account_ok else CheckStatus.FAIL,
                detail=identity_detail,
                next_action=(
                    None
                    if account_ok
                    else (
                        "Run codex login for vandyand@gmail.com in the configured CODEX_HOME "
                        "and confirm the Pro plan."
                    )
                ),
            )
        )
        overrides = self.permission_overrides(profile)
        canary_error: str | None = None
        if self._canary_runner is None:
            canaries: Mapping[str, bool] = {}
        else:
            try:
                outcome = self._canary_runner(profile, overrides)
                canaries = await outcome if inspect.isawaitable(outcome) else outcome
            except Exception as exc:
                canaries = {}
                canary_error = f"{type(exc).__name__}: {exc}"
        required_canaries: set[str] = set(_CANARIES)
        if profile.configuration.get("development_evaluator_socket") is not None:
            required_canaries.add("declared_evaluator_socket_allowed")
        missing = sorted(required_canaries - canaries.keys())
        failed = sorted(
            name for name in required_canaries if not canaries.get(name, False)
        )
        canary_ok = not missing and not failed
        checks.append(
            DoctorCheck(
                name="permission_canaries",
                status=CheckStatus.PASS if canary_ok else CheckStatus.FAIL,
                detail=(
                    "all filesystem, workspace, network, and socket canaries passed"
                    if canary_ok
                    else f"missing={missing}; failed={failed}; error={canary_error}"
                ),
                next_action=(
                    None
                    if canary_ok
                    else "Run the live boundary canary suite; do not enable this profile."
                ),
            )
        )
        compatible = all(check.status == CheckStatus.PASS for check in checks)
        return RuntimeCapabilityReport(
            profile_digest=canonical_digest(profile), compatible=compatible, checks=checks
        )

    @staticmethod
    def permission_overrides(profile: HarnessRuntimeProfile) -> tuple[str, ...]:
        name = "avo-workspace-only"
        socket = profile.configuration.get("development_evaluator_socket")
        codex_permission_contract(socket)
        codex_executable = profile.configuration.get("codex_executable")
        executable_permission = (
            f", {json.dumps(codex_executable)} = \"read\""
            if isinstance(codex_executable, str) and Path(codex_executable).is_absolute()
            else ""
        )
        profile_parts = [
            (
                'filesystem = { ":root" = "deny", ":minimal" = "read", '
                '":tmpdir" = "write", ":slash_tmp" = "deny"'
                f'{executable_permission}, ":workspace_roots" = {{ "." = "write" }} }}'
            )
        ]
        canary_root = profile.configuration.get("canary_root")
        if isinstance(canary_root, str) and Path(canary_root).is_absolute():
            canary_workspace = str(Path(canary_root) / "workspace")
            profile_parts.append(
                f"workspace_roots = {{ {json.dumps(canary_workspace)} = true }}"
            )
        network_proxy = False
        if socket is None:
            profile_parts.append("network = { enabled = false }")
        elif isinstance(socket, str) and socket.startswith("/"):
            network_proxy = True
            profile_parts.append(
                "network = { enabled = true, unix_sockets = { "
                f"{json.dumps(socket)} = \"allow\" }} }}"
            )
        else:
            raise ValueError("development evaluator socket must be an absolute Unix path")
        values = [
            'forced_login_method="chatgpt"',
            f"default_permissions={json.dumps(name)}",
            f"permissions={{ {name} = {{ {', '.join(profile_parts)} }} }}",
            'web_search="disabled"',
            "project_doc_max_bytes=0",
            "check_for_update_on_startup=false",
            "features.hooks=false",
            "features.apps=false",
            "features.plugins=false",
            "features.memories=false",
            "features.multi_agent=false",
            "features.computer_use=false",
            "features.browser_use=false",
        ]
        reasoning_effort = profile.configuration.get("reasoning_effort")
        if reasoning_effort is not None:
            if (
                not isinstance(reasoning_effort, str)
                or reasoning_effort not in CODEX_REASONING_EFFORTS
            ):
                raise ValueError("reasoning_effort is not supported by the Codex profile")
            values.append(f"model_reasoning_effort={json.dumps(reasoning_effort)}")
        if network_proxy:
            values.append("features.network_proxy=true")
        return tuple(values)

    async def prepare(
        self,
        profile: HarnessRuntimeProfile,
        request: VariationSessionRequest,
        workspace_path: str,
        *,
        invocation_id: str,
    ) -> RuntimeSessionRef:
        report = await self.preflight(profile)
        if not report.compatible:
            raise CodexRuntimeError("Codex profile failed preflight")
        workspace = Path(workspace_path).resolve(strict=True)
        if not candidate_workspace_is_vcs_free(workspace):
            raise CodexRuntimeError(
                "Codex candidate workspace and its ancestors must be VCS-free"
            )
        if not candidate_workspace_is_config_free(workspace):
            raise CodexRuntimeError(
                "Codex candidate workspace must not contain agent configuration"
            )
        client = self._create_client(profile, workspace)
        from openai_codex import ApprovalMode

        try:
            thread = await client.thread_start(
                approval_mode=ApprovalMode.deny_all,
                cwd=str(workspace),
                model=profile.requested_model,
            )
        except BaseException:
            await client.close()
            remove_empty_codex_scaffolds(workspace)
            raise
        native_id = cast(str, thread.id)
        self._sessions[native_id] = (client, thread, None)
        self._sequences[native_id] = 0
        self._workspaces[native_id] = workspace
        reference = RuntimeSessionRef(
            adapter_id=self.adapter_id,
            native_session_id=native_id,
            invocation_id=invocation_id,
            storage_class="provider",
            checkpoint=0,
        )
        self._session_refs[native_id] = reference
        return reference

    async def start_turn(
        self,
        profile: HarnessRuntimeProfile,
        request: VariationSessionRequest,
        session: RuntimeSessionRef,
    ) -> RuntimeSessionRef:
        client, thread, handle = self._session(session)
        if handle is not None or session.native_operation_id is not None:
            raise CodexRuntimeError("Codex turn is already started")
        workspace = self._workspaces[session.native_session_id]
        from openai_codex import ApprovalMode

        prompt = profile.configuration.get("task_prompt")
        if not isinstance(prompt, str) or not prompt.strip():
            prompt = (
                "Improve the candidate workspace for the following AVO variation session. "
                "Do not access external resources. Finish with the required JSON "
                "completion.\n" + request.model_dump_json()
            )
        try:
            handle = await thread.turn(
                prompt,
                approval_mode=ApprovalMode.deny_all,
                cwd=str(workspace),
                model=profile.requested_model,
                output_schema=strict_agent_completion_schema(),
            )
        except BaseException:
            await client.close()
            self._detach(session.native_session_id, workspace)
            raise
        self._sessions[session.native_session_id] = (client, thread, handle)
        reference = session.model_copy(
            update={"native_operation_id": cast(str, handle.id)}
        )
        self._session_refs[session.native_session_id] = reference
        return reference

    async def start(
        self,
        profile: HarnessRuntimeProfile,
        request: VariationSessionRequest,
        workspace_path: str,
    ) -> RuntimeSessionRef:
        """Compatibility wrapper for calibration and benchmark scripts."""
        prepared = await self.prepare(
            profile,
            request,
            workspace_path,
            invocation_id=f"codex:{request.session_id}",
        )
        return await self.start_turn(profile, request, prepared)

    async def events(self, session: RuntimeSessionRef) -> AsyncIterator[RuntimeEvent]:
        client, _, handle = self._session(session)
        if handle is None:
            raise CodexRuntimeError("Codex turn has not started")
        try:
            async for notification in handle.stream():
                self._sequences[session.native_session_id] += 1
                method = cast(str, getattr(notification, "method", "unknown"))
                payload = repr(notification).encode("utf-8", errors="replace")
                digest = self._artifact_sink(payload, "codex-runtime-event")
                provider_payload = getattr(notification, "payload", None)
                event_type = self._normalize_event_type(method, provider_payload)
                response = self._agent_message_text(provider_payload)
                if response is not None:
                    self._final_responses[session.native_session_id] = response
                if method == "turn/completed":
                    result = getattr(provider_payload, "turn", None)
                    if result is not None:
                        self._results[session.native_session_id] = result
                yield RuntimeEvent(
                    invocation_id=session.invocation_id or session.native_session_id,
                    sequence=self._sequences[session.native_session_id],
                    event_type=event_type,
                    provider_event_type=method,
                    payload_digest=cast(Any, digest),
                    usage_delta=self._usage_delta(provider_payload),
                    occurred_at=datetime.now(UTC),
                )
        except Exception:
            await client.close()
            workspace = self._workspaces.pop(session.native_session_id, None)
            self._sessions.pop(session.native_session_id, None)
            self._session_refs.pop(session.native_session_id, None)
            if workspace is not None:
                remove_empty_codex_scaffolds(workspace)
            raise

    async def wait(self, session: RuntimeSessionRef) -> AgentCompletion:
        client, _, handle = self._session(session)
        if handle is None:
            raise CodexRuntimeError("Codex turn has not started")
        workspace = self._workspaces[session.native_session_id]
        failed = True
        try:
            result = self._results.get(session.native_session_id)
            if result is None:
                result = await handle.run()
            status = getattr(result, "status", None)
            status_value = getattr(status, "value", status)
            if status_value == "failed":
                error = getattr(result, "error", None)
                message = getattr(error, "message", None)
                raise CodexRuntimeError(
                    "Codex turn failed" + (f": {message}" if message else "")
                )
            completion = self._completion_from_result(session, result)
            failed = False
            return completion
        finally:
            try:
                await client.close()
                remove_empty_codex_scaffolds(workspace)
            except Exception:
                failed = True
                raise
            finally:
                if failed:
                    self._sessions.pop(session.native_session_id, None)
                    self._session_refs.pop(session.native_session_id, None)
                    self._workspaces.pop(session.native_session_id, None)

    async def cancel(self, session: RuntimeSessionRef) -> None:
        client, _, handle = self._session(session)
        try:
            if handle is not None:
                await handle.interrupt()
        finally:
            await client.close()
            remove_empty_codex_scaffolds(self._workspaces[session.native_session_id])

    async def recover(self, native_session_id: str) -> RuntimeSessionRef | None:
        if native_session_id in self._sessions:
            _, _, handle = self._sessions[native_session_id]
            reference = self._session_refs[native_session_id]
            return reference.model_copy(
                update={
                    "native_operation_id": (
                        None if handle is None else cast(str, handle.id)
                    ),
                    "checkpoint": self._sequences.get(native_session_id, 0),
                }
            )
        # The SDK can resume a thread but cannot reattach to an in-flight turn handle.
        # Returning None forces AVO's scheduler into explicit reconciliation.
        return None

    async def inspect(
        self,
        profile: HarnessRuntimeProfile,
        session: RuntimeSessionRef,
        workspace_path: str,
    ) -> RuntimeInspection:
        if session.adapter_id != self.adapter_id:
            raise ValueError("session belongs to another adapter")
        attached = self._sessions.get(session.native_session_id)
        if attached is not None:
            _, _, handle = attached
            if handle is None:
                return RuntimeInspection(state="not_started", session=session)
            result = self._results.get(session.native_session_id)
            if result is None:
                return RuntimeInspection(state="running", session=session)
            completion = self._completion_from_result(session, result)
            return RuntimeInspection(
                state="completed", session=session, completion=completion
            )

        workspace = Path(workspace_path).resolve(strict=True)
        client = self._create_client(profile, workspace)
        try:
            thread = await client.thread_resume(
                session.native_session_id,
                cwd=str(workspace),
                model=profile.requested_model,
            )
            response = await thread.read(include_turns=True)
        except Exception:
            return RuntimeInspection(state="missing", session=session)
        finally:
            await client.close()
        turns = self._inspection_turns(response)
        if not turns:
            return RuntimeInspection(state="not_started", session=session)
        turn = self._matching_turn(turns, session.native_operation_id)
        if turn is None:
            return RuntimeInspection(state="unknown", session=session)
        turn_id = cast(str | None, getattr(turn, "id", None))
        observed = session.model_copy(
            update={"native_operation_id": session.native_operation_id or turn_id}
        )
        status = getattr(getattr(turn, "status", None), "value", getattr(turn, "status", None))
        if status in {"inProgress", "in_progress", "running"}:
            return RuntimeInspection(state="running", session=observed)
        if status in {"interrupted", "cancelled", "canceled"}:
            return RuntimeInspection(state="interrupted", session=observed)
        if status in {"completed", "failed"}:
            try:
                completion = self._completion_from_result(observed, turn)
            except CodexRuntimeError:
                return RuntimeInspection(state="unknown", session=observed)
            return RuntimeInspection(
                state="completed", session=observed, completion=completion
            )
        return RuntimeInspection(state="unknown", session=observed)

    def _create_client(self, profile: HarnessRuntimeProfile, workspace: Path) -> Any:
        from openai_codex import AsyncCodex, CodexConfig

        config = CodexConfig(
            codex_bin=cast(str, profile.configuration["codex_executable"]),
            config_overrides=self.permission_overrides(profile),
            cwd=str(workspace),
            env=self.codex_environment(profile),
        )
        factory = self._client_factory or AsyncCodex
        return factory(config)

    async def _probe_account(self, profile: HarnessRuntimeProfile) -> CodexAccountIdentity:
        from openai_codex import AsyncCodex, CodexConfig

        client = AsyncCodex(
            CodexConfig(
                codex_bin=cast(str, profile.configuration["codex_executable"]),
                config_overrides=('forced_login_method="chatgpt"',),
                env=self.codex_environment(profile),
            )
        )
        try:
            response = await client.account(refresh_token=True)
            document = cast(
                dict[str, object], response.model_dump(mode="json", by_alias=False)
            )
        finally:
            await client.close()
        raw_account = document.get("account")
        if not isinstance(raw_account, dict):
            return CodexAccountIdentity("none", None, None)
        account = cast(dict[str, object], raw_account)
        authentication_type = account.get("type")
        email = account.get("email")
        plan = account.get("plan_type")
        return CodexAccountIdentity(
            authentication_type=(
                authentication_type if isinstance(authentication_type, str) else "unknown"
            ),
            email=email if isinstance(email, str) else None,
            plan=plan if isinstance(plan, str) else None,
        )

    @staticmethod
    def codex_environment(profile: HarnessRuntimeProfile) -> dict[str, str]:
        home = cast(str, profile.configuration["isolated_codex_home"])
        private_tmpdir = cast(str, profile.configuration["private_tmpdir"])
        allowed_ambient = (
            "PATH",
            "LANG",
            "LC_ALL",
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "PATHEXT",
            "TEMP",
            "TMP",
        )
        environment = {
            key: value
            for key in allowed_ambient
            if (value := os.environ.get(key)) is not None
        }
        environment["CODEX_HOME"] = home
        environment["HOME"] = home
        environment["TMPDIR"] = private_tmpdir
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment.setdefault("LANG", "C.UTF-8")
        return environment

    def _session(self, session: RuntimeSessionRef) -> tuple[Any, Any, Any | None]:
        if session.adapter_id != self.adapter_id:
            raise ValueError("session belongs to another adapter")
        try:
            return self._sessions[session.native_session_id]
        except KeyError as exc:
            raise LookupError("Codex session is not attached") from exc

    def _detach(self, native_session_id: str, workspace: Path) -> None:
        self._sessions.pop(native_session_id, None)
        self._session_refs.pop(native_session_id, None)
        self._workspaces.pop(native_session_id, None)
        remove_empty_codex_scaffolds(workspace)

    def _completion_from_result(
        self, session: RuntimeSessionRef, result: object
    ) -> AgentCompletion:
        final_response = getattr(result, "final_response", None)
        if not isinstance(final_response, str):
            final_response = self._final_responses.get(session.native_session_id)
        if not isinstance(final_response, str):
            items = getattr(result, "items", None)
            if isinstance(items, list):
                typed_items = cast(list[object], items)
                for item in reversed(typed_items):
                    candidate = getattr(item, "root", item)
                    text = getattr(candidate, "text", None)
                    if isinstance(text, str):
                        final_response = text
                        break
        if not isinstance(final_response, str):
            raise CodexRuntimeError("Codex completion did not contain JSON text")
        try:
            return AgentCompletion.model_validate_json(final_response)
        except (TypeError, ValueError) as exc:
            raise CodexRuntimeError("Codex did not return the completion schema") from exc

    @staticmethod
    def _inspection_turns(response: object) -> list[object]:
        thread = getattr(response, "thread", response)
        turns = getattr(thread, "turns", None)
        return cast(list[object], turns) if isinstance(turns, list) else []

    @staticmethod
    def _matching_turn(turns: list[object], turn_id: str | None) -> object | None:
        if turn_id is None:
            return turns[0] if len(turns) == 1 else None
        return next((turn for turn in turns if getattr(turn, "id", None) == turn_id), None)

    @staticmethod
    def _normalize_event_type(method: str, payload: object) -> Any:
        normalized = method.lower()
        if method == "turn/started":
            return "session_started"
        if method == "turn/completed":
            turn = getattr(payload, "turn", None)
            status = getattr(turn, "status", None)
            if getattr(status, "value", status) == "failed":
                return "error"
            return "completion"
        if CodexCodingAgentRuntime._agent_message_text(payload) is not None:
            return "message"
        if method.endswith("/started"):
            return "tool_started"
        if method.endswith("/completed"):
            return "tool_completed"
        if "usage" in normalized:
            return "usage"
        if "error" in method:
            return "error"
        return "message"

    @staticmethod
    def _agent_message_text(payload: object) -> str | None:
        item = getattr(payload, "item", None)
        candidate = getattr(item, "root", item)
        text = getattr(candidate, "text", None)
        if not isinstance(text, str):
            return None
        phase = getattr(candidate, "phase", None)
        phase_value = getattr(phase, "value", phase)
        return text if phase_value in {None, "final_answer"} else None

    @staticmethod
    def _usage_delta(payload: object) -> dict[str, int]:
        usage = getattr(payload, "token_usage", None)
        if usage is None or not hasattr(usage, "model_dump"):
            return {}
        document = usage.model_dump(mode="json", by_alias=False)
        if not isinstance(document, dict):
            return {}
        result: dict[str, int] = {}

        def collect(prefix: str, value: object) -> None:
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                result[prefix] = value
            elif isinstance(value, dict):
                typed = cast(dict[str, object], value)
                for key, child in typed.items():
                    collect(f"{prefix}.{key}" if prefix else str(key), child)

        collect("", cast(dict[str, object], document))
        return result
