"""Destructively probe one exact Codex app-server process for reconciliation behavior."""

import argparse
import asyncio
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any, cast

from avo_correlate.adapters.harness.codex import CodexCodingAgentRuntime
from avo_correlate.adapters.harness.codex_canary import CodexLiveCanaryRunner
from avo_correlate.contracts.base import VersionedComponentRef
from avo_correlate.contracts.runtime import HarnessRuntimeProfile
from avo_correlate.contracts.variation import CandidateRef, VariationSessionRequest
from avo_correlate.domain.canonical import canonical_digest

DIGEST_A = "sha256:" + ("a" * 64)
DIGEST_B = "sha256:" + ("b" * 64)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--trusted-key", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    return parser.parse_args()


def _workspace_digest(workspace: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in workspace.rglob("*") if item.is_file()):
        relative = path.relative_to(workspace)
        if relative.parts[0] in {".git", ".codex", ".agents"}:
            continue
        digest.update(relative.as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def _request() -> VariationSessionRequest:
    return VariationSessionRequest(
        session_id="live-hard-failure",
        run_id="live-hard-failure",
        champion=CandidateRef(
            candidate_id="seed", source_tree_digest=DIGEST_A, lineage_sequence=0
        ),
        lineage_index_digest=DIGEST_A,
        initial_context_digest=DIGEST_B,
        tool_capability_token="live-gate-no-tools",
        development_evaluator_refs=[
            VersionedComponentRef(
                component_id="development",
                component_version="1.0.0",
                package_digest=DIGEST_A,
                capability_manifest_digest=DIGEST_B,
            )
        ],
        budget_reservation_id="live-hard-failure",
        random_seed=1,
    )


def _verified_app_server_pid(client: object, executable: Path) -> int:
    async_client = cast(Any, client)._client
    sync_client = async_client._sync
    process = cast(subprocess.Popen[str] | None, sync_client._proc)
    if process is None:
        raise RuntimeError("live Codex app-server process is unavailable")
    pid = process.pid
    if pid <= 1 or process.poll() is not None:
        raise RuntimeError("live Codex app-server process is unavailable")
    proc_root = Path("/proc") / str(pid)
    observed_executable = (proc_root / "exe").resolve(strict=True)
    command = (proc_root / "cmdline").read_bytes().split(b"\0")
    status = (proc_root / "status").read_text(encoding="utf-8")
    parent_line = next(line for line in status.splitlines() if line.startswith("PPid:"))
    parent_pid = int(parent_line.split()[1])
    if not observed_executable.samefile(executable):
        raise RuntimeError("refusing to signal a process with an unexpected executable")
    if b"app-server" not in command or b"stdio://" not in command:
        raise RuntimeError("refusing to signal a process with an unexpected command line")
    if parent_pid != os.getpid():
        raise RuntimeError("refusing to signal a process not owned by this probe")
    return pid


async def _run(arguments: argparse.Namespace) -> dict[str, Any]:
    profile = HarnessRuntimeProfile.model_validate_json(
        arguments.profile.read_text(encoding="utf-8")
    )
    workspace = arguments.workspace.resolve(strict=True)
    profile = profile.model_copy(
        update={
            "configuration": {
                **profile.configuration,
                "task_prompt": (
                    "Do not use tools, run commands, or modify files. Carefully analyze the "
                    "architecture in the workspace, then return the required JSON completion."
                ),
            }
        }
    )
    runtime = CodexCodingAgentRuntime(
        artifact_sink=lambda payload, role: canonical_digest(
            {"role": role, "payload_hex": payload.hex()}
        ),
        canary_runner=CodexLiveCanaryRunner(),
        trusted_plugin_keys={profile.plugin.signer_key_id: arguments.trusted_key.read_bytes()},
    )
    before = _workspace_digest(workspace)
    session = await runtime.start(profile, _request(), str(workspace))
    sessions = cast(
        dict[str, tuple[object, object, object]],
        runtime._sessions,  # pyright: ignore[reportPrivateUsage]
    )
    client = sessions[session.native_session_id][0]
    executable = Path(cast(str, profile.configuration["codex_executable"]))
    pid = _verified_app_server_pid(client, executable)

    async def consume() -> int:
        count = 0
        async for _event in runtime.events(session):
            count += 1
        return count

    consumer = asyncio.create_task(consume())
    await asyncio.sleep(0.1)
    _verified_app_server_pid(client, executable)
    os.kill(pid, 9)
    failure: str | None = None
    try:
        await asyncio.wait_for(consumer, timeout=15)
    except Exception as exc:
        failure = f"{type(exc).__name__}: {exc}"
    if failure is None:
        raise RuntimeError("event stream completed instead of surfacing provider failure")
    recovered = await runtime.recover(session.native_session_id)
    after = _workspace_digest(workspace)
    scaffolds_present = any(
        (workspace / name).exists() for name in (".git", ".codex", ".agents")
    )
    return {
        "profile_digest": canonical_digest(profile),
        "native_session_id": session.native_session_id,
        "provider_failure": failure,
        "recover_returned_none": recovered is None,
        "workspace_unchanged": before == after,
        "scaffolds_present": scaffolds_present,
        "target_verified": True,
    }


def main() -> None:
    print(json.dumps(asyncio.run(_run(_arguments())), sort_keys=True))


if __name__ == "__main__":
    main()
