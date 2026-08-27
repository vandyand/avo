"""Run one repetition of the frozen native/OpenRouter comparison arm."""

import argparse
import asyncio
import hashlib
import json
import secrets
import shutil
import tempfile
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from avo_correlate.adapters.harness.native import NativeAgentHarness
from avo_correlate.adapters.model.openrouter import OpenRouterModelGateway
from avo_correlate.adapters.tools.workspace import WorkspaceToolBroker
from avo_correlate.application.capabilities import CapabilityIssuer
from avo_correlate.contracts.agent import AgentObservation
from avo_correlate.contracts.budgets import UsageRecord
from avo_correlate.contracts.experiment import WorkspaceSpec
from avo_correlate.contracts.model import ModelInvocationRecord
from avo_correlate.contracts.tools import CapabilityClaims
from avo_correlate.domain.canonical import canonical_digest, source_tree_digest
from avo_correlate.domain.workspace import create_vcs_free_binary_patch
from scripts.run_codex_pilot import (
    DEFAULT_EVALUATOR_IMAGE,
    changed_paths,
    evaluate_workspace,
    private_directory,
    read_json,
    remove_generated_python_caches,
    task_root_for,
    variation_request,
    verify_comparison_run_lock,
    verify_local_image,
    verify_pilot_lock,
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--pilot-root", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--git-metadata-root", type=Path, required=True)
    parser.add_argument("--results-root", type=Path, required=True)
    parser.add_argument("--repetition", type=int, required=True)
    parser.add_argument(
        "--purpose", choices=("canary", "comparison"), default="comparison"
    )
    parser.add_argument("--task", action="append", dest="tasks")
    parser.add_argument("--evaluator-image", default=DEFAULT_EVALUATOR_IMAGE)
    return parser.parse_args()


def _profile(path: Path) -> dict[str, Any]:
    profile = read_json(path)
    required = {
        "profile_id",
        "requested_model",
        "observed_canonical_model",
        "reasoning_effort",
        "max_tokens_per_turn",
        "max_turns",
        "max_wall_time_seconds",
        "input_microusd_per_million",
        "output_microusd_per_million",
        "provider_preferences",
        "app_title",
    }
    if not required.issubset(profile):
        raise ValueError("OpenRouter comparison profile is incomplete")
    if profile.get("endpoint") != "https://openrouter.ai/api/v1/chat/completions":
        raise ValueError("OpenRouter comparison endpoint is not approved")
    if profile.get("reasoning_effort") not in {
        "none",
        "low",
        "medium",
        "high",
        "xhigh",
        "max",
    }:
        raise ValueError("OpenRouter reasoning effort is invalid")
    return profile


def _artifact_sink(root: Path) -> Any:
    root.mkdir(parents=True, exist_ok=True)

    def store(payload: bytes, role: str) -> str:
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        path = root / digest.removeprefix("sha256:")
        if not path.exists():
            path.write_bytes(payload)
        role_path = root / f"{digest.removeprefix('sha256:')}.{role}"
        if not role_path.exists():
            role_path.touch()
        return digest

    return store


class PilotToolDispatcher:
    def __init__(
        self,
        broker: WorkspaceToolBroker,
        workspace: Path,
        *,
        run_id: str,
        task_id: str,
        public_command: list[str],
        evaluator_image: str,
        timeout_seconds: int,
        artifact_sink: Callable[[bytes, str], str],
    ) -> None:
        self._broker = broker
        self._workspace = workspace
        self._run_id = run_id
        self._task_id = task_id
        self._public_command = public_command
        self._evaluator_image = evaluator_image
        self._timeout_seconds = timeout_seconds
        self._artifact_sink = artifact_sink
        self._evaluation_outputs: dict[str, bytes] = {}
        self.observations: list[AgentObservation] = []
        self.evaluator_calls = 0

    async def invoke(
        self, tool_id: str, arguments: dict[str, object], *, capability_token: str
    ) -> AgentObservation:
        try:
            if tool_id == "read_file":
                content = self._broker.read_file(
                    capability_token, _required_string(arguments, "path")
                )
                summary = content.decode("utf-8", errors="replace")
                result_digest = "sha256:" + hashlib.sha256(content).hexdigest()
                outcome = "succeeded"
            elif tool_id == "search_workspace":
                results = self._broker.search_workspace(
                    capability_token, _required_string(arguments, "pattern")
                )
                summary = "\n".join(results) if results else "No matches."
                result_digest = canonical_digest(results)
                outcome = "succeeded"
            elif tool_id == "apply_patch":
                patch = _required_string(arguments, "patch").encode()
                self._broker.apply_patch(capability_token, patch)
                result_digest = source_tree_digest(self._workspace)
                summary = f"Patch applied. Current workspace digest: {result_digest}"
                outcome = "succeeded"
            elif tool_id == "replace_text":
                self._broker.replace_text(
                    capability_token,
                    _required_string(arguments, "path"),
                    _required_string(arguments, "old"),
                    _required_string(arguments, "new", allow_empty=True),
                )
                result_digest = source_tree_digest(self._workspace)
                summary = (
                    "Exact replacement applied. Current workspace digest: "
                    f"{result_digest}"
                )
                outcome = "succeeded"
            elif tool_id == "inspect_diff":
                diff = self._broker.inspect_diff(capability_token)
                result_digest = "sha256:" + hashlib.sha256(diff).hexdigest()
                summary = diff.decode("utf-8", errors="replace") or "No changes."
                outcome = "succeeded"
            elif tool_id == "run_development_evaluator":
                self.evaluator_calls += 1
                evaluation = evaluate_workspace(
                    run_id=self._run_id,
                    task_id=self._task_id,
                    phase=f"development-{self.evaluator_calls}",
                    workspace=self._workspace,
                    command=self._public_command,
                    evaluator_image=self._evaluator_image,
                    timeout_seconds=self._timeout_seconds,
                    output_sink=self._capture_evaluator_output,
                )
                result_digest = source_tree_digest(self._workspace)
                outcome = (
                    "succeeded" if evaluation.outcome == "succeeded" else "failed"
                )
                summary = (
                    f"Public evaluator {evaluation.outcome}; exit_code="
                    f"{evaluation.exit_code}; workspace digest: {result_digest}\n"
                    + evaluator_excerpt(
                        self._evaluation_outputs[evaluation.stdout_digest],
                        self._evaluation_outputs[evaluation.stderr_digest],
                    )
                )
            else:
                raise ValueError(f"unsupported tool: {tool_id}")
        except Exception as exc:
            result_digest = source_tree_digest(self._workspace)
            outcome = "failed"
            summary = f"{type(exc).__name__}: {str(exc)[:1500]}"
        observation = AgentObservation(
            tool_id=tool_id,
            outcome=cast(Any, outcome),
            result_digest=cast(Any, result_digest),
            summary=summary[:100_000],
        )
        self.observations.append(observation)
        return observation

    def _capture_evaluator_output(self, payload: bytes, role: str) -> str:
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        stored_digest = self._artifact_sink(payload, role)
        if stored_digest != digest:
            raise RuntimeError("evaluator artifact sink returned the wrong digest")
        self._evaluation_outputs[digest] = payload
        return digest


def _required_string(
    arguments: Mapping[str, object], name: str, *, allow_empty: bool = False
) -> str:
    value = arguments.get(name)
    if not isinstance(value, str) or (not allow_empty and not value):
        qualifier = "a string" if allow_empty else "a non-empty string"
        raise ValueError(f"{name} must be {qualifier}")
    return value


def evaluator_excerpt(stdout: bytes, stderr: bytes, *, limit: int = 12_000) -> str:
    combined = b"stdout:\n" + stdout + b"\nstderr:\n" + stderr
    return combined[:limit].decode("utf-8", errors="replace")


def _partial_usage(
    records: list[ModelInvocationRecord], tool_calls: int
) -> UsageRecord:
    usage = UsageRecord.zero().model_copy(
        update={"variation_sessions": 1, "tool_calls": tool_calls}
    )
    for record in records:
        usage = usage.plus(record.usage)
    return usage


def _developer_prompt(task_prompt: str, files: list[str]) -> str:
    return f"""Repair the supplied candidate workspace.

Task:
{task_prompt}

Candidate files:
{chr(10).join(f'- {path}' for path in files)}

Tool protocol:
- Put tool parameters directly in the typed arguments object; do not encode nested JSON.
- read_file uses path; search_workspace uses pattern.
- replace_text uses path, exact old text, and replacement new text.
- apply_patch uses patch containing a UTF-8 unified git diff.
- inspect_diff and run_development_evaluator use an empty arguments object.

Use one tool action per turn. Read the implementation and public tests before editing. Prefer
replace_text for edits to existing files: copy a unique old substring exactly from read_file and
provide its replacement. Use apply_patch only when replacement cannot express the change; its
patch must use git-style --- a/path and +++ b/path headers. Tools may modify only src/ or tests/.
Run the development evaluator after editing. When it succeeds, return action "propose" and copy
the latest workspace digest from the evaluator observation into proposed_workspace_digest.
Return action "stop" only if you intentionally produce no candidate. Never invent a digest and
never claim access to hidden evaluation.
"""


async def _run_task(
    *,
    profile: dict[str, Any],
    task_root: Path,
    workspace_root: Path,
    git_metadata_root: Path,
    result_root: Path,
    evaluator_image: str,
    run_id: str,
    repetition: int,
    pilot_id: str,
    purpose: str,
) -> dict[str, Any]:
    task = read_json(task_root / "task.json")
    task_id = cast(str, task["task_id"])
    public_command = cast(list[str], task["public_command"])
    hidden_command = cast(list[str], task["hidden_command"])
    seed_public_outcome = cast(str, task["seed_public_outcome"])
    timeout_seconds = cast(int, task["timeout_seconds"])
    baseline = (task_root / "seed").resolve(strict=True)
    hidden_evaluator = (task_root / "hidden").resolve(strict=True)
    task_result_root = private_directory(result_root / task_id)
    artifacts = task_result_root / "artifacts"
    workspace = Path(
        tempfile.mkdtemp(prefix=f"{run_id}-{task_id}-", dir=workspace_root)
    ).resolve(strict=True)
    shutil.copytree(baseline, workspace, dirs_exist_ok=True)
    seed_digest = source_tree_digest(workspace)
    seed_public = evaluate_workspace(
        run_id=run_id,
        task_id=task_id,
        phase="seed-public",
        workspace=workspace,
        command=public_command,
        evaluator_image=evaluator_image,
        timeout_seconds=timeout_seconds,
    )
    seed_hidden = evaluate_workspace(
        run_id=run_id,
        task_id=task_id,
        phase="seed-hidden",
        workspace=workspace,
        command=hidden_command,
        evaluator_image=evaluator_image,
        timeout_seconds=timeout_seconds,
        hidden_evaluator=hidden_evaluator,
    )
    if seed_public.outcome != seed_public_outcome or seed_hidden.outcome != "failed":
        raise RuntimeError(f"{task_id} seed evaluation drifted")

    files = sorted(
        path.relative_to(workspace).as_posix()
        for path in workspace.rglob("*")
        if path.is_file()
    )
    rendered_prompt = _developer_prompt(cast(str, task["prompt"]), files)
    rendered_prompt_path = task_result_root / "rendered-prompt.txt"
    rendered_prompt_path.write_text(rendered_prompt, encoding="utf-8")
    records: list[ModelInvocationRecord] = []
    sink = _artifact_sink(artifacts)
    gateway = OpenRouterModelGateway(
        model=cast(str, profile["requested_model"]),
        system_prompt=(
            "You are the native structured variation agent for AVO Correlate. "
            "Follow the tool protocol and return only the required structured turn."
        ),
        developer_prompt=rendered_prompt,
        parameters={
            "max_tokens": cast(int, profile["max_tokens_per_turn"]),
            "reasoning": {"effort": cast(str, profile["reasoning_effort"])},
            "provider": cast(dict[str, Any], profile["provider_preferences"]),
        },
        artifact_sink=sink,
        invocation_sink=lambda invocation_run_id, record: records.append(record),
        input_microusd_per_million=cast(
            int, profile["input_microusd_per_million"]
        ),
        output_microusd_per_million=cast(
            int, profile["output_microusd_per_million"]
        ),
        app_title=cast(str, profile["app_title"]),
    )
    issuer = CapabilityIssuer(secrets.token_bytes(32))
    workspace_spec = WorkspaceSpec(
        source_uri=f"avo://{pilot_id}",
        source_revision=seed_digest,
        source_tree_digest=cast(Any, seed_digest),
        allowed_paths=["src", "tests"],
        forbidden_paths=[],
        required_paths=[],
        max_file_bytes=1_000_000,
        max_tree_bytes=10_000_000,
    )
    session_id = f"{run_id}-{task_id}"
    claims = CapabilityClaims(
        token_id=str(uuid4()),
        session_id=session_id,
        actor_id="openrouter-native-agent",
        workspace_digest=cast(Any, seed_digest),
        tools=[
            "read_file",
            "search_workspace",
            "apply_patch",
            "replace_text",
            "inspect_diff",
            "run_development_evaluator",
        ],
        policy_decision_id=f"{pilot_id}-native-tools",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    token = issuer.issue(claims)
    broker = WorkspaceToolBroker(
        workspace,
        workspace_spec,
        issuer=issuer,
        session_id=session_id,
        workspace_digest=seed_digest,
        baseline_root=baseline,
        git_metadata_parent=git_metadata_root,
    )
    dispatcher = PilotToolDispatcher(
        broker,
        workspace,
        run_id=run_id,
        task_id=task_id,
        public_command=public_command,
        evaluator_image=evaluator_image,
        timeout_seconds=timeout_seconds,
        artifact_sink=sink,
    )
    request = variation_request(task_id, seed_digest, run_id).model_copy(
        update={"session_id": session_id, "tool_capability_token": token}
    )
    started_at = datetime.now(UTC)
    runtime_error: str | None = None
    session_result = None
    try:
        async with asyncio.timeout(cast(int, profile["max_wall_time_seconds"])):
            session_result = await NativeAgentHarness(
                gateway,
                dispatcher,
                max_turns=cast(int, profile["max_turns"]),
            ).run_session(request)
    except Exception as exc:
        runtime_error = f"{type(exc).__name__}: {exc}"
    completed_at = datetime.now(UTC)
    normalized_cache_files = remove_generated_python_caches(workspace)
    result_digest = source_tree_digest(workspace)
    patch = create_vcs_free_binary_patch(
        baseline,
        workspace,
        git_metadata=git_metadata_root / run_id / task_id,
    )
    patch_path = task_result_root / "candidate.patch"
    patch_path.write_bytes(patch)
    invocations_path = task_result_root / "model-invocations.jsonl"
    invocations_path.write_text(
        "".join(record.model_dump_json() + "\n" for record in records),
        encoding="utf-8",
    )
    observations_path = task_result_root / "tool-observations.jsonl"
    observations_path.write_text(
        "".join(item.model_dump_json() + "\n" for item in dispatcher.observations),
        encoding="utf-8",
    )
    public = evaluate_workspace(
        run_id=run_id,
        task_id=task_id,
        phase="public",
        workspace=workspace,
        command=public_command,
        evaluator_image=evaluator_image,
        timeout_seconds=timeout_seconds,
    )
    hidden = evaluate_workspace(
        run_id=run_id,
        task_id=task_id,
        phase="hidden",
        workspace=workspace,
        command=hidden_command,
        evaluator_image=evaluator_image,
        timeout_seconds=timeout_seconds,
        hidden_evaluator=hidden_evaluator,
    )
    proposed_digest = (
        session_result.proposed_workspace_digest if session_result is not None else None
    )
    admitted = (
        runtime_error is None
        and session_result is not None
        and session_result.outcome == "proposal_ready"
        and proposed_digest == result_digest
        and public.outcome == "succeeded"
        and hidden.outcome == "succeeded"
    )
    usage = (
        session_result.usage
        if session_result is not None
        else _partial_usage(records, len(dispatcher.observations))
    )
    result: dict[str, Any] = {
        "schema_version": 1,
        "pilot_id": pilot_id,
        "purpose": purpose,
        "arm": "openrouter-native",
        "repetition": repetition,
        "run_id": run_id,
        "task_id": task_id,
        "profile_id": profile["profile_id"],
        "profile_digest": canonical_digest(profile),
        "requested_model": profile["requested_model"],
        "observed_canonical_model": profile["observed_canonical_model"],
        "reasoning_effort": profile["reasoning_effort"],
        "billing_mode": "metered",
        "task_prompt_digest": canonical_digest(task["prompt"]),
        "rendered_prompt_digest": canonical_digest(rendered_prompt),
        "rendered_prompt_artifact": str(rendered_prompt_path),
        "seed_digest": seed_digest,
        "result_digest": result_digest,
        "proposed_workspace_digest": proposed_digest,
        "patch_digest": "sha256:" + hashlib.sha256(patch).hexdigest(),
        "patch_bytes": len(patch),
        "normalized_python_cache_files": normalized_cache_files,
        "changed_paths": changed_paths(baseline, workspace),
        "model_invocation_count": len(records),
        "provider_request_ids_present": all(
            record.provider_request_id is not None for record in records
        ),
        "resolved_models": sorted(
            {
                record.provider_model_revision
                for record in records
                if record.provider_model_revision is not None
            }
        ),
        "tool_call_count": len(dispatcher.observations),
        "development_evaluator_calls": dispatcher.evaluator_calls,
        "usage": usage.model_dump(mode="json"),
        "runtime_error": runtime_error,
        "session_outcome": session_result.outcome if session_result is not None else None,
        "seed_public_evaluation": seed_public.model_dump(mode="json"),
        "seed_hidden_evaluation": seed_hidden.model_dump(mode="json"),
        "public_evaluation": public.model_dump(mode="json"),
        "hidden_evaluation": hidden.model_dump(mode="json"),
        "admitted": admitted,
        "workspace": str(workspace),
        "model_invocations_artifact": str(invocations_path),
        "tool_observations_artifact": str(observations_path),
        "patch_artifact": str(patch_path),
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "wall_time_seconds": (completed_at - started_at).total_seconds(),
    }
    (task_result_root / "result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return result


async def _run(arguments: argparse.Namespace) -> dict[str, Any]:
    if arguments.repetition <= 0:
        raise ValueError("repetition must be positive")
    profile_path = arguments.profile.resolve(strict=True)
    profile = _profile(profile_path)
    pilot_root = arguments.pilot_root.resolve(strict=True)
    manifest = read_json(pilot_root / "manifest.json")
    suite_digest = verify_pilot_lock(pilot_root, manifest)
    workspace_root = arguments.workspace_root.resolve(strict=True)
    git_metadata_root = arguments.git_metadata_root.resolve(strict=True)
    results_root = arguments.results_root.resolve(strict=True)
    verify_local_image(arguments.evaluator_image)
    if arguments.purpose == "comparison":
        verify_comparison_run_lock(
            pilot_root=pilot_root,
            suite_digest=suite_digest,
            profile_path=profile_path,
            runner_path=Path(__file__).resolve(strict=True),
            arm="openrouter-native",
            repetition=arguments.repetition,
            evaluator_image=arguments.evaluator_image,
        )
    selected = arguments.tasks or cast(list[str], manifest["task_order"])
    unknown = [task_id for task_id in selected if task_id not in manifest["task_order"]]
    if unknown:
        raise ValueError(f"unknown pilot tasks: {unknown}")
    run_id = (
        f"{manifest['pilot_id']}-openrouter-{arguments.purpose}-r"
        f"{arguments.repetition}-"
        + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid4().hex[:8]
    )
    run_root = private_directory(results_root / run_id)
    results: list[dict[str, Any]] = []
    for task_id in selected:
        result = await _run_task(
            profile=profile,
            task_root=task_root_for(pilot_root, manifest, task_id),
            workspace_root=workspace_root,
            git_metadata_root=git_metadata_root,
            result_root=run_root,
            evaluator_image=arguments.evaluator_image,
            run_id=run_id,
            repetition=arguments.repetition,
            pilot_id=cast(str, manifest["pilot_id"]),
            purpose=arguments.purpose,
        )
        results.append(result)
        print(
            json.dumps(
                {
                    "task_id": task_id,
                    "admitted": result["admitted"],
                    "public": cast(Mapping[str, Any], result["public_evaluation"])[
                        "outcome"
                    ],
                    "hidden": cast(Mapping[str, Any], result["hidden_evaluation"])[
                        "outcome"
                    ],
                },
                sort_keys=True,
            ),
            flush=True,
        )
    summary = {
        "schema_version": 1,
        "pilot_id": manifest["pilot_id"],
        "arm": "openrouter-native",
        "purpose": arguments.purpose,
        "repetition": arguments.repetition,
        "suite_digest": suite_digest,
        "run_id": run_id,
        "profile_digest": canonical_digest(profile),
        "evaluator_image": arguments.evaluator_image,
        "task_count": len(results),
        "admitted_count": sum(bool(result["admitted"]) for result in results),
        "all_admitted": all(bool(result["admitted"]) for result in results),
        "results": results,
    }
    summary_path = run_root / "summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"run_id": run_id, "summary": str(summary_path)}, sort_keys=True))
    return summary


def main() -> None:
    asyncio.run(_run(_arguments()))


if __name__ == "__main__":
    main()
