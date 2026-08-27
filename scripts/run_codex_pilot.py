"""Run the bounded Codex calibration pilot and preserve comparison-ready evidence."""

import argparse
import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from avo_correlate.adapters.harness.codex import (
    CodexCodingAgentRuntime,
    candidate_workspace_is_config_free,
    candidate_workspace_is_vcs_free,
)
from avo_correlate.adapters.harness.codex_canary import CodexLiveCanaryRunner
from avo_correlate.adapters.sandbox.docker import DockerSandbox
from avo_correlate.contracts.base import VersionedComponentRef
from avo_correlate.contracts.runtime import (
    AgentCompletion,
    HarnessRuntimeProfile,
    RuntimeEvent,
)
from avo_correlate.contracts.sandbox import (
    SandboxExecutionResult,
    SandboxExecutionSpec,
    SandboxMount,
)
from avo_correlate.contracts.variation import CandidateRef, VariationSessionRequest
from avo_correlate.domain.canonical import canonical_digest, file_digest, source_tree_digest
from avo_correlate.domain.workspace import create_vcs_free_binary_patch

DEFAULT_EVALUATOR_IMAGE = (
    "python:3.12.10-slim-bookworm@"
    "sha256:97983fa8cc88343512862c62307159a82261c3528dc025f79e5a3f7af43e50b4"
)
DUMMY_DIGEST = "sha256:" + ("0" * 64)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--trusted-key", type=Path, required=True)
    parser.add_argument("--pilot-root", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--git-metadata-root", type=Path, required=True)
    parser.add_argument("--results-root", type=Path, required=True)
    parser.add_argument("--repetition", type=int, default=1)
    parser.add_argument(
        "--purpose", choices=("canary", "comparison"), default="comparison"
    )
    parser.add_argument("--task", action="append", dest="tasks")
    parser.add_argument("--prompt-suffix-file", type=Path)
    parser.add_argument("--evaluator-image", default=DEFAULT_EVALUATOR_IMAGE)
    return parser.parse_args()


def read_json(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"expected a JSON object: {path}")
    return cast(dict[str, Any], document)


def task_root_for(
    pilot_root: Path, manifest: Mapping[str, Any], task_id: str
) -> Path:
    raw_sources = cast(object, manifest.get("task_sources", {}))
    if not isinstance(raw_sources, dict):
        raise ValueError("task_sources must be an object")
    source = cast(dict[object, object], raw_sources).get(
        task_id, f"tasks/{task_id}"
    )
    if not isinstance(source, str) or not source:
        raise ValueError(f"invalid task source for {task_id}")
    resolved = (pilot_root / source).resolve(strict=True)
    allowed_root = pilot_root.parent.resolve(strict=True)
    if not resolved.is_relative_to(allowed_root):
        raise ValueError(f"task source leaves the pilots root: {task_id}")
    return resolved


def verify_pilot_lock(pilot_root: Path, manifest: Mapping[str, Any]) -> str:
    expected = read_json(pilot_root / "digests.json")
    task_ids = cast(list[str], manifest["task_order"])
    tasks = {
        task_id: {
            "task_spec_digest": file_digest(
                task_root_for(pilot_root, manifest, task_id) / "task.json"
            ),
            "seed_tree_digest": source_tree_digest(
                task_root_for(pilot_root, manifest, task_id) / "seed"
            ),
            "hidden_tree_digest": source_tree_digest(
                task_root_for(pilot_root, manifest, task_id) / "hidden"
            ),
        }
        for task_id in task_ids
    }
    actual: dict[str, Any] = {
        "schema_version": 1,
        "pilot_id": manifest["pilot_id"],
        "manifest_digest": file_digest(pilot_root / "manifest.json"),
        "tasks": tasks,
    }
    actual["suite_digest"] = canonical_digest(actual)
    if actual != expected:
        raise RuntimeError("pilot prompts, seeds, or hidden evaluators drifted from lock")
    return actual["suite_digest"]


def verify_comparison_run_lock(
    *,
    pilot_root: Path,
    suite_digest: str,
    profile_path: Path,
    runner_path: Path,
    arm: str,
    repetition: int,
    evaluator_image: str,
) -> dict[str, Any]:
    lock_path = pilot_root / "run-lock.json"
    digest_path = pilot_root / "run-lock.digest"
    lock = read_json(lock_path)
    if file_digest(lock_path) != digest_path.read_text(encoding="utf-8").strip():
        raise RuntimeError("comparison run lock digest drifted")
    common_raw = cast(object, lock.get("common_controls"))
    arms_raw = cast(object, lock.get("arms"))
    if not isinstance(common_raw, dict) or not isinstance(arms_raw, dict):
        raise RuntimeError("comparison run lock is incomplete")
    common = cast(dict[str, Any], common_raw)
    arms = cast(dict[str, Any], arms_raw)
    arm_lock_raw = cast(object, arms.get(arm))
    if not isinstance(arm_lock_raw, dict):
        raise RuntimeError(f"comparison arm is not locked: {arm}")
    arm_lock = cast(dict[str, Any], arm_lock_raw)
    expected_profile = (pilot_root / str(arm_lock.get("profile_path"))).resolve(
        strict=True
    )
    checks: dict[str, bool] = {
        "status": lock.get("status") == "preregistered",
        "suite": lock.get("suite_digest") == suite_digest,
        "repetition": 1 <= repetition <= int(lock.get("repetitions_per_task", 0)),
        "evaluator": common.get("evaluator_image") == evaluator_image,
        "profile_path": expected_profile == profile_path,
        "profile_digest": arm_lock.get("profile_file_digest")
        == file_digest(profile_path),
        "runner_digest": arm_lock.get("runner_digest") == file_digest(runner_path),
    }
    failed = sorted(name for name, passed in checks.items() if not passed)
    if failed:
        raise RuntimeError(f"comparison run lock validation failed: {failed}")
    return lock


def private_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=False)
    os.chmod(path, 0o700)
    return path


def _artifact_sink(root: Path) -> Any:
    root.mkdir(parents=True, exist_ok=True)

    def store(payload: bytes, role: str) -> str:
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        path = root / digest.removeprefix("sha256:")
        if not path.exists():
            path.write_bytes(payload)
            os.chmod(path, 0o600)
        role_path = root / f"{digest.removeprefix('sha256:')}.{role}"
        if not role_path.exists():
            role_path.touch(mode=0o600)
        return digest

    return store


def variation_request(
    task_id: str, seed_digest: str, run_id: str
) -> VariationSessionRequest:
    component = VersionedComponentRef(
        component_id="comparison-hidden-evaluator",
        component_version="1.0.0",
        package_digest=DUMMY_DIGEST,
        capability_manifest_digest=DUMMY_DIGEST,
    )
    return VariationSessionRequest(
        session_id=f"{run_id}-{task_id}",
        run_id=run_id,
        champion=CandidateRef(
            candidate_id=f"{task_id}-seed",
            source_tree_digest=cast(Any, seed_digest),
            lineage_sequence=0,
        ),
        lineage_index_digest=DUMMY_DIGEST,
        initial_context_digest=DUMMY_DIGEST,
        tool_capability_token="pilot-no-external-tools",
        development_evaluator_refs=[component],
        budget_reservation_id=f"{run_id}-{task_id}",
        random_seed=1,
    )


def verify_local_image(image: str) -> None:
    completed = subprocess.run(
        ["docker", "image", "inspect", image],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=False,
        shell=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"pinned evaluator image is not available locally: {image}")


def evaluate_workspace(
    *,
    run_id: str,
    task_id: str,
    phase: str,
    workspace: Path,
    command: list[str],
    evaluator_image: str,
    timeout_seconds: int,
    hidden_evaluator: Path | None = None,
    output_sink: Callable[[bytes, str], str] | None = None,
) -> SandboxExecutionResult:
    workspace_digest = source_tree_digest(workspace)
    sources: dict[str, Path] = {workspace_digest: workspace}
    mounts = [SandboxMount(source_digest=cast(Any, workspace_digest), target="/workspace")]
    if hidden_evaluator is not None:
        evaluator_digest = source_tree_digest(hidden_evaluator)
        sources[evaluator_digest] = hidden_evaluator
        mounts.append(
            SandboxMount(source_digest=cast(Any, evaluator_digest), target="/evaluator")
        )
    sandbox = DockerSandbox(
        image_resolver=lambda _: evaluator_image,
        artifact_resolver=sources.__getitem__,
        output_sink=output_sink,
    )
    return sandbox.execute(
        SandboxExecutionSpec(
            execution_id=f"{run_id}-{task_id}-{phase}",
            image_digest=DUMMY_DIGEST,
            command=command,
            mounts=mounts,
            network_enabled=False,
            timeout_seconds=timeout_seconds,
            memory_bytes=256 * 1024 * 1024,
            output_bytes_limit=1_000_000,
        )
    )


def changed_paths(baseline: Path, candidate: Path) -> list[str]:
    def snapshot(root: Path) -> dict[str, str]:
        return {
            path.relative_to(root).as_posix(): file_digest(path)
            for path in root.rglob("*")
            if path.is_file()
            and not any(part in {".git", ".codex", ".agents"} for part in path.parts)
        }

    before = snapshot(baseline)
    after = snapshot(candidate)
    return sorted(
        path
        for path in before.keys() | after.keys()
        if before.get(path) != after.get(path)
    )


def remove_generated_python_caches(workspace: Path) -> int:
    """Remove only regular .pyc files inside untrusted __pycache__ directories."""
    removed = 0
    directories = sorted(
        (path for path in workspace.rglob("__pycache__")),
        key=lambda path: len(path.parts),
        reverse=True,
    )
    for directory in directories:
        if directory.is_symlink() or not directory.is_dir():
            raise RuntimeError(f"unsafe Python cache path: {directory}")
        for entry in directory.iterdir():
            if entry.is_symlink() or not entry.is_file() or entry.suffix != ".pyc":
                raise RuntimeError(f"unexpected Python cache artifact: {entry}")
            entry.unlink()
            removed += 1
        directory.rmdir()
    return removed


def _usage_observation(events: list[RuntimeEvent]) -> dict[str, int]:
    usage: dict[str, int] = {}
    for event in events:
        for key, value in event.usage_delta.items():
            usage[key] = max(usage.get(key, 0), value)
    return usage


async def _run_task(
    *,
    base_profile: HarnessRuntimeProfile,
    trusted_key: bytes,
    task_root: Path,
    workspace_root: Path,
    git_metadata_root: Path,
    result_root: Path,
    evaluator_image: str,
    run_id: str,
    pilot_id: str,
    prompt_suffix: str,
    repetition: int,
    purpose: str,
) -> dict[str, Any]:
    task = read_json(task_root / "task.json")
    task_id = cast(str, task["task_id"])
    task_prompt = cast(str, task["prompt"])
    prompt = task_prompt + ("\n\n" + prompt_suffix if prompt_suffix else "")
    public_command = cast(list[str], task["public_command"])
    hidden_command = cast(list[str], task["hidden_command"])
    seed_public_outcome = cast(str, task["seed_public_outcome"])
    timeout_seconds = cast(int, task["timeout_seconds"])
    baseline = (task_root / "seed").resolve(strict=True)
    hidden_evaluator = (task_root / "hidden").resolve(strict=True)
    task_result_root = private_directory(result_root / task_id)
    rendered_prompt_path = task_result_root / "rendered-prompt.txt"
    rendered_prompt_path.write_text(prompt + "\n", encoding="utf-8")
    artifacts = task_result_root / "artifacts"
    workspace = Path(
        tempfile.mkdtemp(prefix=f"{run_id}-{task_id}-", dir=workspace_root)
    ).resolve(strict=True)
    os.chmod(workspace, 0o700)
    shutil.copytree(baseline, workspace, dirs_exist_ok=True)
    if not candidate_workspace_is_vcs_free(workspace):
        raise RuntimeError(f"pilot workspace is not VCS-free: {workspace}")
    if not candidate_workspace_is_config_free(workspace):
        raise RuntimeError(f"pilot workspace contains agent configuration: {workspace}")
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
    if seed_public.outcome != seed_public_outcome:
        raise RuntimeError(
            f"{task_id} seed public outcome drifted: {seed_public.outcome}"
        )
    if seed_hidden.outcome != "failed":
        raise RuntimeError(f"{task_id} seed no longer fails hidden evaluation")
    profile = base_profile.model_copy(
        update={"configuration": {**base_profile.configuration, "task_prompt": prompt}}
    )
    runtime = CodexCodingAgentRuntime(
        artifact_sink=_artifact_sink(artifacts),
        canary_runner=CodexLiveCanaryRunner(),
        trusted_plugin_keys={profile.plugin.signer_key_id: trusted_key},
    )
    started_at = datetime.now(UTC)
    events: list[RuntimeEvent] = []
    completion: AgentCompletion | None = None
    native_session_id: str | None = None
    runtime_error: str | None = None
    try:
        session = await runtime.start(
            profile, variation_request(task_id, seed_digest, run_id), str(workspace)
        )
        native_session_id = session.native_session_id
        events = [event async for event in runtime.events(session)]
        completion = await runtime.wait(session)
    except Exception as exc:
        runtime_error = f"{type(exc).__name__}: {exc}"
    completed_at = datetime.now(UTC)
    normalized_cache_files = remove_generated_python_caches(workspace)

    if not candidate_workspace_is_vcs_free(workspace):
        raise RuntimeError("Codex introduced Git metadata into a pilot workspace")
    if not candidate_workspace_is_config_free(workspace):
        raise RuntimeError("Codex introduced agent configuration into a pilot workspace")

    result_digest = source_tree_digest(workspace)
    metadata = git_metadata_root / run_id / task_id
    patch = create_vcs_free_binary_patch(
        baseline,
        workspace,
        git_metadata=metadata,
    )
    patch_path = task_result_root / "candidate.patch"
    patch_path.write_bytes(patch)
    events_path = task_result_root / "events.jsonl"
    events_path.write_text(
        "".join(event.model_dump_json() + "\n" for event in events),
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
    admitted = (
        runtime_error is None
        and completion is not None
        and completion.outcome == "proposal"
        and public.outcome == "succeeded"
        and hidden.outcome == "succeeded"
    )
    result: dict[str, Any] = {
        "schema_version": 1,
        "pilot_id": pilot_id,
        "arm": "codex",
        "purpose": purpose,
        "repetition": repetition,
        "run_id": run_id,
        "task_id": task_id,
        "runtime_profile_id": base_profile.profile_id,
        "runtime_profile_digest": canonical_digest(base_profile),
        "effective_profile_digest": canonical_digest(profile),
        "adapter_id": runtime.adapter_id,
        "native_session_id": native_session_id,
        "model": profile.requested_model,
        "task_prompt_digest": canonical_digest(task_prompt),
        "rendered_prompt_digest": canonical_digest(prompt),
        "rendered_prompt_artifact": str(rendered_prompt_path),
        "billing_mode": "subscription",
        "charged_cost_microusd": None,
        "seed_digest": seed_digest,
        "result_digest": result_digest,
        "patch_digest": "sha256:" + hashlib.sha256(patch).hexdigest(),
        "patch_bytes": len(patch),
        "normalized_python_cache_files": normalized_cache_files,
        "changed_paths": changed_paths(baseline, workspace),
        "event_count": len(events),
        "event_type_counts": {
            event_type: sum(event.event_type == event_type for event in events)
            for event_type in sorted({event.event_type for event in events})
        },
        "usage_observation": _usage_observation(events),
        "completion": (
            completion.model_dump(mode="json") if completion is not None else None
        ),
        "runtime_error": runtime_error,
        "seed_public_evaluation": seed_public.model_dump(mode="json"),
        "seed_hidden_evaluation": seed_hidden.model_dump(mode="json"),
        "public_evaluation": public.model_dump(mode="json"),
        "hidden_evaluation": hidden.model_dump(mode="json"),
        "admitted": admitted,
        "workspace": str(workspace),
        "events_artifact": str(events_path),
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
    base_profile = HarnessRuntimeProfile.model_validate_json(
        profile_path.read_text(encoding="utf-8")
    )
    trusted_key = arguments.trusted_key.resolve(strict=True).read_bytes()
    pilot_root = arguments.pilot_root.resolve(strict=True)
    manifest = read_json(pilot_root / "manifest.json")
    suite_digest = verify_pilot_lock(pilot_root, manifest)
    workspace_root = arguments.workspace_root.resolve(strict=True)
    git_metadata_root = arguments.git_metadata_root.resolve(strict=True)
    results_root = arguments.results_root.resolve(strict=True)
    if not workspace_root.is_dir() or not candidate_workspace_is_vcs_free(workspace_root):
        raise RuntimeError("workspace root must exist outside every Git repository")
    if not git_metadata_root.is_dir() or git_metadata_root.is_relative_to(workspace_root):
        raise RuntimeError("external Git metadata root is invalid")
    verify_local_image(arguments.evaluator_image)
    run_lock: dict[str, Any] | None = None
    if arguments.purpose == "comparison":
        run_lock = verify_comparison_run_lock(
            pilot_root=pilot_root,
            suite_digest=suite_digest,
            profile_path=profile_path,
            runner_path=Path(__file__).resolve(strict=True),
            arm="codex",
            repetition=arguments.repetition,
            evaluator_image=arguments.evaluator_image,
        )

    selected = arguments.tasks or cast(list[str], manifest["task_order"])
    unknown = [task_id for task_id in selected if task_id not in manifest["task_order"]]
    if unknown:
        raise ValueError(f"unknown pilot tasks: {unknown}")
    pilot_id = cast(str, manifest["pilot_id"])
    prompt_suffix = (
        arguments.prompt_suffix_file.resolve(strict=True).read_text(encoding="utf-8").strip()
        if arguments.prompt_suffix_file is not None
        else ""
    )
    if run_lock is not None:
        codex_lock = cast(dict[str, Any], cast(dict[str, Any], run_lock["arms"])["codex"])
        expected_prompt = (
            pilot_root / cast(str, codex_lock["completion_prompt_path"])
        ).resolve(strict=True)
        supplied_prompt = (
            arguments.prompt_suffix_file.resolve(strict=True)
            if arguments.prompt_suffix_file is not None
            else None
        )
        if supplied_prompt != expected_prompt or file_digest(expected_prompt) != codex_lock.get(
            "completion_prompt_digest"
        ):
            raise RuntimeError("Codex comparison completion prompt drifted")
    run_id = (
        f"{pilot_id}-codex-{arguments.purpose}-r{arguments.repetition}-"
        + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid4().hex[:8]
    )
    run_root = private_directory(results_root / run_id)

    doctor_runtime = CodexCodingAgentRuntime(
        artifact_sink=_artifact_sink(run_root / "doctor-artifacts"),
        canary_runner=CodexLiveCanaryRunner(),
        trusted_plugin_keys={base_profile.plugin.signer_key_id: trusted_key},
    )
    doctor = await doctor_runtime.preflight(base_profile)
    if not doctor.compatible:
        raise RuntimeError("Codex profile failed the pilot preflight")
    results: list[dict[str, Any]] = []
    for task_id in selected:
        result = await _run_task(
            base_profile=base_profile,
            trusted_key=trusted_key,
            task_root=task_root_for(pilot_root, manifest, task_id),
            workspace_root=workspace_root,
            git_metadata_root=git_metadata_root,
            result_root=run_root,
            evaluator_image=arguments.evaluator_image,
            run_id=run_id,
            pilot_id=pilot_id,
            prompt_suffix=prompt_suffix,
            repetition=arguments.repetition,
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
        "arm": "codex",
        "purpose": arguments.purpose,
        "repetition": arguments.repetition,
        "suite_digest": suite_digest,
        "run_id": run_id,
        "runtime_profile_digest": canonical_digest(base_profile),
        "evaluator_image": arguments.evaluator_image,
        "task_count": len(results),
        "admitted_count": sum(bool(result["admitted"]) for result in results),
        "all_admitted": all(bool(result["admitted"]) for result in results),
        "results": results,
        "doctor": doctor.model_dump(mode="json"),
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
