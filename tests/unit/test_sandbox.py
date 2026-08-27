import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

from avo_correlate.adapters.sandbox.docker import DockerSandbox, DockerSandboxPolicyError
from avo_correlate.adapters.sandbox.local import LocalProcessSandbox, LocalSandboxPolicyError
from avo_correlate.contracts.sandbox import SandboxExecutionSpec, SandboxMount
from tests.conftest import DIGEST_A, DIGEST_B


def request(*, network: bool = False, target: str = "/workspace") -> SandboxExecutionSpec:
    return SandboxExecutionSpec(
        execution_id="execution-1",
        image_digest=DIGEST_A,
        command=["python", "-m", "pytest"],
        mounts=[SandboxMount(source_digest=DIGEST_B, target=target)],
        network_enabled=network,
        timeout_seconds=60,
        memory_bytes=256 * 1024 * 1024,
        output_bytes_limit=1_000_000,
    )


def test_docker_command_has_required_denials(tmp_path: Path) -> None:
    artifact = tmp_path / "workspace"
    artifact.mkdir()
    sandbox = DockerSandbox(
        image_resolver=lambda _: "reference@sha256:" + ("a" * 64),
        artifact_resolver=lambda _: artifact,
    )
    command = sandbox.build_command(request())
    assert command[0:2] == ["docker", "run"]
    assert "dev.avo-correlate.component=evaluator-sandbox" in command
    assert "dev.avo-correlate.execution-id=execution-1" in command
    assert command[command.index("--network") :][:2] == ["--network", "none"]
    assert "--read-only" in command
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert command[command.index("--security-opt") + 1] == "no-new-privileges"
    assert all("docker.sock" not in item for item in command)


def test_docker_container_names_are_unique_but_execution_labels_are_stable(
    tmp_path: Path,
) -> None:
    artifact = tmp_path / "workspace"
    artifact.mkdir()
    sandbox = DockerSandbox(
        image_resolver=lambda _: "reference@sha256:" + ("a" * 64),
        artifact_resolver=lambda _: artifact,
    )
    first = sandbox.build_command(request())
    second = sandbox.build_command(request())
    first_name = first[first.index("--name") + 1]
    second_name = second[second.index("--name") + 1]
    assert first_name.startswith("avo-")
    assert second_name.startswith("avo-")
    assert first_name != second_name
    assert "dev.avo-correlate.execution-id=execution-1" in first
    assert "dev.avo-correlate.execution-id=execution-1" in second


def test_docker_profile_fails_closed_on_network_and_mounts(tmp_path: Path) -> None:
    artifact = tmp_path / "workspace"
    artifact.mkdir()
    sandbox = DockerSandbox(
        image_resolver=lambda _: "reference@sha256:" + ("a" * 64),
        artifact_resolver=lambda _: artifact,
    )
    with pytest.raises(DockerSandboxPolicyError, match="network"):
        sandbox.build_command(request(network=True))
    with pytest.raises(DockerSandboxPolicyError, match="mount target"):
        sandbox.build_command(request(target="/var/run"))


def test_docker_adapter_captures_evaluator_output_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact = tmp_path / "workspace"
    artifact.mkdir()
    captured: dict[str, bytes] = {}

    def sink(payload: bytes, role: str) -> str:
        digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        captured[role] = payload
        return digest

    def fake_run(
        *_args: object, **_kwargs: object
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b"public output", stderr=b"public warning"
        )

    monkeypatch.setattr(
        "avo_correlate.adapters.sandbox.docker.subprocess.run",
        fake_run,
    )
    sandbox = DockerSandbox(
        image_resolver=lambda _: "reference@sha256:" + ("a" * 64),
        artifact_resolver=lambda _: artifact,
        output_sink=sink,
    )

    result = sandbox.execute(request())

    assert result.outcome == "succeeded"
    assert captured == {
        "evaluator-stdout": b"public output",
        "evaluator-stderr": b"public warning",
    }


def local_request(code: str, *, limit: int = 10_000, timeout: int = 5) -> SandboxExecutionSpec:
    return SandboxExecutionSpec(
        execution_id="local-1",
        image_digest=DIGEST_A,
        command=[sys.executable, "-c", code],
        timeout_seconds=timeout,
        memory_bytes=128 * 1024 * 1024,
        output_bytes_limit=limit,
    )


def test_local_adapter_reports_success_failure_and_output_limits(tmp_path: Path) -> None:
    sandbox = LocalProcessSandbox(tmp_path, allowed_executables={Path(sys.executable).name})
    succeeded = sandbox.execute(local_request("print('ok')"))
    assert succeeded.outcome == "succeeded"
    assert succeeded.exit_code == 0
    assert succeeded.stdout_bytes >= 3

    failed = sandbox.execute(local_request("raise SystemExit(4)"))
    assert failed.outcome == "failed"
    assert failed.exit_code == 4

    oversized = sandbox.execute(local_request("print('too much')", limit=2))
    assert oversized.outcome == "output_limit"


def test_local_adapter_rejects_unapproved_or_networked_execution(tmp_path: Path) -> None:
    denied = LocalProcessSandbox(tmp_path, allowed_executables={"never-approved"})
    with pytest.raises(LocalSandboxPolicyError, match="allowlisted"):
        denied.execute(local_request("pass"))

    sandbox = LocalProcessSandbox(tmp_path, allowed_executables={Path(sys.executable).name})
    networked = local_request("pass").model_copy(update={"network_enabled": True})
    with pytest.raises(LocalSandboxPolicyError, match="network denial"):
        sandbox.execute(networked)


def test_local_adapter_records_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sandbox = LocalProcessSandbox(tmp_path, allowed_executables={Path(sys.executable).name})

    def time_out(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise subprocess.TimeoutExpired(
            cmd=[sys.executable], timeout=1, output=b"partial", stderr=b"late"
        )

    monkeypatch.setattr("avo_correlate.adapters.sandbox.local.subprocess.run", time_out)
    result = sandbox.execute(local_request("pass"))
    assert result.outcome == "timed_out"
    assert result.exit_code is None
    assert result.stdout_bytes == len(b"partial")
