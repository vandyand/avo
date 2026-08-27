"""Hardened Docker sandbox adapter for trusted-team evaluator workloads."""

import hashlib
import secrets
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from avo_correlate.contracts.sandbox import SandboxExecutionResult, SandboxExecutionSpec


class DockerSandboxPolicyError(ValueError):
    pass


class DockerSandbox:
    def __init__(
        self,
        *,
        image_resolver: Callable[[str], str],
        artifact_resolver: Callable[[str], Path],
        output_sink: Callable[[bytes, str], str] | None = None,
        docker_executable: str = "docker",
    ) -> None:
        self._image_resolver = image_resolver
        self._artifact_resolver = artifact_resolver
        self._output_sink = output_sink
        self._docker = docker_executable

    def build_command(self, request: SandboxExecutionSpec) -> list[str]:
        if request.network_enabled:
            raise DockerSandboxPolicyError("v1 Docker profile requires network denial")
        image = self._image_resolver(request.image_digest)
        if image.endswith(":latest") or "sha256:" not in image:
            raise DockerSandboxPolicyError("container image must be digest-pinned")
        execution_hash = hashlib.sha256(request.execution_id.encode()).hexdigest()[:12]
        name = f"avo-{execution_hash}-{secrets.token_hex(4)}"
        command = [
            self._docker,
            "run",
            "--rm",
            "--name",
            name,
            "--label",
            "dev.avo-correlate.component=evaluator-sandbox",
            "--label",
            f"dev.avo-correlate.execution-id={request.execution_id}",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(request.pids_limit),
            "--memory",
            str(request.memory_bytes),
            "--cpus",
            request.cpu_limit,
            "--stop-timeout",
            str(request.termination_grace_seconds),
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=64m",
            "--workdir",
            request.working_directory,
        ]
        for key, value in sorted(request.environment.items()):
            command.extend(["--env", f"{key}={value}"])
        for mount in request.mounts:
            if mount.target not in {"/workspace", "/evaluator", "/output"}:
                raise DockerSandboxPolicyError(f"mount target is not approved: {mount.target}")
            if mount.target != "/output" and not mount.read_only:
                raise DockerSandboxPolicyError("only /output may be writable")
            source = self._artifact_resolver(mount.source_digest).resolve(strict=True)
            if mount.target == "/output" and not mount.read_only:
                if not source.is_dir() or any(source.iterdir()):
                    raise DockerSandboxPolicyError(
                        "writable output mount must be an empty store-controlled directory"
                    )
                source.chmod(0o733)
            option = f"type=bind,src={source},dst={mount.target}"
            if mount.read_only:
                option += ",readonly"
            command.extend(["--mount", option])
        command.append(image)
        command.extend(request.command)
        return command

    def execute(self, request: SandboxExecutionSpec) -> SandboxExecutionResult:
        command = self.build_command(request)
        started = datetime.now(UTC)
        name = command[command.index("--name") + 1]
        stdout = b""
        stderr = b""
        exit_code: int | None = None
        outcome = "failed"
        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=request.timeout_seconds + request.termination_grace_seconds,
                check=False,
                shell=False,
            )
            stdout, stderr = completed.stdout, completed.stderr
            exit_code = completed.returncode
            if len(stdout) + len(stderr) > request.output_bytes_limit:
                outcome = "output_limit"
            else:
                outcome = "succeeded" if exit_code == 0 else "failed"
        except subprocess.TimeoutExpired as exc:
            stdout, stderr = exc.stdout or b"", exc.stderr or b""
            outcome = "timed_out"
            subprocess.run(
                [self._docker, "rm", "--force", name],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=request.termination_grace_seconds,
                check=False,
                shell=False,
            )
        stdout_digest = _digest(stdout)
        stderr_digest = _digest(stderr)
        if self._output_sink is not None:
            if self._output_sink(stdout, "evaluator-stdout") != stdout_digest:
                raise RuntimeError("stdout artifact sink returned the wrong digest")
            if self._output_sink(stderr, "evaluator-stderr") != stderr_digest:
                raise RuntimeError("stderr artifact sink returned the wrong digest")
        return SandboxExecutionResult(
            execution_id=request.execution_id,
            outcome=outcome,
            exit_code=exit_code,
            stdout_digest=stdout_digest,
            stderr_digest=stderr_digest,
            stdout_bytes=len(stdout),
            stderr_bytes=len(stderr),
            started_at=started,
            completed_at=datetime.now(UTC),
        )


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"
