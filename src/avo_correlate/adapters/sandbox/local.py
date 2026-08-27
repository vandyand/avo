"""Trusted-development subprocess adapter used before Docker parity gates."""

import hashlib
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from avo_correlate.contracts.sandbox import SandboxExecutionResult, SandboxExecutionSpec


class LocalSandboxPolicyError(ValueError):
    pass


class LocalProcessSandbox:
    """Run a structured command without a shell; this is not a security boundary."""

    def __init__(self, workspace: Path, *, allowed_executables: set[str]) -> None:
        self._workspace = workspace.resolve()
        self._allowed_executables = allowed_executables

    def execute(self, request: SandboxExecutionSpec) -> SandboxExecutionResult:
        executable = Path(request.command[0]).name.lower()
        if executable not in {item.lower() for item in self._allowed_executables}:
            raise LocalSandboxPolicyError(f"executable is not allowlisted: {executable}")
        if request.network_enabled:
            raise LocalSandboxPolicyError("local adapter cannot prove network denial")
        started = datetime.now(UTC)
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "PYTHONIOENCODING": "utf-8",
            "PYTHONDONTWRITEBYTECODE": "1",
            **request.environment,
        }
        outcome = "failed"
        exit_code: int | None = None
        stdout = b""
        stderr = b""
        try:
            completed = subprocess.run(
                request.command,
                cwd=self._workspace,
                env=environment,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=request.timeout_seconds,
                check=False,
                shell=False,
            )
            stdout = completed.stdout
            stderr = completed.stderr
            exit_code = completed.returncode
            if len(stdout) + len(stderr) > request.output_bytes_limit:
                outcome = "output_limit"
            else:
                outcome = "succeeded" if exit_code == 0 else "failed"
        except subprocess.TimeoutExpired as exc:
            outcome = "timed_out"
            stdout = exc.stdout or b""
            stderr = exc.stderr or b""
        completed_at = datetime.now(UTC)
        return SandboxExecutionResult(
            execution_id=request.execution_id,
            outcome=outcome,
            exit_code=exit_code,
            stdout_digest=_digest(stdout),
            stderr_digest=_digest(stderr),
            stdout_bytes=len(stdout),
            stderr_bytes=len(stderr),
            started_at=started,
            completed_at=completed_at,
        )


def _digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"
