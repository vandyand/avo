import shutil
import subprocess
from pathlib import Path

import pytest

from avo_correlate.adapters.sandbox.docker import DockerSandbox
from avo_correlate.contracts.sandbox import SandboxExecutionSpec, SandboxMount
from avo_correlate.domain.evaluator_reports import parse_evaluation_report
from tests.conftest import DIGEST_A, DIGEST_B

IMAGE = "avo-reference-admission:1.0.0"
DEVELOPMENT_IMAGE = "avo-reference-development:1.0.0"
BASE_IMAGE = (
    "python:3.12.10-slim-bookworm@"
    "sha256:97983fa8cc88343512862c62307159a82261c3528dc025f79e5a3f7af43e50b4"
)


def _image_id() -> str:
    if shutil.which("docker") is None:
        pytest.skip("Docker is unavailable")
    completed = subprocess.run(
        ["docker", "image", "inspect", IMAGE, "--format", "{{.Id}}"],
        capture_output=True,
        check=False,
        shell=False,
        timeout=10,
    )
    if completed.returncode:
        pytest.skip("reference evaluator image is not built")
    return completed.stdout.decode().strip()


def _require_image(image: str) -> None:
    completed = subprocess.run(
        ["docker", "image", "inspect", image],
        capture_output=True,
        check=False,
        shell=False,
        timeout=10,
    )
    if completed.returncode:
        pytest.skip(f"reference evaluator image is not built: {image}")


def test_private_evaluator_runs_with_hardened_profile(tmp_path: Path) -> None:
    image_id = _image_id()
    workspace = tmp_path / "workspace"
    output = tmp_path / "output"
    shutil.copytree(Path("fixtures/reference_project/seed"), workspace)
    shutil.copytree(
        Path("fixtures/reference_project/successful/src"), workspace / "src", dirs_exist_ok=True
    )
    output.mkdir()
    artifacts = {DIGEST_A: workspace, DIGEST_B: output}
    sandbox = DockerSandbox(
        image_resolver=lambda _: image_id,
        artifact_resolver=artifacts.__getitem__,
    )
    result = sandbox.execute(
        SandboxExecutionSpec(
            execution_id="admission-candidate-1",
            image_digest=DIGEST_A,
            command=["evaluate"],
            environment={
                "AVO_CANDIDATE_ID": "candidate-1",
                "AVO_EVALUATION_ID": "evaluation-1",
                "AVO_EVALUATOR_TIER": "admission",
                "AVO_IMAGE_DIGEST": DIGEST_A,
                "AVO_WORKSPACE_DIGEST": DIGEST_B,
            },
            mounts=[
                SandboxMount(source_digest=DIGEST_A, target="/workspace"),
                SandboxMount(source_digest=DIGEST_B, target="/output", read_only=False),
            ],
            network_enabled=False,
            timeout_seconds=30,
            memory_bytes=256 * 1024 * 1024,
            output_bytes_limit=1_000_000,
        )
    )
    assert result.outcome == "succeeded"
    report = parse_evaluation_report(
        (output / "report.json").read_bytes(),
        max_bytes=1_000_000,
        declared_metrics=frozenset({"correctness_score"}),
    )
    assert report.outcome == "passed"
    assert all(constraint.passed for constraint in report.constraints)


def test_development_image_contains_no_private_admission_cases() -> None:
    _require_image(DEVELOPMENT_IMAGE)
    completed = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "python",
            DEVELOPMENT_IMAGE,
            "-c",
            (
                "from pathlib import Path; data=Path('/evaluator/tests.json').read_text(); "
                "assert 'later-window' not in data and 'earliest-tie' not in data"
            ),
        ],
        capture_output=True,
        check=False,
        shell=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")


@pytest.mark.parametrize(
    "attack",
    [
        "from pathlib import Path; Path('/evaluator/tests.json').read_bytes()",
        "from pathlib import Path; Path('/host-escape.txt').write_text('escape')",
        "import socket; socket.create_connection(('1.1.1.1', 53), timeout=1)",
    ],
)
def test_adversarial_hidden_read_write_and_egress_are_blocked(
    tmp_path: Path, attack: str
) -> None:
    _image_id()
    workspace = tmp_path / "workspace"
    output = tmp_path / "output"
    workspace.mkdir()
    output.mkdir()
    artifacts = {DIGEST_A: workspace, DIGEST_B: output}
    sandbox = DockerSandbox(
        image_resolver=lambda _: BASE_IMAGE,
        artifact_resolver=artifacts.__getitem__,
    )
    result = sandbox.execute(
        SandboxExecutionSpec(
            execution_id="adversarial-boundary",
            image_digest=DIGEST_A,
            command=["python", "-c", attack],
            mounts=[
                SandboxMount(source_digest=DIGEST_A, target="/workspace"),
                SandboxMount(source_digest=DIGEST_B, target="/output", read_only=False),
            ],
            timeout_seconds=5,
            memory_bytes=128 * 1024 * 1024,
            output_bytes_limit=100_000,
        )
    )
    assert result.outcome == "failed"
    assert not (tmp_path / "host-escape.txt").exists()
