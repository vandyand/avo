"""Canonical Docker benchmark with workload/platform-time decomposition."""

import platform
import shutil
import subprocess
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory

from avo_correlate.adapters.sandbox import DockerSandbox
from avo_correlate.contracts.operations import PlatformOverheadReport
from avo_correlate.contracts.sandbox import SandboxExecutionSpec, SandboxMount
from avo_correlate.domain.canonical import source_tree_digest
from avo_correlate.domain.evaluator_reports import parse_evaluation_report

_OUTPUT_DIGEST = "sha256:" + ("c" * 64)


def measure_platform_overhead(
    project_root: Path,
    *,
    image: str = "avo-reference-development:1.0.0",
) -> PlatformOverheadReport:
    image_digest = _inspect_image_digest(image)
    with TemporaryDirectory(prefix="avo-platform-benchmark-") as temporary:
        root = Path(temporary)
        workspace = root / "workspace"
        output = root / "output"
        shutil.copytree(project_root / "fixtures/reference_project/seed", workspace)
        shutil.copytree(
            project_root / "fixtures/reference_project/successful/src",
            workspace / "src",
            dirs_exist_ok=True,
        )
        output.mkdir()
        workspace_digest = source_tree_digest(workspace)
        paths = {workspace_digest: workspace, _OUTPUT_DIGEST: output}
        execution = DockerSandbox(
            image_resolver=lambda _: image_digest,
            artifact_resolver=paths.__getitem__,
        ).execute(
            SandboxExecutionSpec(
                execution_id="platform-overhead-benchmark",
                image_digest=image_digest,
                command=["evaluate"],
                environment={
                    "AVO_CANDIDATE_ID": "benchmark-candidate",
                    "AVO_EVALUATION_ID": "benchmark-evaluation",
                    "AVO_EVALUATOR_TIER": "development",
                    "AVO_IMAGE_DIGEST": image_digest,
                    "AVO_WORKSPACE_DIGEST": workspace_digest,
                },
                mounts=[
                    SandboxMount(source_digest=workspace_digest, target="/workspace"),
                    SandboxMount(
                        source_digest=_OUTPUT_DIGEST,
                        target="/output",
                        read_only=False,
                    ),
                ],
                timeout_seconds=30,
                memory_bytes=256 * 1024 * 1024,
                output_bytes_limit=1_000_000,
            )
        )
        if execution.outcome != "succeeded":
            raise RuntimeError(f"benchmark evaluator {execution.outcome}")
        evaluated = parse_evaluation_report(
            (output / "report.json").read_bytes(),
            max_bytes=1_000_000,
            declared_metrics=frozenset({"correctness_score"}),
        )
    wall_clock = Decimal(
        str((execution.completed_at - execution.started_at).total_seconds() * 1000)
    )
    workload = sum(
        (trial.workload_time_ms for trial in evaluated.trial_records), start=Decimal(0)
    )
    return PlatformOverheadReport(
        hardware_class=f"{platform.system().lower()}-{platform.machine().lower()}",
        execution_image_digest=image_digest,
        trial_count=len(evaluated.trial_records),
        wall_clock_ms=wall_clock,
        workload_ms=workload,
        platform_overhead_ms=max(wall_clock - workload, Decimal(0)),
        measured_at=datetime.now(UTC),
    )


def _inspect_image_digest(image: str) -> str:
    completed = subprocess.run(
        ["docker", "image", "inspect", image, "--format", "{{.Id}}"],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=False,
        shell=False,
        timeout=10,
    )
    if completed.returncode:
        raise RuntimeError(f"benchmark image is unavailable: {image}")
    return completed.stdout.decode("utf-8").strip()
