import shutil
import subprocess
from pathlib import Path

import pytest

from avo_correlate.application.performance import measure_platform_overhead

IMAGE = "avo-reference-development:1.0.0"


def test_platform_benchmark_decomposes_evaluator_wall_time() -> None:
    if shutil.which("docker") is None:
        pytest.skip("Docker is unavailable")
    available = subprocess.run(
        ["docker", "image", "inspect", IMAGE],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        shell=False,
        timeout=10,
    )
    if available.returncode:
        pytest.skip("development evaluator image is not built")
    report = measure_platform_overhead(Path.cwd(), image=IMAGE)
    assert report.trial_count == 3
    assert report.wall_clock_ms >= report.workload_ms
    assert report.platform_overhead_ms == report.wall_clock_ms - report.workload_ms
