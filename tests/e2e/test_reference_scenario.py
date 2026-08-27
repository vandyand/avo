import os
import shutil
import subprocess
from pathlib import Path

import pytest

from avo_correlate.application.reference_scenario import ReferenceScenarioRunner

DEVELOPMENT_IMAGE = "sha256:586dcc790c714be468b38874eeb8e48fca53b9b85b3d3e30f3f70ee526d401b2"
ADMISSION_IMAGE = "sha256:972c6afef64519a1f36513d389f62a0d86bb0c7ca10eb53c5eba3103260137c3"


def _require_images() -> None:
    if shutil.which("docker") is None:
        pytest.skip("Docker is unavailable")
    expected_images = {
        "avo-reference-development:1.0.0": DEVELOPMENT_IMAGE,
        "avo-reference-admission:1.0.0": ADMISSION_IMAGE,
    }
    for tag in expected_images:
        completed = subprocess.run(
            ["docker", "image", "inspect", tag],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
            check=False,
            shell=False,
        )
        if completed.returncode:
            pytest.skip(f"reference evaluator image is not built: {tag}")


def test_complete_reference_scenario_is_admitted_and_reconstructable(tmp_path: Path) -> None:
    _require_images()
    result = ReferenceScenarioRunner(
        tmp_path,
        project_root=Path.cwd(),
        development_image_digest=DEVELOPMENT_IMAGE,
        admission_image_digest=ADMISSION_IMAGE,
        development_metadata_path=_metadata_path("development"),
        admission_metadata_path=_metadata_path("admission"),
    ).run()
    assert result.final_state == "completed"
    assert result.candidate_id == "candidate-1"
    assert result.provenance_verified


def _metadata_path(tier: str) -> Path | None:
    for name in (
        f"AVO_REFERENCE_{tier.upper()}_METADATA_FILE",
        f"AVO_REFERENCE_{tier.upper()}_METADATA_PATH",
        f"AVO_{tier.upper()}_IMAGE_METADATA_FILE",
    ):
        value = os.environ.get(name)
        if value:
            return Path(value)
    return None
