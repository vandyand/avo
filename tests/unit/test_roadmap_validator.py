from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ROADMAP = PROJECT_ROOT / "docs" / "roadmap.md"
VALIDATOR = (
    PROJECT_ROOT / ".agents" / "skills" / "avo-roadmap" / "scripts" / "validate_roadmap.py"
)


def _run_validator(roadmap: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VALIDATOR), str(roadmap), *extra],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_authoritative_roadmap_passes() -> None:
    result = _run_validator(ROADMAP, "--max-review-age-days", "45")

    assert result.returncode == 0, result.stderr
    assert "active=AVO-004" in result.stdout


def test_duplicate_milestone_fails_closed(tmp_path: Path) -> None:
    text = ROADMAP.read_text(encoding="utf-8")
    duplicate = text.replace("| AVO-008 |", "| AVO-004 |", 1)
    roadmap = tmp_path / "roadmap.md"
    roadmap.write_text(duplicate, encoding="utf-8")

    result = _run_validator(roadmap)

    assert result.returncode == 1
    assert "duplicate milestone ID: AVO-004" in result.stderr


def test_missing_evidence_link_fails_closed(tmp_path: Path) -> None:
    text = ROADMAP.read_text(encoding="utf-8")
    missing_link = text.replace("implementation-status.md", "does-not-exist.md", 1)
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
    docs = tmp_path / "docs"
    docs.mkdir()
    for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", missing_link):
        if target == "does-not-exist.md":
            continue
        evidence = docs / target
        evidence.parent.mkdir(parents=True, exist_ok=True)
        evidence.touch()
    roadmap = docs / "roadmap.md"
    roadmap.write_text(missing_link, encoding="utf-8")

    result = _run_validator(roadmap)

    assert result.returncode == 1
    assert "local link does not exist: does-not-exist.md" in result.stderr
