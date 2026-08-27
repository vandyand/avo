from pathlib import Path

import pytest

from avo_correlate.domain.workspace import (
    UnsafeWorkspaceError,
    create_vcs_free_binary_patch,
)


def test_external_git_metadata_creates_patch_without_polluting_workspace(
    tmp_path: Path,
) -> None:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    baseline.mkdir()
    candidate.mkdir()
    (baseline / "file.txt").write_text("before\n", encoding="utf-8")
    (candidate / "file.txt").write_text("after\n", encoding="utf-8")
    patch = create_vcs_free_binary_patch(
        baseline, candidate, git_metadata=tmp_path / "external-git"
    )
    assert b"-before" in patch
    assert b"+after" in patch
    assert not (baseline / ".git").exists()
    assert not (candidate / ".git").exists()


def test_external_git_metadata_cannot_be_inside_candidate(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    baseline.mkdir()
    candidate.mkdir()
    with pytest.raises(UnsafeWorkspaceError, match="outside"):
        create_vcs_free_binary_patch(
            baseline, candidate, git_metadata=candidate / "metadata"
        )
