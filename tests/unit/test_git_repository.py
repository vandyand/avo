from __future__ import annotations

# pyright: reportPrivateUsage=false
import hashlib
import io
import os
import stat
import subprocess
import tarfile
from pathlib import Path
from typing import Any

import pytest

from avo_correlate.adapters.git.repository import (
    GitRepositoryError,
    GitRepositoryReader,
    StaleGitSnapshotError,
    _TreeScan,
)

REMOTE = "https://example.invalid/avo.git"
PROTECTION = "sha256:" + "d" * 64


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, text=True, shell=False
    )
    return result.stdout.strip()


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-b", "main")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    _git(tmp_path, "config", "user.name", "AVO Test")
    (tmp_path / "README.md").write_text("baseline\n", encoding="utf-8")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("print('ok')\n", encoding="utf-8")
    _git(tmp_path, "add", "--all")
    _git(tmp_path, "commit", "-m", "baseline")
    _git(tmp_path, "remote", "add", "origin", REMOTE)
    return tmp_path


def _reader(root: Path, **overrides: object) -> GitRepositoryReader:
    values: dict[str, object] = {
        "root": root,
        "target_ref": "main",
        "expected_remote": REMOTE,
        "protection_evidence_digest": PROTECTION,
        "max_file_bytes": 1024,
        "max_tree_bytes": 4096,
    }
    values.update(overrides)
    return GitRepositoryReader(**values)  # type: ignore[arg-type]


def _copy_baseline(candidate: Path) -> None:
    (candidate / "README.md").write_text("baseline\n", encoding="utf-8")
    (candidate / "src").mkdir()
    (candidate / "src" / "main.py").write_text("print('ok')\n", encoding="utf-8")


@pytest.mark.parametrize(
    "overrides",
    [
        {"target_ref": ""},
        {"target_ref": "-bad-ref"},
        {"max_file_bytes": 0},
        {"max_tree_bytes": 0},
        {"max_entries": 0},
        {"expected_remote": ""},
    ],
)
def test_constructor_rejects_unbounded_or_ambiguous_configuration(
    repository: Path, overrides: dict[str, object]
) -> None:
    with pytest.raises(ValueError):
        _reader(repository, **overrides)


def test_snapshot_and_candidate_diff_are_digest_bound(repository: Path, tmp_path: Path) -> None:
    reader = _reader(repository)
    snapshot = reader.snapshot()
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    _copy_baseline(candidate)
    (candidate / "new.txt").write_text("new\n", encoding="utf-8")
    comparison = reader.compare_candidate(candidate, snapshot)

    assert snapshot.target_ref == "main"
    assert snapshot.repository_digest == "sha256:" + hashlib.sha256(REMOTE.encode()).hexdigest()
    assert comparison.base_digest == snapshot.source_tree_digest
    assert comparison.candidate_digest != comparison.base_digest
    assert comparison.changed_paths == ["new.txt"]


def test_snapshot_ignores_dirty_working_tree(repository: Path) -> None:
    head = _git(repository, "rev-parse", "HEAD")
    (repository / "untracked.txt").write_text("ignored by target ref\n", encoding="utf-8")
    snapshot = _reader(repository).snapshot()
    assert snapshot.commit == head


@pytest.mark.parametrize("kind", ["root", "remote", "ref"])
def test_snapshot_rejects_wrong_repository_configuration(
    repository: Path, tmp_path: Path, kind: str
) -> None:
    if kind == "root":
        other_root = tmp_path.parent / "other-root"
        other_root.mkdir()
        reader = _reader(other_root)
    elif kind == "remote":
        reader = _reader(repository, expected_remote="https://other.invalid/avo.git")
    else:
        reader = _reader(repository, target_ref="missing")
    with pytest.raises(GitRepositoryError):
        reader.snapshot()


def test_stale_target_ref_is_rejected(repository: Path, tmp_path: Path) -> None:
    snapshot = _reader(repository).snapshot()
    (repository / "after.txt").write_text("changed head\n", encoding="utf-8")
    _git(repository, "add", "after.txt")
    _git(repository, "commit", "-m", "advance")
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    _copy_baseline(candidate)
    (candidate / "new.txt").write_text("new\n", encoding="utf-8")
    with pytest.raises(StaleGitSnapshotError):
        _reader(repository).compare_candidate(candidate, snapshot)


def test_snapshot_binding_rejects_wrong_ref_or_remote_digest(
    repository: Path, tmp_path: Path
) -> None:
    snapshot = _reader(repository).snapshot()
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    _copy_baseline(candidate)
    (candidate / "new.txt").write_text("new\n", encoding="utf-8")
    with pytest.raises(GitRepositoryError, match="repository/ref"):
        _reader(repository).compare_candidate(
            candidate, snapshot.model_copy(update={"target_ref": "other"})
        )
    with pytest.raises(GitRepositoryError, match="remote digest"):
        _reader(repository).compare_candidate(
            candidate,
            snapshot.model_copy(update={"repository_digest": "sha256:" + "e" * 64}),
        )


def test_snapshot_binding_rejects_archive_digest_mismatch(repository: Path, tmp_path: Path) -> None:
    snapshot = _reader(repository).snapshot()
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    _copy_baseline(candidate)
    (candidate / "new.txt").write_text("new\n", encoding="utf-8")
    with pytest.raises(GitRepositoryError, match="archive digest"):
        _reader(repository).compare_candidate(
            candidate,
            snapshot.model_copy(update={"source_tree_digest": "sha256:" + "e" * 64}),
        )


def test_stable_scan_rejects_inconsistent_repeated_observation(
    repository: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reader = _reader(repository)
    first = _TreeScan("sha256:" + "a" * 64, {}, {})
    second = _TreeScan("sha256:" + "b" * 64, {"x": (0, "sha256:" + "c" * 64, 0)}, {})
    observations = iter((first, second))

    def unstable_scan(*args: Any, **kwargs: Any) -> _TreeScan:
        del args, kwargs
        return next(observations)

    monkeypatch.setattr(reader, "_scan_tree_once", unstable_scan)
    with pytest.raises(GitRepositoryError, match="stable scan"):
        reader._scan_tree(tmp_path)


def test_identical_candidate_is_rejected_as_no_change(repository: Path, tmp_path: Path) -> None:
    snapshot = _reader(repository).snapshot()
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    _copy_baseline(candidate)
    with pytest.raises(GitRepositoryError, match="no changed files"):
        _reader(repository).compare_candidate(candidate, snapshot)


def test_candidate_root_must_be_directory(repository: Path, tmp_path: Path) -> None:
    candidate = tmp_path / "candidate.txt"
    candidate.write_text("not a tree", encoding="utf-8")
    with pytest.raises(GitRepositoryError, match="not a directory"):
        _reader(repository).compare_candidate(candidate, _reader(repository).snapshot())


@pytest.mark.parametrize("bad_name", [".git/config", "a\\b"])
def test_candidate_unsafe_paths_fail_closed(
    repository: Path, tmp_path: Path, bad_name: str
) -> None:
    if os.name == "nt" and "\\" in bad_name:
        pytest.skip("Windows normalizes this path before the adapter can inspect it")
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    path = candidate / Path(bad_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("unsafe", encoding="utf-8")
    with pytest.raises(GitRepositoryError):
        _reader(repository).compare_candidate(candidate, _reader(repository).snapshot())


def test_candidate_case_collision_fails_closed(repository: Path, tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("case-colliding names cannot coexist on this filesystem")
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "a.txt").write_text("a", encoding="utf-8")
    (candidate / "A.txt").write_text("A", encoding="utf-8")
    with pytest.raises(GitRepositoryError):
        _reader(repository).compare_candidate(candidate, _reader(repository).snapshot())


def test_candidate_symlink_and_hardlink_fail_closed(repository: Path, tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    target = candidate / "target.txt"
    target.write_text("target", encoding="utf-8")
    link = candidate / "link.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(GitRepositoryError):
        _reader(repository).compare_candidate(candidate, _reader(repository).snapshot())

    link.unlink()
    hardlink = candidate / "hardlink.txt"
    try:
        os.link(target, hardlink)
    except OSError:
        pytest.skip("hardlink creation is unavailable")
    with pytest.raises(GitRepositoryError):
        _reader(repository).compare_candidate(candidate, _reader(repository).snapshot())


def test_bounds_are_enforced(repository: Path, tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "too-large.txt").write_text("12345", encoding="utf-8")
    with pytest.raises(GitRepositoryError):
        _reader(repository, max_file_bytes=4).compare_candidate(
            candidate, _reader(repository).snapshot()
        )

    with pytest.raises(GitRepositoryError, match="tree exceeds"):
        _reader(repository, max_tree_bytes=1).snapshot()


def test_archive_parser_rejects_malformed_stream(repository: Path, tmp_path: Path) -> None:
    with pytest.raises(tarfile.ReadError):
        _reader(repository)._extract_archive(io.BytesIO(b"not a tar"), tmp_path / "archive")


def test_regular_file_mode_validation_is_fail_closed(repository: Path) -> None:
    regular = os.stat_result((stat.S_IFREG | 0o644, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    assert GitRepositoryReader._same_file_metadata(regular, regular)
    assert not GitRepositoryReader._same_file_metadata(
        regular, os.stat_result((stat.S_IFREG | 0o644, 0, 0, 0, 0, 0, 1, 0, 0, 0))
    )
    with pytest.raises(GitRepositoryError, match="not regular"):
        GitRepositoryReader._validate_regular_metadata(
            os.stat_result((stat.S_IFDIR | 0o755, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        )
    with pytest.raises(GitRepositoryError, match="unsupported file mode"):
        GitRepositoryReader._validate_regular_metadata(
            os.stat_result((stat.S_IFREG | 0o644 | 0o4000, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        )


def test_git_and_file_open_errors_are_redacted_and_fail_closed(
    repository: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failed_run(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise subprocess.CalledProcessError(
            1, ["git"], stderr="https://user:secret@example.invalid"
        )

    monkeypatch.setattr(subprocess, "run", failed_run)
    with pytest.raises(GitRepositoryError) as failure:
        _reader(repository)._git("status")
    assert "secret" not in str(failure.value)

    def failed_open(*args: Any, **kwargs: Any) -> int:
        del args, kwargs
        raise OSError("no")

    monkeypatch.setattr(os, "open", failed_open)
    metadata = os.stat_result((stat.S_IFREG | 0o644, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    with pytest.raises(GitRepositoryError, match="opened safely"):
        GitRepositoryReader._file_digest(repository / "README.md", 1, metadata)


def test_archive_start_and_missing_path_errors_fail_closed(
    repository: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def failed_popen(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise OSError("archive unavailable")

    monkeypatch.setattr(subprocess, "Popen", failed_popen)
    with pytest.raises(GitRepositoryError, match="start git archive"):
        _reader(repository)._archive_into("a" * 40, tmp_path / "archive")
    with pytest.raises(GitRepositoryError, match="cannot be inspected"):
        GitRepositoryReader._is_reparse(tmp_path / "missing")


@pytest.mark.parametrize("path", ["../escape", "a//b", "a\\b", "/absolute", "C:/drive"])
def test_safe_relative_rejects_portability_attacks(repository: Path, path: str) -> None:
    with pytest.raises(GitRepositoryError):
        _reader(repository)._safe_relative(path, set())


def test_safe_relative_rejects_path_length_and_collisions(repository: Path) -> None:
    with pytest.raises(GitRepositoryError, match="exceeds configured bound"):
        _reader(repository)._safe_relative("a" * 4097, set())
    seen: set[str] = set()
    _reader(repository)._safe_relative("src/a.txt", seen)
    with pytest.raises(GitRepositoryError, match="collision"):
        _reader(repository)._safe_relative("src/A.txt", seen)


def test_remote_normalization_and_redaction_are_stable(repository: Path) -> None:
    assert GitRepositoryReader._safe_remote("HTTPS://user:secret@example.invalid:443/avo///") == (
        "https://example.invalid:443/avo"
    )
    assert (
        GitRepositoryReader._safe_remote("git@example.invalid:avo.git")
        == "git@example.invalid:avo.git"
    )
    assert (
        GitRepositoryReader._redact("https://user:secret@example.invalid")
        == "https://example.invalid"
    )
    assert GitRepositoryReader._redact("ssh://user:secret@example.invalid/repo") == (
        "ssh://example.invalid/repo"
    )
    assert GitRepositoryReader._redact("git://token@example.invalid/repo") == (
        "git://example.invalid/repo"
    )


def test_entry_count_bound_applies_to_archive_and_candidate(
    repository: Path, tmp_path: Path
) -> None:
    with pytest.raises(GitRepositoryError, match="entry count"):
        _reader(repository, max_entries=2).snapshot()

    snapshot = _reader(repository, max_entries=10).snapshot()
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    _copy_baseline(candidate)
    (candidate / "new.txt").write_text("new\n", encoding="utf-8")
    with pytest.raises(GitRepositoryError, match="entry count"):
        _reader(repository, max_entries=3).compare_candidate(candidate, snapshot)


@pytest.mark.skipif(os.name == "nt", reason="Windows does not preserve executable mode bits")
def test_executable_mode_is_preserved_and_mode_only_changes_are_reported(
    repository: Path, tmp_path: Path
) -> None:
    os.chmod(repository / "src" / "main.py", 0o755)
    _git(repository, "add", "src/main.py")
    _git(repository, "commit", "-m", "make executable")
    snapshot = _reader(repository).snapshot()

    candidate = tmp_path / "candidate"
    candidate.mkdir()
    _copy_baseline(candidate)
    os.chmod(candidate / "src" / "main.py", 0o755)
    mode_preserved = _reader(repository)._scan_candidate(candidate)
    assert mode_preserved.digest == snapshot.source_tree_digest
    with pytest.raises(GitRepositoryError, match="no changed files"):
        _reader(repository).compare_candidate(candidate, snapshot)

    os.chmod(candidate / "src" / "main.py", 0o644)
    mode_changed = _reader(repository)._scan_candidate(candidate)
    assert mode_changed.digest != mode_preserved.digest
    changed = _reader(repository).compare_candidate(candidate, snapshot)
    assert changed.changed_paths == ["src/main.py"]


def test_addition_deletion_and_rename_paths_are_complete(repository: Path, tmp_path: Path) -> None:
    snapshot = _reader(repository).snapshot()
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "renamed.md").write_text("baseline\n", encoding="utf-8")
    (candidate / "src").mkdir()
    (candidate / "src" / "main.py").write_text("changed\n", encoding="utf-8")
    (candidate / "added.txt").write_text("added\n", encoding="utf-8")
    comparison = _reader(repository).compare_candidate(candidate, snapshot)
    assert comparison.changed_paths == ["added.txt", "README.md", "renamed.md", "src/main.py"]


def test_repository_and_candidate_are_not_mutated(repository: Path, tmp_path: Path) -> None:
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    _copy_baseline(candidate)
    (candidate / "new.txt").write_text("new\n", encoding="utf-8")
    before_head = _git(repository, "rev-parse", "HEAD")
    before_status = _git(repository, "status", "--porcelain=v1", "--untracked-files=all")
    before_files = sorted(path.relative_to(candidate).as_posix() for path in candidate.rglob("*"))
    snapshot = _reader(repository).snapshot()
    _reader(repository).compare_candidate(candidate, snapshot)
    assert _git(repository, "rev-parse", "HEAD") == before_head
    assert _git(repository, "status", "--porcelain=v1", "--untracked-files=all") == before_status
    assert (
        sorted(path.relative_to(candidate).as_posix() for path in candidate.rglob("*"))
        == before_files
    )
