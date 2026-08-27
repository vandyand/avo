from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.verify_git_baseline import BaselineError, verify_baseline


def _git(path: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=path, check=True, capture_output=True, text=True
    ).stdout.strip()


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-b", "main")
    _git(tmp_path, "config", "user.email", "test@example.invalid")
    _git(tmp_path, "config", "user.name", "AVO Test")
    (tmp_path / "README").write_text("baseline\n", encoding="utf-8")
    _git(tmp_path, "add", "README")
    _git(tmp_path, "commit", "-m", "baseline")
    _git(tmp_path, "remote", "add", "origin", "https://github.com/example/avo.git")
    return tmp_path


def test_clean_repository_emits_stable_evidence(repository: Path) -> None:
    first = verify_baseline(repository, expected_remote="https://github.com/example/avo.git")
    second = verify_baseline(repository, expected_remote="https://github.com/example/avo.git")

    assert first == second
    assert first["working_tree"] == "clean"
    assert first["remote"]["url"] == "https://github.com/example/avo.git"
    assert first["protection"] == {"source": "local", "verified": False}
    json.dumps(first, sort_keys=True)


@pytest.mark.parametrize("change", ["dirty", "remote", "commit", "tree", "branch"])
def test_fail_closed(repository: Path, change: str) -> None:
    expected = verify_baseline(repository, expected_remote="https://github.com/example/avo.git")
    if change == "dirty":
        (repository / "new.txt").write_text("untracked", encoding="utf-8")
    elif change == "remote":
        _git(repository, "remote", "set-url", "origin", "https://github.com/other/repo.git")
    elif change == "commit" or change == "tree":
        (repository / "README").write_text("changed\n", encoding="utf-8")
        _git(repository, "commit", "-am", "second")
    else:
        _git(repository, "checkout", "-b", "feature")

    with pytest.raises(BaselineError):
        verify_baseline(
            repository,
            expected_remote="https://github.com/example/avo.git",
            expected_commit=expected["commit"] if change == "commit" else None,
            expected_tree=expected["tree"] if change == "tree" else None,
        )


def test_absent_git_root_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(BaselineError, match=r"git command failed|Git root"):
        verify_baseline(tmp_path, expected_remote="https://github.com/example/avo.git")


def test_missing_remote_fails_closed(repository: Path) -> None:
    _git(repository, "remote", "remove", "origin")
    with pytest.raises(BaselineError):
        verify_baseline(repository, expected_remote="https://github.com/example/avo.git")


def test_protection_evidence_is_recorded(repository: Path, tmp_path: Path) -> None:
    del tmp_path
    evidence = repository.parent / f"{repository.name}-protection.json"
    evidence.write_text(
        json.dumps(
            {
                "source": "remote",
                "branch": "main",
                "remote": "https://github.com/example/avo.git",
                "protected": True,
            }
        ),
        encoding="utf-8",
    )
    result = verify_baseline(
        repository,
        expected_remote="https://github.com/example/avo.git",
        protection_evidence=evidence,
    )
    assert result["protection"] == {
        "branch": "main",
        "remote": "https://github.com/example/avo.git",
        "protected": True,
        "source": "remote",
    }


def test_protection_evidence_mismatch_fails(repository: Path, tmp_path: Path) -> None:
    del tmp_path
    evidence = repository.parent / f"{repository.name}-protection.json"
    evidence.write_text(
        json.dumps(
            {
                "source": "remote",
                "branch": "release",
                "remote": "https://github.com/example/avo.git",
                "protected": True,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(BaselineError):
        verify_baseline(
            repository,
            expected_remote="https://github.com/example/avo.git",
            protection_evidence=evidence,
        )


def test_remote_credentials_are_redacted_from_evidence_and_errors(repository: Path) -> None:
    secret = "super-secret-token"
    _git(
        repository,
        "remote",
        "set-url",
        "origin",
        f"https://robot:{secret}@github.com/example/avo.git",
    )
    result = verify_baseline(
        repository,
        expected_remote="https://github.com/example/avo.git",
    )
    assert secret not in json.dumps(result)
    with pytest.raises(BaselineError) as failure:
        verify_baseline(repository, expected_remote="https://github.com/other/avo.git")
    assert secret not in str(failure.value)


def test_cli_outputs_json(repository: Path) -> None:
    script = Path(__file__).resolve().parents[2] / "scripts" / "verify_git_baseline.py"
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--root",
            str(repository),
            "--expected-remote",
            "https://github.com/example/avo.git",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert json.loads(result.stdout)["schema_version"] == 1
