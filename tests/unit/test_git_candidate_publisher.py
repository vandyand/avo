from __future__ import annotations

# Tests intentionally exercise journal and adapter guard internals for fail-closed coverage.
# pyright: reportPrivateUsage=false
import json
import os
import subprocess
from collections.abc import Callable, Mapping
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from avo_correlate.adapters.git import (
    FilesystemPublicationJournal,
    GitCandidatePublisher,
    GitRepositoryError,
    GitRepositoryReader,
    PublicationAmbiguousError,
    PublicationOutcome,
    PublicationPlan,
)
from avo_correlate.domain.canonical import canonical_digest


def run_git(cwd: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=check
    )
    return result.stdout.strip()


@pytest.fixture
def git_fixture(tmp_path: Path) -> tuple[Path, Path, Path, str, str, str]:
    remote = tmp_path / "remote.git"
    run_git(tmp_path, "init", "--bare", str(remote))
    seed = tmp_path / "seed"
    seed.mkdir()
    run_git(seed, "init", "-b", "main")
    run_git(seed, "config", "user.name", "fixture")
    run_git(seed, "config", "user.email", "fixture@example.invalid")
    (seed / "README.md").write_text("baseline\n", encoding="utf-8")
    run_git(seed, "add", "--all")
    run_git(seed, "commit", "-m", "baseline")
    remote_url = remote.as_uri()
    run_git(seed, "remote", "add", "origin", remote_url)
    run_git(seed, "push", "origin", "main")
    base_commit = run_git(seed, "rev-parse", "HEAD")
    base_tree = run_git(seed, "rev-parse", "HEAD^{tree}")
    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "README.md").write_text("candidate\n", encoding="utf-8")
    (candidate / "new.txt").write_text("new\n", encoding="utf-8")
    reader = GitRepositoryReader(
        seed, "main", remote_url, "sha256:" + "0" * 64, 1024 * 1024, 10 * 1024 * 1024
    )
    scanner_name = "_scan_candidate"
    scanner = cast(Callable[[Path], Any], getattr(reader, scanner_name))
    digest = scanner(candidate).digest
    return remote, seed, candidate, base_commit, base_tree, digest


def publisher(
    remote: Path, digest: str, *, journal_root: Path | None = None
) -> GitCandidatePublisher:
    url = remote.as_uri()
    import hashlib

    remote_digest = "sha256:" + hashlib.sha256(url.encode()).hexdigest()
    return GitCandidatePublisher(
        expected_remote=url,
        repository_digest=remote_digest,
        controller_publisher_identity="avo-controller",
        publication_journal=FilesystemPublicationJournal(
            journal_root or remote.parent / "publication-journal"
        ),
        max_file_bytes=1024 * 1024,
        max_tree_bytes=10 * 1024 * 1024,
        allow_local_remote_for_tests=True,
    )


def test_publish_creates_exact_candidate_commit_and_ref(
    git_fixture: tuple[Path, Path, Path, str, str, str],
) -> None:
    remote, _seed, candidate, base_commit, base_tree, digest = git_fixture
    binding = publisher(remote, digest).publish(candidate, base_commit, base_tree, digest)

    assert binding.verified is True
    assert binding.base_commit == base_commit
    assert binding.base_tree == base_tree
    assert binding.candidate_digest == digest
    assert binding.candidate_ref.startswith("refs/heads/avo/candidate/")
    assert len(binding.candidate_ref.rsplit("/", 1)[-1]) >= 32
    assert run_git(remote, "rev-parse", binding.candidate_ref) == binding.candidate_commit
    assert run_git(
        remote, "rev-list", "--parents", "-n", "1", binding.candidate_commit
    ).split() == [binding.candidate_commit, base_commit]
    assert binding.repository_digest.startswith("sha256:")


def test_publication_retry_reconciles_durable_ref(
    git_fixture: tuple[Path, Path, Path, str, str, str],
) -> None:
    remote, _seed, candidate, base_commit, base_tree, digest = git_fixture
    adapter = publisher(remote, digest)

    first = adapter.publish(candidate, base_commit, base_tree, digest)
    second = adapter.publish(candidate, base_commit, base_tree, digest)

    # The durable plan is the publication idempotency key: a restart/retry
    # reconciles the existing ref instead of creating a second candidate ref.
    assert first.candidate_ref == second.candidate_ref
    assert first.candidate_commit == second.candidate_commit
    assert first.candidate_tree == second.candidate_tree


def test_ref_collision_fails_before_push(
    git_fixture: tuple[Path, Path, Path, str, str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    remote, _seed, candidate, base_commit, base_tree, digest = git_fixture
    ref = "refs/heads/avo/candidate/" + "a" * 32
    run_git(remote, "update-ref", ref, base_commit)

    def fixed_token_hex(_n: int) -> str:
        return "a" * 32

    monkeypatch.setattr(
        "avo_correlate.adapters.git.publisher.secrets.token_hex",
        fixed_token_hex,
    )

    with pytest.raises(GitRepositoryError, match="already exists"):
        publisher(remote, digest).publish(candidate, base_commit, base_tree, digest)
    assert run_git(remote, "rev-parse", ref) == base_commit


@pytest.mark.parametrize("kind", ["digest", "base", "tree"])
def test_mismatch_fails_without_remote_ref(
    git_fixture: tuple[Path, Path, Path, str, str, str], kind: str
) -> None:
    remote, _seed, candidate, base_commit, base_tree, digest = git_fixture
    if kind == "digest":
        supplied_digest = "sha256:" + "f" * 64
        supplied_base, supplied_tree = base_commit, base_tree
    elif kind == "base":
        supplied_digest = digest
        supplied_base, supplied_tree = "0" * 40, base_tree
    else:
        supplied_digest = digest
        supplied_base, supplied_tree = base_commit, "0" * 40
    with pytest.raises(GitRepositoryError):
        publisher(remote, digest).publish(candidate, supplied_base, supplied_tree, supplied_digest)
    assert run_git(remote, "show-ref", "refs/heads/avo/candidate/x", check=False) == ""


def test_git_metadata_is_rejected(
    git_fixture: tuple[Path, Path, Path, str, str, str],
) -> None:
    remote, _seed, candidate, base_commit, base_tree, digest = git_fixture
    (candidate / ".git").mkdir()
    with pytest.raises(GitRepositoryError, match=r"\.git"):
        publisher(remote, digest).publish(candidate, base_commit, base_tree, digest)


def test_external_hardlink_is_rejected(
    git_fixture: tuple[Path, Path, Path, str, str, str], tmp_path: Path
) -> None:
    remote, _seed, candidate, base_commit, base_tree, digest = git_fixture
    outside = tmp_path / "outside.txt"
    try:
        os.link(candidate / "new.txt", outside)
    except OSError as exc:
        pytest.skip(f"hard links unavailable: {exc}")

    with pytest.raises(GitRepositoryError, match="hard-linked"):
        publisher(remote, digest).publish(candidate, base_commit, base_tree, digest)


def test_constructor_binds_repository_digest(
    git_fixture: tuple[Path, Path, Path, str, str, str]
) -> None:
    remote, _seed, _candidate, _base_commit, _base_tree, _digest = git_fixture
    with pytest.raises(ValueError, match="repository_digest"):
        GitCandidatePublisher(
            expected_remote=remote.as_uri(),
            repository_digest="sha256:" + "0" * 64,
            controller_publisher_identity="avo-controller",
            allow_local_remote_for_tests=True,
        )


def test_credential_helper_receives_process_token_only_when_configured(
    git_fixture: tuple[Path, Path, Path, str, str, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    remote, _seed, _candidate, _base_commit, _base_tree, _digest = git_fixture
    token = "ghp-regression-token"
    helper = tmp_path / "askpass"
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.setenv("GITHUB_TOKEN", token)

    configured = publisher(remote, "sha256:" + "1" * 64)
    configured = GitCandidatePublisher(
        expected_remote=remote.as_uri(),
        repository_digest=GitCandidatePublisher._remote_digest(remote.as_uri()),
        controller_publisher_identity="avo-controller",
        publication_journal=configured.publication_journal,
        credential_helper=helper,
        allow_local_remote_for_tests=True,
    )
    assert configured._environment()["GITHUB_TOKEN"] == token
    assert "GITHUB_TOKEN" not in publisher(remote, "sha256:" + "1" * 64)._environment()

    def failed_runner(
        arguments: list[str], cwd: Path, environment: Mapping[str, str], timeout: float
    ) -> subprocess.CompletedProcess[str]:
        del arguments, cwd, environment, timeout
        return subprocess.CompletedProcess(["git"], 1, "", f"authentication failed: {token}")

    configured._runner = failed_runner
    with pytest.raises(GitRepositoryError) as error:
        configured._run(["status"])
    assert token not in str(error.value)


def test_evidence_is_exactly_content_addressed(
    git_fixture: tuple[Path, Path, Path, str, str, str],
) -> None:
    remote, _seed, candidate, base_commit, base_tree, digest = git_fixture
    result = publisher(remote, digest).publish_result(candidate, base_commit, base_tree, digest)

    import hashlib

    assert result.evidence_artifact.digest == "sha256:" + hashlib.sha256(
        result.evidence_bytes
    ).hexdigest()
    assert result.evidence_artifact.size_bytes == len(result.evidence_bytes)
    assert result.binding.publication_evidence_digest == result.evidence_artifact.digest


def test_push_observation_failure_is_reconciled_after_restart(
    git_fixture: tuple[Path, Path, Path, str, str, str],
) -> None:
    remote, _seed, candidate, base_commit, base_tree, digest = git_fixture

    class ObservationFailurePublisher(GitCandidatePublisher):
        def __init__(self, **kwargs: Any) -> None:
            super().__init__(**kwargs)
            self.failed = False

        def _remote_ref_commit(self, clone: Path, ref: str) -> str:
            if not self.failed:
                self.failed = True
                raise GitRepositoryError("injected observation failure")
            return super()._remote_ref_commit(clone, ref)

    journal_root = remote.parent / "restart-journal"
    url = remote.as_uri()
    import hashlib

    remote_digest = "sha256:" + hashlib.sha256(url.encode()).hexdigest()
    first = ObservationFailurePublisher(
        expected_remote=url,
        repository_digest=remote_digest,
        controller_publisher_identity="avo-controller",
        publication_journal=FilesystemPublicationJournal(journal_root),
        max_file_bytes=1024 * 1024,
        max_tree_bytes=10 * 1024 * 1024,
        allow_local_remote_for_tests=True,
    )
    with pytest.raises(PublicationAmbiguousError) as error:
        first.publish(candidate, base_commit, base_tree, digest)

    restarted = publisher(remote, digest, journal_root=journal_root)
    result = restarted.reconcile(error.value.publication_id)
    assert result is not None
    assert result.binding.candidate_ref == error.value.candidate_ref
    assert result.evidence_artifact.digest == result.binding.publication_evidence_digest


def test_live_transport_requires_explicit_github_https() -> None:
    with pytest.raises(ValueError, match=r"remote transport is not allowed"):
        GitCandidatePublisher(
            expected_remote="file:///tmp/repo.git",
            repository_digest="sha256:" + "0" * 64,
            controller_publisher_identity="avo-controller",
        )


def _publication_plan(adapter: GitCandidatePublisher, base_commit: str, base_tree: str,
                      *, candidate_ref: str = "refs/heads/avo/candidate/test") -> PublicationPlan:
    return adapter._new_plan(
        base_commit,
        base_tree,
        "sha256:" + "1" * 64,
        candidate_ref,
        "b" * 40,
        "c" * 40,
    )


def test_journal_rejects_tampered_plan_schema_fields_and_digest(
    git_fixture: tuple[Path, Path, Path, str, str, str], tmp_path: Path
) -> None:
    remote, _seed, _candidate, base_commit, base_tree, _digest = git_fixture
    adapter = publisher(remote, "sha256:" + "1" * 64)
    plan = _publication_plan(adapter, base_commit, base_tree)
    payload = plan.payload()

    with pytest.raises(GitRepositoryError, match="unsupported"):
        FilesystemPublicationJournal._plan_from_payload({**payload, "schema_version": 2})
    with pytest.raises(GitRepositoryError, match="fields"):
        FilesystemPublicationJournal._plan_from_payload({**payload, "unexpected": True})
    with pytest.raises(GitRepositoryError, match="digest"):
        FilesystemPublicationJournal._plan_from_payload(
            {**payload, "publication_id": "sha256:" + "f" * 64}
        )

    journal = FilesystemPublicationJournal(tmp_path / "journal")
    journal.record_plan(plan)
    assert journal.read_plan(plan.publication_id) == plan
    assert journal.read_plan("sha256:" + "f" * 64) is None


def test_journal_rejects_malformed_index_role_identity_and_multiple_matches(
    git_fixture: tuple[Path, Path, Path, str, str, str], tmp_path: Path
) -> None:
    remote, _seed, _candidate, base_commit, base_tree, _digest = git_fixture
    adapter = publisher(remote, "sha256:" + "1" * 64)
    journal = FilesystemPublicationJournal(tmp_path / "journal")
    first = _publication_plan(adapter, base_commit, base_tree)
    journal.record_plan(first)
    index = journal.root / "plans" / (first.publication_id.removeprefix("sha256:") + ".json")
    index_payload = json.loads(index.read_text(encoding="utf-8"))
    index_payload["role"] = "wrong-role"
    index.write_text(json.dumps(index_payload), encoding="utf-8")
    with pytest.raises(GitRepositoryError, match="role"):
        journal.find_matching_plan(
            first.repository_digest, first.expected_remote, base_commit, base_tree,
            first.candidate_digest, first.controller_publisher_identity,
        )

    journal = FilesystemPublicationJournal(tmp_path / "journal-identity")
    journal.record_plan(first)
    index = journal.root / "plans" / (first.publication_id.removeprefix("sha256:") + ".json")
    renamed = journal.root / "plans" / ("f" * 64 + ".json")
    index.rename(renamed)
    with pytest.raises(GitRepositoryError, match="identity"):
        journal.find_matching_plan(
            first.repository_digest, first.expected_remote, base_commit, base_tree,
            first.candidate_digest, first.controller_publisher_identity,
        )

    journal = FilesystemPublicationJournal(tmp_path / "journal-multiple")
    journal.record_plan(first)
    second = _publication_plan(
        adapter, base_commit, base_tree, candidate_ref="refs/heads/avo/candidate/other"
    )
    journal.record_plan(second)
    with pytest.raises(GitRepositoryError, match="multiple"):
        journal.find_matching_plan(
            first.repository_digest, first.expected_remote, base_commit, base_tree,
            first.candidate_digest, first.controller_publisher_identity,
        )


def test_journal_rejects_conflicting_outcome_and_oversized_evidence(tmp_path: Path) -> None:
    journal = FilesystemPublicationJournal(tmp_path / "journal", max_record_bytes=32)
    outcome = PublicationOutcome("sha256:" + "a" * 64, "pushed", "refs/heads/x", "a" * 40, "b" * 40)
    with pytest.raises(GitRepositoryError, match="evidence"):
        journal.record_evidence(b"x" * 33)
    with pytest.raises(GitRepositoryError, match="publication outcome"):
        journal.record_outcome(outcome)

    journal = FilesystemPublicationJournal(tmp_path / "journal-ok")
    journal.record_outcome(outcome)
    conflicting = PublicationOutcome(
        outcome.publication_id, "pushed", outcome.candidate_ref, "c" * 40, "d" * 40
    )
    with pytest.raises(GitRepositoryError, match="conflicting"):
        journal.record_outcome(conflicting)


def test_reconcile_missing_plan_wrong_repository_and_missing_remote_ref(
    git_fixture: tuple[Path, Path, Path, str, str, str], tmp_path: Path
) -> None:
    remote, _seed, _candidate, base_commit, base_tree, _digest = git_fixture
    adapter = publisher(remote, "sha256:" + "1" * 64)
    with pytest.raises(GitRepositoryError, match="not found"):
        adapter.reconcile("sha256:" + "f" * 64)

    journal = FilesystemPublicationJournal(tmp_path / "wrong")
    plan = _publication_plan(adapter, base_commit, base_tree)
    wrong = replace(plan, repository_digest="sha256:" + "f" * 64)
    wrong = replace(wrong, publication_id=canonical_digest(wrong.identity_payload()))
    journal.record_plan(wrong)
    wrong_adapter = publisher(remote, "sha256:" + "1" * 64, journal_root=tmp_path / "wrong")
    with pytest.raises(GitRepositoryError, match="different repository"):
        wrong_adapter.reconcile(wrong.publication_id)

    missing_journal = FilesystemPublicationJournal(tmp_path / "missing")
    missing_journal.record_plan(plan)
    missing_adapter = publisher(remote, "sha256:" + "1" * 64, journal_root=tmp_path / "missing")
    assert missing_adapter.reconcile(plan.publication_id) is None


def test_push_failure_is_ambiguous_and_is_recorded(
    git_fixture: tuple[Path, Path, Path, str, str, str]
) -> None:
    remote, _seed, candidate, base_commit, base_tree, digest = git_fixture

    class PushFailurePublisher(GitCandidatePublisher):
        def _run(self, arguments: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            if arguments and arguments[0] == "push":
                raise GitRepositoryError("connection reset after push")
            return super()._run(arguments, **kwargs)

    adapter = PushFailurePublisher(
        expected_remote=remote.as_uri(),
        repository_digest=GitCandidatePublisher._remote_digest(remote.as_uri()),
        controller_publisher_identity="avo-controller",
        publication_journal=FilesystemPublicationJournal(remote.parent / "push-failure"),
        max_file_bytes=1024 * 1024,
        max_tree_bytes=10 * 1024 * 1024,
        allow_local_remote_for_tests=True,
    )
    with pytest.raises(PublicationAmbiguousError, match="ambiguous"):
        adapter.publish(candidate, base_commit, base_tree, digest)


def test_reconcile_rejects_remote_commit_binding_drift(
    git_fixture: tuple[Path, Path, Path, str, str, str], tmp_path: Path
) -> None:
    remote, _seed, _candidate, base_commit, base_tree, _digest = git_fixture
    adapter = publisher(remote, "sha256:" + "1" * 64)
    plan = _publication_plan(adapter, base_commit, base_tree)
    journal = FilesystemPublicationJournal(tmp_path / "drift")
    journal.record_plan(plan)
    run_git(remote, "update-ref", plan.candidate_ref, base_commit)
    with pytest.raises(GitRepositoryError, match=r"unexpected commit|binding differs"):
        publisher(remote, "sha256:" + "1" * 64, journal_root=tmp_path / "drift").reconcile(
            plan.publication_id
        )


def test_publisher_rejects_missing_journal_malformed_inputs_and_bounds(
    git_fixture: tuple[Path, Path, Path, str, str, str]
) -> None:
    remote, _seed, candidate, base_commit, base_tree, digest = git_fixture
    url = remote.as_uri()
    repository_digest = GitCandidatePublisher._remote_digest(url)
    common: dict[str, Any] = {
        "expected_remote": url,
        "repository_digest": repository_digest,
        "controller_publisher_identity": "avo-controller",
        "allow_local_remote_for_tests": True,
    }
    for updates, message in [
        ({"expected_remote": ""}, "expected_remote"),
        ({"repository_digest": "wrong"}, "repository_digest"),
        ({"controller_publisher_identity": ""}, "controller_publisher_identity"),
        ({"controller_publisher_identity": "bad\nname"}, "forbidden"),
        ({"max_file_bytes": 0}, "bounds"),
        ({"command_timeout_seconds": 0}, "timeout"),
        ({"max_output_bytes": 0}, "max_output"),
    ]:
        with pytest.raises(ValueError, match=message):
            GitCandidatePublisher(**cast(dict[str, Any], common | updates))

    no_journal = GitCandidatePublisher(**common)
    with pytest.raises(GitRepositoryError, match="journal"):
        no_journal.publish(candidate, base_commit, base_tree, digest)
    with pytest.raises(GitRepositoryError, match="candidate digest"):
        publisher(remote, digest).publish(candidate, base_commit, base_tree, "bad")
    with pytest.raises(GitRepositoryError, match="journal"):
        no_journal.reconcile("sha256:" + "f" * 64)
    with pytest.raises(GitRepositoryError, match="identifier"):
        FilesystemPublicationJournal._safe_identifier("../escape")
    with pytest.raises(ValueError, match="max_record_bytes"):
        FilesystemPublicationJournal(remote.parent / "invalid", max_record_bytes=0)
