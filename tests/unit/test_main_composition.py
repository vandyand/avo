"""Adversarial proof tests for offline protected-main composition."""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
    MainGraduationJournalError,
    MainGraduationRecordConflictError,
)
from avo_correlate.adapters.git.main_composition import (
    MainBaseSnapshot,
    MainCompositionAdapter,
    MainCompositionError,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_graduation import MainDeltaManifest, MainSourcePackageBinding
from avo_correlate.contracts.promotion_policy import path_manifest_digest
from avo_correlate.domain.canonical import canonical_digest

DIGEST = "sha256:" + "1" * 64


class _Journal:
    def __init__(self, source: MainSourcePackageBinding) -> None:
        self.source = source
        self.records: dict[str, Any] = {}

    def read_source_package(self, _operation_id: str) -> tuple[MainSourcePackageBinding, None]:
        return self.source, None

    def record_delta(self, value: Any) -> ArtifactRef:
        return self._record("delta", value)

    def record_composition(self, value: Any) -> ArtifactRef:
        return self._record("composition", value)

    def _record(self, role: str, value: Any) -> ArtifactRef:
        data = value.model_dump_json().encode()
        digest = canonical_digest(value)
        ref = ArtifactRef(
            digest=digest,
            size_bytes=len(data),
            media_type=f"application/vnd.avo.main-graduation-{role}+json",
            role=f"main-graduation-{role}",
            created_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
        )
        self.records[role] = value
        return ref


class _BaseReader:
    def __init__(self, snapshot: MainBaseSnapshot) -> None:
        self.snapshot = snapshot

    def fresh_main_base(self) -> MainBaseSnapshot:
        return self.snapshot


class _Adapter(MainCompositionAdapter):
    def __init__(
        self,
        root: Path,
        journal: Any,
        package: Any,
        *,
        base_reader: Any | None = None,
    ) -> None:
        super().__init__(
            root,
            journal,
            repository_digest=DIGEST,
            base_reader=base_reader
            or _BaseReader(
                MainBaseSnapshot(
                    DIGEST,
                    _git(root, "rev-parse", "refs/heads/main"),
                    _git(root, "rev-parse", "refs/heads/main^{tree}"),
                )
            ),
        )
        self.package = package

    def _read_package(
        self, source: MainSourcePackageBinding, durable: MainSourcePackageBinding
    ) -> Any:
        return self.package


def _git(root: Path, *args: str, input: bytes | None = None) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, check=True, capture_output=True, input=input, text=False
    )
    return result.stdout.decode().strip()


def _repo(
    tmp_path: Path, path: str = "feature.txt", *, attributes: bool = False
) -> tuple[Path, str, str, str, str]:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "--quiet", "--initial-branch=main")
    _git(root, "config", "user.name", "test")
    _git(root, "config", "user.email", "test@example.test")
    (root / "base.txt").write_text("base\n", encoding="utf-8")
    if attributes:
        (root / ".gitattributes").write_text("*.txt diff=attacker\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "base")
    parent = _git(root, "rev-parse", "HEAD")
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("change\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "source")
    result = _git(root, "rev-parse", "HEAD")
    result_tree = _git(root, "rev-parse", "HEAD^{tree}")
    parent_tree = _git(root, "rev-parse", f"{parent}^{{tree}}")
    _git(root, "reset", "--hard", "--quiet", parent)
    return root, parent, result, result_tree, parent_tree


def _source(
    parent: str, result: str, result_tree: str, *, changed: list[str]
) -> tuple[MainSourcePackageBinding, Any]:
    request = SimpleNamespace(
        changed_paths=changed,
        path_manifest_attestation=SimpleNamespace(
            path_manifest_digest=path_manifest_digest(changed)
        ),
    )
    bundle = SimpleNamespace(
        request=request,
        decision=SimpleNamespace(risk_class=SimpleNamespace(value="ordinary")),
        snapshot=SimpleNamespace(target_ref="refs/heads/integration"),
        comparison=SimpleNamespace(target_ref="refs/heads/integration"),
    )
    artifact = ArtifactRef(
        digest=DIGEST,
        size_bytes=1,
        media_type="application/vnd.avo.integration-campaign+json",
        role="integration-campaign-package",
        created_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
    )
    binding = MainSourcePackageBinding.model_construct(
        operation_id="sha256:" + "2" * 64,
        source_operation_id="sha256:" + "3" * 64,
        repository_digest=DIGEST,
        package_digest=DIGEST,
        package_artifact=artifact,
        child_artifacts=[artifact.model_copy(update={"role": "source-child"})],
        source_result_commit=result,
        source_result_tree=result_tree,
        source_result_parent=parent,
        source_issuer="source",
    )
    package = SimpleNamespace(
        bundle=bundle,
        intent=SimpleNamespace(
            operation_id=binding.source_operation_id,
            target_ref="refs/heads/integration",
        ),
        observation=SimpleNamespace(base_ref="refs/heads/integration"),
        reconciliation=SimpleNamespace(target_ref="refs/heads/integration"),
        receipt=SimpleNamespace(outcome="applied"),
        deploy_performed=False,
    )
    return binding, package


def test_exact_composition_is_replayable_and_does_not_move_main(tmp_path: Path) -> None:
    root, parent, result, result_tree, parent_tree = _repo(tmp_path)
    binding, package = _source(parent, result, result_tree, changed=["feature.txt"])
    journal = _Journal(binding)
    adapter = _Adapter(root, journal, package)
    base = MainBaseSnapshot(DIGEST, parent, parent_tree)

    first = adapter.compose(binding, base=base)
    second = adapter.compose(binding, base=base)

    assert first.delta == second.delta
    assert first.composition == second.composition
    assert _git(root, "rev-parse", "refs/heads/main") == parent
    assert first.composition.candidate_parent_commit == parent
    assert first.composition.candidate_tree != parent_tree


def test_multi_parent_source_fails_closed(tmp_path: Path) -> None:
    root, parent, _result, _tree, parent_tree = _repo(tmp_path)
    (root / "other.txt").write_text("other\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "other")
    _git(root, "checkout", "--quiet", "-b", "side", parent)
    (root / "side.txt").write_text("side\n", encoding="utf-8")
    _git(root, "add", ".")
    _git(root, "commit", "-m", "side")
    _git(root, "checkout", "--quiet", "main")
    _git(root, "merge", "--no-ff", "side", "-m", "merge")
    result = _git(root, "rev-parse", "HEAD")
    tree = _git(root, "rev-parse", "HEAD^{tree}")
    _git(root, "reset", "--hard", "--quiet", parent)
    binding, package = _source(parent, result, tree, changed=["other.txt"])
    with pytest.raises(MainCompositionError, match="sole-parent"):
        _Adapter(root, _Journal(binding), package).compose(
            binding, base=MainBaseSnapshot(DIGEST, parent, parent_tree)
        )


def test_path_manifest_drift_fails_closed(tmp_path: Path) -> None:
    root, parent, result, tree, parent_tree = _repo(tmp_path)
    binding, package = _source(parent, result, tree, changed=["wrong.txt"])
    with pytest.raises(MainCompositionError, match="path manifest"):
        _Adapter(root, _Journal(binding), package).compose(
            binding, base=MainBaseSnapshot(DIGEST, parent, parent_tree)
        )


def test_disallowed_risk_fails_closed(tmp_path: Path) -> None:
    root, parent, result, tree, parent_tree = _repo(tmp_path, ".github/workflow.yml")
    binding, package = _source(parent, result, tree, changed=[".github/workflow.yml"])
    with pytest.raises(MainCompositionError, match="risk paths"):
        _Adapter(root, _Journal(binding), package).compose(
            binding, base=MainBaseSnapshot(DIGEST, parent, parent_tree)
        )


def test_stale_main_base_fails_closed(tmp_path: Path) -> None:
    root, parent, result, tree, _parent_tree = _repo(tmp_path)
    binding, package = _source(parent, result, tree, changed=["feature.txt"])
    stale = MainBaseSnapshot(DIGEST, result, tree)
    with pytest.raises(MainCompositionError, match="main base changed"):
        _Adapter(root, _Journal(binding), package).compose(binding, base=stale)


def test_main_drift_during_composition_fails_before_durable_records(tmp_path: Path) -> None:
    root, parent, result, tree, parent_tree = _repo(tmp_path)
    binding, package = _source(parent, result, tree, changed=["feature.txt"])

    class ChangingReader:
        calls = 0

        def fresh_main_base(self) -> MainBaseSnapshot:
            self.calls += 1
            if self.calls < 2:
                return MainBaseSnapshot(DIGEST, parent, parent_tree)
            return MainBaseSnapshot(DIGEST, result, tree)

    journal = _Journal(binding)
    with pytest.raises(MainCompositionError, match="main base changed"):
        _Adapter(root, journal, package, base_reader=ChangingReader()).compose(
            binding, base=MainBaseSnapshot(DIGEST, parent, parent_tree)
        )
    assert journal.records == {}


def test_git_environment_cannot_redirect_repository_or_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root, parent, result, tree, _parent_tree = _repo(tmp_path)
    binding, package = _source(parent, result, tree, changed=["feature.txt"])
    adapter = _Adapter(root, _Journal(binding), package)
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "attacker.git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(tmp_path / "attacker-worktree"))
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", str(tmp_path / "attacker-objects"))
    environment = adapter._environment()  # pyright: ignore[reportPrivateUsage]
    assert "GIT_DIR" not in environment
    assert "GIT_WORK_TREE" not in environment
    assert "GIT_OBJECT_DIRECTORY" not in environment
    assert environment["GIT_CONFIG_GLOBAL"] == __import__("os").devnull
    assert environment["GIT_NO_REPLACE_OBJECTS"] == "1"


@pytest.mark.parametrize("path", [".git/config", "nested/.GIT/config"])
def test_git_metadata_paths_are_rejected(path: str, tmp_path: Path) -> None:
    root, parent, result, tree, _parent_tree = _repo(tmp_path)
    binding, package = _source(parent, result, tree, changed=["feature.txt"])
    adapter = _Adapter(root, _Journal(binding), package)
    assert not adapter._safe_path(path)  # pyright: ignore[reportPrivateUsage]
    assert adapter._safe_path("src/feature.py")  # pyright: ignore[reportPrivateUsage]


def test_successful_source_for_wrong_target_is_rejected(tmp_path: Path) -> None:
    root, parent, result, tree, _parent_tree = _repo(tmp_path)
    binding, package = _source(parent, result, tree, changed=["feature.txt"])
    package.intent.target_ref = "refs/heads/main"
    with pytest.raises(MainCompositionError, match="target"):
        _Adapter(root, _Journal(binding), package).compose(binding)


def test_diff_does_not_execute_local_textconv(tmp_path: Path) -> None:
    root, parent, result, tree, parent_tree = _repo(tmp_path, attributes=True)
    marker = tmp_path / "textconv-ran"
    script = tmp_path / "textconv.cmd"
    script.write_text(f"@echo ran>{marker}\n", encoding="utf-8")
    _git(root, "config", "diff.attacker.textconv", str(script))
    binding, package = _source(parent, result, tree, changed=["feature.txt"])
    _Adapter(root, _Journal(binding), package).compose(
        binding, base=MainBaseSnapshot(DIGEST, parent, parent_tree)
    )
    assert not marker.exists()


def test_commit_is_independent_of_local_encoding_configuration(tmp_path: Path) -> None:
    root, parent, result, tree, parent_tree = _repo(tmp_path)
    binding, package = _source(parent, result, tree, changed=["feature.txt"])
    journal = _Journal(binding)
    adapter = _Adapter(root, journal, package)
    base = MainBaseSnapshot(DIGEST, parent, parent_tree)
    _git(root, "config", "i18n.commitEncoding", "ISO-8859-1")
    first = adapter.compose(binding, base=base)
    _git(root, "config", "i18n.commitEncoding", "UTF-8")
    second = adapter.compose(binding, base=base)
    assert first.composition.candidate_commit == second.composition.candidate_commit


def test_retention_ref_survives_gc_and_rejects_conflict(tmp_path: Path) -> None:
    root, parent, result, tree, parent_tree = _repo(tmp_path)
    binding, package = _source(parent, result, tree, changed=["feature.txt"])
    adapter = _Adapter(root, _Journal(binding), package)
    composition = adapter.compose(
        binding, base=MainBaseSnapshot(DIGEST, parent, parent_tree)
    ).composition
    retention = composition.retention_ref
    _git(root, "reflog", "expire", "--expire=now", "--all")
    _git(root, "gc", "--prune=now", "--quiet")
    assert (
        _git(root, "rev-parse", "--verify", retention + "^{commit}")
        == composition.candidate_commit
    )
    with pytest.raises(MainCompositionError, match="conflicting"):
        adapter._retain_candidate(retention, parent)  # pyright: ignore[reportPrivateUsage]


def test_casefold_collision_in_source_tree_is_rejected(tmp_path: Path) -> None:
    root, parent, _result, _tree, parent_tree = _repo(tmp_path)
    blob = _git(root, "hash-object", "-w", "--stdin", input=b"collision\n")
    tree = _git(
        root,
        "mktree",
        input=f"100644 blob {blob}\tFoo\n100644 blob {blob}\tfoo\n".encode(),
    )
    result = _git(root, "commit-tree", tree, "-p", parent, input=b"collision\n")
    binding, package = _source(parent, result, tree, changed=["Foo", "foo"])
    with pytest.raises(MainCompositionError, match="unsafe path"):
        _Adapter(root, _Journal(binding), package).compose(
            binding, base=MainBaseSnapshot(DIGEST, parent, parent_tree)
        )


def test_topology_parser_ignores_non_utf8_commit_message(tmp_path: Path) -> None:
    root, parent, result, result_tree, _parent_tree = _repo(tmp_path)
    tree = _git(root, "rev-parse", f"{parent}^{{tree}}")
    commit = _git(root, "commit-tree", tree, "-p", parent, input=b"message\n\n\xff")
    binding, package = _source(parent, result, result_tree, changed=["feature.txt"])
    adapter = _Adapter(root, _Journal(binding), package)
    parsed_tree, parents = adapter._commit_topology(commit)  # pyright: ignore[reportPrivateUsage]
    assert parsed_tree == tree
    assert parents == [parent]


def test_real_filesystem_journal_replay_and_tamper_detection(tmp_path: Path) -> None:
    root, parent, result, tree, parent_tree = _repo(tmp_path)
    binding, package = _source(parent, result, tree, changed=["feature.txt"])
    journal = MainGraduationJournal(tmp_path / "journal")
    raw_package = journal._store.put_bytes(  # pyright: ignore[reportPrivateUsage]
        b"{}",
        media_type="application/vnd.avo.integration-campaign+json",
        role="integration-campaign-package",
        max_bytes=1024,
    )
    raw_child = journal._store.put_bytes(  # pyright: ignore[reportPrivateUsage]
        b"child",
        media_type="application/vnd.avo.integration-campaign+json",
        role="source-child",
        max_bytes=1024,
    )
    binding = binding.model_copy(
        update={
            "package_artifact": raw_package,
            "package_digest": raw_package.digest,
            "child_artifacts": [raw_child],
        }
    )
    journal._verify_source_package = lambda _package: None  # type: ignore[method-assign, reportPrivateUsage]
    journal.record_source_package(binding)
    adapter = _Adapter(root, journal, package)
    base = MainBaseSnapshot(DIGEST, parent, parent_tree)
    first = adapter.compose(binding, base=base)
    second = adapter.compose(binding, base=base)
    assert first.composition == second.composition
    assert journal.read_delta(binding.operation_id) is not None
    assert journal.read_composition(binding.operation_id) is not None
    conflicting_values = first.delta.model_dump(mode="json")
    conflicting_values.update(
        {
            "changed_paths": ["other.txt"],
            "path_manifest_digest": path_manifest_digest(["other.txt"]),
        }
    )
    conflicting_values["ordinary_risk_digest"] = canonical_digest(
        {
            "ordinary_risk": "ordinary",
            "changed_paths": ["other.txt"],
            "path_manifest_digest": conflicting_values["path_manifest_digest"],
        }
    )
    conflicting_values["delta_digest"] = canonical_digest(
        {key: value for key, value in conflicting_values.items() if key != "delta_digest"}
    )
    conflict = MainDeltaManifest.model_validate(conflicting_values)
    with pytest.raises(MainGraduationRecordConflictError):
        journal.record_delta(conflict)
    assert journal.delete_artifact(first.composition_artifact.digest)
    with pytest.raises(MainGraduationJournalError, match=r"unavailable|tampered|unverifiable"):
        journal.read_composition(binding.operation_id)
