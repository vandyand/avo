"""Adversarial proof tests for offline protected-main composition."""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from avo_correlate.adapters.git.main_composition import (
    MainBaseSnapshot,
    MainCompositionAdapter,
    MainCompositionError,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_graduation import MainSourcePackageBinding
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
    def __init__(self, root: Path, journal: _Journal, package: Any) -> None:
        super().__init__(
            root,
            journal,
            repository_digest=DIGEST,
            base_reader=_BaseReader(
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


def _repo(tmp_path: Path, path: str = "feature.txt") -> tuple[Path, str, str, str, str]:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "--quiet", "--initial-branch=main")
    _git(root, "config", "user.name", "test")
    _git(root, "config", "user.email", "test@example.test")
    (root / "base.txt").write_text("base\n", encoding="utf-8")
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


def test_git_environment_cannot_redirect_repository_or_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root, parent, result, tree, _parent_tree = _repo(tmp_path)
    binding, package = _source(parent, result, tree, changed=["feature.txt"])
    adapter = _Adapter(root, _Journal(binding), package)
    monkeypatch.setenv("GIT_DIR", str(tmp_path / "attacker.git"))
    monkeypatch.setenv("GIT_WORK_TREE", str(tmp_path / "attacker-worktree"))
    environment = adapter._environment()
    assert "GIT_DIR" not in environment
    assert "GIT_WORK_TREE" not in environment
    assert environment["GIT_CONFIG_GLOBAL"] == __import__("os").devnull


def test_successful_source_for_wrong_target_is_rejected(tmp_path: Path) -> None:
    root, parent, result, tree, _parent_tree = _repo(tmp_path)
    binding, package = _source(parent, result, tree, changed=["feature.txt"])
    package.intent.target_ref = "refs/heads/main"
    with pytest.raises(MainCompositionError, match="target"):
        _Adapter(root, _Journal(binding), package).compose(binding)
