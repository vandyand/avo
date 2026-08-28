"""Promotion-controller coverage for trusted rollback bundle construction."""

from pathlib import Path
from typing import Any, cast

import pytest

from avo_correlate.adapters.artifacts import FilesystemArtifactStore
from avo_correlate.application.promotion_service import PromotionController
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_promotion import CandidatePublicationBinding
from avo_correlate.contracts.promotion_bundle import GitRefSnapshot, PromotionControllerConfig
from avo_correlate.contracts.promotion_policy import PromotionConfig
from avo_correlate.domain.canonical import canonical_bytes
from tests.unit.test_rollback_bundle_authority import (  # pyright: ignore[reportPrivateUsage]
    Fixture,
    _evidence,  # pyright: ignore[reportPrivateUsage]
    _publication,  # pyright: ignore[reportPrivateUsage]
)


class Repository:
    def __init__(self, *, stale: bool = False) -> None:
        self.stale = stale
        self.reads = 0
        self.state = GitRefSnapshot(
            repository_digest="sha256:" + "a" * 64,
            target_ref="refs/heads/integration",
            commit="c" * 40,
            tree="b" * 40,
            source_tree_digest="sha256:" + "a" * 64,
            protection_evidence_digest="sha256:" + "a" * 64,
        )

    def snapshot(self) -> GitRefSnapshot:
        self.reads += 1
        if self.stale and self.reads > 1:
            return self.state.model_copy(update={"commit": "e" * 40})
        return self.state

    def compare_candidate(self, root: Path, snapshot: GitRefSnapshot) -> Any:
        del root
        from avo_correlate.contracts.promotion_bundle import WorkspaceComparison

        return WorkspaceComparison(
            target_ref=snapshot.target_ref,
            base_digest=snapshot.source_tree_digest,
            candidate_digest="sha256:" + "b" * 64,
            changed_paths=["src/x.py"],
        )


def config() -> PromotionControllerConfig:
    return PromotionControllerConfig(
        controller_identity="controller",
        controller_version="1",
        base_issuer_id="base-observer",
        path_issuer_id="path-observer",
        policy=PromotionConfig(
            evaluation_epoch=1,
            trusted_gate_issuers={"deterministic": ["ci"], "provenance": ["ci"]},
            trusted_base_issuers=["base-observer"],
            trusted_reviewer_issuers=["reviewer"],
            trusted_path_issuers=["path-observer"],
            rollback_issuer_ids=["controller"],
            rollback_limit=1,
            reviewer_domains={"reviewer": "reviewer-domain"},
            proposer_domains={"proposer": "proposer-domain"},
            candidate_proposers={"sha256:" + "b" * 64: "proposer"},
        ),
    )


def controller(
    root: Path, repository: Repository | None = None
) -> tuple[PromotionController, FilesystemArtifactStore, Path]:
    candidate = root / "candidate"
    candidate.mkdir(parents=True)
    store = FilesystemArtifactStore(root / "artifacts")

    def provenance(_digest: str, _candidate: str, _base: str) -> bool:
        return True

    def evidence(_digest: str, _issuer: str, _candidate: str, _base: str) -> bool:
        return True

    return (
        PromotionController(
            repository or Repository(),
            provenance,
            evidence,
            store,
            trusted_config=config(),
            trusted_repository_root=root / "trusted-repository",
            trusted_artifact_root=store.root,
        ),
        store,
        candidate,
    )


def _inputs(root: Path) -> tuple[Any, Any, Any, CandidatePublicationBinding, ArtifactRef]:
    fixture = Fixture(root / "fixture")
    preauth = fixture.authorize()
    drill = fixture.authority.drill_authorization(preauth, fixture.soak)
    package_bytes = canonical_bytes(fixture.package)
    package_store = FilesystemArtifactStore(root / "controller-artifacts")
    package_ref = package_store.put_bytes(
        package_bytes,
        media_type="application/vnd.avo.integration-campaign+json",
        role="integration-campaign-package",
        max_bytes=2_000_000,
    )
    evidence_bytes = _evidence(fixture, preauth)
    package_store.put_bytes(
        evidence_bytes,
        media_type="application/json",
        role="publication",
        max_bytes=2_000_000,
    )
    publication = _publication(fixture, preauth)
    return fixture, preauth, drill, publication, package_ref


def test_create_rollback_bundle_builds_allow_bundle_and_durable_authority(
    tmp_path: Path,
) -> None:
    fixture, preauth, drill, publication, package_ref = _inputs(tmp_path)
    control, store, candidate = controller(tmp_path)
    # Move the child records into the controller's trusted store.  The package
    # reference remains content-addressed, so only its store location changes.
    store.put_bytes(
        canonical_bytes(fixture.package),
        media_type=package_ref.media_type,
        role=package_ref.role,
        max_bytes=2_000_000,
    )
    evidence = _evidence(fixture, preauth)
    store.put_bytes(
        evidence,
        media_type="application/json",
        role="publication",
        max_bytes=2_000_000,
    )
    result = control.create_rollback_bundle(
        fixture.operation,
        canary_package=fixture.package,
        canary_package_artifact=package_ref,
        drill_authorization=drill,
        candidate_root=candidate,
        publication=publication,
        config=config(),
    )
    assert result.bundle.decision.outcome.value == "allow"
    assert result.bundle.rollback_authorization is not None
    assert result.bundle.rollback_operation_id == preauth.operation_id
    assert result.bundle.comparison.changed_paths == ["src/x.py"]
    control.replay(result.bundle, bundle_digest=result.bundle_digest)


def test_rollback_bundle_rejects_untrusted_input_types_before_store_reads(tmp_path: Path) -> None:
    control, _store, candidate = controller(tmp_path)
    with pytest.raises(TypeError, match="rollback request"):
        control.create_rollback_bundle(
            cast(Any, object()),
            canary_package=cast(Any, object()),
            canary_package_artifact=cast(Any, object()),
            candidate_root=candidate,
            publication=object(),
            config=config(),
        )


def test_rollback_bundle_rejects_stale_repository_before_artifact_write(tmp_path: Path) -> None:
    fixture, preauth, drill, publication, package_ref = _inputs(tmp_path)
    control, store, candidate = controller(tmp_path, Repository(stale=True))
    store.put_bytes(
        canonical_bytes(fixture.package),
        media_type=package_ref.media_type,
        role=package_ref.role,
        max_bytes=2_000_000,
    )
    store.put_bytes(
        _evidence(fixture, preauth),
        media_type="application/json",
        role="publication",
        max_bytes=2_000_000,
    )
    with pytest.raises(RuntimeError, match="repository changed"):
        control.create_rollback_bundle(
            fixture.operation,
            canary_package=fixture.package,
            canary_package_artifact=package_ref,
            drill_authorization=drill,
            candidate_root=candidate,
            publication=publication,
            config=config(),
        )
