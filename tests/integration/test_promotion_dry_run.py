from __future__ import annotations

import subprocess
from pathlib import Path

from avo_correlate.adapters.artifacts import FilesystemArtifactStore
from avo_correlate.adapters.git import GitRepositoryReader
from avo_correlate.application.promotion_service import PromotionController, bundle_bytes
from avo_correlate.contracts.promotion_bundle import (
    PromotionControllerConfig,
    PromotionDryRunInput,
)
from avo_correlate.contracts.promotion_policy import (
    GateAttestation,
    PromotionConfig,
    ReviewerAttestation,
    RollbackAttestation,
)

EVIDENCE = "sha256:" + "e" * 64
PROVENANCE = "sha256:" + "f" * 64
REMOTE = "https://example.invalid/avo.git"


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        shell=False,
    ).stdout.strip()


def _attestation(name: str, candidate: str, base: str) -> GateAttestation:
    return GateAttestation(
        gate_name=name,
        candidate_digest=candidate,
        base_digest=base,
        evidence_digest=EVIDENCE,
        issuer_id="ci",
        passed=True,
        valid_from_epoch=7,
        valid_until_epoch=7,
    )


def test_real_git_dry_run_replays_without_mutating_repository(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init", "-b", "main")
    _git(repository, "config", "user.email", "test@example.invalid")
    _git(repository, "config", "user.name", "AVO Test")
    (repository / "README.md").write_text("baseline\n", encoding="utf-8")
    (repository / "docs").mkdir()
    (repository / "docs" / "guide.md").write_text("before\n", encoding="utf-8")
    _git(repository, "add", "--all")
    _git(repository, "commit", "-m", "baseline")
    _git(repository, "remote", "add", "origin", REMOTE)

    candidate = tmp_path / "candidate"
    candidate.mkdir()
    (candidate / "README.md").write_text("baseline\n", encoding="utf-8")
    (candidate / "docs").mkdir()
    (candidate / "docs" / "guide.md").write_text("after\n", encoding="utf-8")

    reader = GitRepositoryReader(
        repository,
        target_ref="main",
        expected_remote=REMOTE,
        protection_evidence_digest=EVIDENCE,
        max_file_bytes=1024,
        max_tree_bytes=4096,
    )
    snapshot = reader.snapshot()
    comparison = reader.compare_candidate(candidate, snapshot)
    candidate_digest = comparison.candidate_digest
    base_digest = comparison.base_digest
    policy = PromotionConfig(
        evaluation_epoch=7,
        trusted_gate_issuers={"deterministic": ["ci"], "provenance": ["ci"]},
        trusted_base_issuers=["base-controller"],
        trusted_reviewer_issuers=["review-controller"],
        trusted_path_issuers=["path-controller"],
        rollback_issuer_ids=["rollback-controller"],
        rollback_limit=1,
        reviewer_domains={"reviewer-1": "review-domain"},
        proposer_domains={"agent-1": "proposal-domain"},
        candidate_proposers={candidate_digest: "agent-1"},
    )
    config = PromotionControllerConfig(
        controller_identity="promotion-controller",
        controller_version="1",
        base_issuer_id="base-controller",
        path_issuer_id="path-controller",
        policy=policy,
    )
    request = PromotionDryRunInput(
        candidate_id="candidate-1",
        proposer_id="agent-1",
        candidate_digest=candidate_digest,
        gate_attestations=[
            _attestation("deterministic", candidate_digest, base_digest),
            _attestation("provenance", candidate_digest, base_digest),
        ],
        reviewer_attestations=[
            ReviewerAttestation(
                reviewer_id="reviewer-1",
                candidate_digest=candidate_digest,
                base_digest=base_digest,
                evidence_digest=EVIDENCE,
                issuer_id="review-controller",
                approved=True,
                valid_from_epoch=7,
                valid_until_epoch=7,
            )
        ],
        rollback_attestation=RollbackAttestation(
            rollback_count=0,
            candidate_digest=candidate_digest,
            base_digest=base_digest,
            evidence_digest=EVIDENCE,
            issuer_id="rollback-controller",
            available=True,
            valid_from_epoch=7,
            valid_until_epoch=7,
        ),
        source_provenance_digest=PROVENANCE,
        evidence_digests=[EVIDENCE, PROVENANCE],
    )
    store = FilesystemArtifactStore(tmp_path / "artifacts")
    controller = PromotionController(
        reader,
        lambda digest, candidate_value, base_value: (
            digest == PROVENANCE
            and candidate_value == candidate_digest
            and base_value == base_digest
        ),
        lambda digest, _issuer, candidate_value, base_value: (
            digest == EVIDENCE and candidate_value == candidate_digest and base_value == base_digest
        ),
        store,
        trusted_config=config,
        trusted_repository_root=repository,
        trusted_artifact_root=store.root,
    )
    head_before = _git(repository, "rev-parse", "HEAD")
    status_before = _git(repository, "status", "--porcelain=v1", "--untracked-files=all")

    result = controller.dry_run(request, candidate_root=candidate, config=config)
    replay = controller.replay(
        store.read_bytes(result.artifact), bundle_digest=result.bundle_digest
    )

    assert result.bundle.comparison.changed_paths == ["docs/guide.md"]
    assert result.bundle.decision.outcome == "allow"
    assert store.read_bytes(result.artifact) == bundle_bytes(result.bundle)
    assert replay.outcome == "would_apply"
    assert _git(repository, "rev-parse", "HEAD") == head_before
    assert _git(repository, "status", "--porcelain=v1", "--untracked-files=all") == status_before
