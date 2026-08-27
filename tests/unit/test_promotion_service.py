import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from avo_correlate.adapters.artifacts import FilesystemArtifactStore
from avo_correlate.application.promotion_service import (
    PromotionController,
    PromotionEvidenceError,
    PromotionProvenanceError,
    PromotionStaleBaseError,
    _policy_payload,  # pyright: ignore[reportPrivateUsage]
    bundle_bytes,
)
from avo_correlate.contracts.promotion_bundle import (
    GitRefSnapshot,
    PromotionBundle,
    PromotionControllerConfig,
    PromotionDryRunInput,
    PromotionDryRunResult,
    WorkspaceComparison,
)
from avo_correlate.contracts.promotion_policy import (
    GateAttestation,
    PromotionConfig,
    ReviewerAttestation,
    RollbackAttestation,
)
from avo_correlate.domain.canonical import canonical_digest

CANDIDATE = "sha256:" + "a" * 64
BASE = "sha256:" + "b" * 64
EVIDENCE = "sha256:" + "c" * 64


class FakeRepository:
    def __init__(self, *, stale_after_first_snapshot: bool = False) -> None:
        self.snapshot_count = 0
        self.stale_after_first_snapshot = stale_after_first_snapshot
        self.state = GitRefSnapshot(
            repository_digest=EVIDENCE,
            target_ref="refs/heads/main",
            commit="d" * 40,
            tree="e" * 40,
            source_tree_digest=BASE,
            protection_evidence_digest=EVIDENCE,
        )

    def snapshot(self) -> GitRefSnapshot:
        self.snapshot_count += 1
        if self.stale_after_first_snapshot and self.snapshot_count > 1:
            return self.state.model_copy(update={"commit": "f" * 40})
        return self.state

    def compare_candidate(self, root: Path, snapshot: GitRefSnapshot) -> WorkspaceComparison:
        del root
        return WorkspaceComparison(
            target_ref=snapshot.target_ref,
            base_digest=BASE,
            candidate_digest=CANDIDATE,
            changed_paths=["docs/guide.md"],
        )


def _gate(name: str) -> GateAttestation:
    return GateAttestation(
        gate_name=name,
        candidate_digest=CANDIDATE,
        base_digest=BASE,
        evidence_digest=EVIDENCE,
        issuer_id="ci",
        passed=True,
        valid_from_epoch=2,
        valid_until_epoch=2,
    )


def _config() -> PromotionControllerConfig:
    policy = PromotionConfig(
        evaluation_epoch=2,
        trusted_gate_issuers={"deterministic": ["ci"], "provenance": ["ci"]},
        trusted_base_issuers=["base"],
        trusted_reviewer_issuers=["reviewer"],
        trusted_path_issuers=["diff"],
        rollback_issuer_ids=["rollback"],
        rollback_limit=1,
        reviewer_domains={"reviewer-1": "domain-1"},
        proposer_domains={"agent": "agent-domain"},
        candidate_proposers={CANDIDATE: "agent"},
    )
    return PromotionControllerConfig(
        controller_identity="promotion-controller",
        controller_version="1",
        base_issuer_id="base",
        path_issuer_id="diff",
        policy=policy,
    )


def _input(*, production: bool = False) -> PromotionDryRunInput:
    reviewer = ReviewerAttestation(
        reviewer_id="reviewer-1",
        candidate_digest=CANDIDATE,
        base_digest=BASE,
        evidence_digest=EVIDENCE,
        issuer_id="reviewer",
        approved=True,
        valid_from_epoch=2,
        valid_until_epoch=2,
    )
    rollback = RollbackAttestation(
        rollback_count=0,
        candidate_digest=CANDIDATE,
        base_digest=BASE,
        evidence_digest=EVIDENCE,
        issuer_id="rollback",
        available=True,
        valid_from_epoch=2,
        valid_until_epoch=2,
    )
    return PromotionDryRunInput(
        candidate_id="candidate-1",
        proposer_id="agent",
        candidate_digest=CANDIDATE,
        gate_attestations=[] if production else [_gate("provenance"), _gate("deterministic")],
        reviewer_attestations=[reviewer],
        rollback_attestation=rollback,
        source_provenance_digest=EVIDENCE,
        evidence_digests=[EVIDENCE],
    )


def _controller(
    tmp_path: Path,
    repository: FakeRepository | None = None,
    provenance_ok: bool = True,
    evidence_ok: bool = True,
) -> PromotionController:
    (tmp_path / "candidate").mkdir(exist_ok=True)
    artifact_root = tmp_path / "artifacts"
    return PromotionController(
        repository or FakeRepository(),
        lambda digest, candidate, base: (
            provenance_ok and digest == EVIDENCE and candidate == CANDIDATE and base == BASE
        ),
        lambda digest, _issuer, candidate, base: (
            evidence_ok and digest == EVIDENCE and candidate == CANDIDATE and base == BASE
        ),
        FilesystemArtifactStore(artifact_root),
        trusted_config=_config(),
        trusted_repository_root=tmp_path.parent / "trusted-repository",
        trusted_artifact_root=artifact_root,
    )


def test_repeated_dry_run_is_byte_deterministic(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    first = controller.dry_run(_input(), candidate_root=tmp_path / "candidate", config=_config())
    permuted = _input().model_copy(
        update={"gate_attestations": list(reversed(_input().gate_attestations))}
    )
    second = controller.dry_run(permuted, candidate_root=tmp_path / "candidate", config=_config())
    assert first.bundle_digest == second.bundle_digest
    assert bundle_bytes(first.bundle) == bundle_bytes(second.bundle)
    base_evidence = first.bundle.request.base_attestation.evidence_digest
    assert base_evidence != EVIDENCE
    assert base_evidence in first.bundle.evidence_digests


def test_policy_denial_still_produces_a_bundle(tmp_path: Path) -> None:
    repository = FakeRepository()
    repository.compare_candidate = lambda root, snapshot: WorkspaceComparison(
        target_ref=snapshot.target_ref,
        base_digest=BASE,
        candidate_digest=CANDIDATE,
        changed_paths=["production/app.yml"],
    )
    result = _controller(tmp_path, repository).dry_run(
        _input(production=True), candidate_root=tmp_path / "candidate", config=_config()
    )
    assert result.bundle.decision.outcome == "deny"
    assert result.artifact.digest == result.bundle_digest
    assert (
        _controller(tmp_path, repository)
        .replay(result.bundle, bundle_digest=result.bundle_digest)
        .outcome
        == "not_applicable"
    )


def test_caller_cannot_downgrade_pinned_policy(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    trusted = _config()
    weak_policy = trusted.policy.model_copy(update={"low_gates": frozenset({"deterministic"})})
    weak = trusted.model_copy(update={"policy": weak_policy})
    with pytest.raises(ValueError, match="different from the trusted one"):
        controller.dry_run(_input(), candidate_root=tmp_path / "candidate", config=weak)


def test_artifact_store_must_not_overlap_repository(tmp_path: Path) -> None:
    repository_root = tmp_path / "repository"
    artifact_root = repository_root / "artifacts"
    with pytest.raises(ValueError, match="overlap"):
        PromotionController(
            FakeRepository(),
            lambda _digest, _candidate, _base: True,
            lambda _digest, _issuer, _candidate, _base: True,
            FilesystemArtifactStore(artifact_root),
            trusted_config=_config(),
            trusted_repository_root=repository_root,
            trusted_artifact_root=artifact_root,
        )


def test_candidate_must_not_overlap_artifact_store(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    (tmp_path / "artifacts").mkdir(exist_ok=True)
    with pytest.raises(ValueError, match="artifact store"):
        controller.dry_run(_input(), candidate_root=tmp_path / "artifacts", config=_config())


def test_unexpected_gate_evidence_is_rejected_before_artifact_write(tmp_path: Path) -> None:
    invalid = _input().model_copy(
        update={"gate_attestations": [*_input().gate_attestations, _gate("trusted_ci")]}
    )
    with pytest.raises(ValueError, match="unexpected gate"):
        _controller(tmp_path).dry_run(
            invalid, candidate_root=tmp_path / "candidate", config=_config()
        )
    assert not [path for path in (tmp_path / "artifacts" / "objects").rglob("*") if path.is_file()]


def test_provenance_failure_writes_no_bundle(tmp_path: Path) -> None:
    controller = _controller(tmp_path, provenance_ok=False)
    with pytest.raises(PromotionProvenanceError):
        controller.dry_run(_input(), candidate_root=tmp_path / "candidate", config=_config())
    assert not [path for path in (tmp_path / "artifacts" / "objects").rglob("*") if path.is_file()]


def test_unresolved_attestation_evidence_writes_no_bundle(tmp_path: Path) -> None:
    controller = _controller(tmp_path, evidence_ok=False)
    with pytest.raises(PromotionEvidenceError):
        controller.dry_run(_input(), candidate_root=tmp_path / "candidate", config=_config())
    assert not [path for path in (tmp_path / "artifacts" / "objects").rglob("*") if path.is_file()]


def test_stale_before_write_writes_no_bundle(tmp_path: Path) -> None:
    repository = FakeRepository(stale_after_first_snapshot=True)
    controller = _controller(tmp_path, repository)
    with pytest.raises(PromotionStaleBaseError):
        controller.dry_run(_input(), candidate_root=tmp_path / "candidate", config=_config())
    repository.compare_candidate = lambda root, snapshot: WorkspaceComparison(
        target_ref=snapshot.target_ref,
        base_digest=BASE,
        candidate_digest=BASE,
        changed_paths=["docs/guide.md"],
    )
    with pytest.raises(ValueError, match="candidate digest"):
        controller.dry_run(_input(), candidate_root=tmp_path / "candidate", config=_config())
    assert not [path for path in (tmp_path / "artifacts" / "objects").rglob("*") if path.is_file()]


def test_replay_rejects_tampering_noncanonical_and_duplicate_json(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    result = controller.dry_run(_input(), candidate_root=tmp_path / "candidate", config=_config())
    payload = bundle_bytes(result.bundle)
    tampered = result.bundle.model_copy(update={"decision_digest": EVIDENCE})
    invalid = controller.replay(tampered, bundle_digest=result.bundle_digest)
    assert invalid.outcome == "invalid_bundle"
    assert controller.replay(payload + b"\n", bundle_digest=result.bundle_digest).outcome == (
        "invalid_bundle"
    )
    duplicate = b'{"format":"avo-promotion-bundle-v1","format":"avo-promotion-bundle-v1"}'
    assert controller.replay(duplicate, bundle_digest=result.bundle_digest).outcome == (
        "invalid_bundle"
    )


def test_replay_reports_stale_base(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    result = controller.dry_run(_input(), candidate_root=tmp_path / "candidate", config=_config())
    stale_repository = FakeRepository()
    stale_repository.state = stale_repository.state.model_copy(update={"commit": "f" * 40})
    stale = _controller(tmp_path, stale_repository)
    assert stale.replay(result.bundle, bundle_digest=result.bundle_digest).outcome == ("stale_base")


def _replay_updated(
    controller: PromotionController, result: PromotionDryRunResult, **updates: object
):
    bundle = result.bundle.model_copy(update=updates)
    digest = canonical_digest(json.loads(bundle_bytes(bundle)))
    return controller.replay(bundle, bundle_digest=digest)


def test_dry_run_rejects_base_and_candidate_binding_mismatches(tmp_path: Path) -> None:
    repository = FakeRepository()
    repository.compare_candidate = lambda root, snapshot: WorkspaceComparison(
        target_ref=snapshot.target_ref,
        base_digest=CANDIDATE,
        candidate_digest=BASE,
        changed_paths=["docs/guide.md"],
    )
    controller = _controller(tmp_path, repository)
    with pytest.raises(PromotionStaleBaseError):
        controller.dry_run(_input(), candidate_root=tmp_path / "candidate", config=_config())

    repository.compare_candidate = lambda root, snapshot: WorkspaceComparison(
        target_ref=snapshot.target_ref,
        base_digest=BASE,
        candidate_digest=BASE,
        changed_paths=["docs/guide.md"],
    )
    with pytest.raises(ValueError, match="candidate digest"):
        controller.dry_run(_input(), candidate_root=tmp_path / "candidate", config=_config())


def test_dry_run_rejects_unbound_input_evidence_and_repository_overlap(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    extra = "sha256:" + "d" * 64
    invalid = _input().model_copy(update={"evidence_digests": [EVIDENCE, extra]})
    with pytest.raises(PromotionEvidenceError, match="incomplete"):
        controller.dry_run(invalid, candidate_root=tmp_path / "candidate", config=_config())
    repository_root = tmp_path.parent / "trusted-repository"
    repository_root.mkdir(exist_ok=True)
    with pytest.raises(ValueError, match="trusted repository"):
        controller.dry_run(invalid, candidate_root=repository_root, config=_config())


def test_dry_run_allows_missing_rollback_when_other_evidence_is_complete(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    request = _input().model_copy(update={"rollback_attestation": None})
    result = controller.dry_run(request, candidate_root=tmp_path / "candidate")
    assert result.bundle.decision.outcome == "quarantine"
    assert controller.replay(result.bundle, bundle_digest=result.bundle_digest).outcome == (
        "not_applicable"
    )


def test_constructor_rejects_untrusted_artifact_root(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="does not match"):
        PromotionController(
            FakeRepository(),
            lambda _digest, _candidate, _base: True,
            lambda _digest, _issuer, _candidate, _base: True,
            FilesystemArtifactStore(tmp_path / "artifacts"),
            trusted_config=_config(),
            trusted_repository_root=tmp_path / "repo",
            trusted_artifact_root=tmp_path / "other-artifacts",
        )


@pytest.mark.parametrize(
    "field",
    ["request_digest", "decision_digest", "controller_config_digest"],
)
def test_replay_rejects_digest_binding_tampering(tmp_path: Path, field: str) -> None:
    controller = _controller(tmp_path)
    result = controller.dry_run(_input(), candidate_root=tmp_path / "candidate", config=_config())
    report = _replay_updated(controller, result, **{field: EVIDENCE})
    assert report.outcome == "invalid_bundle"
    assert report.errors


def test_replay_rejects_structural_binding_tampering(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    result = controller.dry_run(_input(), candidate_root=tmp_path / "candidate", config=_config())
    request = result.bundle.request.model_copy(update={"candidate_digest": BASE})
    assert _replay_updated(controller, result, request=request).outcome == "invalid_bundle"
    comparison = result.bundle.comparison.model_copy(update={"base_digest": CANDIDATE})
    assert _replay_updated(controller, result, comparison=comparison).outcome == "invalid_bundle"
    snapshot = result.bundle.snapshot.model_copy(update={"source_tree_digest": CANDIDATE})
    assert _replay_updated(controller, result, snapshot=snapshot).outcome == "invalid_bundle"


def test_replay_rejects_attestation_and_evidence_bindings(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    result = controller.dry_run(_input(), candidate_root=tmp_path / "candidate", config=_config())
    base = result.bundle.request.base_attestation.model_copy(update={"passed": False})
    request = result.bundle.request.model_copy(update={"base_attestation": base})
    assert _replay_updated(controller, result, request=request).outcome == "invalid_bundle"
    path = result.bundle.request.path_manifest_attestation.model_copy(
        update={"evidence_digest": EVIDENCE}
    )
    request = result.bundle.request.model_copy(update={"path_manifest_attestation": path})
    assert _replay_updated(controller, result, request=request).outcome == "invalid_bundle"
    provenance = result.bundle.provenance.model_copy(update={"verified": False})
    assert _replay_updated(controller, result, provenance=provenance).outcome == "invalid_bundle"
    evidence = [result.bundle.provenance.source_provenance_digest]
    assert _replay_updated(controller, result, evidence_digests=evidence).outcome == (
        "invalid_bundle"
    )

    extra = "sha256:" + "d" * 64
    extra_evidence = sorted([*result.bundle.evidence_digests, extra])
    extra_provenance = result.bundle.provenance.model_copy(
        update={"evidence_manifest_digest": canonical_digest(extra_evidence)}
    )
    assert (
        _replay_updated(
            controller,
            result,
            evidence_digests=extra_evidence,
            provenance=extra_provenance,
        ).outcome
        == "invalid_bundle"
    )


def test_replay_rejects_unbound_extra_evidence(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    result = controller.dry_run(_input(), candidate_root=tmp_path / "candidate", config=_config())
    extra = "sha256:" + "d" * 64
    evidence = sorted([*result.bundle.evidence_digests, extra])
    provenance = result.bundle.provenance.model_copy(
        update={"evidence_manifest_digest": canonical_digest(evidence)}
    )
    report = _replay_updated(controller, result, evidence_digests=evidence, provenance=provenance)
    assert report.outcome == "invalid_bundle"
    assert "evidence manifest" in report.errors[0]


def test_replay_rejects_policy_config_outside_pinned_controller(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    result = controller.dry_run(_input(), candidate_root=tmp_path / "candidate", config=_config())
    weak_policy = _config().policy.model_copy(update={"low_gates": frozenset({"deterministic"})})
    weak = _config().model_copy(update={"policy": weak_policy})
    config_digest = canonical_digest(_policy_payload(weak))
    report = _replay_updated(
        controller,
        result,
        controller_config=weak,
        controller_config_digest=config_digest,
    )
    assert report.outcome == "invalid_bundle"


def test_replay_handles_non_boolean_verifier_reports(tmp_path: Path) -> None:
    class Report:
        verified = True

    controller = PromotionController(
        FakeRepository(),
        lambda _digest, _candidate, _base: Report(),
        lambda _digest, _issuer, _candidate, _base: Report(),
        FilesystemArtifactStore(tmp_path / "artifacts"),
        trusted_config=_config(),
        trusted_repository_root=tmp_path.parent / "trusted-repository",
        trusted_artifact_root=tmp_path / "artifacts",
    )
    (tmp_path / "candidate").mkdir()
    result = controller.dry_run(_input(), candidate_root=tmp_path / "candidate", config=_config())
    assert controller.replay(result.bundle, bundle_digest=result.bundle_digest).outcome == (
        "would_apply"
    )


def test_replay_rejects_canonical_but_invalid_json() -> None:
    controller = object.__new__(PromotionController)
    report = controller.replay(b"{}", bundle_digest=EVIDENCE)
    assert report.outcome == "invalid_bundle"


def test_replay_rejects_base_and_path_attestation_tampering(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    result = controller.dry_run(_input(), candidate_root=tmp_path / "candidate", config=_config())

    base = result.bundle.request.base_attestation.model_copy(update={"evidence_digest": EVIDENCE})
    request = result.bundle.request.model_copy(update={"base_attestation": base})
    request_digest = canonical_digest(request)
    provenance = result.bundle.provenance.model_copy(update={"request_digest": request_digest})
    assert (
        _replay_updated(
            controller,
            result,
            request=request,
            request_digest=request_digest,
            provenance=provenance,
        ).outcome
        == "invalid_bundle"
    )

    path = result.bundle.request.path_manifest_attestation.model_copy(
        update={"path_manifest_digest": EVIDENCE}
    )
    request = result.bundle.request.model_copy(update={"path_manifest_attestation": path})
    request_digest = canonical_digest(request)
    provenance = result.bundle.provenance.model_copy(
        update={
            "request_digest": request_digest,
            "path_manifest_digest": EVIDENCE,
        }
    )
    assert (
        _replay_updated(
            controller,
            result,
            request=request,
            request_digest=request_digest,
            provenance=provenance,
        ).outcome
        == "invalid_bundle"
    )


def test_replay_rejects_missing_provenance_and_manifest_mismatch(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    result = controller.dry_run(_input(), candidate_root=tmp_path / "candidate", config=_config())
    evidence = [item for item in result.bundle.evidence_digests if item != EVIDENCE]
    provenance = result.bundle.provenance.model_copy(
        update={"evidence_manifest_digest": canonical_digest(evidence)}
    )
    assert (
        _replay_updated(
            controller, result, evidence_digests=evidence, provenance=provenance
        ).outcome
        == "invalid_bundle"
    )
    provenance = result.bundle.provenance.model_copy(update={"evidence_manifest_digest": EVIDENCE})
    assert _replay_updated(controller, result, provenance=provenance).outcome == "invalid_bundle"


def test_replay_rejects_provenance_and_attestation_verifier_failures(tmp_path: Path) -> None:
    producer = _controller(tmp_path)
    result = producer.dry_run(_input(), candidate_root=tmp_path / "candidate", config=_config())
    provenance_failed = _controller(tmp_path, provenance_ok=False)
    assert (
        provenance_failed.replay(result.bundle, bundle_digest=result.bundle_digest).outcome
        == "invalid_bundle"
    )
    evidence_failed = _controller(tmp_path, evidence_ok=False)
    assert (
        evidence_failed.replay(result.bundle, bundle_digest=result.bundle_digest).outcome
        == "invalid_bundle"
    )


def test_replay_rejects_classification_mismatch(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    result = controller.dry_run(_input(), candidate_root=tmp_path / "candidate", config=_config())
    decision = result.bundle.decision.model_copy(update={"reason_codes": ["tampered"]})
    decision_digest = canonical_digest(decision)
    provenance = result.bundle.provenance.model_copy(update={"decision_digest": decision_digest})
    report = _replay_updated(
        controller,
        result,
        decision=decision,
        decision_digest=decision_digest,
        provenance=provenance,
    )
    assert report.outcome == "invalid_bundle"


@pytest.mark.parametrize("path", ["../escape", "a//b", "a\\b", "bad?.txt", "con.txt"])
def test_workspace_comparison_rejects_unsafe_paths(path: str) -> None:
    with pytest.raises(ValidationError):
        WorkspaceComparison(
            target_ref="refs/heads/main",
            base_digest=BASE,
            candidate_digest=CANDIDATE,
            changed_paths=[path],
        )


def test_workspace_comparison_requires_sorted_collision_free_paths() -> None:
    for paths in (["z.txt", "a.txt"], ["a.txt", "A.txt"]):
        with pytest.raises(ValidationError):
            WorkspaceComparison(
                target_ref="refs/heads/main",
                base_digest=BASE,
                candidate_digest=CANDIDATE,
                changed_paths=paths,
            )


def test_bundle_contract_rejects_invalid_git_ids_and_controller_issuers() -> None:
    with pytest.raises(ValidationError):
        GitRefSnapshot(
            repository_digest=EVIDENCE,
            target_ref="refs/heads/main",
            commit="A" * 40,
            tree="e" * 40,
            source_tree_digest=BASE,
            protection_evidence_digest=EVIDENCE,
        )
    with pytest.raises(ValidationError):
        PromotionControllerConfig(
            controller_identity="controller",
            controller_version="1",
            base_issuer_id="untrusted",
            path_issuer_id="diff",
            policy=_config().policy,
        )


def test_dry_run_input_requires_sorted_unique_evidence() -> None:
    with pytest.raises(ValidationError):
        PromotionDryRunInput(
            candidate_id="candidate",
            proposer_id="agent",
            candidate_digest=CANDIDATE,
            source_provenance_digest=EVIDENCE,
            evidence_digests=[EVIDENCE, EVIDENCE],
        )


def test_bundle_contract_rejects_link_mismatch(tmp_path: Path) -> None:
    controller = _controller(tmp_path)
    result = controller.dry_run(_input(), candidate_root=tmp_path / "candidate", config=_config())
    data = result.bundle.model_dump(mode="json")
    data["comparison"]["target_ref"] = "refs/heads/other"
    with pytest.raises(ValidationError, match="refs"):
        PromotionBundle.model_validate(data)
