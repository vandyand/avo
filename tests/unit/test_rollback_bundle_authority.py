from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from avo_correlate.adapters.artifacts import FilesystemArtifactStore
from avo_correlate.adapters.artifacts.rollback_bundle_authority import (
    RollbackBundleAuthorityJournal,
)
from avo_correlate.adapters.git.publisher import PreparedPublication, PublicationPlan
from avo_correlate.application.rollback_bundle_authority import (
    _CANDIDATE_REF,  # pyright: ignore[reportPrivateUsage]
    RollbackBundleAuthority,
    prepared_publication_evidence_digest,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_campaign import (
    IntegrationCampaignEvidencePackage,
    campaign_marker_digest,
)
from avo_correlate.contracts.integration_drill import (
    IntegrationRollbackRequest,
)
from avo_correlate.contracts.integration_promotion import (
    CandidatePublicationBinding,
    integration_operation_id,
)
from avo_correlate.contracts.integration_soak import FailedSoakAttestation
from avo_correlate.contracts.prepublication import (
    RollbackPublicationAuthorityConfig,
    RollbackPublicationAuthorization,
    RollbackSnapshotRestoreFacts,
)
from avo_correlate.contracts.promotion_bundle import RollbackPromotionBundleAuthorization
from avo_correlate.contracts.promotion_policy import PathManifestAttestation
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

# This package is the repository's canonical campaign contract fixture.  It is
# deliberately completed below because the older campaign test fixture models
# some nested provider records with model_construct().
from tests.unit.test_integration_campaign_contracts import (
    _package,  # pyright: ignore[reportPrivateUsage]
)

D = "sha256:" + "a" * 64
G = "a" * 40
H = "b" * 40
J = "c" * 40
C = "d" * 40
K = "sha256:" + "b" * 64
NOW = datetime(2026, 1, 1, tzinfo=UTC)
REF = "refs/heads/avo/candidate/" + "e" * 64


def test_publisher_candidate_ref_namespace_requires_64_hex() -> None:
    assert _CANDIDATE_REF.fullmatch(REF)
    assert _CANDIDATE_REF.fullmatch("refs/heads/avo/candidate/" + "e" * 32) is None
    assert _CANDIDATE_REF.fullmatch("refs/heads/avo/candidate/" + "e" * 64 + "/child") is None


def _complete_package() -> tuple[IntegrationCampaignEvidencePackage, bytes, ArtifactRef]:
    """Return a package that survives canonical JSON model round-tripping."""

    package = _package()
    bundle = package.bundle
    path_attestation = PathManifestAttestation(
        candidate_digest=D,
        base_digest=D,
        evidence_digest=D,
        path_manifest_digest=bundle.request.path_manifest_attestation.path_manifest_digest,
        issuer_id="path",
        valid_from_epoch=1,
        valid_until_epoch=1,
    )
    request = bundle.request.model_copy(update={"path_manifest_attestation": path_attestation})
    evidence_bytes = canonical_bytes({"evidence": "rollback-authority-test"})
    evidence_digest = canonical_digest({"evidence": "rollback-authority-test"})
    evidence_ref = ArtifactRef(
        digest=evidence_digest,
        size_bytes=len(evidence_bytes),
        media_type="application/json",
        role="publication",
        created_at=NOW,
    )
    provenance = bundle.provenance.model_copy(update={"source_provenance_digest": evidence_digest})
    bundle = bundle.model_copy(
        update={
            "request": request,
            "evidence_digests": [evidence_digest],
            "provenance": provenance,
        }
    )
    bundle_digest = canonical_digest(
        __import__(
            "avo_correlate.contracts.promotion_bundle",
            fromlist=["promotion_bundle_payload"],
        ).promotion_bundle_payload(bundle)
    )

    old_intent = package.intent
    identity: dict[str, str] = {
        key: str(getattr(old_intent, key))
        for key in (
            "repository_digest",
            "candidate_ref",
            "target_ref",
            "base_commit",
            "candidate_commit",
            "candidate_digest",
            "provider_identity",
            "provider_api_version",
            "merge_method",
            "candidate_head_commit",
            "target_base_commit",
            "synthetic_merge_commit",
        )
    }
    operation_id = integration_operation_id(
        **identity,
        bundle_digest=bundle_digest,
        publication_evidence_digest=evidence_digest,
        pull_request_number=str(old_intent.pull_request_number),
    )
    lease = package.lease_evidence.model_copy(update={"operation_id": operation_id})
    lease = lease.model_copy(
        update={"digest": canonical_digest(lease.model_dump(exclude={"digest"}, mode="json"))}
    )
    intent = old_intent.model_copy(
        update={
            "operation_id": operation_id,
            "bundle_digest": bundle_digest,
            "publication_evidence_digest": evidence_digest,
            "controller_lease_digest": lease.digest,
        }
    )
    intent_digest = canonical_digest(intent)
    receipt = package.receipt.model_copy(
        update={
            "operation_id": operation_id,
            "intent_digest": intent_digest,
            "bundle_digest": bundle_digest,
        }
    )
    receipt_digest = canonical_digest(receipt)
    report = package.report.model_copy(
        update={
            "operation_id": operation_id,
            "intent_digest": intent_digest,
            "receipt_digest": receipt_digest,
        }
    )
    lease_ref = ArtifactRef(
        digest=canonical_digest(lease),
        size_bytes=len(canonical_bytes(lease)),
        media_type="application/vnd.avo.integration-promotion+json",
        role="promotion-lease-evidence",
        created_at=lease.acquired_at,
    )
    package = package.model_copy(
        update={
            "bundle": bundle,
            "bundle_digest": bundle_digest,
            "publication": package.publication.model_copy(
                update={"publication_evidence_digest": evidence_digest}
            ),
            "evidence_artifacts": [evidence_ref],
            "intent": intent,
            "receipt": receipt,
            "report": report,
            "intent_digest": intent_digest,
            "receipt_digest": receipt_digest,
            "campaign_marker_digest": campaign_marker_digest(intent),
            "lease_evidence": lease,
            "lease_evidence_artifact": lease_ref,
        }
    )
    # Catch fixture drift here, close to the source of any confusing test error.
    IntegrationCampaignEvidencePackage.model_validate_json(canonical_bytes(package))
    return package, evidence_bytes, evidence_ref


class Fixture:
    def __init__(self, root: Path) -> None:
        self.store = FilesystemArtifactStore(root / "authority")
        self.journal = RollbackBundleAuthorityJournal(self.store)
        self.package, self.evidence_bytes, self.evidence_ref = _complete_package()
        self.canary_bytes = canonical_bytes(self.package)
        self.canary_ref = self.store.put_bytes(
            self.canary_bytes,
            media_type="application/vnd.avo.integration-campaign+json",
            role="integration-campaign-package",
            max_bytes=2_000_000,
        )
        self.store.put_bytes(
            canonical_bytes(self.package.lease_evidence),
            media_type=self.package.lease_evidence_artifact.media_type,
            role=self.package.lease_evidence_artifact.role,
            max_bytes=2_000_000,
        )
        self.store.put_bytes(
            self.evidence_bytes,
            media_type=self.evidence_ref.media_type,
            role=self.evidence_ref.role,
            max_bytes=2_000_000,
        )
        self.config = self._config()
        self.operation = IntegrationRollbackRequest(
            operation_id=canonical_digest({"rollback": "operation"}),
            promotion_operation_id=canonical_digest({"promotion": "operation"}),
            repository_digest=D,
            target_ref="refs/heads/integration",
            main_before_commit=G,
            failed_integration_head_commit=J,
            failed_integration_head_tree=H,
            restore_to_commit=G,
            restore_to_tree=G,
            rollback_candidate_commit=C,
            rollback_candidate_parent_commit=J,
        )
        self.facts = RollbackSnapshotRestoreFacts(
            repository_digest=D,
            failed_head_commit=J,
            failed_head_tree=H,
            failed_head_parents=[G],
            restore_commit=G,
            restore_tree=G,
        )
        self.soak = self._soak()
        plan = PublicationPlan(
            publication_id="",
            repository_digest=D,
            expected_remote="https://github.com/example/repo.git",
            base_commit=J,
            base_tree=H,
            candidate_digest=K,
            candidate_ref=REF,
            candidate_commit=C,
            candidate_tree=G,
            controller_publisher_identity="publisher",
            changed_paths=("src/x.py",),
        )
        plan = replace(plan, publication_id=canonical_digest(plan.identity_payload()))
        plan_bytes = canonical_bytes(plan.payload())
        self.plan_ref = self.store.put_bytes(
            plan_bytes,
            media_type="application/vnd.avo.candidate-publication+json",
            role="candidate-publication-plan",
            max_bytes=2_000_000,
        )
        self.prepared = PreparedPublication(plan, root / "candidate", self.plan_ref)
        self.authority = RollbackBundleAuthority(
            self.config,
            self.journal,
            recovery_absence_verifier=lambda _ref, _commit, _base: None,
        )

    @staticmethod
    def _config() -> RollbackPublicationAuthorityConfig:
        values: dict[str, object] = {
            "schema_version": 1,
            "repository_digest": D,
            "target_ref": "refs/heads/integration",
            "soak_issuer_id": "github-app:15368/integration-soak",
            "soak_app_id": 15368,
            "soak_context": "avo integration soak",
            "soak_workflow_path": ".github/workflows/integration-soak.yml",
            "base_issuer_id": "base-observer",
            "path_issuer_id": "path-observer",
            "controller_identity": "controller",
            "publisher_identity": "publisher",
        }
        return RollbackPublicationAuthorityConfig.model_validate(
            {**values, "trusted_config_digest": canonical_digest(values)}
        )

    def _soak(self) -> FailedSoakAttestation:
        values: dict[str, object] = {
            "schema_version": 1,
            "repository_digest": D,
            "integration_ref": "refs/heads/integration",
            "integration_commit": J,
            "integration_tree": H,
            "integration_parent_commit": G,
            "restore_commit": G,
            "restore_tree": G,
            "main_ref": "refs/heads/main",
            "main_commit": G,
            "check_run_id": 1,
            "workflow_id": 2,
            "workflow_run_id": 3,
            "context": "avo integration soak",
            "app_id": 15368,
            "status": "completed",
            "conclusion": "failure",
            "completed_at": NOW,
            "freshness_cutoff": datetime(2025, 12, 31, tzinfo=UTC),
            "workflow_path": ".github/workflows/integration-soak.yml",
            "workflow_blob_digest": D,
            "repository_variables_digest": D,
        }
        digest_values = self._soak_digest_values(values)
        return FailedSoakAttestation.model_validate(
            {**values, "attestation_id": canonical_digest(digest_values)}
        )

    @staticmethod
    def _soak_digest_values(values: dict[str, object]) -> dict[str, object]:
        # Attestation identity is defined over JSON-mode timestamps.
        constructed: Any = FailedSoakAttestation.model_construct(  # type: ignore[reportArgumentType]
            **values  # pyright: ignore[reportArgumentType]
        )
        return constructed.model_dump(exclude={"attestation_id"}, mode="json")

    def authorize(
        self, *, authority: RollbackBundleAuthority | None = None, **updates: Any
    ) -> RollbackPublicationAuthorization:
        values: dict[str, Any] = {
            "operation": self.operation,
            "canary_package_artifact": self.canary_ref,
            "canary_package": self.package,
            "failed_soak": self.soak,
            "facts": self.facts,
            "prepared": self.prepared,
        }
        values.update(updates)
        return (authority or self.authority).authorize(**values)


def _publication(
    fixture: Fixture, authorization: RollbackPublicationAuthorization
) -> CandidatePublicationBinding:
    plan = fixture.prepared.plan
    return CandidatePublicationBinding(
        repository_digest=authorization.repository_digest,
        base_commit=plan.base_commit,
        base_tree=plan.base_tree,
        candidate_digest=plan.candidate_digest,
        candidate_ref=plan.candidate_ref,
        candidate_commit=plan.candidate_commit,
        candidate_tree=plan.candidate_tree,
        controller_publisher_identity=plan.controller_publisher_identity,
        publication_evidence_digest=authorization.publication_evidence_digest,
        verified=True,
        changed_paths=list(plan.changed_paths),
    )


def _evidence(fixture: Fixture, authorization: RollbackPublicationAuthorization) -> bytes:
    plan = fixture.prepared.plan
    return canonical_bytes(
        {
            "schema_version": 1,
            "publication_id": plan.publication_id,
            "repository_digest": authorization.repository_digest,
            "base_commit": plan.base_commit,
            "base_tree": plan.base_tree,
            "candidate_digest": plan.candidate_digest,
            "candidate_ref": plan.candidate_ref,
            "candidate_commit": plan.candidate_commit,
            "candidate_tree": plan.candidate_tree,
            "controller_publisher_identity": plan.controller_publisher_identity,
            "changed_paths": list(plan.changed_paths),
            "verified": True,
        }
    )


def test_prepared_publication_digest_is_deterministic(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    assert (
        prepared_publication_evidence_digest(fixture.prepared) == fixture.prepared.evidence_digest
    )


def test_authorize_success_replay_and_restart(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    first = fixture.authorize()
    assert first.authorized is True
    assert first.candidate_ref == REF
    assert fixture.authorize() == first
    restarted = RollbackBundleAuthority(
        fixture.config,
        RollbackBundleAuthorityJournal(FilesystemArtifactStore(tmp_path / "authority")),
    )
    assert fixture.authorize(authority=restarted) == first
    fixture.journal.require(first)


def test_authorize_materializes_plan_from_publisher_store(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    publisher_store = FilesystemArtifactStore(tmp_path / "publisher")
    plan_bytes = canonical_bytes(fixture.prepared.plan.payload())
    publisher_ref = publisher_store.put_bytes(
        plan_bytes,
        media_type="application/vnd.avo.candidate-publication+json",
        role="candidate-publication-plan",
        max_bytes=2_000_000,
    )
    prepared = PreparedPublication(
        fixture.prepared.plan, fixture.prepared.candidate_root, publisher_ref
    )
    authorization = fixture.authorize(prepared=prepared)
    fixture.journal.require(authorization)
    assert fixture.journal._store.read_bytes(publisher_ref) == plan_bytes  # pyright: ignore[reportPrivateUsage]


def test_authorize_reuses_durable_soak_when_freshness_cutoff_changes(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    authorization = fixture.authorize()
    values = fixture.soak.model_dump(mode="json")
    values["freshness_cutoff"] = "2025-12-30T00:00:00Z"
    constructed = FailedSoakAttestation.model_construct(**values)
    values["attestation_id"] = canonical_digest(
        constructed.model_dump(exclude={"attestation_id"}, mode="json")
    )
    refreshed = FailedSoakAttestation.model_validate(values)
    absence_calls: list[tuple[str, str, str]] = []

    def absence_must_not_be_checked(ref: str, commit: str, base: str) -> None:
        absence_calls.append((ref, commit, base))
        raise AssertionError("crash-after-push recovery must not check remote absence")

    restarted = RollbackBundleAuthority(
        fixture.config,
        RollbackBundleAuthorityJournal(FilesystemArtifactStore(tmp_path / "authority")),
        recovery_absence_verifier=absence_must_not_be_checked,
    )
    assert (
        restarted.authorize(
            operation=fixture.operation,
            canary_package_artifact=fixture.canary_ref,
            canary_package=fixture.package,
            failed_soak=refreshed,
            facts=fixture.facts,
            prepared=fixture.prepared,
        )
        == authorization
    )
    assert absence_calls == []
    assert (
        restarted.drill_authorization(authorization, refreshed).failed_soak_attestation_id
        == authorization.failed_soak_attestation_id
    )


def test_authorize_fails_closed_for_stable_soak_mismatch_after_push(
    tmp_path: Path,
) -> None:
    fixture = Fixture(tmp_path)
    authorization = fixture.authorize()
    values = fixture.soak.model_dump(mode="json")
    values["workflow_run_id"] = 4
    constructed = FailedSoakAttestation.model_construct(**values)
    values["attestation_id"] = canonical_digest(
        constructed.model_dump(exclude={"attestation_id"}, mode="json")
    )
    mismatched = FailedSoakAttestation.model_validate(values)
    absence_calls: list[tuple[str, str, str]] = []

    def existing_candidate_ref(ref: str, commit: str, base: str) -> None:
        absence_calls.append((ref, commit, base))
        raise ValueError("candidate ref already exists")

    restarted = RollbackBundleAuthority(
        fixture.config,
        RollbackBundleAuthorityJournal(FilesystemArtifactStore(tmp_path / "authority")),
        recovery_absence_verifier=existing_candidate_ref,
    )
    with pytest.raises(ValueError, match="fresh failed soak differs from durable authority"):
        restarted.authorize(
            operation=fixture.operation,
            canary_package_artifact=fixture.canary_ref,
            canary_package=fixture.package,
            failed_soak=mismatched,
            facts=fixture.facts,
            prepared=fixture.prepared,
        )
    assert absence_calls == []
    assert fixture.journal.read_authorization(authorization.operation_id) == authorization


def test_legacy_authorization_requires_exact_attestation_for_recovery_bridge(
    tmp_path: Path,
) -> None:
    fixture = Fixture(tmp_path)
    authorization = fixture.authorize()
    index = fixture.journal._root / authorization.operation_id.removeprefix("sha256:")  # pyright: ignore[reportPrivateUsage]
    value = json.loads(index.read_bytes())
    value.pop("failed_soak_artifact")
    index.write_bytes(canonical_bytes(value))

    values = fixture.soak.model_dump(mode="json")
    values["freshness_cutoff"] = "2025-12-30T00:00:00Z"
    constructed = FailedSoakAttestation.model_construct(**values)
    values["attestation_id"] = canonical_digest(
        constructed.model_dump(exclude={"attestation_id"}, mode="json")
    )
    refreshed = FailedSoakAttestation.model_validate(values)
    with pytest.raises(ValueError, match="stored authority"):
        fixture.authorize(failed_soak=refreshed)

    recovered = fixture.authorize(
        failed_soak=refreshed,
        recovery_failed_soak=fixture.soak,
    )
    assert recovered == authorization
    fixture.journal.require(recovered)


def test_journal_rejects_create_once_conflict_and_path_traversal(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    authorization = fixture.authorize()
    changed = authorization.model_copy(
        update={
            "reason": "different reason",
            "authorization_id": canonical_digest(
                {
                    **authorization.model_dump(exclude={"authorization_id"}, mode="json"),
                    "reason": "different reason",
                }
            ),
        }
    )
    with pytest.raises(ValueError, match="conflicting"):
        fixture.journal.record(
            changed,
            canary_package_artifact=fixture.canary_ref,
            publication_plan_artifact=fixture.plan_ref,
        )
    malicious = RollbackPublicationAuthorization.model_construct(operation_id="../../escape")
    with pytest.raises(ValueError, match="not durably recorded"):
        fixture.journal.require(malicious)


@pytest.mark.parametrize("tamper", ["json", "noncanonical", "missing-key", "duplicate-key"])
def test_journal_rejects_malformed_index(tmp_path: Path, tamper: str) -> None:
    fixture = Fixture(tmp_path)
    authorization = fixture.authorize()
    index = fixture.journal._root / authorization.operation_id.removeprefix("sha256:")  # pyright: ignore[reportPrivateUsage]
    if tamper == "json":
        index.write_bytes(b"not json")
    elif tamper == "noncanonical":
        index.write_bytes(b'{"z":1,"a":2}')
    elif tamper == "missing-key":
        value = json.loads(index.read_bytes())
        del value["artifact"]
        index.write_bytes(canonical_bytes(value))
    else:
        index.write_bytes(b'{"authorization":{},"authorization":{}}')
    with pytest.raises(ValueError, match="not durably recorded"):
        fixture.journal.require(authorization)


def test_journal_rejects_missing_and_tampered_authority_artifact(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    authorization = fixture.authorize()
    index = json.loads(
        (fixture.journal._root / authorization.operation_id.removeprefix("sha256:")).read_bytes()  # pyright: ignore[reportPrivateUsage]
    )
    fixture.store.delete(ArtifactRef.model_validate(index["artifact"]).digest)
    with pytest.raises(ValueError, match="not durably recorded"):
        fixture.journal.require(authorization)

    fixture = Fixture(tmp_path / "second")
    authorization = fixture.authorize()
    authority_ref = ArtifactRef.model_validate(
        json.loads(
            (fixture.journal._root / authorization.operation_id.removeprefix("sha256:")).read_text()  # pyright: ignore[reportPrivateUsage]
        )["artifact"]
    )
    fixture.store.path_for_digest(authority_ref.digest).write_bytes(b"tampered")
    with pytest.raises(ValueError, match="not durably recorded"):
        fixture.journal.require(authorization)


@pytest.mark.parametrize(
    "child",
    [
        "canary-metadata",
        "canary-missing",
        "canary-json",
        "canary-operation",
        "plan-metadata",
        "plan-missing",
        "plan-json",
        "plan-topology",
    ],
)
def test_journal_rejects_malformed_or_tampered_children(tmp_path: Path, child: str) -> None:
    fixture = Fixture(tmp_path)
    authorization = fixture.authorize()
    index_path = fixture.journal._root / authorization.operation_id.removeprefix("sha256:")  # pyright: ignore[reportPrivateUsage]
    index = json.loads(index_path.read_bytes())
    if child.startswith("canary"):
        ref = ArtifactRef.model_validate(index["canary_package_artifact"])
        if child == "canary-metadata":
            index["canary_package_artifact"]["role"] = "wrong"
            index_path.write_bytes(canonical_bytes(index))
        elif child == "canary-missing":
            fixture.store.delete(ref.digest)
        elif child == "canary-json":
            fixture.store.path_for_digest(ref.digest).write_bytes(b"{}")
        else:
            value = json.loads(fixture.canary_bytes)
            value["intent"]["operation_id"] = authorization.operation_id
            fixture.store.path_for_digest(ref.digest).write_bytes(canonical_bytes(value))
    else:
        ref = ArtifactRef.model_validate(index["publication_plan_artifact"])
        if child == "plan-metadata":
            index["publication_plan_artifact"]["role"] = "wrong"
            index_path.write_bytes(canonical_bytes(index))
        elif child == "plan-missing":
            fixture.store.delete(ref.digest)
        elif child == "plan-json":
            fixture.store.path_for_digest(ref.digest).write_bytes(b"{}")
        else:
            plan = fixture.prepared.plan
            value = plan.payload()
            value["base_commit"] = G
            fixture.store.path_for_digest(ref.digest).write_bytes(canonical_bytes(value))
    with pytest.raises(ValueError, match="not durably recorded"):
        fixture.journal.require(authorization)


@pytest.mark.parametrize("kind", ["operation", "canary", "facts", "soak", "config", "plan"])
def test_authorize_rejects_mixed_trust_inputs(tmp_path: Path, kind: str) -> None:
    fixture = Fixture(tmp_path)
    if kind == "operation":
        operation = fixture.operation.model_copy(update={"target_ref": "refs/heads/other"})
        updates = {"operation": operation}
    elif kind == "canary":
        facts = fixture.facts.model_copy(update={"restore_commit": H, "failed_head_parents": [H]})
        operation = fixture.operation.model_copy(update={"restore_to_commit": H})
        soak_values = fixture.soak.model_dump(mode="json")
        soak_values.update(restore_commit=H, integration_parent_commit=H)
        soak_values.pop("attestation_id")
        soak = FailedSoakAttestation.model_validate(
            {**soak_values, "attestation_id": canonical_digest(soak_values)}
        )
        updates = {"operation": operation, "facts": facts, "failed_soak": soak}
    elif kind == "facts":
        updates = {"facts": fixture.facts.model_copy(update={"failed_head_tree": G})}
    elif kind == "soak":
        values = fixture.soak.model_dump(mode="json")
        values.update(context="wrong context")
        values.pop("attestation_id")
        malformed_soak = FailedSoakAttestation.model_construct(  # type: ignore[reportArgumentType]
            **values
        )
        updates = {
            "failed_soak": malformed_soak.model_copy(
                update={"attestation_id": canonical_digest(values)}
            )
        }
    elif kind == "config":
        values = fixture.config.model_dump(mode="python")
        values.update(repository_digest=K)
        values.pop("trusted_config_digest")
        config = RollbackPublicationAuthorityConfig.model_validate(
            {**values, "trusted_config_digest": canonical_digest(values)}
        )
        updates = {"authority": RollbackBundleAuthority(config, fixture.journal)}
    else:
        plan = fixture.prepared.plan
        altered = replace(plan, candidate_commit=H)
        updates = {
            "prepared": PreparedPublication(
                altered, fixture.prepared.candidate_root, fixture.plan_ref
            )
        }
    with pytest.raises(
        (ValueError, TypeError), match=r"(mixed|trusted|context|canonical semantic)"
    ):
        fixture.authorize(**updates)  # type: ignore[reportArgumentType]


def test_authorize_rejects_missing_plan_artifact_and_model_construct_roundtrip(
    tmp_path: Path,
) -> None:
    fixture = Fixture(tmp_path)
    with pytest.raises(ValueError, match="durable plan"):
        fixture.authorize(prepared=PreparedPublication(fixture.prepared.plan, Path("candidate")))
    malformed = IntegrationRollbackRequest.model_construct(
        operation_id=D,
        promotion_operation_id=D,
        repository_digest=D,
    )
    with pytest.raises((ValueError, TypeError)):
        fixture.authorize(operation=malformed)


def test_drill_projection_success_and_rejection(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    authorization = fixture.authorize()
    drill = fixture.authority.drill_authorization(authorization, fixture.soak)
    assert drill.operation_id == authorization.operation_id
    assert drill.prepublication_authorization_id == authorization.authorization_id
    assert drill.target_parents == []
    changed_values = fixture.soak.model_dump(mode="json")
    changed_values.update(main_commit=H)
    changed_values.pop("attestation_id")
    changed = FailedSoakAttestation.model_construct(
        **changed_values, attestation_id=canonical_digest(changed_values)
    )
    with pytest.raises(ValueError, match="fresh failed soak differs"):
        fixture.authority.drill_authorization(authorization, changed)
    with pytest.raises(TypeError, match="FailedSoak"):
        fixture.authority.drill_authorization(authorization, object())  # type: ignore[arg-type]


def test_drill_projection_rejects_tampered_stored_soak(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    authorization = fixture.authorize()
    index_path = fixture.journal._root / authorization.operation_id.removeprefix("sha256:")  # pyright: ignore[reportPrivateUsage]
    index = json.loads(index_path.read_bytes())
    soak_ref = ArtifactRef.model_validate(index["failed_soak_artifact"])
    fixture.store.path_for_digest(soak_ref.digest).write_bytes(b"tampered")

    with pytest.raises(ValueError, match="not durably recorded"):
        fixture.authority.drill_authorization(authorization, fixture.soak)


def test_finalize_success_with_bytes_and_artifact_ref(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    authorization = fixture.authorize()
    drill = fixture.authority.drill_authorization(authorization, fixture.soak)
    publication = _publication(fixture, authorization)
    evidence = _evidence(fixture, authorization)
    result = fixture.authority.finalize(
        authorization, publication, evidence=evidence, drill_authorization=drill
    )
    assert isinstance(result, RollbackPromotionBundleAuthorization)
    assert result.authorization_id == canonical_digest(
        result.model_dump(exclude={"authorization_id"}, mode="json")
    )
    evidence_ref = fixture.store.put_bytes(
        evidence,
        media_type="application/vnd.avo.candidate-publication+json",
        role="publication-evidence",
        max_bytes=2_000_000,
    )
    assert (
        fixture.authority.finalize(
            authorization, publication, evidence=evidence_ref, drill_authorization=drill
        )
        == result
    )


@pytest.mark.parametrize(
    "field",
    [
        "repository_digest",
        "base_commit",
        "base_tree",
        "candidate_commit",
        "candidate_tree",
        "candidate_digest",
        "candidate_ref",
        "controller_publisher_identity",
        "publication_evidence_digest",
        "changed_paths",
        "verified",
    ],
)
def test_finalize_rejects_publication_mismatch(tmp_path: Path, field: str) -> None:
    fixture = Fixture(tmp_path)
    authorization = fixture.authorize()
    drill = fixture.authority.drill_authorization(authorization, fixture.soak)
    publication = _publication(fixture, authorization)
    replacements: dict[str, object] = {
        "repository_digest": K,
        "base_commit": G,
        "base_tree": G,
        "candidate_commit": H,
        "candidate_tree": H,
        "candidate_digest": D,
        "candidate_ref": "refs/heads/avo/candidate/" + "f" * 64,
        "controller_publisher_identity": "other",
        "publication_evidence_digest": D,
        "changed_paths": ["src/y.py"],
        "verified": False,
    }
    with pytest.raises(ValueError, match="publication"):
        fixture.authority.finalize(
            authorization,
            publication.model_copy(update={field: replacements[field]}),
            evidence=_evidence(fixture, authorization),
            drill_authorization=drill,
        )


@pytest.mark.parametrize(
    "field",
    [
        "operation_id",
        "prepublication_authorization_id",
        "failed_soak_attestation_id",
        "repository_digest",
        "target_ref",
        "main_before_commit",
        "failed_integration_head_commit",
        "failed_integration_head_tree",
        "restore_to_commit",
        "restore_to_tree",
        "rollback_candidate_commit",
        "rollback_candidate_parent_commit",
    ],
)
def test_finalize_rejects_drill_mismatch(tmp_path: Path, field: str) -> None:
    fixture = Fixture(tmp_path)
    authorization = fixture.authorize()
    drill = fixture.authority.drill_authorization(authorization, fixture.soak)
    replacements = {
        name: K
        for name in (
            "operation_id",
            "prepublication_authorization_id",
            "failed_soak_attestation_id",
            "repository_digest",
        )
    }
    replacements.update(
        {
            name: H
            for name in (
                "main_before_commit",
                "failed_integration_head_commit",
                "restore_to_commit",
                "rollback_candidate_commit",
                "rollback_candidate_parent_commit",
            )
        }
    )
    replacements["failed_integration_head_tree"] = G
    replacements["restore_to_tree"] = H
    replacements["target_ref"] = "refs/heads/other"
    with pytest.raises(ValueError, match="drill authorization"):
        fixture.authority.finalize(
            authorization,
            _publication(fixture, authorization),
            evidence=_evidence(fixture, authorization),
            drill_authorization=drill.model_copy(update={field: replacements[field]}),
        )


@pytest.mark.parametrize("evidence", [b"not json", canonical_bytes({"wrong": True})])
def test_finalize_rejects_malformed_or_different_evidence(tmp_path: Path, evidence: bytes) -> None:
    fixture = Fixture(tmp_path)
    authorization = fixture.authorize()
    drill = fixture.authority.drill_authorization(authorization, fixture.soak)
    with pytest.raises(ValueError, match="evidence"):
        fixture.authority.finalize(
            authorization,
            _publication(fixture, authorization),
            evidence=evidence,
            drill_authorization=drill,
        )
    missing = ArtifactRef(
        digest=authorization.publication_evidence_digest,
        size_bytes=len(_evidence(fixture, authorization)),
        media_type="application/json",
        role="publication-evidence",
        created_at=NOW,
    )
    with pytest.raises(OSError):
        fixture.authority.finalize(
            authorization,
            _publication(fixture, authorization),
            evidence=missing,
            drill_authorization=drill,
        )


def test_finalize_supports_injected_finalizer_and_rejects_invalid_result(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    authorization = fixture.authorize()
    drill = fixture.authority.drill_authorization(authorization, fixture.soak)
    publication = _publication(fixture, authorization)
    evidence = _evidence(fixture, authorization)
    expected = RollbackPromotionBundleAuthorization.model_construct()
    def finalizer(
        _authorization: RollbackPublicationAuthorization,
        _publication: CandidatePublicationBinding,
    ) -> object:
        return expected

    authority = RollbackBundleAuthority(fixture.config, fixture.journal, finalizer=finalizer)
    assert (
        authority.finalize(authorization, publication, evidence=evidence, drill_authorization=drill)
        is expected
    )
    def invalid_finalizer(
        _authorization: RollbackPublicationAuthorization,
        _publication: CandidatePublicationBinding,
    ) -> object:
        return object()

    invalid = RollbackBundleAuthority(
        fixture.config, fixture.journal, finalizer=invalid_finalizer
    )
    with pytest.raises(TypeError, match="invalid authorization"):
        invalid.finalize(authorization, publication, evidence=evidence, drill_authorization=drill)


@pytest.mark.parametrize("value", [object(), object(), object()])
def test_public_finalize_type_fences(tmp_path: Path, value: object) -> None:
    fixture = Fixture(tmp_path)
    with pytest.raises(TypeError):
        fixture.authority.finalize(value, value, evidence=value, drill_authorization=value)  # type: ignore[arg-type]


def test_journal_record_rejects_malformed_existing_index_and_corrupt_artifact(
    tmp_path: Path,
) -> None:
    fixture = Fixture(tmp_path)
    authorization = fixture.authorize()
    index_path = fixture.journal._root / authorization.operation_id.removeprefix("sha256:")  # pyright: ignore[reportPrivateUsage]
    index_path.write_bytes(b"{}")
    with pytest.raises(ValueError, match="index is malformed"):
        fixture.journal.record(
            authorization,
            canary_package_artifact=fixture.canary_ref,
            publication_plan_artifact=fixture.plan_ref,
        )

    fixture = Fixture(tmp_path / "corrupt")
    authorization = fixture.authorize()
    fixture.store.read_bytes = lambda _reference: b"different"  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="artifact is corrupt"):
        fixture.journal.record(
            authorization,
            canary_package_artifact=fixture.canary_ref,
            publication_plan_artifact=fixture.plan_ref,
        )


@pytest.mark.parametrize("field", ["role", "media_type"])
def test_journal_rejects_authority_artifact_metadata(tmp_path: Path, field: str) -> None:
    fixture = Fixture(tmp_path)
    authorization = fixture.authorize()
    index_path = fixture.journal._root / authorization.operation_id.removeprefix("sha256:")  # pyright: ignore[reportPrivateUsage]
    index = json.loads(index_path.read_bytes())
    index["artifact"][field] = "wrong"
    index_path.write_bytes(canonical_bytes(index))
    with pytest.raises(ValueError, match="not durably recorded"):
        fixture.journal.require(authorization)


def test_journal_rejects_different_authority_artifact_bytes(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    authorization = fixture.authorize()
    # The CAS reference is valid, but the bytes returned at the trust boundary
    # no longer equal the authority payload.
    fixture.store.read_bytes = lambda _reference: b"different"  # type: ignore[method-assign]
    with pytest.raises(ValueError, match="not durably recorded"):
        fixture.journal.require(authorization)


def test_journal_strict_child_duplicate_key_and_plan_identity(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    authorization = fixture.authorize()
    index_path = fixture.journal._root / authorization.operation_id.removeprefix("sha256:")  # pyright: ignore[reportPrivateUsage]
    index = json.loads(index_path.read_bytes())
    canary_ref = ArtifactRef.model_validate(index["canary_package_artifact"])
    fixture.store.path_for_digest(canary_ref.digest).write_bytes(
        b'{"schema_version":1,"schema_version":1}'
    )
    with pytest.raises(ValueError, match="not durably recorded"):
        fixture.journal.require(authorization)

    fixture = Fixture(tmp_path / "plan-id")
    authorization = fixture.authorize()
    index_path = fixture.journal._root / authorization.operation_id.removeprefix("sha256:")  # pyright: ignore[reportPrivateUsage]
    index = json.loads(index_path.read_bytes())
    alternate = replace(fixture.prepared.plan, candidate_tree=H)
    alternate = replace(alternate, publication_id=canonical_digest(alternate.identity_payload()))
    alternate_ref = fixture.store.put_bytes(
        canonical_bytes(alternate.payload()),
        media_type="application/vnd.avo.candidate-publication+json",
        role="candidate-publication-plan",
        max_bytes=2_000_000,
    )
    index["publication_plan_artifact"] = alternate_ref.model_dump(mode="json")
    index_path.write_bytes(canonical_bytes(index))
    with pytest.raises(ValueError, match="not durably recorded"):
        fixture.journal.require(authorization)


@pytest.mark.parametrize("which", ["operation", "canary", "artifact", "facts", "prepared", "soak"])
def test_authorize_type_fences(tmp_path: Path, which: str) -> None:
    fixture = Fixture(tmp_path)
    values: dict[str, object] = {
        which if which != "artifact" else "canary_package_artifact": object()
    }
    if which == "soak":
        values["failed_soak"] = object()
    with pytest.raises(TypeError):
        fixture.authorize(**values)  # type: ignore[reportArgumentType]


def test_authorize_rejects_evidence_and_empty_paths(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    bad_ref = fixture.package.evidence_artifacts[0]
    fixture.store.path_for_digest(bad_ref.digest).write_bytes(canonical_bytes({"changed": True}))
    with pytest.raises(ValueError, match="durable canary"):
        fixture.authority.authorize(
            fixture.operation,
            canary_package_artifact=fixture.canary_ref,
            canary_package=fixture.package,
            failed_soak=fixture.soak,
            facts=fixture.facts,
            prepared=fixture.prepared,
        )

    fixture = Fixture(tmp_path / "empty-paths")
    plan = replace(fixture.prepared.plan, changed_paths=())
    empty_prepared = PreparedPublication(plan, fixture.prepared.candidate_root, fixture.plan_ref)
    with pytest.raises(ValueError, match="changed paths"):
        fixture.authority.authorize(
            fixture.operation,
            canary_package_artifact=fixture.canary_ref,
            canary_package=fixture.package,
            failed_soak=fixture.soak,
            facts=fixture.facts,
            prepared=empty_prepared,
        )


@pytest.mark.parametrize("kind", ["digest", "repository", "app", "context", "status"])
def test_soak_validation_fences(tmp_path: Path, kind: str) -> None:
    fixture = Fixture(tmp_path)
    values = fixture.soak.model_dump(mode="json")
    values.pop("attestation_id")
    if kind == "digest":
        soak = FailedSoakAttestation.model_construct(**values, attestation_id="sha256:" + "0" * 64)
    else:
        if kind == "repository":
            values["repository_digest"] = K
        elif kind == "app":
            values["app_id"] = 1
        elif kind == "context":
            values["workflow_path"] = "wrong.yml"
        else:
            values["conclusion"] = "success"
        soak = FailedSoakAttestation.model_construct(
            **values, attestation_id=canonical_digest(values)
        )
    with pytest.raises((ValueError, TypeError), match=r"(canonical|trusted|workflow|completed)"):
        fixture.authority._validate_soak(soak)  # pyright: ignore[reportPrivateUsage]


def test_finalize_type_fences_after_authorization(tmp_path: Path) -> None:
    fixture = Fixture(tmp_path)
    authorization = fixture.authorize()
    drill = fixture.authority.drill_authorization(authorization, fixture.soak)
    with pytest.raises(TypeError, match="publication"):
        fixture.authority.finalize(authorization, object(), evidence=b"", drill_authorization=drill)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="drill"):
        fixture.authority.finalize(
            authorization,
            _publication(fixture, authorization),
            evidence=b"",
            drill_authorization=object(),  # type: ignore[reportArgumentType]
        )  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="evidence"):
        fixture.authority.finalize(
            authorization,
            _publication(fixture, authorization),
            evidence=object(),  # type: ignore[reportArgumentType]
            drill_authorization=drill,
        )  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="evidence artifact"):
        wrong_ref = fixture.store.put_bytes(
            b"{}", media_type="application/json", role="wrong", max_bytes=100
        )
        fixture.authority.finalize(
            authorization,
            _publication(fixture, authorization),
            evidence=wrong_ref,
            drill_authorization=drill,
        )


def test_finalize_rejects_tampered_canary_child_before_authority_output(
    tmp_path: Path,
) -> None:
    fixture = Fixture(tmp_path)
    authorization = fixture.authorize()
    drill = fixture.authority.drill_authorization(authorization, fixture.soak)
    index_path = fixture.journal._root / authorization.operation_id.removeprefix("sha256:")  # pyright: ignore[reportPrivateUsage]
    index = json.loads(index_path.read_bytes())
    index["canary_package_artifact"]["role"] = "tampered"
    index_path.write_bytes(canonical_bytes(index))

    with pytest.raises(ValueError, match="not durably recorded"):
        fixture.authority.finalize(
            authorization,
            _publication(fixture, authorization),
            evidence=_evidence(fixture, authorization),
            drill_authorization=drill,
        )
