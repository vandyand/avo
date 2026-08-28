import hashlib

import pytest

from avo_correlate.application.promotion_service import bundle_bytes
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_campaign import (
    IntegrationCampaignEvidencePackage,
    IntegrationIntentTemplate,
    campaign_marker_digest,
)
from avo_correlate.contracts.integration_promotion import (
    CandidatePublicationBinding,
    PromotionLeaseEvidence,
    integration_operation_id,
)
from avo_correlate.contracts.promotion_policy import (
    PromotionOutcome,
    RiskClass,
    path_manifest_digest,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

D = "sha256:" + "a" * 64
G = "a" * 40
H = "b" * 40
J = "c" * 40
pytestmark = pytest.mark.filterwarnings("ignore:Pydantic serializer warnings")


def _template_values() -> dict[str, object]:
    values: dict[str, object] = {
        "repository_digest": D,
        "candidate_ref": "refs/heads/candidate/x",
        "target_ref": "refs/heads/integration",
        "base_commit": G,
        "base_tree": G,
        "candidate_commit": H,
        "candidate_tree": H,
        "candidate_repository_digest": D,
        "candidate_head_ref": "refs/heads/candidate/x",
        "candidate_head_commit": H,
        "candidate_head_tree": H,
        "target_repository_digest": D,
        "target_base_ref": "refs/heads/integration",
        "target_base_commit": G,
        "target_base_tree": G,
        "synthetic_merge_commit": J,
        "synthetic_merge_tree": H,
        "bundle_digest": D,
        "candidate_digest": D,
        "publication_evidence_digest": D,
        "controller_config_digest": D,
        "protection_evidence_digest": D,
        "evidence_manifest_digest": D,
        "check_evidence_manifest_digest": D,
        "pull_request_number": 7,
        "pull_request_url": "https://github.com/o/r/pull/7",
        "provider_identity": "github",
        "provider_api_version": "2026-01",
        "merge_method": "squash",
    }
    values["operation_id"] = integration_operation_id(
        repository_digest=D,
        pull_request_number="7",
        candidate_ref=str(values["candidate_ref"]),
        target_ref=str(values["target_ref"]),
        base_commit=G,
        candidate_commit=H,
        candidate_head_commit=H,
        target_base_commit=G,
        synthetic_merge_commit=J,
        bundle_digest=D,
        candidate_digest=D,
        publication_evidence_digest=D,
        provider_identity="github",
        provider_api_version="2026-01",
        merge_method="squash",
    )
    return values


def test_template_binds_a_fresh_lease_without_changing_operation_id() -> None:
    template = IntegrationIntentTemplate.model_validate(_template_values())
    bound = template.bind_lease("lease-2", D)
    assert bound.operation_id == template.operation_id
    assert bound.controller_lease_identity == "lease-2"


def test_template_rejects_identity_drift() -> None:
    values = _template_values()
    values["operation_id"] = D
    with pytest.raises(ValueError, match="operation ID"):
        IntegrationIntentTemplate.model_validate(values)


def test_campaign_marker_is_deterministic() -> None:
    template = IntegrationIntentTemplate.model_validate(_template_values())
    assert campaign_marker_digest(template.bind_lease("lease", D)) == campaign_marker_digest(
        template.bind_lease("other-lease", "sha256:" + "b" * 64)
    )


def _package() -> IntegrationCampaignEvidencePackage:
    template = IntegrationIntentTemplate.model_validate(_template_values())
    lease_payload = {
        "schema_version": 1,
        "operation_id": template.operation_id,
        "repository_digest": D,
        "target_ref": "refs/heads/integration",
        "identity": "lease",
        "acquired_at": "2026-01-01T00:00:00Z",
        "expires_at": "2026-01-01T00:05:00Z",
    }
    lease = PromotionLeaseEvidence.model_validate(
        lease_payload | {"digest": canonical_digest(lease_payload)}
    )
    intent = template.bind_lease("lease", lease.digest)
    from avo_correlate.contracts.promotion_bundle import (
        GitRefSnapshot,
        PromotionBundle,
        PromotionControllerConfig,
        PromotionProvenanceBinding,
        WorkspaceComparison,
    )
    from avo_correlate.contracts.promotion_policy import (
        GateAttestation,
        PathManifestAttestation,
        PromotionConfig,
        PromotionDecision,
        PromotionRequest,
    )

    # The nested records are shape-valid fixtures; package validation exercises
    # every cross-record binding and digest.
    bundle = PromotionBundle.model_construct(
        snapshot=GitRefSnapshot.model_construct(
            repository_digest=D,
            target_ref="refs/heads/integration",
            commit=G,
            tree=G,
            source_tree_digest=D,
            protection_evidence_digest=D,
        ),
        comparison=WorkspaceComparison.model_construct(
            target_ref="refs/heads/integration",
            base_digest=D,
            candidate_digest=D,
            changed_paths=["src/x.py"],
        ),
        request=PromotionRequest.model_construct(
            candidate_id="c",
            proposer_id="p",
            candidate_digest=D,
            base_digest=D,
            changed_paths=["src/x.py"],
            path_manifest_attestation=PathManifestAttestation.model_construct(
                path_manifest_digest=path_manifest_digest(["src/x.py"])
            ),
            base_attestation=GateAttestation.model_construct(
                gate_name="base",
                candidate_digest=D,
                base_digest=D,
                evidence_digest=D,
                issuer_id="base",
                passed=True,
                valid_from_epoch=1,
                valid_until_epoch=1,
            ),
        ),
        request_digest=D,
        controller_config=PromotionControllerConfig.model_construct(
            controller_identity="controller",
            controller_version="1",
            base_issuer_id="base",
            path_issuer_id="path",
            policy=PromotionConfig.model_construct(
                evaluation_epoch=1,
                trusted_gate_issuers={},
                trusted_base_issuers=["base"],
                trusted_reviewer_issuers=["review"],
                trusted_path_issuers=["path"],
                rollback_issuer_ids=["rollback"],
                rollback_limit=0,
                reviewer_domains={"r": "d"},
                proposer_domains={"p": "d"},
                candidate_proposers={D: "p"},
                low_gates=frozenset({"deterministic", "provenance"}),
                ordinary_gates=frozenset({"integration_soak"}),
            ),
        ),
        controller_config_digest=D,
        decision=PromotionDecision.model_construct(
            candidate_id="c",
            outcome=PromotionOutcome.ALLOW,
            risk_class=RiskClass.LOW,
            reason_codes=["ok"],
            required_quorum=0,
        ),
        decision_digest=D,
        provenance=PromotionProvenanceBinding.model_construct(
            candidate_digest=D,
            base_digest=D,
            source_provenance_digest=D,
            request_digest=D,
            controller_config_digest=D,
            decision_digest=D,
            path_manifest_digest=path_manifest_digest(["src/x.py"]),
            evidence_manifest_digest=D,
            verified=True,
        ),
        evidence_digests=[D],
    )
    bundle_digest = "sha256:" + hashlib.sha256(bundle_bytes(bundle)).hexdigest()
    identity = _template_values()
    identity["bundle_digest"] = bundle_digest
    identity["operation_id"] = integration_operation_id(
        **{
            key: str(identity[key])
            for key in (
                "repository_digest",
                "candidate_ref",
                "target_ref",
                "base_commit",
                "candidate_commit",
                "candidate_head_commit",
                "target_base_commit",
                "synthetic_merge_commit",
                "bundle_digest",
                "candidate_digest",
                "publication_evidence_digest",
                "provider_identity",
                "provider_api_version",
                "merge_method",
            )
        },
        pull_request_number="7",
    )
    intent = IntegrationIntentTemplate.model_validate(identity).bind_lease("lease", lease.digest)
    # The operation ID includes the final bundle digest, so rebuild the lease
    # evidence after deriving the final intent identity.
    lease_payload["operation_id"] = intent.operation_id
    lease = PromotionLeaseEvidence.model_validate(
        lease_payload | {"digest": canonical_digest(lease_payload)}
    )
    intent = IntegrationIntentTemplate.model_validate(identity).bind_lease("lease", lease.digest)
    observation = __import__(
        "avo_correlate.contracts.integration_promotion", fromlist=["IntegrationProviderObservation"]
    ).IntegrationProviderObservation.model_construct(
        repository_digest=D,
        pull_request_number=7,
        pull_request_url=intent.pull_request_url,
        candidate_repository_digest=D,
        target_repository_digest=D,
        base_ref=intent.target_ref,
        base_commit=G,
        base_tree=G,
        head_ref=intent.candidate_ref,
        head_commit=H,
        candidate_tree=H,
        synthetic_merge_commit=J,
        synthetic_merge_tree=H,
        protection_evidence_digest=D,
        check_evidence_manifest_digest=D,
        provider_identity="github",
        provider_api_version="2026-01",
        open_state="open",
        draft=False,
    )
    reconciliation = __import__(
        "avo_correlate.contracts.integration_promotion",
        fromlist=["IntegrationProviderReconciliation"],
    ).IntegrationProviderReconciliation.model_construct(
        repository_digest=D,
        pull_request_number=7,
        pull_request_url=intent.pull_request_url,
        provider_identity="github",
        provider_api_version="2026-01",
        state="closed",
        merged=True,
        merge_commit=J,
        target_ref=intent.target_ref,
        target_head_commit=J,
        target_head_tree=H,
        target_first_parent=G,
        target_parents=[G],
        protection_evidence_digest=D,
    )
    merge = __import__(
        "avo_correlate.contracts.integration_promotion", fromlist=["IntegrationMergeResult"]
    ).IntegrationMergeResult.model_construct(
        outcome="applied",
        result_commit=J,
        result_tree=H,
        first_parent_commit=G,
        response_digest=D,
    )
    receipt = __import__(
        "avo_correlate.contracts.integration_promotion", fromlist=["IntegrationPromotionReceipt"]
    ).IntegrationPromotionReceipt.model_construct(
        operation_id=intent.operation_id,
        intent_digest=canonical_digest(intent),
        bundle_digest=bundle_digest,
        expected_target_ref=intent.target_ref,
        expected_candidate_commit=H,
        expected_candidate_tree=H,
        expected_base_commit=G,
        expected_protection_evidence_digest=D,
        expected_provider_identity="github",
        expected_provider_api_version="2026-01",
        merge_method="squash",
        applied_result_commit=J,
        applied_result_tree=H,
        applied_result_parent_commit=G,
        outcome="applied",
        observed_target_ref=intent.target_ref,
        observed_base_commit=G,
        observed_head_commit=J,
        observed_head_tree=H,
        observed_protection_evidence_digest=D,
        observed_provider_identity="github",
        observed_provider_api_version="2026-01",
        observation_digest=canonical_digest(reconciliation),
    )
    report = __import__(
        "avo_correlate.contracts.integration_promotion", fromlist=["IntegrationPromotionReport"]
    ).IntegrationPromotionReport.model_construct(
        operation_id=intent.operation_id,
        outcome="applied",
        intent_digest=canonical_digest(intent),
        receipt_digest=canonical_digest(receipt),
        checks=["campaign"],
        errors=[],
    )
    publication = CandidatePublicationBinding(
        repository_digest=D,
        base_commit=G,
        base_tree=G,
        candidate_digest=D,
        candidate_ref=intent.candidate_ref,
        candidate_commit=H,
        candidate_tree=H,
        controller_publisher_identity="controller",
        publication_evidence_digest=D,
        verified=True,
    )
    return IntegrationCampaignEvidencePackage(
        bundle=bundle,
        publication=publication,
        evidence_artifacts=[ArtifactRef.model_construct(digest=D, role="publication")],
        intent=intent,
        observation=observation,
        merge_result=merge,
        reconciliation=reconciliation,
        receipt=receipt,
        report=report,
        bundle_digest=bundle_digest,
        intent_digest=canonical_digest(intent),
        receipt_digest=canonical_digest(receipt),
        campaign_marker_digest=campaign_marker_digest(intent),
        lease_evidence=lease,
        lease_evidence_artifact=ArtifactRef(
            digest=canonical_digest(lease),
            size_bytes=len(canonical_bytes(lease)),
            media_type="application/vnd.avo.integration-promotion+json",
            role="promotion-lease-evidence",
            created_at=lease.acquired_at,
        ),
        main_before_commit=G,
        main_after_commit=G,
        deploy_performed=False,
    )


def test_applied_campaign_package_is_self_contained_and_bound() -> None:
    package = _package()
    assert package.receipt.outcome == "applied"
    assert package.main_before_commit == package.main_after_commit


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("main_after_commit", H, "changed main"),
        ("receipt_digest", D, "receipt digest"),
        ("report", None, "report digest"),
    ],
)
def test_campaign_rejects_adversarial_mismatch(field: str, value: object, message: str) -> None:
    package = _package()
    updates = {field: value}
    if field == "report":
        updates[field] = package.report.model_copy(update={"receipt_digest": D})
    with pytest.raises(ValueError, match=message):
        package.model_copy(update=updates).validate_package()  # pyright: ignore[reportCallIssue]


def test_campaign_package_requires_actual_bound_lease_evidence() -> None:
    package = _package()
    payload = package.lease_evidence.model_dump(mode="json")
    payload["identity"] = "different-lease"
    payload.pop("digest")
    mismatched = PromotionLeaseEvidence.model_validate(
        payload | {"digest": canonical_digest(payload)}
    )
    reference = package.lease_evidence_artifact.model_copy(
        update={
            "digest": canonical_digest(mismatched),
            "size_bytes": len(canonical_bytes(mismatched)),
        }
    )
    with pytest.raises(ValueError, match="lease evidence is not bound"):
        package.model_copy(
            update={"lease_evidence": mismatched, "lease_evidence_artifact": reference}
        ).validate_package()  # pyright: ignore[reportCallIssue]


def test_campaign_package_requires_lease_artifact_digest_binding() -> None:
    package = _package()
    with pytest.raises(ValueError, match="lease evidence artifact"):
        package.model_copy(
            update={
                "lease_evidence_artifact": package.lease_evidence_artifact.model_copy(
                    update={"digest": D}
                )
            }
        ).validate_package()  # pyright: ignore[reportCallIssue]
