from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

import avo_correlate.adapters.artifacts.main_graduation_journal as journal_module
from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
    MainGraduationJournalError,
    MainGraduationRecordConflictError,
    _check_digest,
    _digest_bytes,
    _operation_id,
    _strict_pairs,
    _sync_directory,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_graduation import (
    EligibilityLedgerStarted,
    MainAttestationManifest,
    MainCheckObservation,
    MainCompletionPackage,
    MainCompositionArtifact,
    MainCompositionProof,
    MainDeltaManifest,
    MainGraduationAttempt,
    MainGraduationEligibilityRecord,
    MainGraduationIntent,
    MainGraduationPlan,
    MainInverseDeltaArtifact,
    MainLeaseEvidence,
    MainMergeGroupChecks,
    MainMergeGroupWebhookReceipt,
    MainPreparationAuthorization,
    MainProtectionManifest,
    MainProviderReceipt,
    MainQueueAdmissionObservation,
    MainQueueObservation,
    MainReconciliation,
    MainReleaseAuthorization,
    MainReleaseHoldObservation,
    MainReleaseIssuerBinding,
    MainReleaseTransitionReceipt,
    MainRollbackAuthorization,
    MainRollbackIntent,
    MainSourcePackageBinding,
    main_operation_id,
    main_record_bytes,
    main_record_digest,
)
from avo_correlate.contracts.promotion_policy import path_manifest_digest
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

# This file intentionally exercises journal seams and model validators directly.
# Keep those focused white-box tests type-checked without making private seams public.
# pyright: reportPrivateUsage=false, reportArgumentType=false, reportCallIssue=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false

D = "sha256:" + "1" * 64
D2 = "sha256:" + "2" * 64
R = "sha256:" + "3" * 64
BASE = "a" * 40
HEAD = "b" * 40
TREE = "c" * 40
GROUP = "d" * 40
NOW = datetime(2026, 1, 1, tzinfo=UTC)


def ref(
    digest: str = D, *, role: str = "evidence", media_type: str = "application/json"
) -> ArtifactRef:
    return ArtifactRef(
        digest=digest,
        size_bytes=1,
        media_type=media_type,
        role=role,
        created_at=NOW,
    )


def source() -> MainSourcePackageBinding:
    package_ref = ref(
        role="integration-campaign-package",
        media_type="application/vnd.avo.integration-campaign+json",
    )
    return MainSourcePackageBinding.model_construct(
        operation_id=D,
        source_operation_id=D2,
        repository_digest=R,
        package_digest=D,
        package_artifact=package_ref,
        child_artifacts=[ref(D2, role="source-child")],
        source_result_commit=HEAD,
        source_result_tree=TREE,
        source_result_parent=BASE,
        source_issuer="source-controller",
        source_domain="integration-campaign",
    )


def composition() -> MainCompositionArtifact:
    return MainCompositionArtifact.model_construct(
        operation_id=D,
        repository_digest=R,
        package_digest=D,
        delta_digest=D2,
        base_commit=BASE,
        base_tree=TREE,
        candidate_commit=HEAD,
        candidate_tree=TREE,
        candidate_parent_commit=BASE,
        composition_digest=D2,
        candidate_ref="refs/heads/avo/candidate/" + "1" * 64,
        retention_ref="refs/avo/main-composition/" + "1" * 64,
    )


def issuer() -> MainReleaseIssuerBinding:
    values = {
        "operation_id": D,
        "repository_digest": R,
        "controller_config_digest": D2,
        "issuer_id": "isolated-release",
        "app_id": 9001,
        "isolation_digest": D,
        "issuer_domain": "isolated-release-check",
        "trusted_source_issuer": "source-controller",
        "trusted_source_domain": "integration-campaign",
    }
    probe = MainReleaseIssuerBinding.model_construct(**values, binding_digest=D)
    return MainReleaseIssuerBinding.model_validate(
        {
            **values,
            "binding_digest": canonical_digest(
                probe.model_dump(exclude={"binding_digest"}, mode="json")
            ),
        }
    )


def plan() -> MainGraduationPlan:
    package = source()
    delta = MainDeltaManifest.model_construct(
        operation_id=D,
        repository_digest=R,
        package_digest=D,
        source_result_commit=HEAD,
        source_result_tree=TREE,
        source_result_parent=BASE,
        changed_paths=["src/feature.py"],
        path_manifest_digest=D,
        delta_digest=D2,
        ordinary_risk_digest=D,
    )
    comp = composition()
    binding = issuer()
    proof = MainCompositionProof.model_construct(
        operation_id=D,
        repository_digest=R,
        target_ref="refs/heads/main",
        package_digest=D,
        delta_digest=D2,
        composition_digest=comp.composition_digest,
        source_operation_id=D2,
        source_result_commit=HEAD,
        source_result_parent=BASE,
        source_result_tree=TREE,
        path_manifest_digest=D,
        ordinary_risk_digest=D,
        base_commit=BASE,
        base_tree=TREE,
        candidate_commit=HEAD,
        candidate_tree=TREE,
        candidate_parent_commit=BASE,
        candidate_ref=comp.candidate_ref,
        retention_ref=comp.retention_ref,
        controller_config_digest=D2,
        policy_epoch=D,
        source_issuer="source-controller",
        source_domain="integration-campaign",
        verifier_identity="avo_correlate.adapters.git.main_composition.MainCompositionAdapter",
        verifier_version="1",
        base_observer_identity="avo_correlate.adapters.git.main_composition.MainBaseReader",
        git_root_digest=R,
        proof_digest=D,
    )
    proof_bytes = canonical_bytes(proof)
    proof_ref = ref(
        canonical_digest(proof),
        role="main-graduation-composition-proof",
        media_type="application/vnd.avo.main-graduation-composition-proof+json",
    ).model_copy(update={"size_bytes": len(proof_bytes)})
    return MainGraduationPlan.model_construct(
        operation_id=D,
        repository_digest=R,
        package=package,
        delta=delta,
        composition=comp,
        composition_proof=proof,
        composition_proof_artifact=proof_ref,
        policy_epoch=D,
        controller_config_digest=D2,
        release_issuer_binding=binding,
        evidence_artifacts=[package.package_artifact, *package.child_artifacts],
    )


def authority_plan() -> MainGraduationPlan:
    package_artifact = ref(
        role="integration-campaign-package",
        media_type="application/vnd.avo.integration-campaign+json",
    )
    package = MainSourcePackageBinding.model_validate(
        {
            "operation_id": D,
            "source_operation_id": D2,
            "repository_digest": R,
            "package_digest": D,
            "package_artifact": package_artifact,
            "child_artifacts": [ref(D2, role="source-child")],
            "source_result_commit": HEAD,
            "source_result_tree": TREE,
            "source_result_parent": BASE,
            "source_issuer": "source-controller",
        }
    )
    delta_values = {
        "schema_version": 1,
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "operation_id": D,
        "package_digest": D,
        "source_result_commit": HEAD,
        "source_result_parent": BASE,
        "source_result_tree": TREE,
        "changed_paths": ["src/feature.py"],
        "path_manifest_digest": path_manifest_digest(["src/feature.py"]),
        "ordinary_risk_digest": canonical_digest(
            {
                "ordinary_risk": "ordinary",
                "changed_paths": ["src/feature.py"],
                "path_manifest_digest": path_manifest_digest(["src/feature.py"]),
            }
        ),
        "ordinary_risk": "ordinary",
        "deploy_performed": False,
    }
    delta = MainDeltaManifest.model_validate(
        delta_values | {"delta_digest": canonical_digest(delta_values)}
    )
    composition_values = {
        "schema_version": 1,
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "operation_id": D,
        "package_digest": D,
        "delta_digest": delta.delta_digest,
        "base_commit": BASE,
        "base_tree": TREE,
        "candidate_commit": HEAD,
        "candidate_tree": TREE,
        "candidate_parent_commit": BASE,
        "candidate_ref": "refs/heads/avo/candidate/" + "1" * 64,
        "retention_ref": "refs/avo/main-composition/" + "1" * 64,
        "deploy_performed": False,
    }
    composition = MainCompositionArtifact.model_validate(
        composition_values | {"composition_digest": canonical_digest(composition_values)}
    )
    proof_values = {
        "schema_version": 1,
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "operation_id": D,
        "source_operation_id": D2,
        "package_digest": D,
        "source_result_commit": HEAD,
        "source_result_parent": BASE,
        "source_result_tree": TREE,
        "delta_digest": delta.delta_digest,
        "path_manifest_digest": delta.path_manifest_digest,
        "ordinary_risk_digest": delta.ordinary_risk_digest,
        "composition_digest": composition.composition_digest,
        "base_commit": BASE,
        "base_tree": TREE,
        "candidate_commit": HEAD,
        "candidate_tree": TREE,
        "candidate_parent_commit": BASE,
        "candidate_ref": composition.candidate_ref,
        "retention_ref": composition.retention_ref,
        "controller_config_digest": D2,
        "policy_epoch": D,
        "source_issuer": "source-controller",
        "source_domain": "integration-campaign",
        "verifier_identity": "avo_correlate.adapters.git.main_composition.MainCompositionAdapter",
        "verifier_version": "1",
        "base_observer_identity": "avo_correlate.adapters.git.main_composition.MainBaseReader",
        "git_root_digest": R,
    }
    proof = MainCompositionProof.model_validate(
        {**proof_values, "proof_digest": canonical_digest(proof_values)}
    )
    proof_bytes = canonical_bytes(proof)
    proof_ref = ArtifactRef(
        digest=canonical_digest(proof),
        size_bytes=len(proof_bytes),
        media_type="application/vnd.avo.main-graduation-composition-proof+json",
        role="main-graduation-composition-proof",
        created_at=NOW,
    )
    return MainGraduationPlan.model_validate(
        {
            "operation_id": D,
            "repository_digest": R,
            "target_ref": "refs/heads/main",
            "package": package,
            "delta": delta,
            "composition": composition,
            "composition_proof": proof,
            "composition_proof_artifact": proof_ref,
            "policy_epoch": D,
            "controller_config_digest": D2,
            "release_issuer_binding": issuer(),
            "evidence_artifacts": [package_artifact],
        }
    )


def completion() -> MainCompletionPackage:
    package = source()
    delta = MainDeltaManifest.model_construct(
        operation_id=D,
        repository_digest=R,
        package_digest=D,
        source_result_commit=HEAD,
        source_result_tree=TREE,
        source_result_parent=BASE,
        changed_paths=["src/feature.py"],
        path_manifest_digest=D,
        delta_digest=D2,
        ordinary_risk_digest=D,
    )
    comp = composition()
    binding = issuer()
    topo = canonical_digest(
        {
            "expected_group_parents": [BASE, HEAD],
            "merge_method": "squash",
            "provider_identity": "provider",
            "provider_api_version": "v1",
            "queue_manifest_digest": D,
        }
    )
    check = MainCheckObservation.model_construct(
        name="validation",
        context="validate",
        app_id=15368,
        sha=GROUP,
        status="completed",
        conclusion="success",
        run_id="run",
        nonce="nonce",
        observed_at=NOW,
    )
    checks = MainMergeGroupChecks.model_construct(
        operation_id=D,
        repository_digest=R,
        package_digest=D,
        composition_digest=D2,
        group_sha=GROUP,
        checks=[check],
        allowlisted_contexts=["validate"],
        config_digest=D,
        freshness_cutoff=NOW - timedelta(minutes=1),
        observed_at=NOW,
    )
    queue = MainQueueObservation.model_construct(
        operation_id=D,
        repository_digest=R,
        queue_generation_digest=D,
        queue_manifest_digest=D,
        expected_base_commit=BASE,
        expected_base_tree=TREE,
        protection_manifest_digest=D,
        protection_epoch=D,
        provider_identity="provider",
        provider_api_version="v1",
        expected_group_parents=[BASE, HEAD],
        group_topology_digest=topo,
        merge_method="squash",
        isolated_release_issuer="isolated-release",
        release_issuer_app_id=9001,
        issuer_isolation_digest=D,
        observed_at=NOW,
        pull_request_number=1,
    )
    protection = MainProtectionManifest.model_construct(
        operation_id=D,
        repository_digest=R,
        manifest_digest=D,
        provider_identity="provider",
        provider_api_version="v1",
        isolated_release_issuer="isolated-release",
        release_issuer_app_id=9001,
        issuer_isolation_digest=D,
        protection_epoch=D,
        observed_at=NOW,
    )
    attestation = MainAttestationManifest.model_construct(
        operation_id=D,
        repository_digest=R,
        package_digest=D,
        composition_digest=D2,
        policy_epoch=D,
        reviewer_identity="reviewer",
        reviewer_evidence_digest=D,
        evaluator_identity="evaluator",
        evaluator_evidence_digest=D2,
    )
    lease = MainLeaseEvidence.model_construct(
        operation_id=D,
        repository_digest=R,
        identity="lease",
        acquired_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        lease_digest=D,
    )
    intent = MainGraduationIntent.model_construct(
        operation_id=D,
        repository_digest=R,
        plan_digest=D,
        package_digest=D,
        composition_digest=D2,
        base_commit=BASE,
        base_tree=TREE,
        candidate_commit=HEAD,
        candidate_tree=TREE,
        candidate_ref="refs/heads/avo/candidate/" + "a" * 64,
        lease_identity="lease",
        lease_digest=D,
        lease_evidence=lease,
        lease_evidence_artifact=ref(role="main-graduation-lease-evidence"),
        policy_epoch=D,
        intent_digest=D,
        recorded_at=NOW,
    )
    prep = MainPreparationAuthorization.model_construct(
        operation_id=D,
        repository_digest=R,
        plan_digest=D,
        intent_digest=D,
        package_digest=D,
        composition_digest=D2,
        base_commit=BASE,
        base_tree=TREE,
        candidate_commit=HEAD,
        candidate_tree=TREE,
        lease_identity="lease",
        lease_digest=D,
        policy_epoch=D,
        authorization_digest=D,
        authorized_at=NOW,
    )
    admission = MainQueueAdmissionObservation.model_construct(
        operation_id=D,
        repository_digest=R,
        preparation_authorization_digest=D,
        package_digest=D,
        composition_digest=D2,
        pull_request_number=1,
        pull_request_url="https://example.test/p/1",
        base_commit=BASE,
        base_tree=TREE,
        head_commit=HEAD,
        head_tree=TREE,
        admission_sha=HEAD,
        admission_run_id="admission-run",
        admission_nonce="admission-nonce",
        queue_generation_digest=D,
        protection_manifest_digest=D,
        issuer_identity="isolated-release",
        release_issuer_app_id=9001,
        issuer_isolation_digest=D,
        observed_at=NOW,
    )
    receipt_payload = {
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "operation_id": D,
        "group_sha": GROUP,
        "group_tree": TREE,
        "group_parents": [BASE, HEAD],
        "pull_request_number": 1,
        "queue_generation_digest": D,
        "delivery_id": "delivery-1",
        "body_digest": D,
        "observed_at": NOW,
    }
    receipt_probe = MainMergeGroupWebhookReceipt.model_construct(**receipt_payload)
    receipt = MainMergeGroupWebhookReceipt.model_validate(
        {
            **receipt_payload,
            "receipt_digest": canonical_digest(
                receipt_probe.model_dump(exclude={"receipt_digest"}, mode="json")
            ),
        }
    )
    hold = MainReleaseHoldObservation.model_construct(
        operation_id=D,
        repository_digest=R,
        preparation_authorization_digest=D,
        admission_observation_digest=D,
        package_digest=D,
        composition_digest=D2,
        pull_request_number=1,
        group_sha=GROUP,
        group_tree=TREE,
        group_parents=[BASE, HEAD],
        expected_group_parents=[BASE, HEAD],
        group_topology_digest=topo,
        base_commit=BASE,
        base_tree=TREE,
        composition_tree=TREE,
        queue_generation_digest=D,
        queue_members=[1],
        hold_run_id="hold-run",
        hold_nonce="hold-nonce",
        issuer_identity="isolated-release",
        release_issuer_app_id=9001,
        issuer_isolation_digest=D,
        other_required_checks=checks,
        merge_group_receipt=receipt,
        protection_manifest_digest=D,
        attestation_manifest_digest=D,
        observed_at=NOW,
    )
    authorization = MainReleaseAuthorization.model_construct(
        operation_id=D,
        repository_digest=R,
        preparation_authorization_digest=D,
        admission_observation_digest=D,
        hold_observation_digest=D,
        package_digest=D,
        composition_digest=D2,
        group_sha=GROUP,
        hold_run_id="hold-run",
        hold_nonce="hold-nonce",
        queue_generation_digest=D,
        lease_identity="lease",
        lease_digest=D,
        policy_epoch=D,
        release_issuer_identity="isolated-release",
        release_issuer_app_id=9001,
        issuer_isolation_digest=D,
        authorization_digest=D,
        expires_at=NOW + timedelta(minutes=5),
        authorized_at=NOW,
    )
    transition = MainReleaseTransitionReceipt.model_construct(
        operation_id=D,
        repository_digest=R,
        release_authorization_digest=D,
        group_sha=GROUP,
        hold_run_id="hold-run",
        hold_nonce="hold-nonce",
        issuer_identity="isolated-release",
        release_issuer_app_id=9001,
        issuer_isolation_digest=D,
        outcome="transitioned",
        response_digest=D,
        observed_at=NOW,
    )
    provider = MainProviderReceipt.model_construct(
        operation_id=D,
        repository_digest=R,
        release_authorization_digest=canonical_digest(authorization),
        provider_identity="provider",
        provider_api_version="v1",
        outcome="observed",
        result_commit=HEAD,
        result_tree=TREE,
        result_parents=[BASE],
        response_digest=D,
        observed_at=NOW,
    )
    reconciliation = MainReconciliation.model_construct(
        operation_id=D,
        repository_digest=R,
        state="completed",
        main_commit=HEAD,
        main_tree=TREE,
        main_parents=[BASE],
        expected_tree=TREE,
        expected_base_commit=BASE,
        queue_generation_digest=D,
        transition_receipt_digest=canonical_digest(transition),
    )
    graduation_plan = MainGraduationPlan.model_construct(
        operation_id=D,
        repository_digest=R,
        package=package,
        delta=delta,
        composition=comp,
        policy_epoch=D,
        controller_config_digest=D2,
        release_issuer_binding=binding,
        evidence_artifacts=[package.package_artifact, *package.child_artifacts],
    )
    object.__setattr__(intent, "plan_digest", canonical_digest(graduation_plan))
    object.__setattr__(prep, "plan_digest", canonical_digest(graduation_plan))
    object.__setattr__(prep, "intent_digest", canonical_digest(intent))
    object.__setattr__(authorization, "preparation_authorization_digest", canonical_digest(prep))
    object.__setattr__(authorization, "admission_observation_digest", canonical_digest(admission))
    object.__setattr__(authorization, "hold_observation_digest", canonical_digest(hold))
    object.__setattr__(hold, "admission_observation_digest", canonical_digest(admission))
    object.__setattr__(authorization, "hold_observation_digest", canonical_digest(hold))
    object.__setattr__(provider, "release_authorization_digest", canonical_digest(authorization))
    return MainCompletionPackage.model_construct(
        operation_id=D,
        repository_digest=R,
        plan=graduation_plan,
        source_package=package,
        delta=delta,
        composition=comp,
        queue_observation=queue,
        protection_manifest=protection,
        attestation_manifest=attestation,
        merge_group_checks=checks,
        intent=intent,
        release_issuer_binding=binding,
        preparation_authorization=prep,
        admission_observation=admission,
        hold_observation=hold,
        release_authorization=authorization,
        transition_receipt=transition,
        provider_receipt=provider,
        reconciliation=reconciliation,
        artifacts=[
            ref(role=role)
            for role in (
                "main-graduation-source-package",
                "main-graduation-delta",
                "main-graduation-composition",
                "main-graduation-queue-observation",
                "main-graduation-protection-manifest",
                "main-graduation-attestation-manifest",
                "main-graduation-merge-group-checks",
                "main-graduation-merge-group-webhook-receipt",
                "main-graduation-release-issuer-binding",
                "main-graduation-plan",
                "main-graduation-intent",
                "main-graduation-preparation-authorization",
                "main-graduation-queue-admission",
                "main-graduation-release-hold",
                "main-graduation-release-authorization",
                "main-graduation-release-transition",
                "main-graduation-provider-receipt",
                "main-graduation-reconciliation",
            )
        ],
    )


def test_canonical_helpers_and_journal_identity_guards(tmp_path: Path) -> None:
    record = EligibilityLedgerStarted(
        activation_digest=D,
        repository_digest=R,
        controller_config_digest=D2,
        scheduler_sequence_watermark=0,
        streak=0,
    )
    assert _digest_bytes(b"x").startswith("sha256:")
    assert _operation_id(record) == D
    assert main_operation_id(repository=R) == main_operation_id(repository=R)
    assert main_record_bytes(record) == main_record_bytes(record)
    assert main_record_digest(record) == canonical_digest(record)
    with pytest.raises(ValueError):
        _operation_id(object())
    with pytest.raises(ValueError):
        _operation_id(type("Record", (), {"operation_id": "bad"})())
    with pytest.raises(ValueError):
        _check_digest("bad")
    with pytest.raises(ValueError):
        MainGraduationJournal(tmp_path, max_record_bytes=0)
    assert MainGraduationJournal(tmp_path).root == tmp_path.resolve()


def test_simple_contract_validators_cover_success_and_failure_edges() -> None:
    values = {
        "operation_id": D,
        "repository_digest": R,
        "controller_config_digest": D2,
        "issuer_id": "isolated-release",
        "app_id": 9001,
        "isolation_digest": D,
        "trusted_source_issuer": "source-controller",
    }
    probe = MainReleaseIssuerBinding.model_construct(**values, binding_digest=D)
    assert MainReleaseIssuerBinding.model_validate(
        {
            **values,
            "binding_digest": canonical_digest(
                probe.model_dump(exclude={"binding_digest"}, mode="json")
            ),
        }
    )
    lease_values = {
        "operation_id": D,
        "repository_digest": R,
        "identity": "lease",
        "acquired_at": NOW,
        "expires_at": NOW + timedelta(minutes=1),
    }
    lease_probe = MainLeaseEvidence.model_construct(**lease_values, lease_digest=D)
    assert MainLeaseEvidence.model_validate(
        {
            **lease_values,
            "lease_digest": canonical_digest(
                lease_probe.model_dump(exclude={"lease_digest"}, mode="json")
            ),
        }
    )
    with pytest.raises(ValidationError):
        MainLeaseEvidence.model_validate({**lease_values, "expires_at": NOW, "lease_digest": D})
    delta = MainDeltaManifest(
        operation_id=D,
        repository_digest=R,
        package_digest=D,
        source_result_commit=HEAD,
        source_result_tree=TREE,
        source_result_parent=BASE,
        changed_paths=["src/feature.py"],
        path_manifest_digest=path_manifest_digest(["src/feature.py"]),
        delta_digest=canonical_digest(
            {
                "schema_version": 1,
                "repository_digest": R,
                "target_ref": "refs/heads/main",
                "operation_id": D,
                "package_digest": D,
                "source_result_commit": HEAD,
                "source_result_parent": BASE,
                "source_result_tree": TREE,
                "changed_paths": ["src/feature.py"],
                "path_manifest_digest": path_manifest_digest(["src/feature.py"]),
                "ordinary_risk_digest": canonical_digest(
                    {
                        "ordinary_risk": "ordinary",
                        "changed_paths": ["src/feature.py"],
                        "path_manifest_digest": path_manifest_digest(["src/feature.py"]),
                    }
                ),
                "ordinary_risk": "ordinary",
                "deploy_performed": False,
            }
        ),
        ordinary_risk_digest=canonical_digest(
            {
                "ordinary_risk": "ordinary",
                "changed_paths": ["src/feature.py"],
                "path_manifest_digest": path_manifest_digest(["src/feature.py"]),
            }
        ),
    )
    assert delta.changed_paths == ["src/feature.py"]
    with pytest.raises(ValidationError):
        MainDeltaManifest.model_validate({**delta.model_dump(), "source_result_parent": HEAD})
    valid_comp = MainCompositionArtifact(
        operation_id=D,
        repository_digest=R,
        package_digest=D,
        delta_digest=D2,
        base_commit=BASE,
        base_tree=TREE,
        candidate_commit=HEAD,
        candidate_tree=TREE,
        candidate_parent_commit=BASE,
        composition_digest=canonical_digest(
            {
                "schema_version": 1,
                "repository_digest": R,
                "target_ref": "refs/heads/main",
                "operation_id": D,
                "package_digest": D,
                "delta_digest": D2,
                "base_commit": BASE,
                "base_tree": TREE,
                "candidate_commit": HEAD,
                "candidate_tree": TREE,
                "candidate_parent_commit": BASE,
                "candidate_ref": "refs/heads/avo/candidate/" + "1" * 64,
                "retention_ref": "refs/avo/main-composition/" + "1" * 64,
                "deploy_performed": False,
            }
        ),
        candidate_ref="refs/heads/avo/candidate/" + "1" * 64,
        retention_ref="refs/avo/main-composition/" + "1" * 64,
    )
    assert valid_comp.candidate_parent_commit == BASE
    with pytest.raises(ValidationError):
        MainCompositionArtifact.model_validate(
            {**valid_comp.model_dump(), "candidate_commit": BASE}
        )
    for status, conclusion in (
        ("completed", "neutral"),
        ("in_progress", "pending"),
        ("queued", "pending"),
    ):
        assert MainCheckObservation(
            name="check",
            context="context",
            app_id=15368,
            sha=HEAD,
            status=status,
            conclusion=conclusion,
            run_id="run",
            nonce="nonce",
            observed_at=NOW,
        )
    with pytest.raises(ValidationError):
        MainCheckObservation(
            name="check",
            context="context",
            app_id=15368,
            sha=HEAD,
            status="queued",
            conclusion="success",
            run_id="run",
            nonce="nonce",
            observed_at=NOW,
        )
    assert MainAttestationManifest(
        operation_id=D,
        repository_digest=R,
        package_digest=D,
        composition_digest=D2,
        policy_epoch=D,
        reviewer_identity="reviewer",
        reviewer_evidence_digest=D,
        evaluator_identity="evaluator",
        evaluator_evidence_digest=D2,
    )
    with pytest.raises(ValidationError):
        MainAttestationManifest(
            operation_id=D,
            repository_digest=R,
            package_digest=D,
            composition_digest=D2,
            policy_epoch=D,
            reviewer_identity="same",
            reviewer_evidence_digest=D,
            evaluator_identity="same",
            evaluator_evidence_digest=D2,
        )


def test_remaining_contract_validators_and_aliases() -> None:
    queue_values = {
        "operation_id": D,
        "repository_digest": R,
        "queue_generation_digest": D,
        "queue_manifest_digest": D,
        "expected_base_commit": BASE,
        "expected_base_tree": TREE,
        "protection_manifest_digest": D,
        "protection_epoch": D,
        "provider_identity": "provider",
        "provider_api_version": "v1",
        "expected_group_parents": [BASE, HEAD],
        "merge_method": "squash",
        "isolated_release_issuer": "release",
        "release_issuer_app_id": 9001,
        "issuer_isolation_digest": D,
        "observed_at": NOW,
        "pull_request_number": 1,
    }
    topology = canonical_digest(
        {
            **{
                k: queue_values[k]
                for k in (
                    "expected_group_parents",
                    "pull_request_number",
                    "merge_method",
                    "provider_identity",
                    "provider_api_version",
                )
            },
            "queue_manifest_digest": D,
        }
    )
    queue = MainQueueObservation.model_validate({**queue_values, "group_topology_digest": topology})
    assert queue.target_ref == "refs/heads/main"
    with pytest.raises(ValidationError):
        MainQueueObservation.model_validate({**queue_values, "group_topology_digest": D})
    protection = MainProtectionManifest(
        operation_id=D,
        repository_digest=R,
        manifest_digest=D,
        provider_identity="provider",
        provider_api_version="v1",
        isolated_release_issuer="release",
        release_issuer_app_id=9001,
        issuer_isolation_digest=D,
        protection_epoch=D,
        observed_at=NOW,
    )
    assert protection.required is True
    with pytest.raises(ValidationError):
        MainProtectionManifest.model_validate(
            {**protection.model_dump(), "release_issuer_app_id": 15368}
        )
    provider = MainProviderReceipt(
        operation_id=D,
        repository_digest=R,
        release_authorization_digest=D,
        provider_identity="provider",
        provider_api_version="v1",
        outcome="observed",
        result_commit=HEAD,
        result_tree=TREE,
        result_parents=[BASE],
        response_digest=D,
        observed_at=NOW,
    )
    assert provider.result_parents == [BASE]
    with pytest.raises(ValidationError):
        MainProviderReceipt.model_validate({**provider.model_dump(), "result_parents": []})
    assert MainReconciliation(
        operation_id=D,
        repository_digest=R,
        state="completed",
        main_commit=HEAD,
        main_tree=TREE,
        main_parents=[BASE],
        expected_tree=TREE,
        expected_base_commit=BASE,
        queue_generation_digest=D,
    )
    with pytest.raises(ValidationError):
        MainReconciliation.model_validate(
            {
                "operation_id": D,
                "repository_digest": R,
                "state": "completed",
                "main_commit": HEAD,
                "main_tree": D,
                "main_parents": [HEAD],
                "expected_tree": TREE,
                "expected_base_commit": BASE,
                "queue_generation_digest": D,
            }
        )
    inverse_values = {
        "operation_id": D,
        "repository_digest": R,
        "completion_package_digest": D,
        "current_main_commit": HEAD,
        "current_main_tree": TREE,
        "inverse_changed_paths": ["src/feature.py"],
        "inverse_tree": TREE,
        "policy_epoch": D,
    }
    inverse_probe = MainInverseDeltaArtifact.model_construct(
        **inverse_values, inverse_delta_digest=D
    )
    inverse = MainInverseDeltaArtifact.model_validate(
        {
            **inverse_values,
            "inverse_delta_digest": canonical_digest(
                inverse_probe.model_dump(exclude={"inverse_delta_digest"}, mode="json")
            ),
        }
    )
    assert inverse.inverse_tree == TREE
    assert MainGraduationEligibilityRecord(
        operation_id=D,
        repository_digest=R,
        scheduler_sequence=1,
        submission_digest=D,
        classification="excluded",
        exclusion_reason="not ordinary",
        exclusion_evidence_digest=D,
        ordinary=False,
        nonempty=True,
    )
    with pytest.raises(ValidationError):
        MainGraduationEligibilityRecord(
            operation_id=D,
            repository_digest=R,
            scheduler_sequence=1,
            submission_digest=D,
            classification="eligible",
            ordinary=False,
            nonempty=True,
        )
    with pytest.raises(ValidationError):
        MainGraduationAttempt(
            operation_id=D,
            repository_digest=R,
            scheduler_sequence=1,
            eligibility_record_digest=D,
            terminal_disposition="failed",
        )
    assert MainReleaseTransitionReceipt(
        operation_id=D,
        repository_digest=R,
        release_authorization_digest=D,
        group_sha=GROUP,
        hold_run_id="run",
        hold_nonce="nonce",
        issuer_identity="release",
        release_issuer_app_id=9001,
        issuer_isolation_digest=D,
        outcome="already_transitioned",
        response_digest=D,
        observed_at=NOW,
    )
    with pytest.raises(ValidationError):
        MainReleaseTransitionReceipt(
            operation_id=D,
            repository_digest=R,
            release_authorization_digest=D,
            group_sha=GROUP,
            hold_run_id="run",
            hold_nonce="nonce",
            issuer_identity="release",
            release_issuer_app_id=15368,
            issuer_isolation_digest=D,
            outcome="transitioned",
            response_digest=D,
            observed_at=NOW,
        )


def test_completion_validator_covers_full_cross_stage_closure() -> None:
    package = completion()
    assert package.validate_completion() is package
    object.__setattr__(package.provider_receipt, "outcome", "ambiguous")
    with pytest.raises(ValueError, match="completion requires an observed"):
        package.validate_completion()


def test_merge_group_webhook_receipt_is_cas_indexed_across_restart_and_rebound_conflicts(
    tmp_path: Path,
) -> None:
    package = completion()
    receipt = package.hold_observation.merge_group_receipt
    journal = MainGraduationJournal(tmp_path)
    reference = journal.record_merge_group_webhook_receipt(receipt)
    restarted = MainGraduationJournal(tmp_path)
    durable = restarted.read_merge_group_webhook_receipt(receipt.operation_id)
    assert durable is not None
    assert durable[1] == reference
    rebound_payload = receipt.model_dump(mode="json", exclude={"operation_id", "receipt_digest"})
    rebound_payload["operation_id"] = D2
    rebound_payload["observed_at"] = datetime.fromisoformat(
        str(rebound_payload["observed_at"]).replace("Z", "+00:00")
    )
    rebound_probe = MainMergeGroupWebhookReceipt.model_construct(**rebound_payload)
    rebound = MainMergeGroupWebhookReceipt.model_validate(
        {
            **rebound_payload,
            "receipt_digest": canonical_digest(
                rebound_probe.model_dump(exclude={"receipt_digest"}, mode="json")
            ),
        }
    )
    with pytest.raises(MainGraduationRecordConflictError, match="delivery"):
        restarted.record_merge_group_webhook_receipt(rebound)
    forged = receipt.model_copy(update={"delivery_id": ""})
    with pytest.raises(MainGraduationJournalError):
        restarted.record_merge_group_webhook_receipt(forged)


def test_journal_wrappers_and_low_level_guards(tmp_path: Path) -> None:
    journal = MainGraduationJournal(tmp_path)
    assert journal.read("eligibility", D) is None
    with pytest.raises(ValueError):
        journal.record("unknown", EligibilityLedgerStarted.model_construct(activation_digest=D))
    with pytest.raises(ValueError):
        journal.read("unknown", D)
    readers = (
        "read_ledger_started",
        "read_plan",
        "read_release_issuer_binding",
        "read_source_package",
        "read_delta",
        "read_composition",
        "read_queue_observation",
        "read_protection_manifest",
        "read_attestation_manifest",
        "read_merge_group_checks",
        "read_intent",
        "read_preparation_authorization",
        "read_queue_admission",
        "read_release_hold",
        "read_release_authorization",
        "read_release_transition",
        "read_provider_receipt",
        "read_reconciliation",
        "read_rollback_authorization",
        "read_inverse_delta",
        "read_rollback_intent",
        "read_attempt",
        "read_eligibility",
        "read_completion",
    )
    for name in readers:
        assert getattr(journal, name)(D) is None
    assert (
        journal._run_nonce_path("admission", "run/../x", "nonce").parent.name
        == "admission-run-nonce"
    )
    with pytest.raises(ValueError):
        journal._sequence_path(0)
    with pytest.raises(MainGraduationJournalError):
        journal._read_reference(tmp_path / "missing")
    assert journal.read_eligibility_sequence(1) is None
    with pytest.raises(MainGraduationJournalError):
        journal._index_run_nonce("admission", MainReleaseHoldObservation.model_construct(), ref())
    with pytest.raises(ValueError):
        _strict_pairs([("x", 1), ("x", 2)])
    _sync_directory(tmp_path)


def test_composition_verifier_binding_is_not_public(tmp_path: Path) -> None:
    journal = MainGraduationJournal(tmp_path)
    assert not hasattr(journal, "bind_composition_verifier")
    with pytest.raises(TypeError):
        MainGraduationJournal(tmp_path / "other", composition_verifier=object())  # type: ignore[call-arg]


@pytest.mark.parametrize(
    "field",
    [
        "intent.target_ref",
        "bundle.snapshot.target_ref",
        "bundle.comparison.target_ref",
        "observation.base_ref",
        "reconciliation.target_ref",
    ],
)
def test_journal_requires_exact_five_edge_integration_target_closure(field: str) -> None:
    package: Any = SimpleNamespace(
        intent=SimpleNamespace(target_ref="refs/heads/integration"),
        bundle=SimpleNamespace(
            snapshot=SimpleNamespace(target_ref="refs/heads/integration"),
            comparison=SimpleNamespace(target_ref="refs/heads/integration"),
        ),
        observation=SimpleNamespace(base_ref="refs/heads/integration"),
        reconciliation=SimpleNamespace(target_ref="refs/heads/integration"),
    )
    owner = package
    parts = field.split(".")
    for part in parts[:-1]:
        owner = getattr(owner, part)
    setattr(owner, parts[-1], "refs/heads/main")
    with pytest.raises(ValueError, match="integration target closure"):
        MainGraduationJournal._require_integration_target(package)


def test_new_plan_requires_verifier_even_after_hand_recording_c2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = authority_plan()
    journal = MainGraduationJournal(tmp_path)
    monkeypatch.setattr(journal, "_verify_plan_evidence", lambda _plan: None)
    with pytest.raises(MainGraduationJournalError, match="composition authority"):
        journal.record_plan(value)
    assert not (tmp_path / "main-graduation-index" / "plan").exists()


def test_hand_recorded_valid_looking_c2_cannot_bypass_plan_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = authority_plan()
    journal = MainGraduationJournal(tmp_path)
    monkeypatch.setattr(journal, "_verify_source_package", lambda _source: None)
    monkeypatch.setattr(journal, "_verify_plan_evidence", lambda _plan: None)
    journal.record_source_package(value.package)
    journal.record_delta(value.delta)
    journal.record_composition(value.composition)
    with pytest.raises(MainGraduationJournalError, match="composition authority"):
        journal.record_plan(value)


def test_restart_has_no_live_verifier_rebind_seam(tmp_path: Path) -> None:
    first = MainGraduationJournal(tmp_path)
    second = MainGraduationJournal(tmp_path)
    assert not hasattr(first, "bind_composition_verifier")
    assert not hasattr(second, "bind_composition_verifier")


def test_journal_ledger_indexes_and_tamper_detection(tmp_path: Path) -> None:
    journal = MainGraduationJournal(tmp_path)
    started = EligibilityLedgerStarted(
        activation_digest=D,
        repository_digest=R,
        controller_config_digest=D2,
        scheduler_sequence_watermark=0,
        streak=0,
    )
    stored = journal.record_ledger_started(started)
    assert journal.read_ledger_started(D)[1] == stored  # type: ignore[index]
    eligibility = MainGraduationEligibilityRecord(
        operation_id=D,
        repository_digest=R,
        scheduler_sequence=1,
        submission_digest=D,
        classification="excluded",
        exclusion_reason="not ordinary",
        exclusion_evidence_digest=D,
        ordinary=False,
        nonempty=True,
    )
    journal.record_eligibility(eligibility)
    assert journal.read_eligibility_sequence(1) is not None
    index = tmp_path / "main-graduation-index" / "eligibility" / (D[7:] + ".json")
    index.write_text("{}", encoding="utf-8")
    with pytest.raises(MainGraduationJournalError):
        journal.read_eligibility(D)
    sequence = tmp_path / "main-graduation-index" / "ledger-sequence" / "00000000000000000001.json"
    sequence.write_text('{"operation_id":"' + D + '","operation_id":"' + D + '"}', encoding="utf-8")
    with pytest.raises(MainGraduationJournalError):
        journal.read_eligibility_sequence(1)


def test_completion_orchestration_and_conflict_edges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = MainGraduationJournal(tmp_path)
    package = completion()
    values = journal._child_values(package)
    assert len(values) == 18
    called: list[str] = []
    monkeypatch.setattr(journal, "_require_exact", lambda kind, record: called.append(kind))
    for name in (
        "_verify_source_package",
        "_verify_plan_evidence",
        "_require_preparation_chain",
        "_require_admission",
        "_require_hold",
        "_require_release_authorization",
        "_require_provider_receipt",
        "_require_reconciliation",
    ):
        monkeypatch.setattr(journal, name, lambda record, _name=name: called.append(_name))
    journal._verify_completion_prerequisites(package)
    assert called[:3] == ["source-package", "delta", "composition"]
    assert len(called) == 26
    monkeypatch.setattr(journal, "_verify_completion_prerequisites", lambda package: None)
    with pytest.raises(MainGraduationJournalError, match="content-bound"):
        journal._materialize_children(package)
    with pytest.raises(MainGraduationJournalError, match="metadata mismatch"):
        journal._verify_children(package)
    with pytest.raises(MainGraduationJournalError, match="durable"):
        MainGraduationJournal._require_exact(journal, "plan", package.plan)
    admission = MainQueueAdmissionObservation.model_construct(operation_id=D)
    with pytest.raises(MainGraduationJournalError, match="durable eligibility"):
        journal._require_attempt_eligibility(MainGraduationAttempt.model_construct(operation_id=D))
    with pytest.raises(MainGraduationJournalError, match="durable intent"):
        journal._require_rollback_intent(MainRollbackAuthorization.model_construct(operation_id=D))
    with pytest.raises(MainGraduationJournalError, match="durable inverse"):
        journal._require_inverse_delta(MainRollbackIntent.model_construct(operation_id=D))
    with pytest.raises(MainGraduationJournalError, match="durable release authorization"):
        MainGraduationJournal._require_provider_receipt(
            journal, MainProviderReceipt.model_construct(operation_id=D)
        )
    with pytest.raises(MainGraduationJournalError, match="durable release"):
        MainGraduationJournal._require_release_authorization(
            journal, MainReleaseTransitionReceipt.model_construct(operation_id=D)
        )
    with pytest.raises(MainGraduationJournalError, match="durable pending"):
        MainGraduationJournal._require_hold(
            journal, MainReleaseAuthorization.model_construct(operation_id=D)
        )
    with pytest.raises(MainGraduationJournalError, match="durable queue admission"):
        MainGraduationJournal._require_admission(
            journal, MainReleaseHoldObservation.model_construct(operation_id=D)
        )
    with pytest.raises(MainGraduationJournalError, match="durable queue"):
        MainGraduationJournal._require_queue_admission(journal, admission)
    with pytest.raises(MainGraduationJournalError, match="durable source"):
        MainGraduationJournal._verify_plan_evidence(
            journal, MainGraduationPlan.model_construct(operation_id=D)
        )
    with pytest.raises(MainGraduationJournalError, match="source package or child"):
        MainGraduationJournal._verify_source_package(journal, source())
    with pytest.raises(MainGraduationJournalError, match="lease evidence"):
        journal._verify_intent_lease(
            MainGraduationIntent.model_construct(
                operation_id=D,
                repository_digest=R,
                target_ref="refs/heads/main",
                lease_identity="lease",
                lease_digest=D,
                lease_evidence=MainLeaseEvidence.model_construct(
                    operation_id=D,
                    repository_digest=R,
                    target_ref="refs/heads/main",
                    identity="lease",
                    lease_digest=D,
                ),
                lease_evidence_artifact=ref(),
            )
        )
    nonce_admission = MainQueueAdmissionObservation.model_construct(
        operation_id=D, admission_run_id="run", admission_nonce="nonce"
    )
    assert journal._index_run_nonce("admission", nonce_admission, ref()) is None
    with pytest.raises(MainGraduationRecordConflictError, match="not bound"):
        journal._index_run_nonce("admission", nonce_admission, ref())


def test_plan_intent_and_preparation_validators_close_authority_chain() -> None:
    graduation_plan = plan()
    assert graduation_plan.validate_plan() is graduation_plan
    for field, value in (
        ("repository_digest", D2),
        ("operation_id", D2),
        ("controller_config_digest", D),
    ):
        with pytest.raises(ValueError):
            graduation_plan.model_copy(update={field: value}).validate_plan()
    with pytest.raises(ValueError):
        graduation_plan.model_copy(
            update={
                "evidence_artifacts": [
                    graduation_plan.evidence_artifacts[0],
                    graduation_plan.evidence_artifacts[0],
                ]
            }
        ).validate_plan()
    lease_values = {
        "operation_id": D,
        "repository_digest": R,
        "identity": "lease",
        "acquired_at": NOW,
        "expires_at": NOW + timedelta(minutes=5),
    }
    lease_probe = MainLeaseEvidence.model_construct(**lease_values, lease_digest=D)
    lease = MainLeaseEvidence.model_validate(
        {
            **lease_values,
            "lease_digest": canonical_digest(
                lease_probe.model_dump(exclude={"lease_digest"}, mode="json")
            ),
        }
    )
    lease_payload = main_record_bytes(lease)
    lease_ref = ArtifactRef(
        digest=canonical_digest(lease),
        size_bytes=len(lease_payload),
        media_type="application/vnd.avo.main-graduation-lease-evidence+json",
        role="main-graduation-lease-evidence",
        created_at=NOW,
    )
    intent_values = {
        "operation_id": D,
        "repository_digest": R,
        "plan_digest": canonical_digest(graduation_plan),
        "package_digest": D,
        "composition_digest": D2,
        "base_commit": BASE,
        "base_tree": TREE,
        "candidate_commit": HEAD,
        "candidate_tree": TREE,
        "candidate_ref": "refs/heads/avo/candidate/" + "a" * 64,
        "lease_identity": "lease",
        "lease_digest": lease.lease_digest,
        "lease_evidence": lease,
        "lease_evidence_artifact": lease_ref,
        "policy_epoch": D,
        "recorded_at": NOW,
    }
    intent_probe = MainGraduationIntent.model_construct(**intent_values, intent_digest=D)
    intent = MainGraduationIntent.model_validate(
        {
            **intent_values,
            "intent_digest": canonical_digest(
                intent_probe.model_dump(exclude={"intent_digest"}, mode="json")
            ),
        }
    )
    assert intent.validate_intent() is intent
    with pytest.raises(ValueError):
        intent.model_copy(update={"lease_identity": "other"}).validate_intent()
    prep_values = {
        "operation_id": D,
        "repository_digest": R,
        "plan_digest": canonical_digest(graduation_plan),
        "intent_digest": canonical_digest(intent),
        "package_digest": D,
        "composition_digest": D2,
        "base_commit": BASE,
        "base_tree": TREE,
        "candidate_commit": HEAD,
        "candidate_tree": TREE,
        "lease_identity": "lease",
        "lease_digest": lease.lease_digest,
        "policy_epoch": D,
        "authorized_at": NOW,
    }
    prep_probe = MainPreparationAuthorization.model_construct(**prep_values, authorization_digest=D)
    prep = MainPreparationAuthorization.model_validate(
        {
            **prep_values,
            "authorization_digest": canonical_digest(
                prep_probe.model_dump(exclude={"authorization_digest"}, mode="json")
            ),
        }
    )
    assert prep.validate_authorization() is prep
    with pytest.raises(ValueError):
        prep.model_copy(update={"lease_digest": D2}).validate_authorization()


def test_admission_hold_and_release_contract_validators_cover_bindings() -> None:
    package = completion()
    admission = package.admission_observation
    assert admission.validate_admission() is admission
    for field, value in (
        ("admission_sha", BASE),
        ("head_commit", BASE),
        ("release_issuer_app_id", 15368),
        ("pull_request_url", "http://example.test/p/1"),
    ):
        with pytest.raises(ValueError):
            admission.model_copy(update={field: value}).validate_admission()
    hold = package.hold_observation
    assert hold.validate_hold() is hold
    for field, value in (
        ("queue_members", [2]),
        ("group_parents", [HEAD, BASE]),
        ("group_parents", [BASE, BASE]),
        ("expected_group_parents", [BASE]),
        ("group_tree", BASE),
        ("composition_tree", BASE),
        ("release_issuer_app_id", 15368),
    ):
        with pytest.raises(ValueError):
            hold.model_copy(update={field: value}).validate_hold()
    auth = package.release_authorization
    auth = auth.model_copy(
        update={
            "authorization_digest": canonical_digest(
                auth.model_dump(exclude={"authorization_digest"}, mode="json")
            )
        }
    )
    assert auth.validate_release_authorization() is auth
    with pytest.raises(ValueError):
        auth.model_copy(update={"expires_at": NOW}).validate_release_authorization()
    with pytest.raises(ValueError):
        auth.model_copy(update={"release_issuer_app_id": 15368}).validate_release_authorization()


def test_journal_materializes_and_verifies_every_completion_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = MainGraduationJournal(tmp_path)
    package = completion()
    monkeypatch.setattr(journal, "_verify_completion_prerequisites", lambda _package: None)
    values = journal._child_values(package)
    references = []
    for role, value in values.items():
        payload = canonical_bytes(value)
        references.append(
            ArtifactRef(
                digest=_digest_bytes(payload),
                size_bytes=len(payload),
                media_type=f"application/vnd.avo.{role}+json",
                role=role,
                created_at=NOW,
            )
        )
    object.__setattr__(package, "artifacts", references)
    journal._materialize_children(package)
    journal._verify_children(package)
    object.__setattr__(
        package,
        "artifacts",
        [references[0].model_copy(update={"digest": D2}), *references[1:]],
    )
    with pytest.raises(
        MainGraduationJournalError, match=r"content-bound|metadata mismatch|unreadable"
    ):
        journal._verify_children(package)
    object.__setattr__(package, "artifacts", references)
    journal.delete_artifact(references[-1].digest)
    with pytest.raises(MainGraduationJournalError, match="unreadable"):
        journal._verify_children(package)


def test_journal_deep_stage_bindings_validate_from_durable_map(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = MainGraduationJournal(tmp_path)
    package = completion()
    admission = package.admission_observation
    hold = package.hold_observation
    prep = package.preparation_authorization
    authorization = package.release_authorization
    transition = package.transition_receipt
    object.__setattr__(package.intent, "candidate_ref", package.composition.candidate_ref)
    object.__setattr__(prep, "intent_digest", canonical_digest(package.intent))
    object.__setattr__(admission, "preparation_authorization_digest", canonical_digest(prep))
    object.__setattr__(hold, "preparation_authorization_digest", canonical_digest(prep))
    object.__setattr__(hold, "admission_observation_digest", canonical_digest(admission))
    object.__setattr__(
        hold, "attestation_manifest_digest", canonical_digest(package.attestation_manifest)
    )
    object.__setattr__(authorization, "admission_observation_digest", canonical_digest(admission))
    object.__setattr__(authorization, "preparation_authorization_digest", canonical_digest(prep))
    object.__setattr__(authorization, "hold_observation_digest", canonical_digest(hold))
    object.__setattr__(transition, "release_authorization_digest", canonical_digest(authorization))
    object.__setattr__(
        package.provider_receipt,
        "release_authorization_digest",
        canonical_digest(authorization),
    )
    object.__setattr__(
        package.reconciliation,
        "transition_receipt_digest",
        canonical_digest(transition),
    )
    records = {
        "plan": package.plan,
        "intent": package.intent,
        "preparation-authorization": prep,
        "queue-admission": admission,
        "release-hold": hold,
        "queue": package.queue_observation,
        "protection": package.protection_manifest,
        "attestations": package.attestation_manifest,
        "merge-group-checks": package.merge_group_checks,
        "release-authorization": authorization,
        "release-transition": transition,
        "provider-receipt": package.provider_receipt,
        "reconciliation": package.reconciliation,
        "merge-group-webhook-receipt": hold.merge_group_receipt,
    }

    def read(kind: str, _operation_id: str) -> tuple[Any, ArtifactRef] | None:
        value = records.get(kind)
        return None if value is None else (value, ref())

    monkeypatch.setattr(journal, "_read", read)
    journal._require_preparation_chain(prep)
    journal._require_queue_admission(admission)
    journal._require_admission(hold)
    journal._require_hold(authorization)
    journal._require_release_authorization(transition)
    journal._require_provider_receipt(package.provider_receipt)
    journal._require_reconciliation(package.reconciliation)


def test_journal_source_package_closure_reads_all_canonical_children(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = MainGraduationJournal(tmp_path)
    package_bytes = b"{}"
    child_bytes = b'{"child":true}'
    package_ref = ArtifactRef(
        digest=_digest_bytes(package_bytes),
        size_bytes=len(package_bytes),
        media_type="application/vnd.avo.integration-campaign+json",
        role="integration-campaign-package",
        created_at=NOW,
    )
    child_ref = ArtifactRef(
        digest=_digest_bytes(child_bytes),
        size_bytes=len(child_bytes),
        media_type="application/vnd.avo.child+json",
        role="child",
        created_at=NOW,
    )
    lease_bytes = b'{"lease":true}'
    lease_ref = child_ref.model_copy(
        update={
            "digest": _digest_bytes(lease_bytes),
            "size_bytes": len(lease_bytes),
            "role": "promotion-lease-evidence",
            "media_type": "application/vnd.avo.main-graduation-lease-evidence+json",
        }
    )
    source = SimpleNamespace(
        receipt=SimpleNamespace(outcome="applied", applied_result_commit=HEAD,
                                applied_result_tree=TREE, applied_result_parent_commit=BASE),
        reconciliation=SimpleNamespace(
            target_ref="refs/heads/integration", target_head_commit=HEAD,
            target_head_tree=TREE, target_first_parent=BASE, target_parents=[BASE],
        ),
        intent=SimpleNamespace(
            target_ref="refs/heads/integration", repository_digest=R,
            operation_id=D2,
        ),
        bundle=SimpleNamespace(
            snapshot=SimpleNamespace(target_ref="refs/heads/integration"),
            comparison=SimpleNamespace(target_ref="refs/heads/integration"),
            controller_config=SimpleNamespace(controller_identity="source-controller"),
        ),
        observation=SimpleNamespace(base_ref="refs/heads/integration"),
        evidence_artifacts=[child_ref],
        lease_evidence_artifact=lease_ref,
        deploy_performed=False,
    )
    binding = MainSourcePackageBinding.model_construct(
        operation_id=D,
        source_operation_id=D2,
        repository_digest=R,
        package_digest=D,
        package_artifact=package_ref,
        child_artifacts=[child_ref, lease_ref],
        source_result_commit=HEAD,
        source_result_tree=TREE,
        source_result_parent=BASE,
        source_issuer="source-controller",
        source_domain="integration-campaign",
    )
    monkeypatch.setattr(
        journal_module.IntegrationCampaignEvidencePackage,
        "model_validate",
        staticmethod(lambda _parsed: source),
    )
    monkeypatch.setattr(journal_module, "verify_campaign_package_artifact", lambda *_args: D)
    monkeypatch.setattr(
        journal._store,
        "read_bytes",
        lambda reference: (
            package_bytes
            if reference == package_ref
            else lease_bytes
            if reference == lease_ref
            else child_bytes
        ),
    )
    journal._verify_source_package(binding)
    for field, value in (
        ("deploy_performed", True),
        ("intent", SimpleNamespace(target_ref="refs/heads/integration", repository_digest=D,
                                   operation_id=D2)),
        ("evidence_artifacts", []),
    ):
        broken = SimpleNamespace(**{**vars(source), field: value})
        monkeypatch.setattr(
            journal_module.IntegrationCampaignEvidencePackage,
            "model_validate",
            staticmethod(lambda _parsed, broken=broken: broken),
        )
        with pytest.raises(MainGraduationJournalError):
            journal._verify_source_package(binding)


def test_journal_intent_lease_and_webhook_metadata_are_verified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = MainGraduationJournal(tmp_path)
    read_bytes = journal._store.read_bytes
    package = completion()
    intent = package.intent
    lease_values = {
        "operation_id": intent.operation_id,
        "repository_digest": intent.repository_digest,
        "target_ref": intent.target_ref,
        "identity": intent.lease_identity,
        "acquired_at": NOW,
        "expires_at": NOW + timedelta(minutes=5),
    }
    lease_probe = MainLeaseEvidence.model_construct(**lease_values, lease_digest=D)
    lease = MainLeaseEvidence.model_validate(
        {
            **lease_values,
            "lease_digest": canonical_digest(
                lease_probe.model_dump(exclude={"lease_digest"}, mode="json")
            ),
        }
    )
    object.__setattr__(intent, "lease_evidence", lease)
    object.__setattr__(intent, "lease_digest", lease.lease_digest)
    lease_bytes = canonical_bytes(lease)
    lease_ref = ArtifactRef(
        digest=_digest_bytes(lease_bytes),
        size_bytes=len(lease_bytes),
        media_type="application/vnd.avo.main-graduation-lease-evidence+json",
        role="main-graduation-lease-evidence",
        created_at=NOW,
    )
    object.__setattr__(intent, "lease_evidence_artifact", lease_ref)
    monkeypatch.setattr(journal._store, "read_bytes", lambda _reference: lease_bytes)
    journal._verify_intent_lease(intent)
    monkeypatch.setattr(journal._store, "read_bytes", lambda _reference: b"{}")
    with pytest.raises(MainGraduationJournalError, match="lease"):
        journal._verify_intent_lease(intent)
    monkeypatch.setattr(journal._store, "read_bytes", read_bytes)

    receipt = package.hold_observation.merge_group_receipt
    reference = journal.record_merge_group_webhook_receipt(receipt)
    delivery_index = journal._webhook_delivery_path(receipt.delivery_id)
    envelope = json.loads(delivery_index.read_text(encoding="utf-8"))
    envelope["reference"]["role"] = "wrong"
    delivery_index.write_text(json.dumps(envelope, separators=(",", ":")), encoding="utf-8")
    with pytest.raises(MainGraduationRecordConflictError, match="reference"):
        journal.read_merge_group_webhook_receipt(receipt.operation_id)
    assert reference.digest


def test_journal_record_read_and_sequence_integrity_edges(tmp_path: Path) -> None:
    journal = MainGraduationJournal(tmp_path)
    started = EligibilityLedgerStarted(
        activation_digest=D,
        repository_digest=R,
        controller_config_digest=D2,
        scheduler_sequence_watermark=0,
        streak=0,
    )
    first = journal.record_ledger_started(started)
    assert journal.record_ledger_started(started) == first
    with pytest.raises(MainGraduationRecordConflictError):
        journal.record_ledger_started(started.model_copy(update={"streak": 1}))
    eligibility = MainGraduationEligibilityRecord(
        operation_id=D,
        repository_digest=R,
        scheduler_sequence=1,
        submission_digest=D,
        classification="excluded",
        exclusion_reason="not ordinary",
        exclusion_evidence_digest=D,
        ordinary=False,
        nonempty=True,
    )
    journal.record_eligibility(eligibility)
    assert journal.read_eligibility_sequence(1) is not None
    sequence = tmp_path / "main-graduation-index" / "ledger-sequence" / "00000000000000000001.json"
    sequence.write_text('{"operation_id":"bad","reference":{}}', encoding="utf-8")
    with pytest.raises(MainGraduationJournalError):
        journal.read_eligibility_sequence(1)
    sequence.write_text(
        json.dumps(
            {"operation_id": D, "reference": first.model_dump(mode="json")},
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    with pytest.raises(MainGraduationJournalError):
        journal.read_eligibility_sequence(1)
    index = tmp_path / "main-graduation-index" / "ledger-started" / (D[7:] + ".json")
    index.write_text("{}", encoding="utf-8")
    with pytest.raises(MainGraduationJournalError):
        journal.read_ledger_started(D)


def test_journal_run_nonce_index_is_create_once_and_strictly_recoverable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = MainGraduationJournal(tmp_path)
    record = MainQueueAdmissionObservation.model_construct(
        operation_id=D, admission_run_id="admission-run", admission_nonce="admission-nonce"
    )
    reference = ref()
    monkeypatch.setattr(journal, "_read", lambda _kind, _key: (record, reference))
    assert journal._index_run_nonce("admission", record, reference) is None
    assert journal._index_run_nonce("admission", record, reference) == reference
    path = journal._run_nonce_path("admission", "admission-run", "admission-nonce")
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(MainGraduationJournalError, match="run/nonce"):
        journal._index_run_nonce("admission", record, reference)
    with pytest.raises(MainGraduationJournalError, match="malformed"):
        journal._index_run_nonce("wrong", record, reference)
