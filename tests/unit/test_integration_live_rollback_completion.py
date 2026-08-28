from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from avo_correlate.adapters.artifacts.live_rollback_completion_journal import (
    LiveRollbackCompletionJournal,
    LiveRollbackCompletionJournalError,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_live_rollback_completion import (
    LiveRollbackCheckEntry,
    LiveRollbackCompletionPackage,
    LiveRollbackManifestEvidence,
    LiveRollbackProtectionEntry,
    LiveRollbackPublicationEvidence,
    LiveRollbackPublicationOutcome,
    LiveRollbackPublicationPlan,
    LiveRollbackWorkflowEvidence,
)
from avo_correlate.contracts.integration_promotion import (
    IntegrationProviderObservation,
    IntegrationProviderReconciliation,
)
from avo_correlate.contracts.synthetic_validation import (
    SyntheticValidationCompletionProof,
    SyntheticValidationCreateAuthorization,
    SyntheticValidationObservation,
    SyntheticValidationOutcome,
    SyntheticValidationPlan,
    SyntheticValidationRequest,
    synthetic_validation_operation_id,
    validation_ref_for,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest
from tests.unit.test_integration_live_rollback import (  # pyright: ignore[reportPrivateUsage]
    _package_fixture,  # pyright: ignore[reportPrivateUsage]
)

D = "sha256:" + "a" * 64
NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _ref(value: object, role: str, media_type: str) -> ArtifactRef:
    return ArtifactRef(
        digest=canonical_digest(value),
        size_bytes=len(canonical_bytes(value)),
        media_type=media_type,
        role=role,
        created_at=NOW,
    )


def _completion_fixture() -> LiveRollbackCompletionPackage:
    core = _package_fixture()  # pyright: ignore[reportPrivateUsage]
    request = core.request
    plan_values: dict[str, Any] = {
        "schema_version": 1,
        "repository_digest": request.repository_digest,
        "base_commit": request.failed_integration_head_commit,
        "base_tree": request.failed_integration_head_tree,
        "candidate_digest": core.bundle.request.candidate_digest,
        "candidate_ref": core.publication.candidate_ref,
        "candidate_commit": request.rollback_candidate_commit,
        "candidate_tree": request.restore_to_tree,
        "controller_identity": "controller",
        "target_ref": request.target_ref,
    }
    plan_values["publication_id"] = canonical_digest(plan_values)
    publication_plan = LiveRollbackPublicationPlan.model_construct(**plan_values)
    publication_evidence = LiveRollbackPublicationEvidence.model_construct(
        publication_id=publication_plan.publication_id,
        repository_digest=request.repository_digest,
        remote="https://github.com/vandyand/avo.git",
        candidate_ref=publication_plan.candidate_ref,
        candidate_commit=publication_plan.candidate_commit,
        candidate_tree=publication_plan.candidate_tree,
        base_commit=publication_plan.base_commit,
        base_tree=publication_plan.base_tree,
        candidate_digest=publication_plan.candidate_digest,
    )
    publication_outcome = LiveRollbackPublicationOutcome.model_construct(
        publication_id=publication_plan.publication_id,
        repository_digest=request.repository_digest,
        base_commit=publication_plan.base_commit,
        base_tree=publication_plan.base_tree,
        candidate_ref=publication_plan.candidate_ref,
        candidate_commit=publication_plan.candidate_commit,
        candidate_tree=publication_plan.candidate_tree,
        candidate_digest=publication_plan.candidate_digest,
        outcome="verified",
        evidence_digest=canonical_digest(publication_evidence),
    )
    provider_observation = IntegrationProviderObservation.model_construct(
        repository_digest=request.repository_digest,
        pull_request_number=99,
        pull_request_url="https://github.com/vandyand/avo/pull/99",
        candidate_repository_digest=request.repository_digest,
        target_repository_digest=request.repository_digest,
        base_ref=request.target_ref,
        base_commit=request.failed_integration_head_commit,
        base_tree=request.failed_integration_head_tree,
        head_ref=publication_plan.candidate_ref,
        head_commit=publication_plan.candidate_commit,
        candidate_tree=publication_plan.candidate_tree,
        synthetic_merge_commit=core.promotion_intent.synthetic_merge_commit,
        synthetic_merge_tree=core.promotion_intent.synthetic_merge_tree,
        protection_evidence_digest=core.promotion_intent.protection_evidence_digest,
        check_evidence_manifest_digest=D,
        provider_identity=core.promotion_intent.provider_identity,
        provider_api_version=core.promotion_intent.provider_api_version,
        open_state="open",
        draft=False,
    )
    provider_reconciliation = IntegrationProviderReconciliation.model_construct(
        repository_digest=request.repository_digest,
        pull_request_number=99,
        pull_request_url="https://github.com/vandyand/avo/pull/99",
        provider_identity=provider_observation.provider_identity,
        provider_api_version=provider_observation.provider_api_version,
        state="closed",
        merged=True,
        merge_commit=core.promotion_receipt.applied_result_commit,
        target_ref=request.target_ref,
        target_head_commit=core.promotion_receipt.applied_result_commit,
        target_head_tree=core.promotion_receipt.applied_result_tree,
        target_first_parent=request.failed_integration_head_commit,
        target_parents=[request.failed_integration_head_commit],
        protection_evidence_digest=provider_observation.protection_evidence_digest,
    )
    check_manifest = LiveRollbackManifestEvidence.model_construct(
        kind="trusted-check-manifest",
        repository_digest=request.repository_digest,
        target_ref=request.target_ref,
        source_commit=provider_observation.synthetic_merge_commit,
        manifest_digest=provider_observation.check_evidence_manifest_digest,
        provider_identity=provider_observation.provider_identity,
        provider_api_version=provider_observation.provider_api_version,
            entries=[
                "avo synthetic validate (ubuntu-latest)",
                "avo synthetic validate (windows-latest)",
            ],
            check_entries=[LiveRollbackCheckEntry.model_construct(
            name="avo synthetic validate",
            app_id=15368,
            context="avo synthetic validate (ubuntu-latest)",
            sha=provider_observation.synthetic_merge_commit,
            status="completed",
                conclusion="success",
                completed_at=NOW,
            ), LiveRollbackCheckEntry.model_construct(
                name="avo synthetic validate",
                app_id=15368,
                context="avo synthetic validate (windows-latest)",
                sha=provider_observation.synthetic_merge_commit,
                status="completed",
                conclusion="success",
                completed_at=NOW,
            )],
            protection_entries=[],
            freshness_cutoff=NOW - timedelta(hours=1),
            observed_at=NOW,
        source_pinned=True,
    )
    protection_manifest = LiveRollbackManifestEvidence.model_construct(
        kind="protection-manifest",
        repository_digest=request.repository_digest,
        target_ref=request.target_ref,
        source_commit=request.failed_integration_head_commit,
        manifest_digest=provider_observation.protection_evidence_digest,
        provider_identity=provider_observation.provider_identity,
        provider_api_version=provider_observation.provider_api_version,
            entries=["validate (ubuntu-latest)", "validate (windows-latest)"],
        check_entries=[],
            protection_entries=[LiveRollbackProtectionEntry.model_construct(
                context="validate (ubuntu-latest)",
                required=True,
                enforced=True,
            ), LiveRollbackProtectionEntry.model_construct(
                context="validate (windows-latest)",
                required=True,
                enforced=True,
            )],
            freshness_cutoff=NOW - timedelta(hours=1),
            observed_at=NOW,
        source_pinned=True,
    )
    workflow = LiveRollbackWorkflowEvidence.model_construct(
        repository_digest=request.repository_digest,
        target_ref=request.target_ref,
        source_commit=request.failed_integration_head_commit,
        workflow_path=".github/workflows/synthetic-validation.yml",
        workflow_blob_digest=D,
        repository_variables_digest=D,
        repository_variables_match=True,
        provider_identity=provider_observation.provider_identity,
        provider_api_version=provider_observation.provider_api_version,
    )
    validation_observation = SyntheticValidationObservation.model_construct(
        repository_digest=request.repository_digest,
        base_ref=request.target_ref,
        base_commit=request.failed_integration_head_commit,
        base_tree=request.failed_integration_head_tree,
        head_ref=publication_plan.candidate_ref,
        head_commit=publication_plan.candidate_commit,
        head_tree=publication_plan.candidate_tree,
        synthetic_commit=provider_observation.synthetic_merge_commit,
        synthetic_tree=provider_observation.synthetic_merge_tree,
    )
    validation_request = SyntheticValidationRequest.model_construct(
        observation=validation_observation,
        target_repository_digest=request.repository_digest,
        target_ref=request.target_ref,
        target_identity="pr-99",
            trusted_check_contexts=[
                "avo synthetic validate (ubuntu-latest)",
                "avo synthetic validate (windows-latest)",
            ],
        provider_identity=provider_observation.provider_identity,
        provider_api_version=provider_observation.provider_api_version,
    )
    validation_operation = synthetic_validation_operation_id(validation_request)
    validation_plan = SyntheticValidationPlan.model_construct(
        operation_id=validation_operation,
        request=validation_request,
        validation_ref=validation_ref_for(validation_operation),
        expected_commit=provider_observation.synthetic_merge_commit,
        expected_tree=provider_observation.synthetic_merge_tree,
    )
    validation_authorization = SyntheticValidationCreateAuthorization.model_construct(
        operation_id=validation_plan.operation_id,
        plan_digest=validation_plan.plan_digest,
        validation_ref=validation_plan.validation_ref,
        expected_commit=validation_plan.expected_commit,
        expected_tree=validation_plan.expected_tree,
    )
    validation_outcome = SyntheticValidationOutcome.model_construct(
        operation_id=validation_plan.operation_id,
        plan_digest=validation_plan.plan_digest,
        validation_ref=validation_plan.validation_ref,
        expected_commit=validation_plan.expected_commit,
        expected_tree=validation_plan.expected_tree,
        outcome="created",
        observed_commit=validation_plan.expected_commit,
        observed_tree=validation_plan.expected_tree,
    )
    cleanup_proof = SyntheticValidationCompletionProof.model_construct(
        operation_id=validation_plan.operation_id,
        plan_digest=validation_plan.plan_digest,
        completion_digest=canonical_digest(core),
        completed=True,
    )
    cleanup_outcome = SyntheticValidationOutcome.model_construct(
        operation_id=validation_plan.operation_id,
        plan_digest=validation_plan.plan_digest,
        validation_ref=validation_plan.validation_ref,
        expected_commit=validation_plan.expected_commit,
        expected_tree=validation_plan.expected_tree,
        outcome="cleaned",
    )
    records: dict[str, object] = {
        "integration-live-rollback-package": core,
        "candidate-publication-plan": publication_plan,
        "candidate-publication-outcome": publication_outcome,
        "candidate-publication-evidence": publication_evidence,
        "integration-provider-observation": provider_observation,
        "integration-provider-reconciliation": provider_reconciliation,
        "trusted-check-manifest": check_manifest,
        "protection-manifest": protection_manifest,
        "workflow-evidence": workflow,
        "synthetic-validation-plan": validation_plan,
        "synthetic-validation-authorization": validation_authorization,
        "synthetic-validation-outcome": validation_outcome,
        "synthetic-validation-cleanup-proof": cleanup_proof,
        "synthetic-validation-cleanup": cleanup_outcome,
    }
    artifacts = [
        _ref(value, role, _media_type(role)) for role, value in records.items()
    ]
    return LiveRollbackCompletionPackage.model_validate(
        {
            "operation_id": core.operation_id,
            "core_package": core,
            "core_package_artifact": artifacts[0],
            "publication_plan": publication_plan,
            "publication_outcome": publication_outcome,
            "publication_evidence": publication_evidence,
            "provider_observation": provider_observation,
            "provider_reconciliation": provider_reconciliation,
            "check_manifest": check_manifest,
            "protection_manifest": protection_manifest,
            "workflow_evidence": workflow,
            "validation_plan": validation_plan,
            "validation_authorization": validation_authorization,
            "validation_outcome": validation_outcome,
            "cleanup_proof": cleanup_proof,
            "cleanup_outcome": cleanup_outcome,
            "artifacts": artifacts,
            "main_before_commit": request.main_before_commit,
            "main_after_commit": request.main_before_commit,
        }
    )


def _media_type(role: str) -> str:
    if role == "integration-live-rollback-package":
        return "application/vnd.avo.integration-live-rollback+json"
    if role.startswith("candidate-publication"):
        return "application/vnd.avo.candidate-publication+json"
    if role.startswith("integration-provider"):
        return "application/vnd.avo.integration-provider+json"
    if role in {"trusted-check-manifest", "protection-manifest"}:
        return "application/vnd.avo.integration-manifest+json"
    if role == "workflow-evidence":
        return "application/vnd.avo.workflow-evidence+json"
    return "application/vnd.avo.synthetic-validation+json"


def test_completion_package_binds_outer_evidence() -> None:
    package = _completion_fixture()
    assert package.cleanup_outcome.outcome == "cleaned"
    assert package.provider_reconciliation.target_parents == [
        package.core_package.request.failed_integration_head_commit
    ]


def test_completion_package_rejects_tampered_manifest() -> None:
    package = _completion_fixture()
    manifest = package.check_manifest.model_copy(
        update={"manifest_digest": "sha256:" + "b" * 64}
    )
    with pytest.raises(ValueError, match=r"provider-bound|artifact|topology"):
        package.model_copy(update={"check_manifest": manifest}).validate_package()  # pyright: ignore[reportCallIssue]


def test_completion_journal_indexes_only_after_cleanup(tmp_path: Path) -> None:
    package = _completion_fixture()
    journal = LiveRollbackCompletionJournal(tmp_path)
    assert journal.record_package(package).role == "integration-live-rollback-completion-package"
    assert journal.record_package(package) == journal.record_package(package)
    pending = package.model_copy(
        update={
            "cleanup_outcome": package.cleanup_outcome.model_copy(update={"outcome": "created"})
        }
    )
    with pytest.raises(LiveRollbackCompletionJournalError, match=r"cleanup|semantic"):
        journal.record_package(pending)


def test_completion_journal_rejects_missing_or_tampered_child(tmp_path: Path) -> None:
    package = _completion_fixture()
    journal = LiveRollbackCompletionJournal(tmp_path)
    journal.record_package(package)
    child = next(item for item in package.artifacts if item.role == "workflow-evidence")
    journal._store.path_for_digest(child.digest).unlink()  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(LiveRollbackCompletionJournalError, match=r"child|unverifiable"):
        journal.read_package(package.operation_id)


def test_completion_journal_semantically_validates_before_index(tmp_path: Path) -> None:
    package = _completion_fixture()
    journal = LiveRollbackCompletionJournal(tmp_path)
    invalid = package.model_copy(update={"deploy_performed": True})
    with pytest.raises(LiveRollbackCompletionJournalError, match="semantic"):
        journal.record_package(invalid)
    assert not (tmp_path / "live-rollback-completion-index").exists()
    traversal = package.model_copy(update={"operation_id": "../escape"})
    with pytest.raises(LiveRollbackCompletionJournalError, match="semantic"):
        journal.record_package(traversal)
    assert not (tmp_path / "escape.json").exists()


def test_completion_package_rejects_duplicate_or_stale_exact_checks() -> None:
    package = _completion_fixture()
    check = package.check_manifest.check_entries[0]
    duplicate = package.check_manifest.model_copy(
        update={"check_entries": [check, check]}
    )
    with pytest.raises(ValueError, match=r"exact|contexts|artifact|topology"):
        package.model_copy(update={"check_manifest": duplicate}).validate_package()  # pyright: ignore[reportCallIssue]
    stale = check.model_copy(update={"completed_at": NOW - timedelta(hours=2)})
    stale_manifest = package.check_manifest.model_copy(
        update={"check_entries": [stale, package.check_manifest.check_entries[1]]}
    )
    with pytest.raises(ValueError, match=r"exact|freshness|artifact|topology"):
        package.model_copy(update={"check_manifest": stale_manifest}).validate_package()  # pyright: ignore[reportCallIssue]


def test_completion_package_binds_reconciliation_protection_digest() -> None:
    package = _completion_fixture()
    changed = package.provider_reconciliation.model_copy(
        update={"protection_evidence_digest": "sha256:" + "b" * 64}
    )
    with pytest.raises(ValueError, match=r"topology|provider"):
        package.model_copy(update={"provider_reconciliation": changed}).validate_package()  # pyright: ignore[reportCallIssue]
