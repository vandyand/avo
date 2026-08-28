from typing import cast

import pytest

from avo_correlate.contracts.integration_promotion import (
    CandidatePublicationBinding,
    IntegrationPromotionIntent,
    IntegrationPromotionReceipt,
    IntegrationProviderObservation,
    IntegrationProviderReconciliation,
    integration_operation_id,
)

D = "sha256:" + "a" * 64
G = "a" * 40
H = "b" * 40
C = "c" * 40


def identity() -> dict[str, str]:
    return {
        "repository_digest": D,
        "candidate_ref": "refs/heads/candidate/x",
        "controller_lease_digest": D,
        "controller_lease_identity": "controller",
        "target_ref": "refs/heads/integration",
        "base_commit": G,
        "candidate_commit": H,
        "bundle_digest": D,
        "candidate_digest": D,
        "publication_evidence_digest": D,
        "provider_identity": "github",
        "provider_api_version": "2026-01",
        "merge_method": "squash",
        "pull_request_number": "7",
    }


def intent(**updates: object) -> IntegrationPromotionIntent:
    values: dict[str, object] = {
        **identity(),
        "operation_id": D,
        "base_tree": G,
        "candidate_tree": H,
        "controller_config_digest": D,
        "protection_evidence_digest": D,
        "evidence_manifest_digest": D,
        "check_evidence_manifest_digest": D,
        "candidate_repository_digest": D,
        "candidate_head_ref": "refs/heads/candidate/x",
        "candidate_head_commit": H,
        "candidate_head_tree": H,
        "target_repository_digest": D,
        "target_base_ref": "refs/heads/integration",
        "target_base_commit": G,
        "target_base_tree": G,
        "synthetic_merge_commit": H,
        "synthetic_merge_tree": H,
        "pull_request_number": 7,
        "pull_request_url": "https://github.com/o/r/pull/7",
        "state": "intent_recorded",
    }
    values.update(updates)
    if "operation_id" not in updates:
        current_identity = {
            key: cast(str, values[key])
            for key in (
                "repository_digest",
                "candidate_ref",
                "target_ref",
                "base_commit",
                "candidate_commit",
                "bundle_digest",
                "candidate_digest",
                "publication_evidence_digest",
                "provider_identity",
                "provider_api_version",
                "merge_method",
            )
        }
        current_identity["pull_request_number"] = str(values["pull_request_number"])
        current_identity.update(
            candidate_head_commit=cast(str, values["candidate_head_commit"]),
            target_base_commit=cast(str, values["target_base_commit"]),
            synthetic_merge_commit=cast(str, values["synthetic_merge_commit"]),
        )
        values["operation_id"] = integration_operation_id(**current_identity)
    return IntegrationPromotionIntent.model_validate(values)


def test_valid_intent_and_deterministic_identity() -> None:
    first = intent()
    second = intent()
    assert first == second


def test_candidate_publication_binding_is_strict_and_verified() -> None:
    binding = CandidatePublicationBinding(
        repository_digest=D,
        base_commit=G,
        base_tree=G,
        candidate_digest=D,
        candidate_ref="refs/heads/candidate/x",
        candidate_commit=H,
        candidate_tree=H,
        controller_publisher_identity="controller",
        publication_evidence_digest=D,
        verified=True,
    )
    assert binding.verified is True
    with pytest.raises(ValueError, match="verified"):
        CandidatePublicationBinding.model_validate(
            {**binding.model_dump(mode="python"), "verified": False}
        )
    with pytest.raises(ValueError, match="Git object"):
        CandidatePublicationBinding(
            repository_digest=D,
            base_commit="invalid",
            base_tree=G,
            candidate_digest=D,
            candidate_ref="refs/heads/candidate/x",
            candidate_commit=H,
            candidate_tree=H,
            controller_publisher_identity="controller",
            publication_evidence_digest=D,
            verified=True,
        )


def test_operation_identity_is_stable_across_fresh_execution_leases() -> None:
    first = intent()
    second = intent(
        controller_lease_identity="fresh-controller-lease",
        controller_lease_digest="sha256:" + "b" * 64,
    )
    assert first.operation_id == second.operation_id


def test_publication_evidence_changes_operation_identity() -> None:
    first = intent()
    second = intent(
        publication_evidence_digest="sha256:" + "b" * 64,
        operation_id=integration_operation_id(
            **{
                **{
                    key: str(getattr(first, key))
                    for key in (
                        "repository_digest",
                        "candidate_ref",
                        "target_ref",
                        "base_commit",
                        "candidate_commit",
                        "bundle_digest",
                        "candidate_digest",
                        "provider_identity",
                        "provider_api_version",
                        "merge_method",
                    )
                },
                "publication_evidence_digest": "sha256:" + "b" * 64,
                "pull_request_number": str(first.pull_request_number),
                "candidate_head_commit": first.candidate_head_commit,
                "target_base_commit": first.target_base_commit,
                "synthetic_merge_commit": first.synthetic_merge_commit,
            }
        ),
    )
    assert first.operation_id != second.operation_id


def test_main_and_deployment_targets_are_rejected() -> None:
    with pytest.raises(ValueError, match="main"):
        intent(target_ref="refs/heads/main")
    with pytest.raises(ValueError, match="deployment"):
        intent(target_ref="refs/heads/production-deploy")


def test_ref_confusion_and_malformed_objects_are_rejected() -> None:
    with pytest.raises(ValueError, match="differ"):
        intent(candidate_ref="refs/heads/integration")
    with pytest.raises(ValueError, match="Git object"):
        intent(base_commit="not-a-commit")
    with pytest.raises(ValueError, match="operation ID"):
        intent(operation_id=D)
    with pytest.raises(ValueError, match="case-insensitively"):
        intent(candidate_ref="refs/heads/INTEGRATION")


def test_intent_rejects_pr_binding_and_synthetic_tree_confusion() -> None:
    with pytest.raises(ValueError, match="base binding"):
        intent(target_base_commit=H)
    with pytest.raises(ValueError, match="candidate binding"):
        intent(candidate_head_tree=G)
    with pytest.raises(ValueError, match="synthetic merge tree"):
        intent(synthetic_merge_tree=G)


def test_success_receipt_requires_exact_head_and_provider_binding() -> None:
    values = {
        "operation_id": D,
        "intent_digest": D,
        "bundle_digest": D,
        "outcome": "applied",
        "observed_target_ref": "refs/heads/integration",
        "observed_base_commit": G,
        "observed_head_commit": C,
        "observed_head_tree": H,
        "expected_target_ref": "refs/heads/integration",
        "expected_candidate_commit": H,
        "expected_candidate_tree": H,
        "expected_base_commit": G,
        "expected_protection_evidence_digest": D,
        "expected_provider_identity": "github",
        "expected_provider_api_version": "2026-01",
        "merge_method": "squash",
        "applied_result_commit": C,
        "applied_result_tree": H,
        "applied_result_parent_commit": G,
        "observed_protection_evidence_digest": D,
        "observed_provider_identity": "github",
        "observed_provider_api_version": "2026-01",
        "observation_digest": D,
    }
    assert IntegrationPromotionReceipt.model_validate(values).outcome == "applied"
    with pytest.raises(ValueError, match="expected protected"):
        IntegrationPromotionReceipt.model_validate({**values, "observed_head_tree": G})


def test_non_applied_receipt_rejects_success_fields_and_missing_reconciliation_error() -> None:
    base = {
        "operation_id": D,
        "intent_digest": D,
        "bundle_digest": D,
        "outcome": "stale_base",
        "observed_target_ref": "refs/heads/integration",
        "observed_base_commit": G,
        "expected_target_ref": "refs/heads/integration",
        "expected_candidate_commit": H,
        "expected_candidate_tree": H,
        "expected_base_commit": G,
        "expected_protection_evidence_digest": D,
        "expected_provider_identity": "github",
        "expected_provider_api_version": "2026-01",
        "observed_protection_evidence_digest": D,
        "observed_provider_identity": "github",
        "observed_provider_api_version": "2026-01",
        "observation_digest": D,
        "merge_method": "squash",
    }
    assert IntegrationPromotionReceipt.model_validate(base).outcome == "stale_base"
    with pytest.raises(ValueError, match="reconciliation-required"):
        IntegrationPromotionReceipt.model_validate({**base, "outcome": "reconciliation_required"})


def test_provider_observation_requires_open_non_draft_pr_and_same_repositories() -> None:
    values = {
        "repository_digest": D,
        "pull_request_number": 7,
        "pull_request_url": "https://github.com/o/r/pull/7",
        "candidate_repository_digest": D,
        "target_repository_digest": D,
        "base_ref": "refs/heads/integration",
        "base_commit": G,
        "base_tree": G,
        "head_ref": "refs/heads/candidate/x",
        "head_commit": H,
        "candidate_tree": H,
        "synthetic_merge_commit": C,
        "synthetic_merge_tree": H,
        "protection_evidence_digest": D,
        "check_evidence_manifest_digest": D,
        "provider_identity": "github",
        "provider_api_version": "2026-01",
        "open_state": "open",
        "draft": False,
    }
    assert IntegrationProviderObservation.model_validate(values).open_state == "open"
    with pytest.raises(ValueError, match="repository"):
        IntegrationProviderObservation.model_validate(
            {**values, "target_repository_digest": "sha256:" + "b" * 64}
        )
    with pytest.raises(ValueError):
        IntegrationProviderObservation.model_validate({**values, "draft": True})


def test_provider_reconciliation_accepts_merged_and_unmerged_records() -> None:
    common = {
        "repository_digest": D,
        "pull_request_number": 7,
        "pull_request_url": "https://github.com/o/r/pull/7",
        "provider_identity": "github",
        "provider_api_version": "2026-01",
        "target_ref": "refs/heads/integration",
        "target_head_commit": C,
        "target_head_tree": H,
        "target_first_parent": G,
        "target_parents": [G],
        "protection_evidence_digest": D,
    }
    merged = IntegrationProviderReconciliation.model_validate(
        {**common, "state": "closed", "merged": True, "merge_commit": C}
    )
    unmerged = IntegrationProviderReconciliation.model_validate(
        {**common, "state": "open", "merged": False}
    )
    assert merged.merged and not unmerged.merged
    with pytest.raises(ValueError, match="closed"):
        IntegrationProviderReconciliation.model_validate(
            {**common, "state": "open", "merged": True, "merge_commit": C}
        )
    with pytest.raises(ValueError, match="contradict"):
        IntegrationProviderReconciliation.model_validate(
            {**common, "state": "closed", "merged": False, "merge_commit": C}
        )


def test_provider_reconciliation_rejects_two_parent_merged_topology() -> None:
    common = {
        "repository_digest": D,
        "pull_request_number": 7,
        "pull_request_url": "https://github.com/o/r/pull/7",
        "provider_identity": "github",
        "provider_api_version": "2026-01",
        "target_ref": "refs/heads/integration",
        "target_head_commit": C,
        "target_head_tree": H,
        "target_first_parent": G,
        "target_parents": [G, "e" * 40],
        "protection_evidence_digest": D,
    }
    with pytest.raises(ValueError, match="exactly one parent"):
        IntegrationProviderReconciliation.model_validate(
            {**common, "state": "closed", "merged": True, "merge_commit": C}
        )
