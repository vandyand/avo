"""Explicit deterministic authority used by Phase-A journal tests."""

from __future__ import annotations

from avo_correlate.contracts import (
    MainLeaseEvidenceRecord,
    MainMutationFenceResolution,
    MainMutationReceipt,
    MainProviderPostStateObservation,
    MainProviderReceipt,
    MainReconciliation,
)


class DeterministicPhaseAAuthorityVerifier:
    """Small controller stand-in; absence is intentionally never implicit."""

    def verify_lease_evidence(self, record: MainLeaseEvidenceRecord) -> None:
        if record.evidence_digest == record.lease_digest:
            raise ValueError("test lease evidence must bind distinct evidence digest")

    def verify_fence_resolution(
        self,
        resolution: MainMutationFenceResolution,
        source_receipt: MainMutationReceipt,
    ) -> None:
        if resolution.resolved_receipt_digest != source_receipt.receipt_digest:
            raise ValueError("test resolution is not bound to its receipt")
        if resolution.resolved_at < source_receipt.observed_at:
            raise ValueError("test resolution predates its source receipt")
        if not resolution.provider_identity or not resolution.provider_api_version:
            raise ValueError("test resolution lacks provider authority")

    def verify_provider_post_state(
        self,
        observation: MainProviderPostStateObservation,
        provider_receipt: MainProviderReceipt,
        reconciliation: MainReconciliation,
    ) -> None:
        if not observation.authoritative:
            raise ValueError("test provider observation is not authoritative")
        if (
            observation.operation_id != provider_receipt.operation_id
            or observation.repository_digest != provider_receipt.repository_digest
            or observation.target_ref != provider_receipt.target_ref
            or observation.provider_identity != provider_receipt.provider_identity
            or observation.provider_api_version != provider_receipt.provider_api_version
            or observation.result_commit != provider_receipt.result_commit
            or observation.result_tree != provider_receipt.result_tree
            or observation.result_parents != provider_receipt.result_parents
            or observation.release_authorization_digest
            != provider_receipt.release_authorization_digest
            or observation.response_digest != provider_receipt.response_digest
            or observation.observed_at != provider_receipt.observed_at
            or observation.result_commit != reconciliation.main_commit
            or observation.result_tree != reconciliation.main_tree
            or observation.result_parents != reconciliation.main_parents
        ):
            raise ValueError("test provider post-state binding differs")


TEST_PHASE_A_AUTHORITY = DeterministicPhaseAAuthorityVerifier()
