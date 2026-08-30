"""Explicit deterministic authority used by Phase-A journal tests."""

from __future__ import annotations

from avo_correlate.contracts import (
    MainLeaseEvidenceRecord,
    MainMutationFenceResolution,
    MainMutationReceipt,
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


TEST_PHASE_A_AUTHORITY = DeterministicPhaseAAuthorityVerifier()
