"""Trusted, content-addressed evidence adapters."""

from avo_correlate.adapters.evidence.campaign_quality import (
    ContentAddressedEvidenceResolver,
    EvidenceArtifactError,
    TrustedCampaignQualityAdapter,
)

__all__ = [
    "ContentAddressedEvidenceResolver",
    "EvidenceArtifactError",
    "TrustedCampaignQualityAdapter",
]
