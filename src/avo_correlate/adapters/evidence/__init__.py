"""Trusted, content-addressed evidence adapters."""

from avo_correlate.adapters.evidence.campaign_quality import (
    ContentAddressedEvidenceResolver,
    EvidenceArtifactError,
    TrustedCampaignQualityAdapter,
)
from avo_correlate.adapters.evidence.main_graduation import MainGraduationAttester

__all__ = [
    "ContentAddressedEvidenceResolver",
    "EvidenceArtifactError",
    "MainGraduationAttester",
    "TrustedCampaignQualityAdapter",
]
