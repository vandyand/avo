"""Versioned boundary contracts."""

from avo_correlate.contracts.base import ActorRef, ArtifactRef, StrictModel, VersionedComponentRef
from avo_correlate.contracts.budgets import BudgetSpec, UsageRecord
from avo_correlate.contracts.evaluation import AdmissionDecision, EvaluationRecord
from avo_correlate.contracts.experiment import ExperimentSpec
from avo_correlate.contracts.integration_campaign import (
    CampaignCompletionPlan,
    CampaignDiscoveryEvidence,
    CampaignFinalEvidenceRecord,
    CampaignOpenedEvidence,
    CampaignPreparationEvidence,
    IntegrationCampaignEvidencePackage,
    IntegrationIntentTemplate,
)
from avo_correlate.contracts.integration_promotion import (
    CandidatePublicationBinding,
    IntegrationMergeResult,
    IntegrationPromotionIntent,
    IntegrationPromotionReceipt,
    IntegrationPromotionReport,
    IntegrationProviderObservation,
    IntegrationProviderReconciliation,
    PromotionLeaseEvidence,
    PromotionMutationAuthorization,
)
from avo_correlate.contracts.policy import PolicyDecision
from avo_correlate.contracts.promotion_bundle import (
    GitRefSnapshot,
    PromotionBundle,
    PromotionControllerConfig,
    PromotionDryRunInput,
    PromotionDryRunResult,
    PromotionProvenanceBinding,
    PromotionReplayReport,
    WorkspaceComparison,
)
from avo_correlate.contracts.promotion_policy import (
    PromotionConfig,
    PromotionDecision,
    PromotionRequest,
)
from avo_correlate.contracts.runtime import (
    AgentCompletion,
    EconomicUsageRecord,
    HarnessInvocationRecord,
    HarnessRuntimeProfile,
    ReconciliationCaseRecord,
    RuntimeCapabilityReport,
    RuntimeEvent,
    RuntimeInspection,
    RuntimeSessionRef,
)
from avo_correlate.contracts.variation import (
    CandidateManifest,
    VariationAttemptRecord,
    VariationSessionRequest,
    VariationSessionResult,
)

__all__ = [
    "ActorRef",
    "AdmissionDecision",
    "AgentCompletion",
    "ArtifactRef",
    "BudgetSpec",
    "CampaignCompletionPlan",
    "CampaignDiscoveryEvidence",
    "CampaignFinalEvidenceRecord",
    "CampaignOpenedEvidence",
    "CampaignPreparationEvidence",
    "CandidateManifest",
    "CandidatePublicationBinding",
    "EconomicUsageRecord",
    "EvaluationRecord",
    "ExperimentSpec",
    "GitRefSnapshot",
    "HarnessInvocationRecord",
    "HarnessRuntimeProfile",
    "IntegrationCampaignEvidencePackage",
    "IntegrationIntentTemplate",
    "IntegrationMergeResult",
    "IntegrationPromotionIntent",
    "IntegrationPromotionReceipt",
    "IntegrationPromotionReport",
    "IntegrationProviderObservation",
    "IntegrationProviderReconciliation",
    "PolicyDecision",
    "PromotionBundle",
    "PromotionConfig",
    "PromotionControllerConfig",
    "PromotionDecision",
    "PromotionDryRunInput",
    "PromotionDryRunResult",
    "PromotionLeaseEvidence",
    "PromotionMutationAuthorization",
    "PromotionProvenanceBinding",
    "PromotionReplayReport",
    "PromotionRequest",
    "ReconciliationCaseRecord",
    "RuntimeCapabilityReport",
    "RuntimeEvent",
    "RuntimeInspection",
    "RuntimeSessionRef",
    "StrictModel",
    "UsageRecord",
    "VariationAttemptRecord",
    "VariationSessionRequest",
    "VariationSessionResult",
    "VersionedComponentRef",
    "WorkspaceComparison",
]
