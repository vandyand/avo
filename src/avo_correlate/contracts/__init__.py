"""Versioned boundary contracts."""

from avo_correlate.contracts.base import ActorRef, ArtifactRef, StrictModel, VersionedComponentRef
from avo_correlate.contracts.budgets import BudgetSpec, UsageRecord
from avo_correlate.contracts.evaluation import AdmissionDecision, EvaluationRecord
from avo_correlate.contracts.experiment import ExperimentSpec
from avo_correlate.contracts.policy import PolicyDecision
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
    "CandidateManifest",
    "EconomicUsageRecord",
    "EvaluationRecord",
    "ExperimentSpec",
    "HarnessInvocationRecord",
    "HarnessRuntimeProfile",
    "PolicyDecision",
    "PromotionConfig",
    "PromotionDecision",
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
]
