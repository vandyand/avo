"""Export authoritative JSON Schemas from boundary models."""

import json
from pathlib import Path

from avo_correlate.contracts import (
    AdmissionDecision,
    CampaignCompletionPlan,
    CampaignDiscoveryEvidence,
    CampaignFinalEvidenceRecord,
    CampaignOpenedEvidence,
    CampaignPreparationEvidence,
    CandidateManifest,
    CandidatePublicationBinding,
    EvaluationRecord,
    ExperimentSpec,
    GitRefSnapshot,
    IntegrationCampaignEvidencePackage,
    IntegrationIntentTemplate,
    IntegrationMergeResult,
    IntegrationPromotionIntent,
    IntegrationPromotionReceipt,
    IntegrationPromotionReport,
    IntegrationProviderObservation,
    IntegrationProviderReconciliation,
    PolicyDecision,
    PromotionBundle,
    PromotionConfig,
    PromotionControllerConfig,
    PromotionDecision,
    PromotionDryRunInput,
    PromotionDryRunResult,
    PromotionLeaseEvidence,
    PromotionMutationAuthorization,
    PromotionProvenanceBinding,
    PromotionReplayReport,
    PromotionRequest,
    VariationAttemptRecord,
    VariationSessionRequest,
    VariationSessionResult,
    WorkspaceComparison,
)
from avo_correlate.contracts.advisory import (
    AdvisoryEvaluationSummary,
    AdvisoryEvidenceItem,
    AdvisoryFinding,
    AdvisoryPatchReview,
    AdvisoryPatchReviewInput,
)
from avo_correlate.contracts.advisory_evaluation import (
    AdvisoryCaseScore,
    AdvisoryEvaluationCase,
    AdvisoryEvaluationReport,
    AdvisoryEvaluationResultManifest,
)
from avo_correlate.contracts.agent import AgentContext, AgentObservation, AgentTurn
from avo_correlate.contracts.inference import StructuredInferenceContext
from avo_correlate.contracts.model import ModelInvocationRecord, ModelRequest, ModelResponse
from avo_correlate.contracts.operations import (
    DryRunReport,
    PlatformOverheadReport,
    ReferenceScenarioResult,
)
from avo_correlate.contracts.plugins import PluginCapabilityManifest, SignedPluginManifest
from avo_correlate.contracts.projections import (
    ArtifactMetadataProjection,
    CandidateProjection,
    SessionProjection,
    SessionRuntimeProjection,
)
from avo_correlate.contracts.provenance import ProvenanceExport, VerificationReport
from avo_correlate.contracts.review import ReviewDecision, ReviewRequest, ReviewStatus
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
from avo_correlate.contracts.sandbox import SandboxExecutionResult, SandboxExecutionSpec
from avo_correlate.contracts.search import SearchCandidate, SearchDecision, SearchState
from avo_correlate.contracts.supervisor import SupervisorDirective, SupervisorObservation
from avo_correlate.contracts.tools import CapabilityClaims, ToolInvocationRecord

MODELS = (
    ExperimentSpec,
    VariationSessionRequest,
    VariationSessionResult,
    VariationAttemptRecord,
    CandidateManifest,
    EvaluationRecord,
    AdmissionDecision,
    PolicyDecision,
    PromotionConfig,
    GitRefSnapshot,
    WorkspaceComparison,
    PromotionControllerConfig,
    PromotionDryRunInput,
    PromotionProvenanceBinding,
    PromotionBundle,
    PromotionDryRunResult,
    PromotionReplayReport,
    PromotionRequest,
    PromotionDecision,
    IntegrationCampaignEvidencePackage,
    CampaignCompletionPlan,
    CampaignDiscoveryEvidence,
    CampaignFinalEvidenceRecord,
    CampaignOpenedEvidence,
    CampaignPreparationEvidence,
    CandidatePublicationBinding,
    IntegrationIntentTemplate,
    IntegrationMergeResult,
    IntegrationPromotionIntent,
    IntegrationPromotionReceipt,
    IntegrationPromotionReport,
    IntegrationProviderObservation,
    IntegrationProviderReconciliation,
    PromotionLeaseEvidence,
    PromotionMutationAuthorization,
    SandboxExecutionSpec,
    SandboxExecutionResult,
    DryRunReport,
    CapabilityClaims,
    ToolInvocationRecord,
    ModelRequest,
    ModelResponse,
    ModelInvocationRecord,
    ProvenanceExport,
    VerificationReport,
    SessionProjection,
    CandidateProjection,
    ArtifactMetadataProjection,
    AgentContext,
    AgentObservation,
    AgentTurn,
    StructuredInferenceContext,
    AdvisoryEvidenceItem,
    AdvisoryEvaluationSummary,
    AdvisoryPatchReviewInput,
    AdvisoryFinding,
    AdvisoryPatchReview,
    AdvisoryEvaluationCase,
    AdvisoryCaseScore,
    AdvisoryEvaluationReport,
    AdvisoryEvaluationResultManifest,
    SupervisorObservation,
    SupervisorDirective,
    SearchCandidate,
    SearchState,
    SearchDecision,
    ReviewRequest,
    ReviewDecision,
    ReviewStatus,
    PluginCapabilityManifest,
    SignedPluginManifest,
    ReferenceScenarioResult,
    PlatformOverheadReport,
    AgentCompletion,
    EconomicUsageRecord,
    HarnessInvocationRecord,
    HarnessRuntimeProfile,
    ReconciliationCaseRecord,
    RuntimeCapabilityReport,
    RuntimeEvent,
    RuntimeInspection,
    RuntimeSessionRef,
    SessionRuntimeProjection,
)


def export(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for model in MODELS:
        destination = output_dir / f"{model.__name__}.v1.schema.json"
        destination.write_text(
            json.dumps(model.model_json_schema(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )


if __name__ == "__main__":
    export(Path("schemas"))
