"""Executable reference scenario joining the v1 trust zones end to end."""

import asyncio
import os
import shutil
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from uuid import uuid4

from avo_correlate.adapters.artifacts import FilesystemArtifactStore
from avo_correlate.adapters.harness.native import NativeAgentHarness
from avo_correlate.adapters.harness.reference import (
    ReferenceModelGateway,
    ReferenceToolDispatcher,
)
from avo_correlate.adapters.persistence import Database
from avo_correlate.adapters.policy import BuiltinPolicyEngine
from avo_correlate.adapters.sandbox import DockerSandbox
from avo_correlate.adapters.tools import WorkspaceToolBroker
from avo_correlate.application.artifact_service import ArtifactService
from avo_correlate.application.budget_service import BudgetService
from avo_correlate.application.capabilities import CapabilityIssuer
from avo_correlate.application.evidence_service import EvidenceService
from avo_correlate.application.provenance_service import ProvenanceService
from avo_correlate.application.run_service import RunService
from avo_correlate.application.session_service import SessionService
from avo_correlate.contracts.base import ActorRef
from avo_correlate.contracts.budgets import UsageRecord
from avo_correlate.contracts.evaluation import AdmissionDecision, EvaluationRecord
from avo_correlate.contracts.experiment import ExperimentSpec
from avo_correlate.contracts.lifecycle import RunState
from avo_correlate.contracts.operations import ReferenceScenarioResult
from avo_correlate.contracts.policy import PolicyRequest
from avo_correlate.contracts.policy_bundle import PolicyBundle
from avo_correlate.contracts.sandbox import SandboxExecutionSpec, SandboxMount
from avo_correlate.contracts.tools import CapabilityClaims
from avo_correlate.contracts.variation import (
    CandidateManifest,
    CandidateRef,
    VariationAttemptRecord,
    VariationSessionRequest,
)
from avo_correlate.devtools.oci_image import resolve_verified_image
from avo_correlate.domain.admission import compare_evaluations
from avo_correlate.domain.canonical import canonical_digest, source_tree_digest
from avo_correlate.domain.evaluator_reports import parse_evaluation_report

_OUTPUT_DIGEST = "sha256:" + ("c" * 64)


class ReferenceScenarioRunner:
    def __init__(
        self,
        root: Path,
        *,
        project_root: Path,
        development_image_digest: str,
        admission_image_digest: str,
        development_image_reference: str = "avo-reference-development:1.0.0",
        admission_image_reference: str = "avo-reference-admission:1.0.0",
        development_metadata_path: Path | None = None,
        admission_metadata_path: Path | None = None,
    ) -> None:
        self._root = root
        self._project = project_root
        self._development_image = development_image_digest
        self._admission_image = admission_image_digest
        self._development_image_reference = development_image_reference
        self._admission_image_reference = admission_image_reference
        self._development_metadata_path = development_metadata_path or _metadata_path(
            "development"
        )
        self._admission_metadata_path = admission_metadata_path or _metadata_path("admission")

    def run(self) -> ReferenceScenarioResult:
        spec = ExperimentSpec.model_validate_json(
            (self._project / "examples/reference-experiment.json").read_text(encoding="utf-8")
        )
        database = Database(self._root / "state.db")
        database.initialize()
        runs = RunService(database)
        runs.create_experiment(spec)
        run_id = "reference-run-1"
        runs.create_run(
            spec.experiment_id,
            actor_id="reference-operator",
            run_id=run_id,
            prepare=True,
        )
        runs.transition(run_id, RunState.RUNNING, actor_id="reference-operator")
        workspace = self._root / "workspace"
        shutil.copytree(self._project / "fixtures/reference_project/seed", workspace)
        champion = runs.get_run(run_id).champion_id
        if champion is None:
            raise RuntimeError("reference run lacks seed champion")

        budgets = BudgetService(database)
        session_estimate = _usage(
            input_tokens=1_000,
            output_tokens=1_000,
            tool_calls=10,
            sessions=1,
            sandbox_cpu_seconds=60,
            artifact_bytes=5_000_000,
        )
        session_reservation = budgets.reserve(
            run_id,
            activity_key="variation:session-1",
            estimated=session_estimate,
            actor_id="scheduler",
        )
        issuer = CapabilityIssuer(b"reference-capability-signing-key!"[:32])
        expires = datetime.now(UTC) + timedelta(minutes=30)
        claims = CapabilityClaims(
            token_id="reference-token-1",
            session_id="session-1",
            actor_id="reference-harness",
            workspace_digest=spec.workspace.source_tree_digest,
            tools=["read_file", "apply_patch", "run_development_evaluator"],
            policy_decision_id="session-policy-1",
            expires_at=expires,
        )
        token = issuer.issue(claims)
        request = VariationSessionRequest(
            session_id="session-1",
            run_id=run_id,
            champion=CandidateRef(
                candidate_id=champion,
                source_tree_digest=spec.workspace.source_tree_digest,
                lineage_sequence=0,
            ),
            lineage_index_digest=canonical_digest([champion]),
            initial_context_digest=canonical_digest(
                {"objective": spec.objective, "success_criteria": spec.success_criteria}
            ),
            tool_capability_token=token,
            development_evaluator_refs=[spec.development_evaluators[0].component],
            budget_reservation_id=session_reservation,
            random_seed=7,
        )
        sessions = SessionService(database)
        sessions.enqueue(request)
        sessions.start(request.session_id)
        store = FilesystemArtifactStore(self._root / "artifacts")
        artifacts = ArtifactService(database, store)
        patch_bytes = (self._project / "fixtures/reference_project/successful.patch").read_bytes()
        patch_ref = artifacts.put_bytes(
            patch_bytes,
            run_id=run_id,
            owner_type="session",
            owner_id=request.session_id,
            media_type="text/x-diff",
            role="candidate-patch",
            retention_class="candidate-evidence",
            max_bytes=1_000_000,
            actor_id="reference-harness",
        )
        broker = WorkspaceToolBroker(
            workspace,
            spec.workspace,
            issuer=issuer,
            session_id=request.session_id,
            workspace_digest=spec.workspace.source_tree_digest,
        )
        development_records: list[tuple[EvaluationRecord, bytes]] = []

        def development_evaluator() -> bool:
            record, raw = self._evaluate(
                workspace,
                candidate_id="candidate-1",
                evaluation_id="development-candidate-1",
                tier="development",
                image_digest=self._development_image,
                image_reference=self._development_image_reference,
                metadata_path=self._development_metadata_path,
            )
            development_records.append((record, raw))
            return record.outcome == "passed"

        dispatcher = ReferenceToolDispatcher(
            broker,
            workspace,
            patches={"successful": patch_bytes},
            development_evaluator=development_evaluator,
        )
        gateway = ReferenceModelGateway(patch_ref.digest)
        result = asyncio.run(
            NativeAgentHarness(gateway, dispatcher, max_turns=5).run_session(request)
        )
        if result.outcome != "proposal_ready" or result.proposed_workspace_digest is None:
            raise RuntimeError("reference harness did not produce a candidate")
        finished_at = datetime.now(UTC)
        sessions.record_attempt(
            VariationAttemptRecord(
                attempt_id="attempt-1",
                session_id=request.session_id,
                parent_workspace_digest=spec.workspace.source_tree_digest,
                result_workspace_digest=result.proposed_workspace_digest,
                patch_digest=patch_ref.digest,
                development_evaluation_ids=["development-candidate-1"],
                tool_trace_digest=canonical_digest(dispatcher.observations),
                outcome="improved",
                started_at=dispatcher.started_at,
                completed_at=finished_at,
            )
        )
        sessions.finish(result)
        dev_record, dev_raw = development_records[0]
        dev_ref = artifacts.put_bytes(
            dev_raw,
            run_id=run_id,
            owner_type="candidate",
            owner_id="candidate-1",
            media_type="application/json",
            role="development-evaluation",
            retention_class="evaluator-evidence",
            max_bytes=1_000_000,
            actor_id="development-evaluator",
        )
        manifest = CandidateManifest(
            candidate_id="candidate-1",
            run_id=run_id,
            session_id=request.session_id,
            parent_candidate_ids=[champion],
            base_workspace_digest=spec.workspace.source_tree_digest,
            source_tree_digest=result.proposed_workspace_digest,
            patch_artifact=patch_ref,
            result_artifacts=[dev_ref],
            harness_ref=spec.harness.component,
            model_config_digest=spec.harness.model_config_digest,
            context_digest=request.initial_context_digest,
            attempt_index_digest=result.attempt_index_digest,
            execution_profile_digest=spec.development_evaluators[0].profile_digest,
            policy_bundle_digest=spec.policy_bundle_digest,
            created_at=finished_at,
        )
        evidence = EvidenceService(database)
        evidence.stage_candidate(manifest)
        evidence.record_evaluation(
            dev_record.model_copy(update={"evidence_artifacts": [dev_ref]}),
            evaluator_key="development:reference-v1",
        )

        evaluation_reservation = budgets.reserve(
            run_id,
            activity_key="admission:candidate-1",
            estimated=_usage(
                sandbox_cpu_seconds=60,
                authoritative_evaluations=2,
                artifact_bytes=2_000_000,
            ),
            actor_id="admission-controller",
        )
        incumbent_record, incumbent_raw = self._evaluate(
            self._project / "fixtures/reference_project/seed",
            candidate_id=champion,
            evaluation_id="admission-incumbent",
            tier="admission",
            image_digest=self._admission_image,
            image_reference=self._admission_image_reference,
            metadata_path=self._admission_metadata_path,
        )
        candidate_record, admission_raw = self._evaluate(
            workspace,
            candidate_id="candidate-1",
            evaluation_id="admission-candidate-1",
            tier="admission",
            image_digest=self._admission_image,
            image_reference=self._admission_image_reference,
            metadata_path=self._admission_metadata_path,
        )
        admission_ref = artifacts.put_bytes(
            admission_raw,
            run_id=run_id,
            owner_type="candidate",
            owner_id="candidate-1",
            media_type="application/json",
            role="admission-evaluation",
            retention_class="admitted-lineage",
            max_bytes=1_000_000,
            actor_id="admission-evaluator",
        )
        candidate_record = candidate_record.model_copy(
            update={"evidence_artifacts": [admission_ref]}
        )
        evidence.record_evaluation(
            candidate_record, evaluator_key="admission:reference-v1"
        )
        policy = PolicyBundle.model_validate_json(
            (self._project / "examples/reference-policy.json").read_text(encoding="utf-8")
        )
        policy_decision = BuiltinPolicyEngine(policy).decide(
            PolicyRequest(
                action="candidate.admit",
                resource=f"run/{run_id}/candidate/candidate-1",
                actor_id="admission-controller",
            )
        )
        if policy_decision.outcome != "allow":
            raise RuntimeError("reference admission policy did not allow the candidate")
        evidence.record_policy_decision(
            run_id, policy_decision, candidate_id="candidate-1"
        )
        comparison = compare_evaluations(
            incumbent_record,
            candidate_record,
            metric="correctness_score",
            direction="maximize",
            minimum_effect=Decimal("1"),
        )
        admission_id = "admission-1"
        evidence.commit_admission(
            run_id,
            AdmissionDecision(
                admission_id=admission_id,
                candidate_id="candidate-1",
                expected_champion_id=champion,
                evaluation_ids=[candidate_record.evaluation_id],
                policy_decision_ids=[policy_decision.decision_id],
                outcome="admit",
                reason_codes=["constraints_passed", "statistical_improvement"],
                comparison=comparison,
                decided_by=ActorRef(
                    actor_type="service", actor_id="admission-controller"
                ),
                decided_at=datetime.now(UTC),
            ),
        )
        actual_session = result.usage.model_copy(
            update={
                "sandbox_cpu_seconds": 1,
                "artifact_bytes": len(patch_bytes) + len(dev_raw),
            }
        )
        budgets.complete(
            session_reservation, actual=actual_session, actor_id="scheduler"
        )
        budgets.complete(
            evaluation_reservation,
            actual=_usage(
                sandbox_cpu_seconds=2,
                authoritative_evaluations=2,
                artifact_bytes=len(incumbent_raw) + len(admission_raw),
            ),
            actor_id="admission-controller",
        )
        runs.transition(run_id, RunState.COMPLETED, actor_id="supervisor")
        provenance = ProvenanceService(database)
        exported = provenance.export_run(run_id)
        verified = provenance.verify(exported)
        if not verified.verified:
            raise RuntimeError(f"reference provenance failed: {verified.errors}")
        return ReferenceScenarioResult(
            run_id=run_id,
            session_id=request.session_id,
            candidate_id="candidate-1",
            admission_id=admission_id,
            final_state="completed",
            provenance_digest=exported.manifest_digest,
            provenance_verified=True,
        )

    def _evaluate(
        self,
        workspace: Path,
        *,
        candidate_id: str,
        evaluation_id: str,
        tier: str,
        image_digest: str,
        image_reference: str,
        metadata_path: Path | None,
    ) -> tuple[EvaluationRecord, bytes]:
        output = self._root / f"output-{evaluation_id}-{uuid4()}"
        output.mkdir(parents=True)
        workspace_digest = source_tree_digest(workspace)
        paths = {workspace_digest: workspace, _OUTPUT_DIGEST: output}
        verified_image = resolve_verified_image(
            image_reference,
            image_digest,
            metadata_file=metadata_path,
        )
        sandbox = DockerSandbox(
            image_resolver=lambda _: verified_image.execution_reference,
            artifact_resolver=paths.__getitem__,
        )
        executed = sandbox.execute(
            SandboxExecutionSpec(
                execution_id=evaluation_id,
                image_digest=verified_image.reviewed_manifest,
                command=["evaluate"],
                environment={
                    "AVO_CANDIDATE_ID": candidate_id,
                    "AVO_EVALUATION_ID": evaluation_id,
                    "AVO_EVALUATOR_TIER": tier,
                    "AVO_IMAGE_DIGEST": verified_image.reviewed_manifest,
                    "AVO_WORKSPACE_DIGEST": workspace_digest,
                },
                mounts=[
                    SandboxMount(source_digest=workspace_digest, target="/workspace"),
                    SandboxMount(
                        source_digest=_OUTPUT_DIGEST,
                        target="/output",
                        read_only=False,
                    ),
                ],
                timeout_seconds=30,
                memory_bytes=256 * 1024 * 1024,
                output_bytes_limit=1_000_000,
            )
        )
        if executed.outcome != "succeeded":
            raise RuntimeError(f"reference evaluator sandbox {executed.outcome}")
        raw = (output / "report.json").read_bytes()
        return (
            parse_evaluation_report(
                raw,
                max_bytes=1_000_000,
                declared_metrics=frozenset({"correctness_score"}),
            ),
            raw,
        )


def _usage(
    *,
    input_tokens: int = 0,
    output_tokens: int = 0,
    tool_calls: int = 0,
    sessions: int = 0,
    sandbox_cpu_seconds: int = 0,
    authoritative_evaluations: int = 0,
    artifact_bytes: int = 0,
) -> UsageRecord:
    return UsageRecord.zero().model_copy(
        update={
            "model_input_tokens": input_tokens,
            "model_output_tokens": output_tokens,
            "tool_calls": tool_calls,
            "variation_sessions": sessions,
            "sandbox_cpu_seconds": sandbox_cpu_seconds,
            "authoritative_evaluations": authoritative_evaluations,
            "artifact_bytes": artifact_bytes,
        }
    )


def _metadata_path(tier: str) -> Path | None:
    """Read only the fixed CI metadata location for a trusted evaluator tier."""

    for name in (
        f"AVO_REFERENCE_{tier.upper()}_METADATA_FILE",
        f"AVO_REFERENCE_{tier.upper()}_METADATA_PATH",
        f"AVO_{tier.upper()}_IMAGE_METADATA_FILE",
    ):
        value = os.environ.get(name)
        if value:
            return Path(value)
    return None
