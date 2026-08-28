"""Durable single-lineage campaign activities for coding-agent variations."""

from __future__ import annotations

import inspect
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast
from uuid import NAMESPACE_URL, uuid5

from avo_correlate.adapters.persistence.models import ActivityRow
from avo_correlate.application.activity_service import ActivityService
from avo_correlate.application.artifact_service import ArtifactService
from avo_correlate.application.budget_service import BudgetService
from avo_correlate.application.evidence_service import EvidenceService
from avo_correlate.application.ports import CodingAgentRuntime
from avo_correlate.application.run_service import RunService
from avo_correlate.application.runtime_service import RuntimeService
from avo_correlate.application.scheduler import (
    ActivityRecovery,
    ActivityResult,
    FailureDisposition,
    RecoveryDisposition,
    Scheduler,
)
from avo_correlate.application.session_service import SessionService
from avo_correlate.application.terminal_budget_service import TerminalBudgetService
from avo_correlate.contracts.base import Sha256Digest, VersionedComponentRef
from avo_correlate.contracts.budgets import UsageRecord
from avo_correlate.contracts.evaluation import AdmissionDecision, EvaluationRecord
from avo_correlate.contracts.lifecycle import RunState, VariationSessionState
from avo_correlate.contracts.policy import PolicyDecision
from avo_correlate.contracts.promotion_policy import PromotionPolicy, RiskClass
from avo_correlate.contracts.runtime import (
    AgentCompletion,
    EconomicUsageRecord,
    HarnessInvocationRecord,
    HarnessRuntimeProfile,
    RuntimeEvent,
)
from avo_correlate.contracts.variation import (
    CandidateManifest,
    VariationAttemptRecord,
    VariationSessionRequest,
    VariationSessionResult,
)
from avo_correlate.domain.budgets import BudgetExceededError
from avo_correlate.domain.canonical import canonical_digest, file_digest, source_tree_digest
from avo_correlate.domain.workspace import create_vcs_free_binary_patch


@dataclass(frozen=True)
class CampaignWorkspace:
    """Control-plane paths for one immutable base and mutable candidate tree."""

    baseline: Path
    candidate: Path
    git_metadata: Path


WorkspaceResolver = Callable[[VariationSessionRequest], CampaignWorkspace]
EvaluationRunner = Callable[
    [CandidateManifest],
    tuple[tuple[str, EvaluationRecord], ...]
    | Awaitable[tuple[tuple[str, EvaluationRecord], ...]],
]


@dataclass(frozen=True)
class AdmissionPackage:
    policy_decisions: tuple[PolicyDecision, ...]
    decision: AdmissionDecision


AdmissionDecider = Callable[
    [CandidateManifest, tuple[EvaluationRecord, ...]],
    AdmissionPackage | Awaitable[AdmissionPackage],
]


class CampaignRuntimeError(RuntimeError):
    """A campaign activity could not establish an unambiguous durable result."""


class CampaignAuthorityPathError(CampaignRuntimeError):
    """A candidate attempts to modify a trusted authority or control-plane path."""


def validate_campaign_workspace(
    workspace: CampaignWorkspace, event_spool_root: Path
) -> tuple[Path, Path]:
    """Resolve and prove that candidate, metadata, and control-plane roots are disjoint."""
    baseline = workspace.baseline.resolve(strict=True)
    candidate = workspace.candidate.resolve(strict=True)
    metadata = workspace.git_metadata.resolve()
    spool = event_spool_root.resolve()
    protected = (baseline, candidate)
    if baseline == candidate or any(
        left.is_relative_to(right)
        for left, right in ((baseline, candidate), (candidate, baseline))
    ):
        raise CampaignRuntimeError("baseline and candidate trees must be disjoint")
    for root in protected:
        if metadata == root or metadata.is_relative_to(root):
            raise CampaignRuntimeError("external Git metadata is inside a workspace")
        if spool == root or spool.is_relative_to(root):
            raise CampaignRuntimeError("runtime event spool is inside a workspace")
    if any((ancestor / ".git").exists() for ancestor in (candidate, *candidate.parents)):
        raise CampaignRuntimeError("candidate workspace and ancestors must be VCS-free")
    if any(candidate.rglob(".git")):
        raise CampaignRuntimeError("candidate workspace contains Git metadata")
    return baseline, candidate


class CodingVariationActivityHandler:
    """Run one coding-agent variation and hand a frozen proposal to evaluation."""

    activity_kind = "variation"

    def __init__(
        self,
        *,
        runtime: CodingAgentRuntime,
        profile: HarnessRuntimeProfile,
        sessions: SessionService,
        invocations: RuntimeService,
        budgets: BudgetService,
        terminal_budgets: TerminalBudgetService,
        evidence: EvidenceService,
        activities: ActivityService,
        artifacts: ArtifactService,
        workspace_resolver: WorkspaceResolver,
        event_spool_root: Path,
        evaluation_estimate: UsageRecord,
        harness_ref: VersionedComponentRef,
        model_config_digest: Sha256Digest,
        policy_bundle_digest: Sha256Digest,
        actor_id: str = "coding-agent-worker",
    ) -> None:
        self._runtime = runtime
        self._profile = profile
        self._sessions = sessions
        self._invocations = invocations
        self._budgets = budgets
        self._terminal_budgets = terminal_budgets
        self._evidence = evidence
        self._activities = activities
        self._artifacts = artifacts
        self._workspace_resolver = workspace_resolver
        self._event_spool_root = event_spool_root.resolve()
        self._event_spool_root.mkdir(parents=True, exist_ok=True)
        self._evaluation_estimate = evaluation_estimate
        self._harness_ref = harness_ref
        self._model_config_digest = model_config_digest
        self._policy_bundle_digest = policy_bundle_digest
        self._actor_id = actor_id

    async def recover(self, activity: ActivityRow) -> ActivityRecovery:
        invocation = self._invocations.find_activity_invocation(activity.activity_id)
        if invocation is None:
            return ActivityRecovery(RecoveryDisposition.NOT_STARTED)
        if invocation.state == "completed":
            if activity.session_id is None or activity.budget_reservation_id is None:
                return ActivityRecovery(RecoveryDisposition.AMBIGUOUS)
            result = self._sessions.get_result(activity.session_id)
            if result is None:
                return ActivityRecovery(RecoveryDisposition.AMBIGUOUS)
            if result.outcome == "proposal_ready":
                candidate = self._evidence.get_session_candidate(activity.session_id)
                if candidate is None:
                    return ActivityRecovery(RecoveryDisposition.AMBIGUOUS)
                result_digest = canonical_digest(candidate)
            else:
                result_digest = canonical_digest(result)
            try:
                self._budgets.complete(
                    activity.budget_reservation_id,
                    actual=result.usage,
                    actor_id=self._actor_id,
                )
            except BudgetExceededError:
                self._terminal_budgets.settle_exhausted_variation(
                    run_id=activity.run_id,
                    activity_id=activity.activity_id,
                    reservation_id=activity.budget_reservation_id,
                    result_digest=result_digest,
                    actual=result.usage,
                    required_evaluation=self._evaluation_estimate,
                    policy_bundle_digest=self._policy_bundle_digest,
                    actor_id=self._actor_id,
                    lease_epoch=activity.lease_epoch,
                )
            return ActivityRecovery(
                RecoveryDisposition.DURABLE_RESULT,
                ActivityResult(result_digest),
            )
        if invocation.state == "failed":
            return ActivityRecovery(
                RecoveryDisposition.DURABLE_RESULT,
                ActivityResult(canonical_digest(invocation)),
            )
        if invocation.state == "reconciliation_required":
            return ActivityRecovery(RecoveryDisposition.AMBIGUOUS)
        if invocation.runtime_session is None or activity.session_id is None:
            return ActivityRecovery(RecoveryDisposition.RESUMABLE)
        request = self._sessions.get_request(activity.session_id)
        workspace = self._workspace_resolver(request)
        inspection = await self._runtime.inspect(
            self._profile,
            invocation.runtime_session,
            str(workspace.candidate),
        )
        if inspection.state in {"not_started", "completed"}:
            return ActivityRecovery(RecoveryDisposition.RESUMABLE)
        return ActivityRecovery(RecoveryDisposition.AMBIGUOUS)

    async def execute(self, activity: ActivityRow, lease_epoch: int) -> ActivityResult:
        if activity.session_id is None or activity.budget_reservation_id is None:
            raise CampaignRuntimeError("variation activity lacks session or budget context")
        request = self._sessions.get_request(activity.session_id)
        workspace = self._workspace_resolver(request)
        baseline, candidate = validate_campaign_workspace(
            workspace, self._event_spool_root
        )
        before_digest = source_tree_digest(baseline)
        if before_digest != request.champion.source_tree_digest:
            raise CampaignRuntimeError("materialized champion digest does not match the request")
        if self._sessions.get_state(request.session_id) == VariationSessionState.QUEUED:
            self._sessions.start(request.session_id)

        invocation_id = f"harness:{activity.activity_id}"
        invocation = self._invocations.find_activity_invocation(activity.activity_id)
        if invocation is None:
            billing_mode = cast(
                Literal["subscription", "local", "unknown"],
                {
                    "subscription": "subscription",
                    "api_key": "unknown",
                    "none": "local",
                }[self._profile.authentication_class],
            )
            invocation = HarnessInvocationRecord(
                invocation_id=invocation_id,
                activity_id=activity.activity_id,
                run_id=request.run_id,
                session_id=request.session_id,
                profile_digest=canonical_digest(self._profile),
                runtime_id=cast(str, getattr(self._runtime, "adapter_id", "unknown")),
                state="started",
                adapter_version=cast(
                    str, getattr(self._runtime, "adapter_version", "unknown")
                ),
                runtime_version=cast(
                    str, getattr(self._runtime, "runtime_version", "unknown")
                ),
                requested_model=self._profile.requested_model,
                workspace_before_digest=cast(Any, before_digest),
                economics=EconomicUsageRecord(
                    billing_mode=billing_mode,
                    cost_source="none",
                ),
                started_at=datetime.now(UTC),
            )
            self._invocations.record_invocation(invocation)

        session_ref = invocation.runtime_session
        if session_ref is None:
            report = await self._runtime.preflight(self._profile)
            if not report.compatible:
                raise CampaignRuntimeError("coding-agent runtime failed preflight")
            session_ref = await self._runtime.prepare(
                self._profile,
                request,
                str(candidate),
                invocation_id=invocation_id,
            )
            invocation = invocation.model_copy(update={"runtime_session": session_ref})
            self._invocations.replace_invocation(invocation)

        if session_ref.native_operation_id is None:
            inspection = await self._runtime.inspect(
                self._profile, session_ref, str(candidate)
            )
            if inspection.state == "not_started":
                session_ref = await self._runtime.start_turn(
                    self._profile, request, session_ref
                )
                invocation = invocation.model_copy(
                    update={"state": "running", "runtime_session": session_ref}
                )
                self._invocations.replace_invocation(invocation)
            elif inspection.state == "completed":
                session_ref = inspection.session
            else:
                raise CampaignRuntimeError(
                    f"prepared Codex thread is {inspection.state}; reconciliation required"
                )
        else:
            inspection = await self._runtime.inspect(
                self._profile, session_ref, str(candidate)
            )

        events: list[RuntimeEvent] = []
        spool_path = self._spool_path(invocation_id)
        if inspection.state == "completed":
            completion = inspection.completion
            if completion is None:
                raise CampaignRuntimeError("completed runtime inspection lacks completion")
        else:
            async for event in self._runtime.events(session_ref):
                events.append(event)
                self._append_spool(spool_path, event)
            completion = await self._runtime.wait(session_ref)

        usage = _usage_from_events(events)
        stream_bytes = (
            spool_path.read_bytes()
            if spool_path.exists()
            else b"".join(
                event.model_dump_json().encode("utf-8") + b"\n" for event in events
            )
        )
        stream_ref = self._artifacts.put_bytes(
            stream_bytes,
            run_id=request.run_id,
            owner_type="invocation",
            owner_id=invocation_id,
            media_type="application/x-ndjson",
            role="runtime-event-stream",
            retention_class="campaign-evidence",
            max_bytes=16 * 1024 * 1024,
            actor_id=self._actor_id,
        )
        after_digest = source_tree_digest(candidate)
        completed = invocation.model_copy(
            update={
                "state": "completed",
                "runtime_session": session_ref,
                "workspace_after_digest": after_digest,
                "event_stream_artifact_digest": stream_ref.digest,
                "completion": completion,
                "usage": _runtime_usage(events),
                "completed_at": datetime.now(UTC),
            }
        )
        try:
            outcome_digest = await self._finalize_completion(
                request=request,
                activity=activity,
                workspace=workspace,
                completion=completion,
                usage=usage,
                event_stream_digest=stream_ref.digest,
                before_digest=before_digest,
                after_digest=after_digest,
            )
        except BudgetExceededError:
            result = self._sessions.get_result(request.session_id)
            frozen = self._evidence.get_session_candidate(request.session_id)
            if result is None or frozen is None:
                raise
            outcome_digest = canonical_digest(frozen)
            self._invocations.replace_invocation(completed)
            self._terminal_budgets.settle_exhausted_variation(
                run_id=request.run_id,
                activity_id=activity.activity_id,
                reservation_id=activity.budget_reservation_id,
                result_digest=outcome_digest,
                actual=result.usage,
                required_evaluation=self._evaluation_estimate,
                policy_bundle_digest=self._policy_bundle_digest,
                actor_id=self._actor_id,
                lease_epoch=lease_epoch,
            )
            spool_path.unlink(missing_ok=True)
            return ActivityResult(outcome_digest)
        self._invocations.replace_invocation(completed)
        try:
            self._budgets.complete(
                activity.budget_reservation_id,
                actual=usage,
                actor_id=self._actor_id,
            )
        except BudgetExceededError:
            self._terminal_budgets.settle_exhausted_variation(
                run_id=request.run_id,
                activity_id=activity.activity_id,
                reservation_id=activity.budget_reservation_id,
                result_digest=outcome_digest,
                actual=usage,
                required_evaluation=self._evaluation_estimate,
                policy_bundle_digest=self._policy_bundle_digest,
                actor_id=self._actor_id,
                lease_epoch=lease_epoch,
            )
        spool_path.unlink(missing_ok=True)
        return ActivityResult(outcome_digest)

    def classify_failure(
        self, activity: ActivityRow, error: Exception
    ) -> FailureDisposition:
        del error
        invocation = self._invocations.find_activity_invocation(activity.activity_id)
        if invocation is not None and invocation.runtime_session is not None:
            try:
                spool_path = self._spool_path(invocation.invocation_id)
                stream_digest = invocation.event_stream_artifact_digest
                if spool_path.exists():
                    reference = self._artifacts.put_bytes(
                        spool_path.read_bytes(),
                        run_id=invocation.run_id,
                        owner_type="invocation",
                        owner_id=invocation.invocation_id,
                        media_type="application/x-ndjson",
                        role="runtime-event-stream-partial",
                        retention_class="reconciliation-evidence",
                        max_bytes=16 * 1024 * 1024,
                        actor_id=self._actor_id,
                    )
                    stream_digest = reference.digest
                self._invocations.replace_invocation(
                    invocation.model_copy(
                        update={
                            "state": "reconciliation_required",
                            "event_stream_artifact_digest": stream_digest,
                            "error_class": "ambiguous_runtime_failure",
                        }
                    )
                )
            except Exception:
                pass
            return FailureDisposition.RECONCILE
        return FailureDisposition.RETRY

    def _spool_path(self, invocation_id: str) -> Path:
        name = canonical_digest(invocation_id).removeprefix("sha256:") + ".jsonl"
        return self._event_spool_root / name

    @staticmethod
    def _append_spool(path: Path, event: RuntimeEvent) -> None:
        payload = event.model_dump_json().encode("utf-8") + b"\n"
        if path.exists() and path.stat().st_size + len(payload) > 16 * 1024 * 1024:
            raise CampaignRuntimeError("runtime event spool exceeds 16 MiB")
        with path.open("ab") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())

    async def _finalize_completion(
        self,
        *,
        request: VariationSessionRequest,
        activity: ActivityRow,
        workspace: CampaignWorkspace,
        completion: AgentCompletion,
        usage: UsageRecord,
        event_stream_digest: str,
        before_digest: str,
        after_digest: str,
    ) -> str:
        attempt_digest = canonical_digest(
            {
                "completion": completion,
                "event_stream_digest": event_stream_digest,
                "workspace_digest": after_digest,
            }
        )
        attempt_id = str(uuid5(NAMESPACE_URL, f"avo:attempt:{activity.activity_id}"))
        completed_at = datetime.now(UTC)
        if completion.outcome == "stop":
            self._sessions.record_attempt(
                VariationAttemptRecord(
                    attempt_id=attempt_id,
                    session_id=request.session_id,
                    parent_workspace_digest=cast(Any, before_digest),
                    development_evaluation_ids=[],
                    tool_trace_digest=cast(Any, event_stream_digest),
                    outcome="abandoned",
                    started_at=completed_at,
                    completed_at=completed_at,
                )
            )
            result = VariationSessionResult(
                session_id=request.session_id,
                outcome="exhausted",
                attempt_index_digest=cast(Any, attempt_digest),
                usage=usage,
            )
            self._sessions.finish(result)
            return canonical_digest(result)

        if before_digest == after_digest:
            raise CampaignRuntimeError("Codex proposed a candidate without workspace changes")
        patch = create_vcs_free_binary_patch(
            workspace.baseline,
            workspace.candidate,
            git_metadata=workspace.git_metadata,
        )
        changed_paths = _changed_workspace_paths(workspace.baseline, workspace.candidate)
        try:
            risk = PromotionPolicy.derive_risk(changed_paths)
        except ValueError as exc:
            raise CampaignAuthorityPathError(
                "candidate changed paths failed canonical validation"
            ) from exc
        if risk in {RiskClass.CONSTITUTIONAL, RiskClass.PRODUCTION}:
            raise CampaignAuthorityPathError(
                "candidate changes trusted authority paths; completion rejected "
                f"before candidate staging (risk={risk.value})"
            )
        candidate_id = str(
            uuid5(NAMESPACE_URL, f"avo:candidate:{activity.activity_id}:{after_digest}")
        )
        patch_ref = self._artifacts.put_bytes(
            patch,
            run_id=request.run_id,
            owner_type="candidate",
            owner_id=candidate_id,
            media_type="text/x-diff",
            role="candidate-patch",
            retention_class="candidate-evidence",
            max_bytes=16 * 1024 * 1024,
            actor_id=self._actor_id,
        )
        rationale_ref = self._artifacts.put_bytes(
            completion.model_dump_json().encode("utf-8"),
            run_id=request.run_id,
            owner_type="candidate",
            owner_id=candidate_id,
            media_type="application/json",
            role="agent-rationale",
            retention_class="candidate-evidence",
            max_bytes=1024 * 1024,
            actor_id=self._actor_id,
        )
        self._sessions.record_attempt(
            VariationAttemptRecord(
                attempt_id=attempt_id,
                session_id=request.session_id,
                parent_workspace_digest=cast(Any, before_digest),
                result_workspace_digest=cast(Any, after_digest),
                patch_digest=patch_ref.digest,
                development_evaluation_ids=[],
                tool_trace_digest=cast(Any, event_stream_digest),
                outcome="improved",
                started_at=completed_at,
                completed_at=completed_at,
            )
        )
        result = VariationSessionResult(
            session_id=request.session_id,
            outcome="proposal_ready",
            proposed_workspace_digest=cast(Any, after_digest),
            proposed_patch_digest=patch_ref.digest,
            rationale_artifact=rationale_ref,
            attempt_index_digest=cast(Any, attempt_digest),
            usage=usage,
        )
        self._sessions.finish(result)
        manifest = CandidateManifest(
            candidate_id=candidate_id,
            run_id=request.run_id,
            session_id=request.session_id,
            parent_candidate_ids=[request.champion.candidate_id],
            base_workspace_digest=cast(Any, before_digest),
            source_tree_digest=cast(Any, after_digest),
            patch_artifact=patch_ref,
            result_artifacts=[rationale_ref],
            harness_ref=self._harness_ref,
            model_config_digest=self._model_config_digest,
            context_digest=request.initial_context_digest,
            attempt_index_digest=cast(Any, attempt_digest),
            execution_profile_digest=canonical_digest(self._profile),
            policy_bundle_digest=self._policy_bundle_digest,
            created_at=completed_at,
        )
        self._evidence.stage_candidate(manifest)
        evaluation_key = f"evaluate:{candidate_id}"
        evaluation_reservation = self._budgets.reserve(
            request.run_id,
            activity_key=evaluation_key,
            estimated=self._evaluation_estimate,
            actor_id=self._actor_id,
        )
        self._activities.enqueue(
            request.run_id,
            activity_key=evaluation_key,
            input_digest=canonical_digest(manifest),
            actor_id=self._actor_id,
            session_id=request.session_id,
            budget_reservation_id=evaluation_reservation,
        )
        return canonical_digest(manifest)


class CandidateEvaluationActivityHandler:
    """Run private evaluators after the candidate workspace is frozen."""

    activity_kind = "evaluate"

    def __init__(
        self,
        *,
        evidence: EvidenceService,
        activities: ActivityService,
        budgets: BudgetService,
        evaluator_keys: tuple[str, ...],
        runner: EvaluationRunner,
        actor_id: str = "authoritative-evaluator",
    ) -> None:
        if not evaluator_keys or len(evaluator_keys) != len(set(evaluator_keys)):
            raise ValueError("evaluator keys must be non-empty and unique")
        self._evidence = evidence
        self._activities = activities
        self._budgets = budgets
        self._evaluator_keys = evaluator_keys
        self._runner = runner
        self._actor_id = actor_id

    def recover(self, activity: ActivityRow) -> ActivityRecovery:
        candidate_id = _activity_subject(activity, self.activity_kind)
        existing = dict(self._evidence.list_evaluations(candidate_id))
        if set(self._evaluator_keys).issubset(existing):
            digests = [canonical_digest(existing[key]) for key in self._evaluator_keys]
            if activity.budget_reservation_id is None:
                raise CampaignRuntimeError("evaluation activity lacks a budget reservation")
            self._budgets.complete(
                activity.budget_reservation_id,
                actual=_evaluation_usage(tuple(existing[key] for key in self._evaluator_keys)),
                actor_id=self._actor_id,
            )
            return ActivityRecovery(
                RecoveryDisposition.DURABLE_RESULT,
                ActivityResult(canonical_digest(digests)),
            )
        return ActivityRecovery(RecoveryDisposition.RESUMABLE)

    async def execute(self, activity: ActivityRow, lease_epoch: int) -> ActivityResult:
        del lease_epoch
        candidate_id = _activity_subject(activity, self.activity_kind)
        if activity.budget_reservation_id is None:
            raise CampaignRuntimeError("evaluation activity lacks a budget reservation")
        manifest = self._evidence.get_candidate(candidate_id)
        outcome = self._runner(manifest)
        records = await outcome if inspect.isawaitable(outcome) else outcome
        returned = tuple(key for key, _ in records)
        if returned != self._evaluator_keys:
            raise CampaignRuntimeError(
                f"evaluator keys differ from the frozen profile: {returned}"
            )
        digests: list[str] = []
        for key, record in records:
            if record.candidate_id != candidate_id:
                raise CampaignRuntimeError("evaluator returned another candidate")
            digests.append(self._evidence.record_evaluation(record, evaluator_key=key))
        self._activities.enqueue(
            manifest.run_id,
            activity_key=f"admit:{candidate_id}",
            input_digest=canonical_digest(digests),
            actor_id=self._actor_id,
            session_id=manifest.session_id,
        )
        self._budgets.complete(
            activity.budget_reservation_id,
            actual=_evaluation_usage(tuple(record for _, record in records)),
            actor_id=self._actor_id,
        )
        return ActivityResult(canonical_digest(digests))

    @staticmethod
    def classify_failure(
        activity: ActivityRow, error: Exception
    ) -> FailureDisposition:
        del activity, error
        return FailureDisposition.RETRY


class CandidateAdmissionActivityHandler:
    """Apply policy and admission outside the coding-agent trust boundary."""

    activity_kind = "admit"

    def __init__(
        self,
        *,
        evidence: EvidenceService,
        runs: RunService,
        decider: AdmissionDecider,
        complete_on_admission: bool = True,
        actor_id: str = "admission-controller",
    ) -> None:
        self._evidence = evidence
        self._runs = runs
        self._decider = decider
        self._complete_on_admission = complete_on_admission
        self._actor_id = actor_id

    def recover(self, activity: ActivityRow) -> ActivityRecovery:
        candidate_id = _activity_subject(activity, self.activity_kind)
        decision = self._evidence.get_admission(candidate_id)
        if decision is None:
            return ActivityRecovery(RecoveryDisposition.RESUMABLE)
        return ActivityRecovery(
            RecoveryDisposition.DURABLE_RESULT,
            ActivityResult(canonical_digest(decision)),
        )

    async def execute(self, activity: ActivityRow, lease_epoch: int) -> ActivityResult:
        del lease_epoch
        candidate_id = _activity_subject(activity, self.activity_kind)
        manifest = self._evidence.get_candidate(candidate_id)
        evaluations = tuple(
            record for _, record in self._evidence.list_evaluations(candidate_id)
        )
        if not evaluations:
            raise CampaignRuntimeError("admission requires authoritative evaluations")
        outcome = self._decider(manifest, evaluations)
        package = await outcome if inspect.isawaitable(outcome) else outcome
        if package.decision.candidate_id != candidate_id:
            raise CampaignRuntimeError("admission decision names another candidate")
        for policy in package.policy_decisions:
            self._evidence.record_policy_decision(
                manifest.run_id, policy, candidate_id=candidate_id
            )
        self._evidence.commit_admission(manifest.run_id, package.decision)
        if package.decision.outcome == "admit" and self._complete_on_admission:
            run = self._runs.get_run(manifest.run_id)
            if RunState(run.state) == RunState.RUNNING:
                self._runs.transition(
                    manifest.run_id,
                    RunState.COMPLETED,
                    actor_id=self._actor_id,
                    expected_revision=run.revision,
                    reason="first_admission",
                    idempotency_key=f"complete:{package.decision.admission_id}",
                )
        return ActivityResult(canonical_digest(package.decision))

    @staticmethod
    def classify_failure(
        activity: ActivityRow, error: Exception
    ) -> FailureDisposition:
        del activity, error
        return FailureDisposition.RETRY


class LocalCampaignWorker:
    """Small local worker entrypoint; remote execution remains deliberately deferred."""

    def __init__(
        self,
        activities: ActivityService,
        *,
        worker_id: str,
        variation: CodingVariationActivityHandler,
        evaluation: CandidateEvaluationActivityHandler,
        admission: CandidateAdmissionActivityHandler,
        lease_seconds: int = 30,
    ) -> None:
        self._scheduler = Scheduler(
            activities, worker_id=worker_id, lease_seconds=lease_seconds
        )
        self._scheduler.register(variation.activity_kind, variation)
        self._scheduler.register(evaluation.activity_kind, evaluation)
        self._scheduler.register(admission.activity_kind, admission)

    async def run_once(self) -> bool:
        return await self._scheduler.run_once_async()

    async def run_until_idle(self, *, max_activities: int = 100) -> int:
        if max_activities <= 0:
            raise ValueError("max_activities must be positive")
        completed = 0
        while completed < max_activities and await self.run_once():
            completed += 1
        return completed


def _activity_subject(activity: ActivityRow, expected_kind: str) -> str:
    kind, separator, subject = activity.activity_key.partition(":")
    if kind != expected_kind or not separator or not subject:
        raise CampaignRuntimeError(f"invalid {expected_kind} activity key")
    return subject


def _changed_workspace_paths(baseline: Path, candidate: Path) -> list[str]:
    """Return changed relative paths from the trusted workspace trees.

    Completion must not rely on model-provided path claims. File contents and
    executable mode are compared directly, while the canonical promotion
    policy validates the resulting path manifest and derives its risk.
    """

    def entries(root: Path) -> dict[str, tuple[str, str, int]]:
        result: dict[str, tuple[str, str, int]] = {}
        for path in root.rglob("*"):
            relative = path.relative_to(root).as_posix()
            stat = path.lstat()
            mode = stat.st_mode & 0o777
            if path.is_symlink():
                result[relative] = ("symlink", path.readlink().as_posix(), mode)
            elif path.is_file():
                result[relative] = ("file", file_digest(path), mode)
            elif path.is_dir():
                # Empty directories are not represented by the generated patch.
                continue
            else:
                raise CampaignAuthorityPathError(
                    f"candidate contains unsupported workspace entry: {relative}"
                )
        return result

    baseline_entries = entries(baseline)
    candidate_entries = entries(candidate)
    return sorted(
        relative
        for relative in baseline_entries.keys() | candidate_entries.keys()
        if baseline_entries.get(relative) != candidate_entries.get(relative)
    )


def _runtime_usage(events: list[RuntimeEvent]) -> dict[str, int]:
    observed: dict[str, int] = {}
    for event in events:
        for key, value in event.usage_delta.items():
            observed[key] = max(observed.get(key, 0), value)
    return observed


def _usage_from_events(events: list[RuntimeEvent]) -> UsageRecord:
    observed = _runtime_usage(events)

    def maximum(*suffixes: str) -> int:
        return max(
            (
                value
                for key, value in observed.items()
                if any(key == suffix or key.endswith(f".{suffix}") for suffix in suffixes)
            ),
            default=0,
        )

    return UsageRecord.zero().model_copy(
        update={
            "model_input_tokens": maximum("input_tokens", "prompt_tokens"),
            "model_output_tokens": maximum("output_tokens", "completion_tokens"),
            "variation_sessions": 1,
        }
    )


def _evaluation_usage(records: tuple[EvaluationRecord, ...]) -> UsageRecord:
    return UsageRecord.zero().model_copy(
        update={
            "authoritative_evaluations": len(records),
            "artifact_bytes": sum(
                artifact.size_bytes
                for record in records
                for artifact in record.evidence_artifacts
            ),
        }
    )
