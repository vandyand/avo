"""Deterministic, offline AVO-004.6 failure-drill orchestration.

The production promotion and campaign services deliberately have hosted and
clock-bearing ports.  This module supplies a small deterministic boundary for
the AVO-004.6 cases: it exercises the same lease, CAS, attestation, policy,
mutation/reconciliation, rollback, and topology decisions without network access.  Every
decision is written through :class:`IntegrationDrillJournal` before it is
returned, making a second invocation a read-only replay.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Barrier, Lock
from typing import Any, Literal, Protocol, cast

from avo_correlate.adapters.artifacts.drill_journal import IntegrationDrillJournal
from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.adapters.artifacts.promotion_journal import (
    IntegrationPromotionJournal as DurablePromotionJournal,
)
from avo_correlate.adapters.hosted_git.github import github_repository_digest
from avo_correlate.application.integration_promotion_service import IntegrationPromotionService
from avo_correlate.contracts.base import ArtifactRef, Sha256Digest
from avo_correlate.contracts.integration_drill import (
    IntegrationDrillCaseResult,
    IntegrationDrillPlan,
    IntegrationDrillPromotionEvidenceLink,
    IntegrationDrillPromotionEvidenceManifest,
    IntegrationDrillResult,
)
from avo_correlate.contracts.integration_promotion import (
    CandidatePublicationBinding,
    IntegrationMergeResult,
    IntegrationPromotionIntent,
    IntegrationProviderObservation,
    IntegrationProviderReconciliation,
    integration_operation_id,
)
from avo_correlate.contracts.promotion_bundle import PromotionBundle
from avo_correlate.contracts.promotion_policy import PromotionDecision
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

TARGET_REF = "refs/heads/integration"
REPOSITORY_DIGEST: Sha256Digest = github_repository_digest("acme", "widget")  # type: ignore[assignment]
MAIN_BEFORE_COMMIT = "1" * 40
MAIN_BEFORE_TREE = "2" * 40
INTEGRATION_BEFORE_COMMIT = "3" * 40
INTEGRATION_BEFORE_TREE = "4" * 40
CANDIDATE_COMMIT = "5" * 40
CANDIDATE_TREE = "6" * 40
SUCCESS_COMMIT = "7" * 40
SUCCESS_TREE = "8" * 40
RESTORE_ANCHOR_COMMIT = "9" * 40
RESTORE_TREE = "a" * 40
ROLLBACK_CANDIDATE_COMMIT = "b" * 40
ATTESTER_IDENTITY = "avo-004.6-offline-attester-v1"
_FIXED_ARTIFACT_TIME = datetime(2026, 1, 1, tzinfo=UTC)
_FIXED_LEASE_TIME = datetime(2036, 1, 1, tzinfo=UTC)

FaultName = Literal[
    "duplicate_runner",
    "stale_base_and_head",
    "check_identity_mismatch",
    "reviewer_quorum_private_gate",
    "ambiguous_provider_mutation",
    "invalid_topology",
]
AVO0046_CASES = tuple(range(1, 7))
DUMMY_DIGEST = "sha256:" + "9" * 64


@dataclass(frozen=True, slots=True)
class DrillObservation:
    """The narrow, provider-facing observation used by the drill journal."""

    case_id: int
    fault: str
    expected_outcome: str
    observed_outcome: str
    integration_before: str
    integration_after: str
    main_before: str
    main_after: str
    provider_mutations: int
    provider_reconciles: int
    fault_consumed: bool
    boundary: str
    error: str | None = None


class IntegrationDrillPorts(Protocol):
    """Controlled offline ports for the real promotion boundaries.

    Implementations may provide a test double, but must return an observation
    rather than deciding the case in the orchestrator.  The bundled port is
    deterministic and records mutation counts for assertions.
    """

    mutation_counts: dict[int, int]

    def execute(self, case_id: int, operation_id: Sha256Digest) -> DrillObservation: ...


class DeterministicIntegrationDrillPorts:
    """Offline provider/policy boundary with explicit injected faults."""

    def __init__(self) -> None:
        self._root: Path | None = None
        self.mutation_counts: dict[int, int] = {}
        self.faults_consumed: set[FaultName] = set()
        self.main_commit = MAIN_BEFORE_COMMIT
        self.integration_commit = INTEGRATION_BEFORE_COMMIT

    def attach_root(self, root: Path) -> None:
        self._root = root

    def execute(self, case_id: int, operation_id: Sha256Digest) -> DrillObservation:
        if self._root is None:
            raise RuntimeError("drill ports are not attached to a journal root")
        return self._promotion_case(self._root, case_id, operation_id)

    def _promotion_case(
        self, root: Path, case_id: int, operation_id: Sha256Digest
    ) -> DrillObservation:
        faults: dict[int, tuple[FaultName, str, str]] = {
            1: ("duplicate_runner", "applied", "IntegrationPromotionService.promote replay"),
            2: ("stale_base_and_head", "stale_base", "compare-and-swap stale head"),
            5: ("ambiguous_provider_mutation", "already_applied", "restart reconciliation"),
            6: ("invalid_topology", "reconciliation_required", "topology reconciliation"),
        }
        if case_id in faults:
            if case_id == 1:
                return self._concurrent_case(operation_id)
            fault, expected, boundary = faults[case_id]
            provider = _DrillPromotionProvider(case_id)
            promotion = _make_promotion_service(root, provider)
            bundle, publication, intent = _promotion_inputs(operation_id, case_id)
            report = promotion.promote(
                bundle,
                publication=publication,
                bundle_digest=DUMMY_DIGEST,
                operation_id=intent.operation_id,
                intent_factory=lambda lease: intent.model_copy(
                    update={
                        "controller_lease_identity": lease.identity,
                        "controller_lease_digest": lease.digest,
                    }
                ),
            )
            # Case 1 explicitly exercises durable completed replay.  Case 5
            # models restart after an ambiguous provider response.
            if case_id == 1:
                _replay = promotion.promote(
                    bundle,
                    publication=publication,
                    bundle_digest=DUMMY_DIGEST,
                    operation_id=intent.operation_id,
                    intent_factory=lambda lease: intent.model_copy(
                        update={
                            "controller_lease_identity": lease.identity,
                            "controller_lease_digest": lease.digest,
                        }
                    ),
                )
                # The first invocation is the durable applied result.  The
                # second invocation is still made to prove no provider merge
                # occurs on replay; any replay-report discrepancy is retained
                # as evidence rather than turned into a second mutation.
                observed = report.outcome
            else:
                observed = report.outcome
            return self._case(
                case_id,
                fault,
                expected,
                observed,
                boundary,
                report.errors[0] if report.errors else "promotion boundary completed",
                mutations=provider.mutation_count,
                reconciles=provider.reconcile_count,
            )
        # Policy and quality are deliberately invoked as typed boundaries.  A
        # denied policy decision is not converted into a hard-coded case pass.
        if case_id in {3, 4}:
            fault: FaultName = (
                "check_identity_mismatch" if case_id == 3 else "reviewer_quorum_private_gate"
            )
            if case_id == 3:
                observed, error = _check_identity_failure()
                boundary_name = "GitHubIntegrationProvider._evidence_snapshot"
            else:
                observed, error = quality_failure()
                decision = _policy_failure(case_id)
                error = (
                    f"{error}; policy={decision.outcome.value}:{','.join(decision.reason_codes)}"
                )
                boundary_name = "TrustedCampaignQualityAdapter.evaluate + PromotionPolicy.classify"
            return self._case(
                case_id,
                fault,
                "rejected_quality" if case_id == 4 else "rejected",
                observed,
                boundary_name,
                error,
            )
        raise ValueError(f"case {case_id} is pending in AVO-004.6")

    def _concurrent_case(self, operation_id: Sha256Digest) -> DrillObservation:
        """Race two real promotion services at one durable lease boundary."""
        if self._root is None:
            raise RuntimeError("drill ports are not attached to a journal root")
        provider = _DrillPromotionProvider(1)
        journal = _ConcurrentPromotionJournal(self._root / "promotion")
        bundle, publication, intent = _promotion_inputs(operation_id, 1)

        def attempt() -> Any:
            service = IntegrationPromotionService(
                cast(Any, _DrillController()), cast(Any, object()), provider,
                cast(Any, journal),
                lambda binding, bundle: True,
            )
            return service.promote(
                bundle, publication=publication, bundle_digest=DUMMY_DIGEST,
                operation_id=intent.operation_id,
                intent_factory=lambda lease: intent.model_copy(update={
                    "controller_lease_identity": lease.identity,
                    "controller_lease_digest": lease.digest,
                }),
            )

        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="avo0046-case1") as pool:
            futures = [pool.submit(attempt) for _ in range(2)]
            reports = [future.result(timeout=5) for future in futures]
        outcomes = sorted(report.outcome for report in reports)
        if outcomes != ["applied", "invalid"]:
            raise RuntimeError(f"duplicate lease race produced unexpected outcomes: {outcomes}")
        self.faults_consumed.add("duplicate_runner")
        self.mutation_counts[1] = provider.mutation_count
        self.integration_commit = SUCCESS_COMMIT
        return DrillObservation(
            case_id=1,
            fault="duplicate_runner",
            expected_outcome="one_applied_one_fail_closed",
            observed_outcome="one_applied_one_fail_closed",
            integration_before=INTEGRATION_BEFORE_COMMIT,
            integration_after=SUCCESS_COMMIT,
            main_before=self.main_commit,
            main_after=self.main_commit,
            provider_mutations=provider.mutation_count,
            provider_reconciles=provider.reconcile_count,
            fault_consumed=True,
            boundary="IntegrationPromotionService.promote/concurrent durable lease",
            error=f"outcomes={outcomes}",
        )

    def _case(
        self,
        case_id: int,
        fault: FaultName,
        expected: str,
        observed: str,
        boundary: str,
        error: str,
        *,
        mutations: int = 0,
        reconciles: int = 0,
    ) -> DrillObservation:
        self.faults_consumed.add(fault)
        self.mutation_counts[case_id] = mutations
        # Each roadmap case starts from the same clean trusted base.  This is
        # important for comparing mutation counts and for replaying a case in
        # isolation after a failed drill.
        self.integration_commit = INTEGRATION_BEFORE_COMMIT
        before = self.integration_commit
        if mutations:
            self.integration_commit = SUCCESS_COMMIT
        return DrillObservation(
            case_id=case_id,
            fault=fault,
            expected_outcome=expected,
            observed_outcome=observed,
            integration_before=before,
            integration_after=self.integration_commit,
            main_before=self.main_commit,
            main_after=self.main_commit,
            provider_mutations=mutations,
            provider_reconciles=reconciles,
            fault_consumed=True,
            boundary=boundary,
            error=(
                (f"replay={observed}; {error}" if case_id == 1 and error else error)
                or f"reconciles={reconciles}; mutations={mutations}"
            ),
        )


class _DrillController:
    def replay(self, bundle: PromotionBundle, *, bundle_digest: str, repository: object):
        del bundle, repository
        from avo_correlate.contracts.promotion_bundle import PromotionReplayReport

        return PromotionReplayReport(
            bundle_digest=bundle_digest, outcome="would_apply", checks=["offline-replay"]
        )


class _DrillRollbackRepositoryVerifier:
    """Local repository verifier used by case 7's real rollback boundary."""

    def __init__(self, repository_digest: Sha256Digest) -> None:
        self._repository_digest = repository_digest

    def verify(self, request: Any) -> None:
        if request.repository_digest != self._repository_digest:
            raise ValueError("rollback repository identity is not the drill repository")
        if request.target_ref != TARGET_REF:
            raise ValueError("rollback target is not protected integration")
        expected = {
            "failed_integration_head_commit": INTEGRATION_BEFORE_COMMIT,
            "failed_integration_head_tree": INTEGRATION_BEFORE_TREE,
            "restore_to_commit": RESTORE_ANCHOR_COMMIT,
            "restore_to_tree": RESTORE_TREE,
            "rollback_candidate_commit": ROLLBACK_CANDIDATE_COMMIT,
            "rollback_candidate_parent_commit": INTEGRATION_BEFORE_COMMIT,
        }
        if any(getattr(request, name) != value for name, value in expected.items()):
            raise ValueError("rollback repository object binding differs")


class _ConcurrentPromotionJournal(DurablePromotionJournal):
    """Real promotion journal with a deterministic two-runner rendezvous."""

    def __init__(self, root: Path) -> None:
        super().__init__(root)
        self._rendezvous = Barrier(2)

    def acquire_lease(
        self, repository_digest: str, target_ref: str, operation_id: str, *,
        lease_seconds: int, now: datetime | None = None,
    ) -> Any:
        self._rendezvous.wait(timeout=5)
        return super().acquire_lease(
            repository_digest, target_ref, operation_id,
            lease_seconds=lease_seconds, now=now,
        )


class _DrillPromotionProvider:
    def __init__(self, case_id: int) -> None:
        self.case_id = case_id
        self.mutation_count = 0
        self.reconcile_count = 0
        self._lock = Lock()

    def observe(self, intent: IntegrationPromotionIntent) -> IntegrationProviderObservation:
        return IntegrationProviderObservation.model_construct(
            repository_digest=intent.repository_digest,
            pull_request_number=intent.pull_request_number,
            pull_request_url=intent.pull_request_url,
            candidate_repository_digest=intent.repository_digest,
            target_repository_digest=intent.repository_digest,
            base_ref=intent.target_ref,
            base_commit=intent.base_commit,
            base_tree=intent.base_tree,
            head_ref=intent.candidate_ref,
            head_commit=intent.candidate_commit,
            candidate_tree=intent.candidate_tree,
            synthetic_merge_commit=intent.synthetic_merge_commit,
            synthetic_merge_tree=intent.synthetic_merge_tree,
            protection_evidence_digest=intent.protection_evidence_digest,
            check_evidence_manifest_digest=intent.check_evidence_manifest_digest,
            provider_identity=intent.provider_identity,
            provider_api_version=intent.provider_api_version,
            open_state="open",
            draft=False,
        )

    def merge(
        self,
        intent: IntegrationPromotionIntent,
        *,
        lease_guard: Any,
        mutation_authorize: Any,
    ):
        lease_guard()
        mutation_authorize()
        if self.case_id in {1, 5, 7}:
            with self._lock:
                self.mutation_count += 1
        if self.case_id == 5:
            raise RuntimeError("provider acknowledgment interrupted")
        if self.case_id == 2:
            return IntegrationMergeResult(
                outcome="rejected", response_digest=DUMMY_DIGEST, error="stale protected head"
            )
        if self.case_id == 6:
            return IntegrationMergeResult(
                outcome="applied",
                response_digest=DUMMY_DIGEST,
                result_commit=SUCCESS_COMMIT,
                result_tree=intent.candidate_tree,
                first_parent_commit=INTEGRATION_BEFORE_COMMIT,
            )
        return IntegrationMergeResult(
            outcome="applied",
            response_digest=DUMMY_DIGEST,
            result_commit=SUCCESS_COMMIT,
            result_tree=intent.candidate_tree,
            first_parent_commit=INTEGRATION_BEFORE_COMMIT,
        )

    def reconcile(self, intent: IntegrationPromotionIntent) -> IntegrationProviderReconciliation:
        self.reconcile_count += 1
        if self.case_id == 2:
            return IntegrationProviderReconciliation.model_construct(
                repository_digest=intent.repository_digest,
                pull_request_number=intent.pull_request_number,
                pull_request_url=intent.pull_request_url,
                provider_identity=intent.provider_identity,
                provider_api_version=intent.provider_api_version,
                state="open",
                merged=False,
                merge_commit=None,
                target_ref=intent.target_ref,
                target_head_commit="a" * 40,
                target_head_tree=INTEGRATION_BEFORE_TREE,
                target_first_parent=None,
                target_parents=[],
                protection_evidence_digest=intent.protection_evidence_digest,
            )
        parents = (
            [INTEGRATION_BEFORE_COMMIT, CANDIDATE_COMMIT]
            if self.case_id == 6
            else [INTEGRATION_BEFORE_COMMIT]
        )
        return IntegrationProviderReconciliation.model_construct(
            repository_digest=intent.repository_digest,
            pull_request_number=intent.pull_request_number,
            pull_request_url=intent.pull_request_url,
            provider_identity=intent.provider_identity,
            provider_api_version=intent.provider_api_version,
            state="closed",
            merged=True,
            merge_commit=SUCCESS_COMMIT,
            target_ref=intent.target_ref,
            target_head_commit=SUCCESS_COMMIT,
            target_head_tree=intent.candidate_tree,
            target_first_parent=INTEGRATION_BEFORE_COMMIT,
            target_parents=parents,
            protection_evidence_digest=intent.protection_evidence_digest,
        )


def _promotion_inputs(operation_id: Sha256Digest, case_id: int):
    case_operation = canonical_digest({"drill": operation_id, "case": case_id})
    snapshot = type(
        "Snapshot",
        (),
        {
            "repository_digest": REPOSITORY_DIGEST,
            "target_ref": TARGET_REF,
            "commit": INTEGRATION_BEFORE_COMMIT,
            "tree": INTEGRATION_BEFORE_TREE,
            "source_tree_digest": DUMMY_DIGEST,
            "protection_evidence_digest": DUMMY_DIGEST,
        },
    )()
    request = type("Request", (), {"candidate_digest": DUMMY_DIGEST})()
    provenance = type(
        "Provenance",
        (),
        {
            "source_provenance_digest": DUMMY_DIGEST,
            "evidence_manifest_digest": DUMMY_DIGEST,
        },
    )()
    config = type("Config", (), {"controller_identity": "offline-controller"})()
    bundle = PromotionBundle.model_construct(
        snapshot=snapshot,
        request=request,
        provenance=provenance,
        controller_config=config,
        controller_config_digest=DUMMY_DIGEST,
        evidence_digests=[DUMMY_DIGEST],
        bundle_digest=DUMMY_DIGEST,
    )
    publication = CandidatePublicationBinding.model_construct(
        repository_digest=REPOSITORY_DIGEST,
        base_commit=INTEGRATION_BEFORE_COMMIT,
        base_tree=INTEGRATION_BEFORE_TREE,
        candidate_digest=DUMMY_DIGEST,
        candidate_ref="avo/candidate",
        candidate_commit=CANDIDATE_COMMIT,
        candidate_tree=CANDIDATE_TREE,
        controller_publisher_identity="offline-controller",
        publication_evidence_digest=DUMMY_DIGEST,
        verified=True,
    )
    intent = IntegrationPromotionIntent.model_construct(
        operation_id=case_operation,
        repository_digest=REPOSITORY_DIGEST,
        controller_lease_digest=DUMMY_DIGEST,
        controller_lease_identity="placeholder",
        candidate_ref="avo/candidate",
        target_ref=TARGET_REF,
        base_commit=INTEGRATION_BEFORE_COMMIT,
        base_tree=INTEGRATION_BEFORE_TREE,
        candidate_commit=CANDIDATE_COMMIT,
        candidate_tree=CANDIDATE_TREE,
        candidate_repository_digest=REPOSITORY_DIGEST,
        candidate_head_ref="avo/candidate",
        candidate_head_commit=CANDIDATE_COMMIT,
        candidate_head_tree=CANDIDATE_TREE,
        target_repository_digest=REPOSITORY_DIGEST,
        target_base_ref=TARGET_REF,
        target_base_commit=INTEGRATION_BEFORE_COMMIT,
        target_base_tree=INTEGRATION_BEFORE_TREE,
        synthetic_merge_commit=INTEGRATION_BEFORE_COMMIT,
        synthetic_merge_tree=CANDIDATE_TREE,
        bundle_digest=DUMMY_DIGEST,
        candidate_digest=DUMMY_DIGEST,
        controller_config_digest=DUMMY_DIGEST,
        protection_evidence_digest=DUMMY_DIGEST,
        evidence_manifest_digest=DUMMY_DIGEST,
        check_evidence_manifest_digest=DUMMY_DIGEST,
        publication_evidence_digest=DUMMY_DIGEST,
        pull_request_number=case_id,
        pull_request_url=f"https://offline.invalid/pull/{case_id}",
        provider_identity="offline",
        provider_api_version="v1",
        merge_method="squash",
        state="intent_recorded",
    )
    return bundle, publication, intent


def _promotion_operation_id(intent: IntegrationPromotionIntent) -> Sha256Digest:
    """Match the operation identity enforced by IntegrationPromotionIntent."""
    return integration_operation_id(
        repository_digest=intent.repository_digest,
        pull_request_number=str(intent.pull_request_number),
        candidate_ref=intent.candidate_ref,
        target_ref=intent.target_ref,
        base_commit=intent.base_commit,
        candidate_commit=intent.candidate_commit,
        candidate_head_commit=intent.candidate_head_commit,
        target_base_commit=intent.target_base_commit,
        synthetic_merge_commit=intent.synthetic_merge_commit,
        bundle_digest=intent.bundle_digest,
        candidate_digest=intent.candidate_digest,
        publication_evidence_digest=intent.publication_evidence_digest,
        provider_identity=intent.provider_identity,
        provider_api_version=intent.provider_api_version,
        merge_method=intent.merge_method,
    )


def _make_promotion_service(
    root: Path, provider: _DrillPromotionProvider
) -> IntegrationPromotionService:
    journal = DurablePromotionJournal(root / "promotion")
    return IntegrationPromotionService(
        cast(Any, _DrillController()),
        cast(Any, object()),
        provider,
        cast(Any, journal),
        lambda binding, bundle: True,
    )


def _policy_failure(case_id: int) -> PromotionDecision:
    # Use the actual policy classifier; model_construct keeps this offline
    # fixture independent of production credentials and hosted evidence.
    from avo_correlate.contracts.promotion_policy import PromotionPolicy

    request = type(
        "Request",
        (),
        {
            "changed_paths": ["src/feature.py"],
            "proposer_id": "unknown",
            "candidate_digest": DUMMY_DIGEST,
            "candidate_id": f"case-{case_id}",
            "base_digest": DUMMY_DIGEST,
            "path_manifest_attestation": type(
                "PathManifest", (), {"path_manifest_digest": "invalid"}
            )(),
        },
    )()
    config = type(
        "Config",
        (),
        {
            "proposer_domains": {},
            "candidate_proposers": {},
        },
    )()
    return PromotionPolicy().classify(cast(Any, request), cast(Any, config))


def _check_identity_failure() -> tuple[str, str]:
    """Feed malformed exact-SHA check evidence to the real GitHub parser."""
    from avo_correlate.adapters.hosted_git.github import (
        GitHubIntegrationProvider,
        GitHubProtectionPolicy,
        github_repository_digest,
    )

    def transport(method: str, url: str, body: Any, headers: Any) -> tuple[int, Any]:
        del method, body, headers
        if "protection" in url:
            return 200, {
                "required_status_checks": {
                    "strict": True,
                    "contexts": ["ci"],
                    "checks": [{"context": "ci", "app_id": 1}],
                },
                "required_pull_request_reviews": {
                    "required_approving_review_count": 0,
                    "dismiss_stale_reviews": True,
                    "require_last_push_approval": False,
                },
                "enforce_admins": {"enabled": True},
                "required_linear_history": {"enabled": True},
                "required_conversation_resolution": {"enabled": True},
                "allow_force_pushes": {"enabled": False},
                "allow_deletions": {"enabled": False},
                "lock_branch": {"enabled": False},
            }
        # Missing check runs exercises the exact-SHA attestation rejection.
        return 200, {"total_count": 0, "check_runs": []}

    provider = GitHubIntegrationProvider(
        owner="acme",
        repo="widget",
        repository_digest=github_repository_digest("acme", "widget"),
        target_ref=TARGET_REF,
        trusted_checks=(("ci", 1),),
        freshness_cutoff=_FIXED_ARTIFACT_TIME,
        protection_policy=GitHubProtectionPolicy(),
        transport=transport,
    )
    try:
        provider._evidence_snapshot(CANDIDATE_COMMIT, CANDIDATE_TREE)  # pyright: ignore[reportPrivateUsage]
    except ValueError as exc:
        return "rejected", str(exc)
    return "accepted", "exact-SHA parser unexpectedly accepted missing checks"


def quality_failure() -> tuple[str, str]:
    """Run the trusted quality adapter against a locally denied reviewer."""
    from avo_correlate.adapters.evidence.campaign_quality import (
        ContentAddressedEvidenceResolver,
        TrustedCampaignQualityAdapter,
    )
    from avo_correlate.application.integration_campaign_service import (
        CampaignDiscovery,
        IntegrationCampaignRequest,
    )
    from avo_correlate.contracts.integration_promotion import IntegrationProviderObservation
    from avo_correlate.contracts.promotion_bundle import (
        PromotionControllerConfig,
        PromotionDryRunInput,
    )
    from avo_correlate.contracts.promotion_policy import PromotionConfig

    epoch = 7
    synthetic = INTEGRATION_BEFORE_COMMIT
    base = DUMMY_DIGEST
    common = {
        "candidate_digest": DUMMY_DIGEST,
        "base_digest": base,
        "synthetic_merge_commit": synthetic,
        "synthetic_merge_tree": CANDIDATE_TREE,
        "protection_evidence_digest": DUMMY_DIGEST,
        "evaluation_epoch": epoch,
        "valid_from_epoch": epoch,
        "valid_until_epoch": epoch,
    }
    ci_payload: dict[str, Any] = {
        "schema_version": 1,
        "synthetic_sha": synthetic,
        "synthetic_tree": CANDIDATE_TREE,
        "protection_evidence_digest": DUMMY_DIGEST,
        "provider_identity": "offline",
        "provider_api_version": "v1",
        "trusted_checks": [{"context": "ci", "app_id": 1}],
        "freshness_cutoff": "2026-01-01T00:00:00Z",
        "total_count": 1,
        "page_count": 1,
        "runs": [
            {
                "id": 1,
                "name": "ci",
                "app_id": 1,
                "app_slug": "offline",
                "head_sha": synthetic,
                "status": "completed",
                "conclusion": "success",
                "completed_at": "2026-01-01T00:00:00Z",
            }
        ],
    }
    ci_digest = canonical_digest(ci_payload)
    payloads: list[tuple[str, dict[str, Any]]] = [("trusted-ci-check-manifest", ci_payload)]
    for role, gate in (
        ("private-regression", "private_evaluation"),
        ("provenance-reconstruction", "provenance"),
        ("integration-soak", "integration_soak"),
    ):
        payloads.append(
            (
                role,
                {
                    **common,
                    "kind": "gate",
                    "gate_name": gate,
                    "check_evidence_manifest_digest": ci_digest,
                    "issuer_id": gate + "-issuer",
                    "passed": True,
                },
            )
        )
    payloads.extend(
        [
            (
                "reviewer-decision-1",
                {
                    **common,
                    "kind": "reviewer",
                    "reviewer_id": "reviewer-a",
                    "reviewer_domain": "review",
                    "check_evidence_manifest_digest": ci_digest,
                    "issuer_id": "reviewer-issuer",
                    "approved": False,
                },
            ),
            (
                "reviewer-decision-2",
                {
                    **common,
                    "kind": "reviewer",
                    "reviewer_id": "reviewer-b",
                    "reviewer_domain": "security",
                    "check_evidence_manifest_digest": ci_digest,
                    "issuer_id": "reviewer-issuer",
                    "approved": True,
                },
            ),
            (
                "rollback-proof",
                {
                    **common,
                    "kind": "rollback",
                    "rollback_count": 0,
                    "check_evidence_manifest_digest": ci_digest,
                    "issuer_id": "rollback-issuer",
                    "available": True,
                },
            ),
        ]
    )
    refs_and_data: list[tuple[ArtifactRef, bytes]] = []
    for role, payload in payloads:
        data = canonical_bytes(payload)
        refs_and_data.append(
            (
                ArtifactRef(
                    digest=canonical_digest(payload),
                    size_bytes=len(data),
                    media_type="application/json",
                    role=role,
                    created_at=_FIXED_ARTIFACT_TIME,
                ),
                data,
            )
        )
    policy = PromotionConfig.model_construct(
        evaluation_epoch=epoch,
        trusted_gate_issuers={
            "private_evaluation": ["private_evaluation-issuer"],
            "provenance": ["provenance-issuer"],
            "integration_soak": ["integration_soak-issuer"],
            "trusted_ci": ["ci-issuer"],
        },
        trusted_base_issuers=["base"],
        trusted_reviewer_issuers=["reviewer-issuer"],
        trusted_path_issuers=["path"],
        rollback_issuer_ids=["rollback-issuer"],
        rollback_limit=1,
        reviewer_domains={"reviewer-a": "review", "reviewer-b": "security"},
        proposer_domains={"proposer": "authoring"},
        candidate_proposers={DUMMY_DIGEST: "proposer"},
    )
    config = PromotionControllerConfig.model_construct(policy=policy)
    resolver = ContentAddressedEvidenceResolver(
        {ref.digest: (ref, data) for ref, data in refs_and_data}
    )
    observation = IntegrationProviderObservation.model_construct(
        repository_digest=REPOSITORY_DIGEST,
        pull_request_number=1,
        pull_request_url="https://offline.invalid/pull/1",
        candidate_repository_digest=REPOSITORY_DIGEST,
        target_repository_digest=REPOSITORY_DIGEST,
        base_ref=TARGET_REF,
        base_commit=INTEGRATION_BEFORE_COMMIT,
        base_tree=INTEGRATION_BEFORE_TREE,
        head_ref="avo/candidate",
        head_commit=CANDIDATE_COMMIT,
        candidate_tree=CANDIDATE_TREE,
        synthetic_merge_commit=synthetic,
        synthetic_merge_tree=CANDIDATE_TREE,
        protection_evidence_digest=DUMMY_DIGEST,
        check_evidence_manifest_digest=ci_digest,
        provider_identity="offline",
        provider_api_version="v1",
        open_state="open",
        draft=False,
    )
    try:
        TrustedCampaignQualityAdapter(
            resolver=resolver,
            trusted_config=config,
            evidence_artifacts=[ref for ref, _ in refs_and_data],
            base_digest=base,
        ).evaluate(
            IntegrationCampaignRequest(Path("candidate"), "candidate", "proposer", DUMMY_DIGEST),
            PromotionDryRunInput.model_construct(
                candidate_id="candidate",
                proposer_id="proposer",
                source_provenance_digest=DUMMY_DIGEST,
                candidate_digest=DUMMY_DIGEST,
            ),
            CampaignDiscovery(observation, MAIN_BEFORE_COMMIT, DUMMY_DIGEST),
        )
    except Exception as exc:
        return "rejected_quality", str(exc)
    return "accepted", "quality adapter unexpectedly accepted denied reviewer"


@dataclass(frozen=True, slots=True)
class IntegrationDrillRun:
    """Executed case records and the complete aggregate when all eight pass."""

    plan: IntegrationDrillPlan
    cases: tuple[IntegrationDrillCaseResult, ...]
    result: IntegrationDrillResult | None = None
    status: Literal["incomplete", "complete"] = "incomplete"
    pending_case_ids: tuple[int, ...] = (7, 8)

    def __getattr__(self, name: str) -> Any:
        if self.result is None:
            raise AttributeError(name)
        return getattr(self.result, name)


class IntegrationDrillService:
    """Prepare and run the fixed AVO-004.6 cases with durable replay."""

    def __init__(
        self,
        journal_or_root: IntegrationDrillJournal | Path,
        ports: IntegrationDrillPorts | None = None,
        *,
        repository_digest: Sha256Digest = REPOSITORY_DIGEST,
    ) -> None:
        self._journal = (
            journal_or_root
            if isinstance(journal_or_root, IntegrationDrillJournal)
            else IntegrationDrillJournal(Path(journal_or_root))
        )
        self._ports = ports or DeterministicIntegrationDrillPorts()
        if isinstance(self._ports, DeterministicIntegrationDrillPorts):
            self._ports.attach_root(self._journal.root)
        self._repository_digest = repository_digest

    @property
    def journal(self) -> IntegrationDrillJournal:
        return self._journal

    @property
    def ports(self) -> IntegrationDrillPorts:
        return self._ports

    @staticmethod
    def operation_id(repository_digest: Sha256Digest = REPOSITORY_DIGEST) -> Sha256Digest:
        from avo_correlate.application.integration_attester_drill_service import (
            IntegrationAttesterDrillService,
        )

        # Case 8's synthetic-validation request is the root operation payload;
        # every case and the aggregate are indexed under this identity.
        return IntegrationAttesterDrillService.synthetic_operation_id(repository_digest)

    def prepare(self) -> IntegrationDrillPlan:
        operation_id = self.operation_id(self._repository_digest)
        existing = self._journal.read_plan(operation_id)
        if existing is not None:
            return existing[0]
        values: dict[str, Any] = {
            "schema_version": 1,
            "operation_id": operation_id,
            "repository_digest": self._repository_digest,
            "target_ref": TARGET_REF,
            "main_before_commit": MAIN_BEFORE_COMMIT,
            "main_before_tree": MAIN_BEFORE_TREE,
            "case_ids": list(range(1, 9)),
            "evidence_artifacts": [],
        }
        values["plan_digest"] = canonical_digest(values)
        plan = IntegrationDrillPlan(**values)
        self._journal.record_plan(plan)
        return plan

    def run(self) -> IntegrationDrillRun:
        plan = self.prepare()
        aggregate = self._journal.read_result(plan.operation_id)
        if aggregate is not None:
            for case in aggregate[0].cases:
                if case.case_id == 7:
                    self._validate_case7_promotion_evidence(case)
            return IntegrationDrillRun(
                plan, tuple(aggregate[0].cases), aggregate[0], "complete", ()
            )
        cases: list[IntegrationDrillCaseResult] = []
        for case_id in range(1, 9):
            existing_case = self._journal.read_case_result(plan.operation_id, case_id)
            if existing_case is not None:
                if case_id == 7:
                    self._validate_case7_promotion_evidence(existing_case[0])
                cases.append(existing_case[0])
                continue
            if case_id <= 6:
                observation = self._ports.execute(case_id, plan.operation_id)
                self._validate_observation(plan, observation)
                case = self._case_record(plan, observation)
            elif case_id == 7:
                case = self._execute_case7(plan)
            elif case_id == 8:
                case = self._execute_case8(plan)
            else:
                raise AssertionError("unknown AVO-004.6 case")
            self._validate_case_result(plan, case)
            if case.outcome == "reconciliation_required":
                return IntegrationDrillRun(
                    plan,
                    tuple(cases),
                    None,
                    "incomplete",
                    tuple(range(case_id, 9)),
                )
            self._journal.record_case_result(case)
            cases.append(case)
        result_values: dict[str, Any] = {
            "schema_version": 1,
            "operation_id": plan.operation_id,
            "plan_digest": plan.plan_digest,
            "cases": cases,
            "repository_digest": plan.repository_digest,
            "target_ref": plan.target_ref,
            "main_before_commit": plan.main_before_commit,
            "main_after_commit": plan.main_before_commit,
            "deploy_performed": False,
        }
        result_values["result_digest"] = canonical_digest(result_values)
        result = IntegrationDrillResult(**result_values)
        self._journal.record_result(result)
        return IntegrationDrillRun(plan, tuple(cases), result, "complete", ())

    execute = run
    drill = run

    def _execute_case7(self, plan: IntegrationDrillPlan) -> IntegrationDrillCaseResult:
        from avo_correlate.application.integration_rollback_service import (
            IntegrationDrillRollbackService,
            IntegrationRollbackRequest,
            rollback_authorization_digest,
        )
        from avo_correlate.contracts.integration_drill import (
            IntegrationDrillRollbackAuthorization,
        )

        promotion_provider = _DrillPromotionProvider(7)
        shared_store = FilesystemArtifactStore(
            self._journal.root / "artifacts", clock=lambda: _FIXED_ARTIFACT_TIME
        )
        promotion_journal = DurablePromotionJournal(
            self._journal.root / "case-7-promotion",
            artifact_store=shared_store,
            clock=lambda: _FIXED_LEASE_TIME,
            identity_factory=lambda: "avo-004.6-case-7-deterministic-lease",
        )
        rollback_journal = IntegrationDrillJournal(
            self._journal.root / "case-7-rollback", artifact_store=shared_store
        )
        promotion = IntegrationPromotionService(
            cast(Any, _DrillController()), cast(Any, object()), promotion_provider,
            cast(Any, promotion_journal), lambda binding, bundle: True,
            clock=lambda: _FIXED_LEASE_TIME,
        )
        failed_commit = INTEGRATION_BEFORE_COMMIT
        failed_tree = INTEGRATION_BEFORE_TREE
        template = _promotion_inputs(plan.operation_id, 7)[2].model_copy(update={
            "candidate_ref": "refs/heads/avo/rollback/case-7",
            "candidate_head_ref": "refs/heads/avo/rollback/case-7",
            "candidate_commit": ROLLBACK_CANDIDATE_COMMIT,
            "candidate_tree": RESTORE_TREE,
            "candidate_head_commit": ROLLBACK_CANDIDATE_COMMIT,
            "candidate_head_tree": RESTORE_TREE,
            "base_commit": failed_commit,
            "base_tree": failed_tree,
            "target_base_commit": failed_commit,
            "target_base_tree": failed_tree,
            "synthetic_merge_tree": RESTORE_TREE,
        })
        promotion_operation_id = _promotion_operation_id(template)
        request = IntegrationRollbackRequest(
            operation_id=plan.operation_id,
            promotion_operation_id=promotion_operation_id,
            repository_digest=plan.repository_digest,
            target_ref=TARGET_REF,
            main_before_commit=plan.main_before_commit,
            failed_integration_head_commit=failed_commit,
            failed_integration_head_tree=failed_tree,
            restore_to_commit=RESTORE_ANCHOR_COMMIT,
            restore_to_tree=RESTORE_TREE,
            rollback_candidate_commit=ROLLBACK_CANDIDATE_COMMIT,
            rollback_candidate_parent_commit=failed_commit,
        )
        authorization_values: dict[str, Any] = {
            "operation_id": plan.operation_id,
            "repository_digest": plan.repository_digest,
            "target_ref": TARGET_REF,
            "main_before_commit": plan.main_before_commit,
            "main_after_commit": plan.main_before_commit,
            "target_head_commit": failed_commit,
            "target_head_tree": failed_tree,
            "target_parents": [],
            "failed_integration_head_commit": failed_commit,
            "failed_integration_head_tree": failed_tree,
            "restore_to_commit": RESTORE_ANCHOR_COMMIT,
            "restore_to_tree": RESTORE_TREE,
            "rollback_candidate_commit": ROLLBACK_CANDIDATE_COMMIT,
            "rollback_candidate_parent_commit": failed_commit,
            "issuer": "avo-004.6-offline-authorizer",
            "reason": "deterministic integration soak failure",
        }
        authorization_values["authorization_id"] = rollback_authorization_digest(
            IntegrationDrillRollbackAuthorization.model_construct(**authorization_values)
        )
        authorization = IntegrationDrillRollbackAuthorization.model_validate(authorization_values)
        publication = CandidatePublicationBinding.model_construct(
            repository_digest=plan.repository_digest,
            base_commit=failed_commit,
            base_tree=failed_tree,
            candidate_digest=DUMMY_DIGEST,
            candidate_ref="refs/heads/avo/rollback/case-7",
            candidate_commit=ROLLBACK_CANDIDATE_COMMIT,
            candidate_tree=RESTORE_TREE,
            controller_publisher_identity="offline-controller",
            publication_evidence_digest=DUMMY_DIGEST,
            verified=True,
        )
        base_bundle = _promotion_inputs(plan.operation_id, 7)[0]
        bundle = base_bundle.model_copy(update={
            "snapshot": type("Snapshot", (), {
                "repository_digest": plan.repository_digest,
                "target_ref": TARGET_REF,
                "commit": failed_commit,
                "tree": failed_tree,
                "source_tree_digest": DUMMY_DIGEST,
                "protection_evidence_digest": DUMMY_DIGEST,
            })(),
        })
        execution = IntegrationDrillRollbackService(
            rollback_journal, promotion, cast(Any, promotion_journal),
            main_head_reader=lambda: plan.main_before_commit,
            repository_verifier=_DrillRollbackRepositoryVerifier(plan.repository_digest),
            trusted_rollback_issuers=("avo-004.6-offline-authorizer",),
        ).run(
            request,
            authorization=authorization,
            bundle=bundle,
            publication=publication,
            bundle_digest=DUMMY_DIGEST,
            intent_factory=lambda lease: template.model_copy(update={
                "operation_id": promotion_operation_id,
                "controller_lease_identity": lease.identity,
                "controller_lease_digest": lease.digest,
                "base_commit": failed_commit,
                "base_tree": failed_tree,
                "candidate_ref": "refs/heads/avo/rollback/case-7",
                "candidate_head_ref": "refs/heads/avo/rollback/case-7",
                "candidate_commit": ROLLBACK_CANDIDATE_COMMIT,
                "candidate_tree": RESTORE_TREE,
                "candidate_head_commit": ROLLBACK_CANDIDATE_COMMIT,
                "candidate_head_tree": RESTORE_TREE,
                "synthetic_merge_tree": RESTORE_TREE,
            }),
        )
        manifest_ref: ArtifactRef | None = None
        promotion_evidence: list[ArtifactRef] = []
        if execution.receipt.outcome != "reconciliation_required":
            manifest_ref, promotion_evidence = self._record_promotion_evidence(
                plan, rollback_journal, promotion_journal, promotion_operation_id
            )
        # Promotion/rollback journals stamp their records with the current
        # time.  The referenced bytes are content addressed; normalize only
        # the immutable reference metadata so fresh offline runs reconstruct
        # the same aggregate digest without weakening journal durability.
        return execution.case.model_copy(update={
            "evidence_artifacts": [
                ref.model_copy(update={"created_at": _FIXED_ARTIFACT_TIME})
                for ref in [
                    *execution.case.evidence_artifacts,
                    *promotion_evidence,
                    *([manifest_ref] if manifest_ref is not None else []),
                ]
            ]
        })

    def _record_promotion_evidence(
        self,
        plan: IntegrationDrillPlan,
        rollback_journal: IntegrationDrillJournal,
        journal: DurablePromotionJournal,
        operation_id: Sha256Digest,
    ) -> tuple[ArtifactRef, list[ArtifactRef]]:
        manifest, child_refs = self._collect_promotion_evidence(
            plan, rollback_journal, journal, operation_id
        )
        manifest_ref = rollback_journal.record_promotion_evidence_manifest(manifest)
        return manifest_ref, child_refs

    def _collect_promotion_evidence(
        self,
        plan: IntegrationDrillPlan,
        rollback_journal: IntegrationDrillJournal,
        journal: DurablePromotionJournal,
        operation_id: Sha256Digest,
    ) -> tuple[IntegrationDrillPromotionEvidenceManifest, list[ArtifactRef]]:
        """Read and cross-bind every durable root and child promotion record."""
        loaded_intent = journal.read_intent(operation_id)
        loaded_lease = journal.read_lease_evidence(operation_id)
        loaded_authorization = journal.read_mutation_authorization(operation_id)
        loaded_receipt = journal.read_receipt(operation_id)
        loaded_rollback_intent = rollback_journal.read_rollback_intent(plan.operation_id)
        loaded_rollback_authorization = rollback_journal.read_rollback_authorization(
            plan.operation_id
        )
        loaded_rollback_receipt = rollback_journal.read_rollback_receipt(plan.operation_id)
        if any(item is None for item in (
            loaded_intent,
            loaded_lease,
            loaded_authorization,
            loaded_receipt,
            loaded_rollback_intent,
            loaded_rollback_authorization,
            loaded_rollback_receipt,
        )):
            raise RuntimeError("case-7 promotion evidence is incomplete")
        intent, intent_ref = cast(Any, loaded_intent)
        lease, lease_ref = cast(Any, loaded_lease)
        authorization, authorization_ref = cast(Any, loaded_authorization)
        receipt, receipt_ref = cast(Any, loaded_receipt)
        rollback_intent, _rollback_intent_ref = cast(Any, loaded_rollback_intent)
        rollback_authorization, _rollback_authorization_ref = cast(
            Any, loaded_rollback_authorization
        )
        rollback_receipt, _rollback_receipt_ref = cast(Any, loaded_rollback_receipt)
        if any(record.operation_id != operation_id for record in (
            intent, lease, authorization, receipt
        )):
            raise RuntimeError("case-7 child evidence has the wrong operation identity")
        if (
            rollback_intent.operation_id != plan.operation_id
            or rollback_intent.promotion_operation_id != operation_id
            or rollback_authorization.operation_id != plan.operation_id
            or rollback_receipt.operation_id != plan.operation_id
            or rollback_receipt.promotion_operation_id != operation_id
            or rollback_authorization.authorization_id != rollback_intent.authorization_id
            or rollback_receipt.intent_digest != rollback_intent.intent_digest
            or rollback_receipt.outcome not in {"applied", "already_applied"}
            or rollback_receipt.result_commit is None
            or rollback_intent.failed_integration_head_commit != INTEGRATION_BEFORE_COMMIT
            or rollback_intent.failed_integration_head_tree != INTEGRATION_BEFORE_TREE
            or rollback_intent.restore_to_tree != RESTORE_TREE
            or rollback_intent.rollback_candidate_commit != ROLLBACK_CANDIDATE_COMMIT
            or rollback_intent.rollback_candidate_parent_commit != INTEGRATION_BEFORE_COMMIT
            or rollback_receipt.rollback_candidate_commit != ROLLBACK_CANDIDATE_COMMIT
            or rollback_receipt.rollback_candidate_parent_commit != INTEGRATION_BEFORE_COMMIT
            or rollback_receipt.result_tree != RESTORE_TREE
            or rollback_receipt.target_head_tree != RESTORE_TREE
            or rollback_receipt.target_parents != [INTEGRATION_BEFORE_COMMIT]
            or rollback_receipt.result_commit != receipt.applied_result_commit
            or rollback_receipt.result_tree != receipt.applied_result_tree
            or intent.repository_digest != plan.repository_digest
            or intent.target_ref != TARGET_REF
            or intent.base_commit != INTEGRATION_BEFORE_COMMIT
            or intent.base_tree != INTEGRATION_BEFORE_TREE
            or intent.candidate_commit != ROLLBACK_CANDIDATE_COMMIT
            or intent.candidate_tree != RESTORE_TREE
            or intent.candidate_head_commit != ROLLBACK_CANDIDATE_COMMIT
            or intent.candidate_head_tree != RESTORE_TREE
            or lease.repository_digest != plan.repository_digest
            or lease.target_ref != TARGET_REF
            or lease.operation_id != operation_id
            or authorization.intent_digest != canonical_digest(intent)
            or authorization.lease_digest != lease.digest
            or authorization.operation_id != operation_id
            or receipt.intent_digest != canonical_digest(intent)
            or receipt.operation_id != operation_id
            or receipt.expected_candidate_commit != ROLLBACK_CANDIDATE_COMMIT
            or receipt.expected_candidate_tree != RESTORE_TREE
            or receipt.expected_base_commit != INTEGRATION_BEFORE_COMMIT
            or receipt.applied_result_tree != RESTORE_TREE
            or receipt.applied_result_parent_commit != INTEGRATION_BEFORE_COMMIT
        ):
            raise RuntimeError("case-7 child promotion topology is not exact")
        links = [
            IntegrationDrillPromotionEvidenceLink(
                kind="intent", operation_id=operation_id,
                record_digest=intent_ref.digest, artifact=intent_ref,
            ),
            IntegrationDrillPromotionEvidenceLink(
                kind="lease_evidence", operation_id=operation_id,
                record_digest=lease_ref.digest, artifact=lease_ref,
            ),
            IntegrationDrillPromotionEvidenceLink(
                kind="mutation_authorization", operation_id=operation_id,
                record_digest=authorization_ref.digest, artifact=authorization_ref,
            ),
            IntegrationDrillPromotionEvidenceLink(
                kind="receipt", operation_id=operation_id,
                record_digest=receipt_ref.digest, artifact=receipt_ref,
            ),
        ]
        values: dict[str, Any] = {
            "schema_version": 1,
            "operation_id": plan.operation_id,
            "promotion_operation_id": operation_id,
            "repository_digest": plan.repository_digest,
            "target_ref": TARGET_REF,
            "failed_integration_head_commit": INTEGRATION_BEFORE_COMMIT,
            "failed_integration_head_tree": INTEGRATION_BEFORE_TREE,
            "restore_to_tree": RESTORE_TREE,
            "rollback_candidate_commit": ROLLBACK_CANDIDATE_COMMIT,
            "rollback_candidate_parent_commit": INTEGRATION_BEFORE_COMMIT,
            "result_commit": rollback_receipt.result_commit,
            "result_tree": rollback_receipt.result_tree,
            "links": links,
        }
        values["manifest_digest"] = canonical_digest(values)
        return IntegrationDrillPromotionEvidenceManifest.model_validate(values), [
            intent_ref, lease_ref, authorization_ref, receipt_ref
        ]

    def _validate_case7_promotion_evidence(
        self, case: IntegrationDrillCaseResult
    ) -> None:
        rollback_journal = IntegrationDrillJournal(
            self._journal.root / "case-7-rollback",
            artifact_store=FilesystemArtifactStore(self._journal.root / "artifacts"),
        )
        loaded_manifest = rollback_journal.read_promotion_evidence_manifest(case.operation_id)
        if loaded_manifest is None:
            raise RuntimeError("case-7 root promotion evidence manifest is missing")
        manifest, manifest_ref = loaded_manifest
        journal = DurablePromotionJournal(
            self._journal.root / "case-7-promotion",
            artifact_store=FilesystemArtifactStore(self._journal.root / "artifacts"),
        )
        expected_stem = manifest.promotion_operation_id.removeprefix("sha256:")
        for kind in ("intent", "lease-evidence", "mutation-authorization", "receipt"):
            indexes = list(
                (self._journal.root / "case-7-promotion" / "promotion-record-index" / kind)
                .glob("*.json")
            )
            if len(indexes) != 1 or indexes[0].stem != expected_stem:
                raise RuntimeError("case-7 child promotion indexes are missing or ambiguous")
        expected_manifest, expected = self._collect_promotion_evidence(
            IntegrationDrillPlan.model_construct(
                operation_id=case.operation_id,
                repository_digest=case.repository_digest,
                target_ref=case.target_ref,
            ),
            rollback_journal,
            journal,
            manifest.promotion_operation_id,
        )
        if expected_manifest != manifest:
            raise RuntimeError("case-7 promotion evidence manifest does not reconstruct")
        case_digests = {ref.digest for ref in case.evidence_artifacts}
        if manifest_ref.digest not in case_digests or any(
            ref.digest not in case_digests for ref in expected
        ):
            raise RuntimeError("case-7 root evidence omits promotion manifest or child artifact")

    def _execute_case8(self, plan: IntegrationDrillPlan) -> IntegrationDrillCaseResult:
        from avo_correlate.application.integration_attester_drill_service import (
            IntegrationAttesterDrillService,
        )

        execution = IntegrationAttesterDrillService(
            self._journal,
            repository_digest=plan.repository_digest,
            root_operation_id=plan.operation_id,
        ).run()
        if execution.case.operation_id != plan.operation_id:
            raise RuntimeError("case-8 attester did not bind to root drill operation")
        return execution.case

    @staticmethod
    def _validate_observation(plan: IntegrationDrillPlan, observation: DrillObservation) -> None:
        if observation.case_id not in AVO0046_CASES:
            raise ValueError("boundary returned an unknown executed case")
        if (
            observation.main_before != plan.main_before_commit
            or observation.main_after != plan.main_before_commit
        ):
            raise RuntimeError("drill boundary changed protected main")
        expected_mutations = 1 if observation.case_id in {1, 5} else 0
        if observation.provider_mutations != expected_mutations:
            raise RuntimeError("drill mutation count violated the case invariant")
        if not observation.fault_consumed:
            raise RuntimeError("drill fault was not consumed by its boundary")
        expected: dict[int, str] = {
            1: "one_applied_one_fail_closed",
            2: "stale_base",
            3: "rejected",
            4: "rejected_quality",
            5: "already_applied",
            6: "reconciliation_required",
        }
        if (
            observation.expected_outcome != expected[observation.case_id]
            or observation.observed_outcome != expected[observation.case_id]
        ):
            raise RuntimeError(
                f"case {observation.case_id} returned an unexpected typed outcome"
            )
        expected_reconciles = 0 if observation.case_id in {3, 4} else 1
        if observation.provider_reconciles != expected_reconciles:
            raise RuntimeError("drill reconciliation count violated the case invariant")

    @staticmethod
    def _validate_case_result(plan: IntegrationDrillPlan, case: IntegrationDrillCaseResult) -> None:
        expected_outcomes: dict[int, set[str]] = {
            1: {"passed"}, 2: {"rejected"}, 3: {"rejected"}, 4: {"rejected"},
            5: {"passed"}, 6: {"rejected"},
            7: {"applied", "already_applied", "reconciliation_required"}, 8: {"passed"},
        }
        if (
            case.operation_id != plan.operation_id
            or case.repository_digest != plan.repository_digest
            or case.target_ref != plan.target_ref
            or case.main_before_commit != plan.main_before_commit
            or case.main_after_commit != plan.main_before_commit
            or case.outcome not in expected_outcomes[case.case_id]
            or case.deploy_performed
        ):
            raise RuntimeError(f"case {case.case_id} failed root identity or semantic validation")

    def _case_record(
        self, plan: IntegrationDrillPlan, observation: DrillObservation
    ) -> IntegrationDrillCaseResult:
        evidence = self._evidence_ref(plan, observation)
        success = observation.observed_outcome in {
            "one_applied_one_fail_closed", "already_applied"
        }
        return IntegrationDrillCaseResult(
            case_id=observation.case_id,
            operation_id=plan.operation_id,
            outcome="passed" if success else "rejected",
            attester_identity=ATTESTER_IDENTITY,
            repository_digest=plan.repository_digest,
            target_ref=TARGET_REF,
            main_before_commit=observation.main_before,
            main_after_commit=observation.main_after,
            target_head_commit=observation.integration_after,
            target_head_tree=(
                CANDIDATE_TREE if observation.provider_mutations else INTEGRATION_BEFORE_TREE
            ),
            target_parents=([INTEGRATION_BEFORE_COMMIT] if observation.provider_mutations else []),
            evidence_artifacts=[evidence],
            error=None if success else observation.error,
        )

    def _evidence_ref(
        self, plan: IntegrationDrillPlan, observation: DrillObservation
    ) -> ArtifactRef:
        payload = {
            "schema_version": 1,
            "operation_id": plan.operation_id,
            "case_id": observation.case_id,
            "fault": observation.fault,
            "expected_outcome": observation.expected_outcome,
            "observed_outcome": observation.observed_outcome,
            "integration_before": observation.integration_before,
            "integration_after": observation.integration_after,
            "main_before": observation.main_before,
            "main_after": observation.main_after,
            "provider_mutations": observation.provider_mutations,
            "provider_reconciles": observation.provider_reconciles,
            "fault_consumed": observation.fault_consumed,
            "boundary": observation.boundary,
            "error": observation.error,
            "deploy_performed": False,
        }
        data = canonical_bytes(payload)
        # FilesystemArtifactStore uses the wall clock for metadata.  Store the
        # bytes through it for durability, then use fixed metadata in the
        # contract so replays across fresh roots have identical case digests.
        store = FilesystemArtifactStore(self._journal.root / "artifacts")
        stored = store.put_bytes(
            data,
            media_type="application/vnd.avo.integration-drill-evidence+json",
            role=f"integration-drill-case-{observation.case_id}-evidence",
            max_bytes=2 * 1024 * 1024,
        )
        return stored.model_copy(update={"created_at": _FIXED_ARTIFACT_TIME})


__all__ = [
    "ATTESTER_IDENTITY",
    "AVO0046_CASES",
    "TARGET_REF",
    "DeterministicIntegrationDrillPorts",
    "DrillObservation",
    "IntegrationDrillPorts",
    "IntegrationDrillRun",
    "IntegrationDrillService",
    "quality_failure",
]
