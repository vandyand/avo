"""Run one resumable, PR-native AVO-004.6 live rollback.

The hosted adapters are deliberately dependency-injected.  This keeps the CLI
from treating untrusted JSON as a soak or authorization and lets deployments
construct the existing GitCandidatePublisher/GitHub providers with their
trusted configuration before invoking :class:`LiveRollbackOperator`.
"""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from avo_correlate.adapters.artifacts import FilesystemArtifactStore
from avo_correlate.adapters.artifacts.campaign_journal import CampaignCompletionJournal
from avo_correlate.adapters.artifacts.live_rollback_completion_journal import (
    LiveRollbackCompletionJournal,
)
from avo_correlate.adapters.git import GitCandidatePublisher
from avo_correlate.adapters.hosted_git import (
    GitHubCampaignProvider,
    GitHubIntegrationProvider,
    github_repository_digest,
)
from avo_correlate.application.integration_live_rollback_completion_service import (
    LiveRollbackCompletionExecution,
    LiveRollbackCompletionInputs,
    LiveRollbackCompletionService,
)
from avo_correlate.application.integration_live_rollback_service import (
    LiveIntegrationRollbackService,
    LiveRollbackExecution,
)
from avo_correlate.application.integration_promotion_service import IntegrationPromotionService
from avo_correlate.application.integration_rollback_service import IntegrationDrillRollbackService
from avo_correlate.application.synthetic_validation_service import SyntheticValidationService
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_campaign import IntegrationCampaignEvidencePackage
from avo_correlate.contracts.integration_drill import (
    IntegrationDrillRollbackAuthorization,
    IntegrationRollbackRequest,
)
from avo_correlate.contracts.integration_live_rollback_completion import (
    LiveRollbackCompletionPackage,
)
from avo_correlate.contracts.integration_promotion import (
    CandidatePublicationBinding,
    IntegrationPromotionIntent,
)
from avo_correlate.contracts.promotion_bundle import PromotionBundle

REMOTE = "https://github.com/vandyand/avo.git"
OWNER = "vandyand"
REPOSITORY = "avo"
TARGET_REF = "refs/heads/integration"
MAIN_REF = "refs/heads/main"
TRUSTED_CHECKS = (
    ("avo synthetic validate (ubuntu-latest)", 15368),
    ("avo synthetic validate (windows-latest)", 15368),
)
PROTECTION_CHECKS = (("validate (ubuntu-latest)", 15368), ("validate (windows-latest)", 15368))


@dataclass(frozen=True, slots=True)
class LiveRollbackHostedWiring:
    """The existing hosted boundaries used by the live rollback operator."""

    publisher: GitCandidatePublisher
    campaign_provider: GitHubCampaignProvider
    promotion: IntegrationPromotionService
    drill: IntegrationDrillRollbackService
    core: LiveIntegrationRollbackService
    validation: SyntheticValidationService


@dataclass(frozen=True, slots=True)
class LiveRollbackPreflight:
    """Authenticated, zero-mutation state required before rollback wiring."""

    operation_id: str
    canary_operation_id: str
    repository_digest: str
    failed_head_commit: str
    failed_head_tree: str
    main_commit: str
    workflow_digest: str


@dataclass(frozen=True, slots=True)
class RollbackBundleAuthorityInput:
    """Authenticated facts a controller-owned rollback authority must bind.

    This is intentionally not a JSON CLI shape.  In particular, the canary
    package, its artifact reference, and the candidate publication are typed
    durable records; substituting a caller assertion for any of them is not a
    valid authorization request.
    """

    operation_id: str
    canary_package: IntegrationCampaignEvidencePackage
    canary_package_artifact: ArtifactRef
    repository_digest: str
    target_ref: str
    main_commit: str
    failed_head_commit: str
    failed_head_tree: str
    restore_to_commit: str
    restore_to_tree: str
    publication: CandidatePublicationBinding
    candidate_digest: str
    changed_paths: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AuthorizedRollbackBundle:
    """The only admissible policy/authorization input for live rollback.

    The authority, not a CLI caller, must create a bundle whose policy evidence
    is valid for this restore candidate and a rollback authorization whose
    issuer is allowed by that same policy.  The runner revalidates every
    topology binding before handing either record to the mutation services.
    """

    bundle: PromotionBundle
    bundle_digest: str
    authorization: IntegrationDrillRollbackAuthorization


class RollbackBundleAuthority(Protocol):
    """Controller-owned source of fresh, candidate-bound rollback authority."""

    def authorize(self, request: RollbackBundleAuthorityInput) -> AuthorizedRollbackBundle: ...


class LiveRollbackHostedRunner:
    """Hosted authority preflight and durable completion replay fence."""

    def __init__(self, provider: GitHubIntegrationProvider, state_root: Path) -> None:
        self.provider = provider
        self.state_root = state_root.resolve()

    def preflight(self, operation_id: str, canary_operation_id: str) -> LiveRollbackPreflight:
        self.provider.verify_repository_binding()
        journal = CampaignCompletionJournal(
            self.state_root / "completion",
            artifact_store=FilesystemArtifactStore(self.state_root / "artifacts"),
        )
        loaded = journal.read_package(canary_operation_id)
        if loaded is None:
            raise RuntimeError("successful canary package is missing from durable state")
        canary, _canary_ref = loaded
        target = self.provider.read_authority_ref(TARGET_REF)
        main = self.provider.read_authority_ref(MAIN_REF)
        if (
            canary.report.outcome not in {"applied", "already_applied"}
            or canary.receipt.applied_result_commit != target.commit
            or canary.receipt.applied_result_tree != target.tree
            or canary.main_before_commit != main.commit
            or canary.main_after_commit != main.commit
        ):
            raise RuntimeError("successful canary is stale against current target or main")
        workflow = self.provider.observe_workflow_authority(canary.intent.base_commit)
        return LiveRollbackPreflight(
            operation_id=operation_id,
            canary_operation_id=canary_operation_id,
            repository_digest=self.provider.repository_digest,
            failed_head_commit=target.commit,
            failed_head_tree=target.tree,
            main_commit=main.commit,
            workflow_digest=workflow.workflow_blob_digest,
        )

    def completed(
        self, operation_id: str
    ) -> tuple[LiveRollbackCompletionPackage, ArtifactRef] | None:
        """Read the immutable outer package from the shared artifact store.

        The journal verifies every named child on read. A corrupt index or a
        missing child therefore fails closed rather than allowing a restart to
        replay a hosted mutation.
        """

        return LiveRollbackCompletionJournal(
            self.state_root / "live-rollback-completion",
            artifact_store=FilesystemArtifactStore(self.state_root / "artifacts"),
        ).read_package(operation_id)

    def replay_or_execute(
        self,
        operation_id: str,
        execute: Callable[[], LiveRollbackCompletionExecution],
    ) -> LiveRollbackCompletionExecution:
        """Return a durable completion, otherwise invoke the typed lifecycle."""

        existing = self.completed(operation_id)
        if existing is not None:
            package, reference = existing
            core_package = package.core_package
            return LiveRollbackCompletionExecution(
                core=LiveRollbackExecution(
                    rollback=LiveIntegrationRollbackService._execution_from_package(core_package),  # pyright: ignore[reportPrivateUsage]
                    package=core_package,
                    package_artifact=package.core_package_artifact,
                    replayed=True,
                ),
                package=package,
                package_artifact=reference,
                validation_outcome=package.validation_outcome,
                cleanup_outcome=package.cleanup_outcome,
                replayed=True,
            )
        return execute()


class LiveRollbackOperator:
    """Small orchestration boundary; all provider mutations stay in services."""

    def __init__(
        self, wiring: LiveRollbackHostedWiring, completion: LiveRollbackCompletionService
    ) -> None:
        self.wiring = wiring
        self.completion = completion

    def execute(
        self,
        request: IntegrationRollbackRequest,
        *,
        canary_package: IntegrationCampaignEvidencePackage,
        canary_package_artifact: ArtifactRef,
        authorization: IntegrationDrillRollbackAuthorization,
        bundle: PromotionBundle,
        publication: CandidatePublicationBinding,
        bundle_digest: str,
        intent_factory: Callable[[Any], IntegrationPromotionIntent],
        inputs: LiveRollbackCompletionInputs,
    ) -> LiveRollbackCompletionExecution:
        """Execute or replay a fully typed, canary-bound rollback operation."""

        return self.completion.run(
            request,
            canary_package=canary_package,
            canary_package_artifact=canary_package_artifact,
            authorization=authorization,
            bundle=bundle,
            publication=publication,
            bundle_digest=bundle_digest,
            intent_factory=intent_factory,
            inputs=inputs,
        )


def run(
    operator: LiveRollbackOperator,
    request: IntegrationRollbackRequest,
    **kwargs: Any,
) -> LiveRollbackCompletionExecution:
    """Testable/operator embedding entrypoint for one resumable operation."""

    return operator.execute(request, **kwargs)


def redact_secret(value: str) -> str:
    """Return a stable non-secret representation for logs and CLI summaries."""

    return "<redacted>" if value else "<absent>"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--operation-id", required=True)
    parser.add_argument("--canary-operation-id", required=True)
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument("--dry-run", action="store_true")
    return parser


def _assert_vcs_free_candidate(candidate_root: Path) -> None:
    """Reject a checkout or nested Git metadata before publication is possible."""

    candidate = candidate_root.resolve()
    if not candidate.is_dir():
        raise ValueError("candidate root is missing")
    if (candidate / ".git").exists():
        raise ValueError("rollback candidate must be VCS-free restore content")
    if any(path.name == ".git" for path in candidate.rglob(".git")):
        raise ValueError("rollback candidate contains nested VCS metadata")


def main() -> int:
    args = build_parser().parse_args()
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print(json.dumps({"status": "blocked", "error": "GITHUB_TOKEN is required"}))
        return 2
    provider = GitHubIntegrationProvider(
        owner=OWNER,
        repo=REPOSITORY,
        repository_digest=github_repository_digest(OWNER, REPOSITORY),
        target_ref=TARGET_REF,
        trusted_checks=TRUSTED_CHECKS,
        protection_checks=PROTECTION_CHECKS,
        freshness_cutoff=datetime.now(UTC) - timedelta(hours=1),
        token=token,
    )
    runner = LiveRollbackHostedRunner(provider, args.state_root)
    try:
        _assert_vcs_free_candidate(args.candidate_root)
        completed = runner.completed(args.operation_id)
        if completed is not None:
            package, reference = completed
            summary = {
                "schema_version": 1,
                "operation_id": package.operation_id,
                "completion_digest": reference.digest,
                "core_digest": package.core_package_artifact.digest,
                "status": "already_completed",
            }
            print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
            return 0
        preflight = runner.preflight(args.operation_id, args.canary_operation_id)
    except (OSError, RuntimeError, ValueError) as exc:
        print(json.dumps({"status": "blocked", "error": redact_secret(str(exc))}))
        return 2
    if not args.repository_root.is_dir():
        print(json.dumps({"status": "blocked", "error": "candidate or repository root missing"}))
        return 2
    summary = {
        "schema_version": 1,
        "operation_id": preflight.operation_id,
        "canary_operation_id": preflight.canary_operation_id,
        "repository_digest": preflight.repository_digest,
        "failed_head_commit": preflight.failed_head_commit,
        "failed_head_tree": preflight.failed_head_tree,
        "main_commit": preflight.main_commit,
        "workflow_digest": preflight.workflow_digest,
        "status": "preflight_ok" if args.dry_run else "blocked",
        "reason": (
            None
            if args.dry_run
            else "live lifecycle wiring requires controller-owned rollback policy inputs"
        ),
    }
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0 if args.dry_run else 2


if __name__ == "__main__":
    raise SystemExit(main())
