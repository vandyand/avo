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
import re
import stat
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from avo_correlate.adapters.artifacts import FilesystemArtifactStore
from avo_correlate.adapters.artifacts.campaign_journal import CampaignCompletionJournal
from avo_correlate.adapters.artifacts.drill_journal import IntegrationDrillJournal
from avo_correlate.adapters.artifacts.live_rollback_completion_journal import (
    LiveRollbackCompletionJournal,
)
from avo_correlate.adapters.artifacts.live_rollback_journal import LiveRollbackJournal
from avo_correlate.adapters.artifacts.promotion_journal import IntegrationPromotionJournal
from avo_correlate.adapters.artifacts.rollback_bundle_authority import (
    RollbackBundleAuthorityJournal,
)
from avo_correlate.adapters.artifacts.synthetic_validation_journal import SyntheticValidationJournal
from avo_correlate.adapters.git import (
    FilesystemPublicationJournal,
    GitCandidatePublisher,
    GitRepositoryReader,
    PreparedPublication,
)
from avo_correlate.adapters.hosted_git import (
    GitHubCampaignProvider,
    GitHubIntegrationProvider,
    github_repository_digest,
)
from avo_correlate.application.integration_live_rollback_completion_service import (
    LiveRollbackCompletionExecution,
    LiveRollbackCompletionInputs,
    LiveRollbackCompletionService,
    LiveRollbackCoreJournalCompletionProofVerifier,
)
from avo_correlate.application.integration_live_rollback_service import (
    LiveIntegrationRollbackService,
    LiveRollbackExecution,
    LiveRollbackTargetObservation,
)
from avo_correlate.application.integration_promotion_service import IntegrationPromotionService
from avo_correlate.application.integration_rollback_service import (
    IntegrationDrillRollbackService,
)
from avo_correlate.application.promotion_service import PromotionController
from avo_correlate.application.rollback_bundle_authority import RollbackBundleAuthority
from avo_correlate.application.synthetic_validation_service import SyntheticValidationService
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_campaign import IntegrationCampaignEvidencePackage
from avo_correlate.contracts.integration_drill import (
    IntegrationDrillRollbackAuthorization,
    IntegrationRollbackRequest,
)
from avo_correlate.contracts.integration_live_rollback_completion import (
    LiveRollbackCompletionPackage,
    LiveRollbackPublicationEvidence,
    LiveRollbackPublicationOutcome,
    LiveRollbackPublicationPlan,
)
from avo_correlate.contracts.integration_promotion import (
    CandidatePublicationBinding,
    IntegrationPromotionIntent,
)
from avo_correlate.contracts.integration_soak import SOAK_CONTEXT, SOAK_WORKFLOW_PATH
from avo_correlate.contracts.prepublication import (
    SOAK_ISSUER_ID,
    RollbackPublicationAuthorityConfig,
    RollbackSnapshotRestoreFacts,
)
from avo_correlate.contracts.promotion_bundle import (
    PromotionBundle,
    PromotionControllerConfig,
    promotion_bundle_digest,
)
from avo_correlate.contracts.promotion_policy import PromotionConfig
from avo_correlate.contracts.synthetic_validation import SyntheticValidationCreateAuthorization
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

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
ROLLBACK_CONTROLLER_ID = "avo-004.6-live-rollback-controller"
ROLLBACK_PUBLISHER_ID = "avo-004.6-live-rollback-publisher"
ROLLBACK_BASE_ISSUER = "avo-004.6-live-rollback-base"
ROLLBACK_PATH_ISSUER = "avo-004.6-live-rollback-path"
CANARY_CONTROLLER_ID = "avo-live-controller"
CANARY_BASE_ISSUER = "avo-base"
CANARY_PATH_ISSUER = "avo-path"
CANARY_ROLLBACK_ISSUER = "avo-rollback-controller"
_SHA256_ID = re.compile(r"^sha256:[0-9a-f]{64}$")


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
    canary_package: IntegrationCampaignEvidencePackage
    canary_package_artifact: ArtifactRef


class LiveRollbackHostedRunner:
    """Hosted authority preflight and durable completion replay fence."""

    def __init__(self, provider: GitHubIntegrationProvider, state_root: Path) -> None:
        self.provider = provider
        self.state_root = state_root.resolve()

    def preflight(self, operation_id: str, canary_operation_id: str) -> LiveRollbackPreflight:
        _check_operation_id(operation_id)
        _check_operation_id(canary_operation_id)
        self.provider.verify_repository_binding()
        journal = CampaignCompletionJournal(
            self.state_root / "completion",
            artifact_store=FilesystemArtifactStore(self.state_root / "artifacts"),
        )
        loaded = journal.read_package(canary_operation_id)
        if loaded is None:
            raise RuntimeError("successful canary package is missing from durable state")
        canary, canary_ref = loaded
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
            canary_package=canary,
            canary_package_artifact=canary_ref,
        )

    def completed(
        self, operation_id: str
    ) -> tuple[LiveRollbackCompletionPackage, ArtifactRef] | None:
        """Read the immutable outer package from the shared artifact store.

        The journal verifies every named child on read. A corrupt index or a
        missing child therefore fails closed rather than allowing a restart to
        replay a hosted mutation.
        """

        _check_operation_id(operation_id)
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

        _check_operation_id(operation_id)
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


class _TokenPublisher(GitCandidatePublisher):
    """Keep the GitHub credential process-local while Git uses askpass."""

    def _environment(self) -> dict[str, str]:
        environment = super()._environment()
        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            raise RuntimeError("GITHUB_TOKEN is required for live publication")
        environment["GITHUB_TOKEN"] = token
        return environment


def _askpass_path(state_root: Path) -> Path:
    """Write a credential helper containing no credential bytes."""

    state_root.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        path = state_root / "github-askpass.cmd"
        data = (
            "@echo off\r\n"
            "set \"AVO_ASKPASS_PROMPT=%~1\"\r\n"
            "powershell.exe -NoProfile -NonInteractive -Command \"$p = "
            "[Environment]::GetEnvironmentVariable('AVO_ASKPASS_PROMPT'); if ($p "
            "-match '(?i)username') { [Console]::Out.WriteLine('x-access-token'); "
            "exit 0 }; if ($p -match '(?i)password') { "
            "[Console]::Out.WriteLine([Environment]::GetEnvironmentVariable('GITHUB_TOKEN')); "
            "exit 0 }; exit 1\"\r\n"
            "exit /b %errorlevel%\r\n"
        )
    else:
        path = state_root / "github-askpass.sh"
        data = (
            "#!/bin/sh\ncase \"$1\" in\n"
            "  *[Uu]sername*) printf '%s\\n' 'x-access-token' ;;\n"
            "  *[Pp]assword*) printf '%s\\n' \"$GITHUB_TOKEN\" ;;\n"
            "  *) exit 1 ;;\nesac\n"
        )
    path.write_text(data, encoding="utf-8", newline="")
    if os.name != "nt":
        path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    return path


def _main_head(provider: GitHubIntegrationProvider) -> str:
    return provider.read_authority_ref(MAIN_REF).commit


def _target_observation(provider: GitHubIntegrationProvider) -> LiveRollbackTargetObservation:
    target = provider.read_authority_ref(TARGET_REF)
    return LiveRollbackTargetObservation(
        repository_digest=target.repository_digest,
        target_ref=target.ref,
        commit=target.commit,
        tree=target.tree,
        parent_commits=target.parents,
    )


def _authority_config() -> RollbackPublicationAuthorityConfig:
    """Return the base-controlled trust configuration, never a canary value."""

    values: dict[str, object] = {
        "schema_version": 1,
        "repository_digest": github_repository_digest(OWNER, REPOSITORY),
        "target_ref": TARGET_REF,
        "soak_issuer_id": SOAK_ISSUER_ID,
        "soak_app_id": 15368,
        "soak_context": SOAK_CONTEXT,
        "soak_workflow_path": SOAK_WORKFLOW_PATH,
        "base_issuer_id": ROLLBACK_BASE_ISSUER,
        "path_issuer_id": ROLLBACK_PATH_ISSUER,
        "controller_identity": ROLLBACK_CONTROLLER_ID,
        "publisher_identity": ROLLBACK_PUBLISHER_ID,
    }
    return RollbackPublicationAuthorityConfig.model_validate(
        {**values, "trusted_config_digest": canonical_digest(values)}
    )


def _rollback_controller_config() -> PromotionControllerConfig:
    """Return the immutable controller policy used for rollback only."""

    return PromotionControllerConfig(
        controller_identity=ROLLBACK_CONTROLLER_ID,
        controller_version="avo-004.6-live-rollback-v1",
        base_issuer_id=ROLLBACK_BASE_ISSUER,
        path_issuer_id=ROLLBACK_PATH_ISSUER,
        policy=PromotionConfig(
            evaluation_epoch=0,
            trusted_gate_issuers={},
            trusted_base_issuers=[ROLLBACK_BASE_ISSUER],
            trusted_reviewer_issuers=[ROLLBACK_CONTROLLER_ID],
            trusted_path_issuers=[ROLLBACK_PATH_ISSUER],
            rollback_issuer_ids=[ROLLBACK_CONTROLLER_ID],
            rollback_limit=1,
            reviewer_domains={ROLLBACK_CONTROLLER_ID: "avo.invalid"},
            proposer_domains={ROLLBACK_CONTROLLER_ID: "avo.invalid"},
            candidate_proposers={"sha256:" + "0" * 64: ROLLBACK_CONTROLLER_ID},
        ),
    )


def _validate_canary_trust_matches_fixed(preflight: LiveRollbackPreflight) -> None:
    """Treat the canary policy as evidence, rejecting authority substitutions."""

    config = preflight.canary_package.bundle.controller_config
    if (
        config.controller_identity != CANARY_CONTROLLER_ID
        or config.base_issuer_id != CANARY_BASE_ISSUER
        or config.path_issuer_id != CANARY_PATH_ISSUER
        or CANARY_ROLLBACK_ISSUER not in config.policy.rollback_issuer_ids
    ):
        raise RuntimeError("durable canary controller identity differs from fixed rollback trust")


def _rollback_request(
    preflight: LiveRollbackPreflight,
    rollback_candidate_commit: str,
    promotion_operation_id: str,
    *,
    restore_commit: str,
    restore_tree: str,
) -> IntegrationRollbackRequest:
    return IntegrationRollbackRequest(
        operation_id=preflight.operation_id,
        promotion_operation_id=promotion_operation_id,
        repository_digest=preflight.repository_digest,
        target_ref=TARGET_REF,
        main_before_commit=preflight.main_commit,
        failed_integration_head_commit=preflight.failed_head_commit,
        failed_integration_head_tree=preflight.failed_head_tree,
        restore_to_commit=restore_commit,
        restore_to_tree=restore_tree,
        rollback_candidate_commit=rollback_candidate_commit,
        rollback_candidate_parent_commit=preflight.failed_head_commit,
    )


def _publication_inputs(
    publication: CandidatePublicationBinding,
) -> tuple[
    LiveRollbackPublicationPlan,
    LiveRollbackPublicationOutcome,
    LiveRollbackPublicationEvidence,
]:
    raw = {
        "repository_digest": publication.repository_digest,
        "base_commit": publication.base_commit,
        "base_tree": publication.base_tree,
        "candidate_digest": publication.candidate_digest,
        "candidate_ref": publication.candidate_ref,
        "candidate_commit": publication.candidate_commit,
        "candidate_tree": publication.candidate_tree,
        "controller_identity": publication.controller_publisher_identity,
        "target_ref": TARGET_REF,
    }
    plan = LiveRollbackPublicationPlan.model_validate(
        {**raw, "publication_id": canonical_digest({"schema_version": 1, **raw})}
    )
    evidence = LiveRollbackPublicationEvidence(
        publication_id=plan.publication_id,
        repository_digest=publication.repository_digest,
        remote=REMOTE,
        candidate_ref=publication.candidate_ref,
        candidate_commit=publication.candidate_commit,
        candidate_tree=publication.candidate_tree,
        base_commit=publication.base_commit,
        base_tree=publication.base_tree,
        candidate_digest=publication.candidate_digest,
    )
    outcome = LiveRollbackPublicationOutcome(
        publication_id=plan.publication_id,
        repository_digest=publication.repository_digest,
        base_commit=publication.base_commit,
        base_tree=publication.base_tree,
        candidate_ref=publication.candidate_ref,
        candidate_commit=publication.candidate_commit,
        candidate_tree=publication.candidate_tree,
        candidate_digest=publication.candidate_digest,
        outcome="verified",
        evidence_digest=canonical_digest(evidence),
    )
    return plan, outcome, evidence


def execute_live(
    preflight: LiveRollbackPreflight,
    *,
    provider: GitHubIntegrationProvider,
    state_root: Path,
    repository_root: Path,
    candidate_root: Path,
) -> LiveRollbackCompletionExecution:
    """Run the one hosted rollback lifecycle from controller-owned records."""

    _check_operation_id(preflight.operation_id)
    _check_operation_id(preflight.canary_operation_id)
    _assert_safe_roots(state_root, repository_root, candidate_root)
    _validate_canary_trust_matches_fixed(preflight)
    artifact_store = FilesystemArtifactStore(state_root / "artifacts")
    # This is the independent, authenticated rollback trigger.  Nothing that
    # can mutate GitHub is constructed before it has proven the failed soak,
    # its pinned workflow/check identity, exact main fence, and sole-parent
    # restore topology.
    failed_soak = provider.observe_failed_soak_attestation(TARGET_REF)
    facts = RollbackSnapshotRestoreFacts(
        repository_digest=failed_soak.repository_digest,
        target_ref=failed_soak.integration_ref,
        failed_head_commit=failed_soak.integration_commit,
        failed_head_tree=failed_soak.integration_tree,
        failed_head_parents=[failed_soak.integration_parent_commit],
        restore_commit=failed_soak.restore_commit,
        restore_tree=failed_soak.restore_tree,
    )
    if (
        facts.repository_digest != preflight.repository_digest
        or facts.failed_head_commit != preflight.failed_head_commit
        or facts.failed_head_tree != preflight.failed_head_tree
        or failed_soak.main_commit != preflight.main_commit
        or preflight.canary_package.intent.base_commit != facts.restore_commit
        or preflight.canary_package.intent.base_tree != facts.restore_tree
    ):
        raise RuntimeError("failed soak, canary, target, or main fence is stale")
    hosted_target = provider.observe_integration(TARGET_REF)
    if (
        hosted_target.commit != preflight.failed_head_commit
        or hosted_target.tree != preflight.failed_head_tree
        or _main_head(provider) != preflight.main_commit
    ):
        raise RuntimeError("authenticated target or main changed before rollback publication")
    repository = GitRepositoryReader(
        repository_root,
        TARGET_REF,
        REMOTE,
        hosted_target.protection_evidence_digest,
        10 * 1024 * 1024,
        100 * 1024 * 1024,
    )
    snapshot = repository.snapshot()
    if (
        snapshot.repository_digest != preflight.repository_digest
        or snapshot.commit != preflight.failed_head_commit
        or snapshot.tree != preflight.failed_head_tree
    ):
        raise RuntimeError("local trusted repository differs from authenticated failed target")
    comparison = repository.compare_candidate(candidate_root, snapshot)
    if comparison.candidate_digest == snapshot.source_tree_digest:
        raise RuntimeError("restore candidate does not differ from failed integration target")
    _validate_pre_publish_rollback(preflight, snapshot, comparison.candidate_digest)

    publication_journal = FilesystemPublicationJournal(state_root / "publication")
    publisher = _TokenPublisher(
        expected_remote=REMOTE,
        repository_digest=preflight.repository_digest,
        controller_publisher_identity=ROLLBACK_PUBLISHER_ID,
        publication_journal=publication_journal,
        credential_helper=_askpass_path(state_root),
    )
    # Preparation writes only a local durable plan.  The stored authorization
    # is required by publish_prepared before the first remote ref update.
    prepared: PreparedPublication = publisher.prepare(
        candidate_root, snapshot.commit, snapshot.tree, comparison.candidate_digest
    )
    provisional_request = _rollback_request(
        preflight,
        prepared.plan.candidate_commit,
        canonical_digest({"rollback": preflight.operation_id}),
        restore_commit=facts.restore_commit,
        restore_tree=facts.restore_tree,
    )
    authority_journal = RollbackBundleAuthorityJournal(artifact_store)
    authority = RollbackBundleAuthority(_authority_config(), authority_journal)
    preauthorization = authority.authorize(
        provisional_request,
        canary_package_artifact=preflight.canary_package_artifact,
        canary_package=preflight.canary_package,
        failed_soak=failed_soak,
        facts=facts,
        prepared=prepared,
    )
    # A drill authorization is a projection of the durable preauthorization
    # and provider observation; the runner never asserts authorization itself.
    drill_authorization = authority.drill_authorization(preauthorization, failed_soak)
    published = publisher.reconcile_authorized(
        prepared.publication_id,
        preauthorization,
        authorization_journal=cast(Any, authority_journal),
    )
    if published is None:
        published = publisher.publish_prepared(
            prepared,
            authorization=preauthorization,
            authorization_journal=cast(Any, authority_journal),
        )
    publication = published.binding
    publication_evidence = artifact_store.put_bytes(
        published.evidence_bytes,
        media_type=published.evidence_artifact.media_type,
        role=published.evidence_artifact.role,
        max_bytes=2 * 1024 * 1024,
    )
    if publication_evidence.digest != publication.publication_evidence_digest:
        raise RuntimeError("published candidate evidence was not durably materialized")

    def provenance_verifier(digest: str, candidate: str, base: str) -> bool:
        return (
            digest == publication.publication_evidence_digest
            and candidate == publication.candidate_digest
            and base == snapshot.source_tree_digest
        )

    def evidence_verifier(digest: str, issuer: str, candidate: str, base: str) -> bool:
        return (
            candidate == publication.candidate_digest
            and base == snapshot.source_tree_digest
            and (
                (digest == publication.publication_evidence_digest
                 and issuer == publication.controller_publisher_identity)
                or (
                    digest == snapshot.protection_evidence_digest
                    and issuer == ROLLBACK_BASE_ISSUER
                )
            )
        )

    controller = PromotionController(
        repository,
        provenance_verifier,
        evidence_verifier,
        artifact_store,
        trusted_config=_rollback_controller_config(),
        trusted_repository_root=repository_root,
        trusted_artifact_root=artifact_store.root,
    )
    finalized_authorization = authority.finalize(
        preauthorization,
        publication,
        evidence=publication_evidence,
        drill_authorization=drill_authorization,
    )
    bundle_result = controller.create_rollback_bundle(
        provisional_request,
        canary_package=preflight.canary_package,
        canary_package_artifact=preflight.canary_package_artifact,
        drill_authorization=drill_authorization,
        rollback_authorization=finalized_authorization,
        candidate_root=candidate_root,
        publication=publication,
    )
    bundle = bundle_result.bundle
    bundle_digest = bundle_result.bundle_digest
    if bundle_digest != promotion_bundle_digest(bundle):
        raise RuntimeError("rollback bundle digest differs from controller result")

    validation_journal = SyntheticValidationJournal(
        state_root / "synthetic-validation", artifact_store=artifact_store
    )
    promotion_journal = IntegrationPromotionJournal(
        state_root / "promotion", artifact_store=artifact_store
    )
    rollback_journal = IntegrationDrillJournal(
        state_root / "rollback", artifact_store=artifact_store
    )
    core_journal = LiveRollbackJournal(state_root / "live-rollback", artifact_store=artifact_store)
    completion_journal = LiveRollbackCompletionJournal(
        state_root / "live-rollback-completion", artifact_store=artifact_store
    )
    validation = SyntheticValidationService(
        provider,
        validation_journal,
        completion_proof_verifier=cast(
            Any,
            LiveRollbackCoreJournalCompletionProofVerifier(
                lambda: core_journal.read_package(preflight.operation_id)
            ),
        ),
    )
    campaign_provider = GitHubCampaignProvider(provider, validation_service=validation)
    opened = campaign_provider.open_or_reconcile(publication)
    discovery, evidence_snapshot = campaign_provider.discover_with_evidence(opened, publication)
    preparation = campaign_provider.bind(
        publication,
        bundle,
        bundle_digest,
        opened,
        discovery,
        expected_main_commit=preflight.main_commit,
    )
    request = _rollback_request(
        preflight,
        publication.candidate_commit,
        preparation.template.operation_id,
        restore_commit=facts.restore_commit,
        restore_tree=facts.restore_tree,
    )

    class RepositoryVerifier:
        def verify(self, request: IntegrationRollbackRequest) -> None:
            provider.verify_live_rollback_topology(
                failed_integration_head_commit=request.failed_integration_head_commit,
                failed_integration_head_tree=request.failed_integration_head_tree,
                restore_to_commit=request.restore_to_commit,
                restore_to_tree=request.restore_to_tree,
                rollback_candidate_commit=request.rollback_candidate_commit,
                rollback_candidate_tree=request.restore_to_tree,
                rollback_candidate_parent_commit=request.rollback_candidate_parent_commit,
                current_target_commit=request.failed_integration_head_commit,
                current_target_tree=request.failed_integration_head_tree,
                current_target_parents=(facts.restore_commit,),
                main_commit=request.main_before_commit,
            )

    promotion = IntegrationPromotionService(
        controller,
        repository,
        provider,
        cast(Any, promotion_journal),
        lambda binding, bundle: (
            binding == publication
            and bundle.request.candidate_digest == binding.candidate_digest
        ),
    )
    drill = IntegrationDrillRollbackService(
        rollback_journal,
        promotion,
        promotion_journal,
        main_head_reader=lambda: _main_head(provider),
        repository_verifier=RepositoryVerifier(),
        trusted_rollback_issuers=(ROLLBACK_CONTROLLER_ID,),
    )
    core = LiveIntegrationRollbackService(
        drill,
        rollback_journal,
        core_journal,
        promotion_journal,
        main_head_reader=lambda: _main_head(provider),
        target_observation_reader=lambda: _target_observation(provider),
    )
    completion = LiveRollbackCompletionService(
        core,
        validation,
        cast(Any, completion_journal),
        current_target_observation=lambda: _target_observation(provider),
        main_head_reader=lambda: _main_head(provider),
        provider_reconciliation_reader=provider.reconcile,
    )
    check_manifest, protection_manifest = provider.live_rollback_manifests(
        evidence_snapshot, protection_source_commit=preflight.failed_head_commit
    )
    workflow = provider.observe_workflow_authority(preflight.failed_head_commit)
    validation_plan = campaign_provider.validation_plan
    if validation_plan is None:
        raise RuntimeError("exact validation plan was not durably created")
    validation_authorization = validation.read_durable_authorization(
        SyntheticValidationCreateAuthorization(
            operation_id=validation_plan.operation_id,
            plan_digest=validation_plan.plan_digest,
            validation_ref=validation_plan.validation_ref,
            expected_commit=validation_plan.expected_commit,
            expected_tree=validation_plan.expected_tree,
        )
    )
    if validation_authorization is None:
        raise RuntimeError("exact validation authorization is missing")
    plan, outcome, publication_proof = _publication_inputs(publication)
    inputs = LiveRollbackCompletionInputs(
        publication_plan=plan,
        publication_outcome=outcome,
        publication_evidence=publication_proof,
        provider_observation=discovery.observation,
        provider_reconciliation=provider.reconcile(
            preparation.template.bind_lease("rollback-observation", "sha256:" + "0" * 64)
        ),
        check_manifest=check_manifest,
        protection_manifest=protection_manifest,
        workflow_evidence=workflow,
        validation_plan=validation_plan,
        validation_authorization=validation_authorization,
    )
    wiring = LiveRollbackHostedWiring(
        publisher, campaign_provider, promotion, drill, core, validation
    )
    return LiveRollbackOperator(wiring, completion).execute(
        request,
        canary_package=preflight.canary_package,
        canary_package_artifact=preflight.canary_package_artifact,
        authorization=drill_authorization,
        bundle=bundle,
        publication=publication,
        bundle_digest=bundle_digest,
        intent_factory=lambda lease: preparation.template.bind_lease(lease.identity, lease.digest),
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


def _assert_safe_roots(state_root: Path, repository_root: Path, candidate_root: Path) -> None:
    """Fence local state and candidate trees before any journal or hosted work."""

    repository = repository_root.resolve(strict=True)
    candidate = candidate_root.resolve(strict=True)
    state = state_root.resolve()
    if not candidate.is_dir():
        raise ValueError("rollback candidate root is missing")
    if not repository.is_dir():
        raise ValueError("trusted repository root is missing")
    pairs = ((state, repository), (state, candidate), (candidate, repository))
    if any(_roots_overlap(left, right) for left, right in pairs):
        raise ValueError("state, repository, and candidate roots must be disjoint")
    _assert_vcs_free_candidate(candidate)


def _roots_overlap(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _check_operation_id(value: str) -> None:
    if _SHA256_ID.fullmatch(value) is None:
        raise ValueError("operation ID must be a lowercase SHA-256 digest")


def _validate_completed_canary(
    package: LiveRollbackCompletionPackage, canary_operation_id: str
) -> None:
    canary = package.core_package.canary_package
    canary_ref = package.core_package.canary_package_artifact
    if (
        package.core_package.canary_operation_id != canary_operation_id
        or canary.intent.operation_id != canary_operation_id
        or canary_ref.digest != canonical_digest(canary)
        or canary_ref.size_bytes != len(canonical_bytes(canary))
        or canary_ref.role != "integration-campaign-package"
        or canary_ref.media_type != "application/vnd.avo.integration-campaign+json"
    ):
        raise ValueError("completed package is bound to a different canary operation")


def _validate_pre_publish_rollback(
    preflight: LiveRollbackPreflight, snapshot: Any, candidate_digest: str
) -> None:
    """Validate immutable rollback facts before constructing a publisher."""

    if (
        snapshot.repository_digest != preflight.repository_digest
        or snapshot.target_ref != TARGET_REF
        or snapshot.commit != preflight.failed_head_commit
        or snapshot.tree != preflight.failed_head_tree
        or preflight.canary_package.report.outcome not in {"applied", "already_applied"}
        or preflight.canary_package.receipt.applied_result_commit != snapshot.commit
        or preflight.canary_package.receipt.applied_result_tree != snapshot.tree
        or preflight.canary_package.main_before_commit != preflight.main_commit
        or preflight.canary_package.main_after_commit != preflight.main_commit
        or candidate_digest == snapshot.source_tree_digest
    ):
        raise ValueError("rollback request preconditions are stale or untrusted")
    # The eventual candidate commit is created by the publisher. Validate the
    # request shape and all controller-owned facts now; the exact commit is
    # rebound immediately after publication before any further hosted action.
    provisional = IntegrationRollbackRequest(
        operation_id=preflight.operation_id,
        promotion_operation_id=canonical_digest({"rollback": preflight.operation_id}),
        repository_digest=preflight.repository_digest,
        target_ref=TARGET_REF,
        main_before_commit=preflight.main_commit,
        failed_integration_head_commit=preflight.failed_head_commit,
        failed_integration_head_tree=preflight.failed_head_tree,
        restore_to_commit=preflight.canary_package.intent.base_commit,
        restore_to_tree=preflight.canary_package.intent.base_tree,
        rollback_candidate_commit=preflight.failed_head_commit,
        rollback_candidate_parent_commit=preflight.failed_head_commit,
    )
    IntegrationRollbackRequest.model_validate(provisional.model_dump(mode="json"))


def main() -> int:
    args = build_parser().parse_args()
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        print(json.dumps({"status": "blocked", "error": "GITHUB_TOKEN is required"}))
        return 2
    try:
        _check_operation_id(args.operation_id)
        _check_operation_id(args.canary_operation_id)
        _assert_safe_roots(args.state_root, args.repository_root, args.candidate_root)
    except (OSError, RuntimeError, ValueError) as exc:
        print(json.dumps({"status": "blocked", "error": redact_secret(str(exc))}))
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
        completed = runner.completed(args.operation_id)
        if completed is not None:
            package, reference = completed
            _validate_completed_canary(package, args.canary_operation_id)
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
        "status": "preflight_ok",
    }
    if args.dry_run:
        print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
        return 0
    try:
        execution = execute_live(
            preflight,
            provider=provider,
            state_root=args.state_root,
            repository_root=args.repository_root,
            candidate_root=args.candidate_root,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(json.dumps({"status": "blocked", "error": redact_secret(str(exc))}))
        return 2
    if execution.package is None or execution.package_artifact is None:
        print(json.dumps({"operation_id": args.operation_id, "status": "reconciliation_required"}))
        return 2
    print(
        json.dumps(
            {
                "schema_version": 1,
                "operation_id": execution.package.operation_id,
                "completion_digest": execution.package_artifact.digest,
                "core_digest": execution.package.core_package_artifact.digest,
                "status": "completed" if not execution.replayed else "already_completed",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
