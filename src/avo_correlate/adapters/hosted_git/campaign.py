"""GitHub-backed provider lifecycle for one AVO-004.5 campaign.

This module is deliberately a thin composition layer.  ``github.py`` owns the
provider's REST parsing and fail-closed merge/reconciliation rules; this class
only translates those records into the application campaign port.  In
particular, it never performs a write to ``main`` (or any deployment ref).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, cast
from urllib.parse import quote

from avo_correlate.adapters.hosted_git.github import (
    GitHubEvidenceSnapshot,
    GitHubIntegrationProvider,
    GitHubPullRequestBinding,
    GitHubPullRequestDiscovery,
)
from avo_correlate.application.integration_campaign_service import (
    CampaignDiscovery,
    CampaignFinalEvidence,
    CampaignOpened,
    CampaignPreparation,
    campaign_open_identity,
)
from avo_correlate.application.synthetic_validation_service import SyntheticValidationService
from avo_correlate.contracts.integration_campaign import (
    IntegrationIntentTemplate,
    campaign_marker_digest,
)
from avo_correlate.contracts.integration_promotion import (
    CandidatePublicationBinding,
    IntegrationMergeResult,
    IntegrationPromotionIntent,
    IntegrationPromotionReport,
    IntegrationProviderObservation,
)
from avo_correlate.contracts.promotion_bundle import PromotionBundle, promotion_bundle_digest
from avo_correlate.contracts.synthetic_validation import (
    SyntheticValidationOutcome,
    SyntheticValidationPlan,
)
from avo_correlate.domain.canonical import canonical_digest

_GIT_OBJECT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


def _git_object(value: str, context: str) -> str:
    if not _GIT_OBJECT.fullmatch(value):
        raise ValueError(f"malformed {context}")
    return value


@dataclass(frozen=True, slots=True)
class GitHubCampaignProvider:
    """Adapt a strict :class:`GitHubIntegrationProvider` to campaign stages.

    ``main_head_reader`` is injectable so callers can bind the read to their
    trusted repository state adapter.  When omitted, the same GitHub provider
    is used for a read-only ``refs/heads/main`` observation.  The adapter does
    not expose or accept a main mutation operation.
    """

    github: GitHubIntegrationProvider
    main_ref: str = "refs/heads/main"
    main_head_reader: Callable[[], str] | None = None
    pull_request_title: str = "AVO candidate for protected integration"
    pull_request_body: str = "Automated AVO campaign candidate."
    validation_service: SyntheticValidationService | None = None
    validation_plan: SyntheticValidationPlan | None = field(
        default=None, init=False, repr=False, compare=False
    )
    validation_outcome: SyntheticValidationOutcome | None = field(
        default=None, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if self.main_ref != "refs/heads/main":
            raise ValueError("campaign main ref must be exactly refs/heads/main")
        if not self.pull_request_title.strip() or "\x00" in self.pull_request_title:
            raise ValueError("pull request title is malformed")
        if "\x00" in self.pull_request_body:
            raise ValueError("pull request body is malformed")

    @property
    def _provider(self) -> GitHubIntegrationProvider:
        return self.github

    def open_or_reconcile(self, publication: CandidatePublicationBinding) -> CampaignOpened:
        """Create or recover the sole PR for this exact published candidate."""
        binding = self._provider.open_or_reconcile_campaign_pull_request(
            publication.candidate_ref,
            publication.candidate_commit,
            base_commit=publication.base_commit,
            title=self.pull_request_title,
            body=self.pull_request_body,
        )
        self._validate_open_binding(binding, publication)
        opened = CampaignOpened(
            pull_request_number=binding.number,
            pull_request_url=binding.url,
            target_ref=self._provider.target_ref,
            base_commit=binding.base_commit,
            base_tree=publication.base_tree,
            open_identity="sha256:" + "0" * 64,
        )
        result = CampaignOpened(
            pull_request_number=opened.pull_request_number,
            pull_request_url=opened.pull_request_url,
            target_ref=opened.target_ref,
            base_commit=opened.base_commit,
            base_tree=opened.base_tree,
            open_identity=campaign_open_identity(publication, opened),
        )
        self._trigger_validation(result, publication)
        return result

    def _trigger_validation(
        self, opened: CampaignOpened, publication: CandidatePublicationBinding
    ) -> SyntheticValidationOutcome | None:
        service = self.validation_service
        if service is None:
            return None
        observation = self._provider.observe_synthetic_validation(
            opened.pull_request_number,
            candidate_ref=publication.candidate_ref,
            candidate_commit=publication.candidate_commit,
            base_commit=publication.base_commit,
        )
        if (
            observation.repository_digest != publication.repository_digest
            or observation.base_ref != opened.target_ref
            or observation.base_commit != publication.base_commit
            or observation.base_tree != publication.base_tree
            or observation.head_ref != publication.candidate_ref
            or observation.head_commit != publication.candidate_commit
            or observation.head_tree != publication.candidate_tree
        ):
            raise ValueError("synthetic validation observation is not publication-bound")
        plan = service.prepare(
            observation,
            target_repository_digest=publication.repository_digest,
            target_ref=opened.target_ref,
            target_identity=opened.open_identity,
            trusted_check_contexts=tuple(name for name, _app_id in self._provider.trusted_checks),
            provider_identity=self._provider.provider_identity,
            provider_api_version=self._provider.provider_api_version,
        )
        outcome = service.trigger(plan)
        object.__setattr__(self, "validation_plan", plan)
        object.__setattr__(self, "validation_outcome", outcome)
        if outcome.outcome not in {"created", "already_present", "reconciled"}:
            raise ValueError(
                "synthetic validation trigger did not reach an exact ref: "
                f"{outcome.outcome}: {outcome.error or 'unknown error'}"
            )
        return outcome

    def discover(
        self, opened: CampaignOpened, publication: CandidatePublicationBinding
    ) -> CampaignDiscovery:
        """Read exact PR/synthetic/check/protection state and independent main head."""
        discovered, _evidence = self.discover_with_evidence(opened, publication)
        return discovered

    def discover_with_evidence(
        self, opened: CampaignOpened, publication: CandidatePublicationBinding
    ) -> tuple[CampaignDiscovery, GitHubEvidenceSnapshot]:
        """Return discovery and raw provider evidence from one API observation."""
        self._validate_opened_identity(opened, publication)
        discovery = self._provider.discover_campaign_evidence(
            opened.pull_request_number,
            candidate_ref=publication.candidate_ref,
            candidate_commit=publication.candidate_commit,
            base_commit=publication.base_commit,
        )
        observation = self._observation(discovery, publication)
        if observation.base_ref != opened.target_ref:
            raise ValueError("provider discovery target ref drifted")
        if (
            observation.base_commit != opened.base_commit
            or observation.base_tree != opened.base_tree
        ):
            raise ValueError("provider discovery base drifted")
        return (
            CampaignDiscovery(
                observation=observation,
                main_before_commit=self._read_main_head(),
                open_identity=opened.open_identity,
            ),
            discovery.evidence,
        )

    def bind(
        self,
        publication: CandidatePublicationBinding,
        bundle: PromotionBundle,
        bundle_digest: str,
        opened: CampaignOpened,
        discovery: CampaignDiscovery,
        *,
        expected_main_commit: str | None = None,
    ) -> CampaignPreparation:
        """Bind the immutable bundle to exact hosted evidence and one marker."""
        self._validate_opened_identity(opened, publication)
        if discovery.open_identity != opened.open_identity:
            raise ValueError("campaign discovery identity drifted")
        expected_bundle_digest = promotion_bundle_digest(bundle)
        if bundle_digest != expected_bundle_digest:
            raise ValueError("promotion bundle digest mismatch")
        self._validate_bundle_snapshot(bundle, publication, discovery.observation)
        observation = discovery.observation
        template_values: dict[str, object] = {
            "repository_digest": publication.repository_digest,
            "candidate_ref": publication.candidate_ref,
            "target_ref": opened.target_ref,
            "base_commit": publication.base_commit,
            "base_tree": publication.base_tree,
            "candidate_commit": publication.candidate_commit,
            "candidate_tree": publication.candidate_tree,
            "candidate_repository_digest": publication.repository_digest,
            "candidate_head_ref": publication.candidate_ref,
            "candidate_head_commit": publication.candidate_commit,
            "candidate_head_tree": publication.candidate_tree,
            "target_repository_digest": publication.repository_digest,
            "target_base_ref": opened.target_ref,
            "target_base_commit": publication.base_commit,
            "target_base_tree": publication.base_tree,
            "synthetic_merge_commit": observation.synthetic_merge_commit,
            "synthetic_merge_tree": observation.synthetic_merge_tree,
            "bundle_digest": bundle_digest,
            "candidate_digest": publication.candidate_digest,
            "controller_config_digest": bundle.controller_config_digest,
            "protection_evidence_digest": observation.protection_evidence_digest,
            "evidence_manifest_digest": bundle.provenance.evidence_manifest_digest,
            "check_evidence_manifest_digest": observation.check_evidence_manifest_digest,
            "publication_evidence_digest": publication.publication_evidence_digest,
            "pull_request_number": opened.pull_request_number,
            "pull_request_url": opened.pull_request_url,
            "provider_identity": observation.provider_identity,
            "provider_api_version": observation.provider_api_version,
            "merge_method": "squash",
        }
        if expected_main_commit is not None:
            template_values["expected_main_commit"] = expected_main_commit
        operation_identity = {
            "repository_digest": str(template_values["repository_digest"]),
            "pull_request_number": str(template_values["pull_request_number"]),
            "candidate_ref": str(template_values["candidate_ref"]),
            "target_ref": str(template_values["target_ref"]),
            "base_commit": str(template_values["base_commit"]),
            "candidate_commit": str(template_values["candidate_commit"]),
            "candidate_head_commit": str(template_values["candidate_head_commit"]),
            "target_base_commit": str(template_values["target_base_commit"]),
            "synthetic_merge_commit": str(template_values["synthetic_merge_commit"]),
            "bundle_digest": str(template_values["bundle_digest"]),
            "candidate_digest": str(template_values["candidate_digest"]),
            "publication_evidence_digest": str(template_values["publication_evidence_digest"]),
            "provider_identity": str(template_values["provider_identity"]),
            "provider_api_version": str(template_values["provider_api_version"]),
            "merge_method": str(template_values["merge_method"]),
        }
        if template_values.get("expected_main_commit") is not None:
            operation_identity["expected_main_commit"] = str(
                template_values["expected_main_commit"]
            )
        template_values["operation_id"] = canonical_digest(operation_identity)
        template = IntegrationIntentTemplate.model_validate(template_values)
        # The marker is intentionally derived from the lease-independent
        # operation identity.  A template bind is only a local validation
        # record; it never writes a journal or authorizes a merge.
        marker_intent = IntegrationPromotionIntent.model_validate(
            {
                **template.model_dump(mode="python"),
                "controller_lease_identity": "campaign-marker",
                "controller_lease_digest": "sha256:" + "0" * 64,
                "state": "intent_recorded",
            }
        )
        marker = campaign_marker_digest(marker_intent)
        updated = self._provider.update_campaign_marker(marker_intent)
        if not self._has_marker(updated.body, marker):
            raise ValueError("GitHub campaign marker was not persisted")
        verified = self._provider.verify_campaign_marker(marker_intent)
        if not self._has_marker(verified.body, marker):
            raise ValueError("GitHub campaign marker verification failed")
        rebound = self._provider.discover_campaign_evidence(
            opened.pull_request_number,
            candidate_ref=publication.candidate_ref,
            candidate_commit=publication.candidate_commit,
            base_commit=publication.base_commit,
            campaign_marker=marker,
        )
        rebound_observation = self._observation(rebound, publication)
        if rebound_observation != observation:
            raise ValueError("provider evidence changed while binding campaign marker")
        return CampaignPreparation(
            template=template,
            observation=rebound_observation,
            marker_verified=True,
            open_identity=opened.open_identity,
            marker_digest=marker,
        )

    def final_evidence(
        self,
        intent: IntegrationPromotionIntent,
        report: IntegrationPromotionReport,
        observation: IntegrationProviderObservation,
    ) -> CampaignFinalEvidence:
        """Reconcile once and derive only a report-consistent merge result."""
        if report.operation_id != intent.operation_id:
            raise ValueError("campaign report operation does not match intent")
        if observation.pull_request_number != intent.pull_request_number:
            raise ValueError("campaign observation does not match intent")
        reconciliation = self._provider.reconcile(intent)
        response_digest = canonical_digest(
            {
                "report": report.model_dump(mode="json"),
                "reconciliation": reconciliation.model_dump(mode="json"),
            }
        )
        if report.outcome == "applied":
            if not reconciliation.merged:
                raise ValueError("applied report has no merged provider reconciliation")
            if (
                reconciliation.merge_commit is None
                or reconciliation.merge_commit != reconciliation.target_head_commit
                or reconciliation.target_head_tree != intent.candidate_tree
                or reconciliation.target_first_parent != intent.base_commit
            ):
                raise ValueError("applied report has inexact provider result")
            result = IntegrationMergeResult(
                outcome="applied",
                result_commit=reconciliation.target_head_commit,
                result_tree=reconciliation.target_head_tree,
                first_parent_commit=reconciliation.target_first_parent,
                response_digest=response_digest,
                main_protection_evidence_digest=reconciliation.main_protection_evidence_digest,
            )
        elif report.outcome == "already_applied":
            result = IntegrationMergeResult(
                outcome="ambiguous",
                response_digest=response_digest,
                error="provider reconciliation indicates an already-applied result",
            )
        else:
            result = IntegrationMergeResult(
                outcome="rejected",
                response_digest=response_digest,
                error=f"campaign report outcome was {report.outcome}",
            )
        return CampaignFinalEvidence(reconciliation=reconciliation, merge_result=result)

    def _read_main_head(self) -> str:
        if self.main_head_reader is not None:
            return _git_object(self.main_head_reader(), "main head commit")
        # This uses the existing provider's read-only transport primitives; no
        # branch/ref mutation is possible through this path.
        branch = self.main_ref.removeprefix("refs/heads/")
        provider = cast(Any, self._provider)
        raw_value: object = provider._call(
            "GET", provider._path(f"git/ref/heads/{quote(branch, safe='')}"),
        )
        if not isinstance(raw_value, dict):
            raise ValueError("malformed main ref response")
        raw_ref = cast(dict[str, object], raw_value)
        raw_object = raw_ref.get("object")
        if not isinstance(raw_object, dict):
            raise ValueError("malformed main ref object")
        raw_object_typed = cast(dict[str, object], raw_object)
        sha = raw_object_typed.get("sha")
        if not isinstance(sha, str):
            raise ValueError("malformed main ref SHA")
        return _git_object(sha, "main head commit")

    @staticmethod
    def _has_marker(body: str, marker: str) -> bool:
        return f"AVO-Campaign-Marker: {marker}" in {line.strip() for line in body.splitlines()}

    def _validate_open_binding(
        self, binding: GitHubPullRequestBinding, publication: CandidatePublicationBinding
    ) -> None:
        if (
            binding.base_commit != publication.base_commit
            or binding.head_ref != publication.candidate_ref
            or binding.head_commit != publication.candidate_commit
            or binding.base_ref != self._provider.target_ref
            or binding.state != "open"
            or binding.draft
        ):
            raise ValueError("opened pull request is not bound to the publication")

    def _validate_opened_identity(
        self, opened: CampaignOpened, publication: CandidatePublicationBinding
    ) -> None:
        if (
            opened.target_ref != self._provider.target_ref
            or opened.base_commit != publication.base_commit
            or opened.base_tree != publication.base_tree
            or opened.open_identity != campaign_open_identity(publication, opened)
        ):
            raise ValueError("opened campaign identity is not exact")

    def _observation(
        self,
        discovery: GitHubPullRequestDiscovery, publication: CandidatePublicationBinding
    ) -> IntegrationProviderObservation:
        pull = discovery.pull_request
        evidence = discovery.evidence
        if (
            pull.head_ref != publication.candidate_ref
            or pull.head_commit != publication.candidate_commit
            or pull.base_commit != publication.base_commit
        ):
            raise ValueError("provider pull request is not publication-bound")
        return IntegrationProviderObservation(
            repository_digest=publication.repository_digest,
            pull_request_number=pull.number,
            pull_request_url=pull.url,
            candidate_repository_digest=publication.repository_digest,
            target_repository_digest=publication.repository_digest,
            base_ref=pull.base_ref,
            base_commit=pull.base_commit,
            base_tree=publication.base_tree,
            head_ref=pull.head_ref,
            head_commit=pull.head_commit,
            candidate_tree=publication.candidate_tree,
            synthetic_merge_commit=evidence.synthetic_merge_commit,
            synthetic_merge_tree=evidence.synthetic_merge_tree,
            protection_evidence_digest=evidence.protection_evidence_digest,
            check_evidence_manifest_digest=evidence.check_evidence_manifest_digest,
            provider_identity=self._provider.provider_identity,
            provider_api_version=self._provider.provider_api_version,
            open_state="open",
            draft=False,
        )

    @staticmethod
    def _validate_bundle_snapshot(
        bundle: PromotionBundle,
        publication: CandidatePublicationBinding,
        observation: IntegrationProviderObservation,
    ) -> None:
        if (
            bundle.snapshot.repository_digest != publication.repository_digest
            or bundle.snapshot.target_ref != observation.base_ref
            or bundle.snapshot.commit != publication.base_commit
            or bundle.snapshot.tree != publication.base_tree
            or bundle.snapshot.protection_evidence_digest
            != observation.protection_evidence_digest
            or bundle.request.candidate_digest != publication.candidate_digest
            or bundle.provenance.source_provenance_digest
            != publication.publication_evidence_digest
        ):
            raise ValueError("promotion bundle snapshot is not bound to hosted evidence")


__all__ = ["GitHubCampaignProvider"]
