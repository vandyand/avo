"""Strict, content-addressed contracts for protected-main graduation.

This module deliberately has its own namespace.  In particular, an integration
promotion observation is never a main release observation: the two SHA-specific
release-check states are represented by separate records.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal, TypeVar

from pydantic import (
    AliasChoices,
    Field,
    StrictBool,
    StrictInt,
    StringConstraints,
    field_validator,
    model_validator,
)

from avo_correlate.contracts.base import (
    ArtifactRef,
    NonEmptyString,
    Sha256Digest,
    StrictModel,
    require_aware_datetime,
)
from avo_correlate.contracts.promotion_policy import PromotionPolicy, RiskClass
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

GitObject = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")]
MainRef = Literal["refs/heads/main"]


def _paths(paths: list[str]) -> list[str]:
    from avo_correlate.contracts.promotion_policy import is_valid_promotion_path

    if paths != sorted(paths, key=lambda item: (item.casefold(), item)):
        raise ValueError("changed paths must be sorted")
    if len({item.casefold() for item in paths}) != len(paths):
        raise ValueError("changed paths must be unique")
    if any(not is_valid_promotion_path(path) for path in paths):
        raise ValueError("changed paths must be normalized relative POSIX paths")
    if PromotionPolicy.derive_risk(paths) is not RiskClass.ORDINARY:
        raise ValueError("main delta paths must classify as ordinary")
    return paths


def _aware(value: datetime) -> datetime:
    return require_aware_datetime(value)


class MainBound(StrictModel):
    """Common fixed target binding; candidate input cannot choose the target."""

    repository_digest: Sha256Digest
    target_ref: MainRef = "refs/heads/main"


class MainValidationIdentity(StrictModel):
    """The validation principal is fixed to App 15368."""

    app_id: Literal[15368] = 15368
    identity: NonEmptyString


class MainReleaseIssuerBinding(MainBound):
    """Immutable controller root for release and integration-package authority."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    controller_config_digest: Sha256Digest
    issuer_id: NonEmptyString
    app_id: StrictInt = Field(gt=0)
    isolation_digest: Sha256Digest
    issuer_domain: Literal["isolated-release-check"] = "isolated-release-check"
    trusted_source_issuer: NonEmptyString
    trusted_source_domain: Literal["integration-campaign"] = "integration-campaign"
    binding_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_isolation(self) -> MainReleaseIssuerBinding:
        if self.app_id == 15368:
            raise ValueError("validation App 15368 cannot be the release issuer")
        if self.issuer_id == self.trusted_source_issuer:
            raise ValueError("release issuer cannot approve its own source package")
        if self.binding_digest != canonical_digest(
            self.model_dump(exclude={"binding_digest"}, mode="json")
        ):
            raise ValueError("release issuer binding digest mismatch")
        return self


class MainLeaseEvidence(MainBound):
    """Durable main-target lease proof; opaque lease digests are insufficient."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    identity: NonEmptyString
    acquired_at: datetime
    expires_at: datetime
    lease_digest: Sha256Digest

    _aware_acquired_at = field_validator("acquired_at")(_aware)
    _aware_expires_at = field_validator("expires_at")(_aware)

    @model_validator(mode="after")
    def validate_lease_evidence(self) -> MainLeaseEvidence:
        if self.expires_at <= self.acquired_at:
            raise ValueError("main lease evidence must expire after acquisition")
        if self.lease_digest != canonical_digest(
            self.model_dump(exclude={"lease_digest"}, mode="json")
        ):
            raise ValueError("main lease evidence digest mismatch")
        return self


class MainSourcePackageBinding(MainBound):
    """Immutable binding to a complete successful integration package."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    # Upstream campaign identity is deliberately distinct from this main
    # graduation operation; source evidence cannot be replayed as a stage.
    source_operation_id: Sha256Digest
    package_digest: Sha256Digest = Field(
        validation_alias=AliasChoices(
            "package_digest", "integration_package_digest", "source_package_digest"
        )
    )
    package_artifact: ArtifactRef
    child_artifacts: list[ArtifactRef] = Field(min_length=1)
    source_result_commit: GitObject
    source_result_tree: GitObject
    source_result_parent: GitObject
    source_issuer: NonEmptyString
    source_domain: Literal["integration-campaign"] = "integration-campaign"
    completion_state: Literal["successful"] = "successful"
    deploy_performed: Literal[False] = False

    @model_validator(mode="after")
    def validate_source(self) -> MainSourcePackageBinding:
        if self.source_operation_id == self.operation_id:
            raise ValueError("source campaign operation must differ from main graduation operation")
        digests = [child.digest for child in self.child_artifacts]
        if len(digests) != len(set(digests)):
            raise ValueError("source package children must be unique")
        roles = [child.role for child in self.child_artifacts]
        if len(roles) != len(set(roles)):
            raise ValueError("source package child roles must be unique")
        if self.package_artifact.digest != self.package_digest:
            raise ValueError("source package digest differs from raw package artifact")
        if self.package_artifact.role != "integration-campaign-package":
            raise ValueError("source package raw artifact has the wrong role")
        if self.package_artifact.media_type != "application/vnd.avo.integration-campaign+json":
            raise ValueError("source package raw artifact has the wrong media type")
        if self.source_result_parent == self.source_result_commit:
            raise ValueError("source result parent must differ from result")
        return self


class MainDeltaManifest(MainBound):
    """The exact sole-parent-to-result delta selected from the source package."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    package_digest: Sha256Digest
    source_result_commit: GitObject
    source_result_parent: GitObject
    source_result_tree: GitObject
    changed_paths: list[NonEmptyString] = Field(min_length=1)
    path_manifest_digest: Sha256Digest
    delta_digest: Sha256Digest
    ordinary_risk_digest: Sha256Digest
    ordinary_risk: Literal["ordinary"] = "ordinary"
    deploy_performed: Literal[False] = False

    _valid_paths = field_validator("changed_paths")(_paths)

    @model_validator(mode="after")
    def validate_delta(self) -> MainDeltaManifest:
        if self.source_result_parent == self.source_result_commit:
            raise ValueError("delta must have a distinct sole parent")
        return self


class MainCompositionArtifact(MainBound):
    """Deterministic application of the source delta to one fresh main base."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    package_digest: Sha256Digest
    delta_digest: Sha256Digest
    base_commit: GitObject
    base_tree: GitObject
    candidate_commit: GitObject
    candidate_tree: GitObject
    candidate_parent_commit: GitObject
    composition_digest: Sha256Digest
    candidate_ref: NonEmptyString
    deploy_performed: Literal[False] = False

    @model_validator(mode="after")
    def validate_composition(self) -> MainCompositionArtifact:
        if self.candidate_parent_commit != self.base_commit:
            raise ValueError("composed candidate must be parented by fresh main base")
        if self.candidate_commit == self.base_commit:
            raise ValueError("composed candidate must be a new commit")
        return self


class MainCheckObservation(StrictModel):
    schema_version: Literal[1] = 1
    name: NonEmptyString
    context: NonEmptyString
    app_id: StrictInt = Field(gt=0)
    sha: GitObject
    status: Literal["completed", "in_progress", "queued"]
    conclusion: Literal["success", "neutral", "failure", "pending"]
    run_id: NonEmptyString
    nonce: NonEmptyString
    observed_at: datetime

    _aware_observed_at = field_validator("observed_at")(_aware)

    @model_validator(mode="after")
    def validate_check(self) -> MainCheckObservation:
        if self.status == "completed" and self.conclusion not in {"success", "failure", "neutral"}:
            raise ValueError("completed check has an invalid conclusion")
        if self.status != "completed" and self.conclusion != "pending":
            raise ValueError("non-completed check must be pending")
        return self


class MainProtectionManifest(MainBound):
    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    manifest_digest: Sha256Digest
    provider_identity: NonEmptyString
    provider_api_version: NonEmptyString
    required: Literal[True] = True
    queue_required: Literal[True] = True
    max_entries_per_group: Literal[1] = 1
    bypass_allowed: Literal[False] = False
    direct_merge_allowed: Literal[False] = False
    isolated_release_issuer: NonEmptyString
    release_issuer_app_id: StrictInt = Field(gt=0)
    issuer_isolation_digest: Sha256Digest
    validation_app_id: Literal[15368] = 15368
    release_context: Literal["avo-main-release"] = "avo-main-release"
    protection_epoch: Sha256Digest
    observed_at: datetime

    _aware_observed_at = field_validator("observed_at")(_aware)

    @model_validator(mode="after")
    def validate_protection(self) -> MainProtectionManifest:
        if self.release_issuer_app_id == self.validation_app_id:
            raise ValueError("validation App 15368 cannot be the release issuer")
        return self


class MainQueueObservation(MainBound):
    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    queue_generation_digest: Sha256Digest
    queue_manifest_digest: Sha256Digest
    queue_enabled: Literal[True] = True
    max_entries_per_group: Literal[1] = 1
    bypass_allowed: Literal[False] = False
    direct_merge_allowed: Literal[False] = False
    expected_base_commit: GitObject
    expected_base_tree: GitObject
    protection_manifest_digest: Sha256Digest
    protection_epoch: Sha256Digest
    provider_identity: NonEmptyString
    provider_api_version: NonEmptyString
    # The provider's documented synthetic-merge topology, captured from the
    # queue configuration.  A group observation cannot choose its own shape.
    expected_group_parents: list[GitObject] = Field(min_length=1)
    group_topology_digest: Sha256Digest
    merge_method: Literal["squash"]
    isolated_release_issuer: NonEmptyString
    release_issuer_app_id: StrictInt = Field(gt=0)
    issuer_isolation_digest: Sha256Digest
    observed_at: datetime

    _aware_observed_at = field_validator("observed_at")(_aware)

    @model_validator(mode="after")
    def validate_queue_issuer(self) -> MainQueueObservation:
        if self.release_issuer_app_id == 15368:
            raise ValueError("validation App 15368 cannot be the release issuer")
        if self.expected_base_commit == "":
            raise ValueError("queue base is required")
        expected_topology = canonical_digest(
            {
                "expected_group_parents": self.expected_group_parents,
                "merge_method": self.merge_method,
                "provider_identity": self.provider_identity,
                "provider_api_version": self.provider_api_version,
                "queue_manifest_digest": self.queue_manifest_digest,
            }
        )
        if self.group_topology_digest != expected_topology:
            raise ValueError("queue group topology digest mismatch")
        return self


class MainMergeGroupChecks(MainBound):
    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    package_digest: Sha256Digest
    composition_digest: Sha256Digest
    group_sha: GitObject
    checks: list[MainCheckObservation] = Field(min_length=1)
    allowlisted_contexts: list[NonEmptyString] = Field(min_length=1)
    config_digest: Sha256Digest
    validation_app_id: Literal[15368] = 15368
    freshness_cutoff: datetime
    observed_at: datetime

    _aware_freshness_cutoff = field_validator("freshness_cutoff")(_aware)
    _aware_observed_at = field_validator("observed_at")(_aware)

    @model_validator(mode="after")
    def validate_group_checks(self) -> MainMergeGroupChecks:
        if any(
            check.sha != self.group_sha
            or check.app_id != self.validation_app_id
            or check.status != "completed"
            or check.conclusion != "success"
            for check in self.checks
        ):
            raise ValueError("all merge-group checks must bind the exact group SHA")
        contexts = {check.context for check in self.checks}
        allowed = set(self.allowlisted_contexts)
        if (
            contexts != allowed
            or len(allowed) != len(self.allowlisted_contexts)
            or len(self.checks) != len(contexts)
        ):
            raise ValueError("checks must exactly match the allowlisted contexts")
        if self.observed_at < self.freshness_cutoff or any(
            check.observed_at < self.freshness_cutoff for check in self.checks
        ):
            raise ValueError("merge-group checks are stale")
        return self


class MainAttestationManifest(MainBound):
    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    package_digest: Sha256Digest
    composition_digest: Sha256Digest
    policy_epoch: Sha256Digest
    reviewer_identity: NonEmptyString
    reviewer_evidence_digest: Sha256Digest
    evaluator_identity: NonEmptyString
    evaluator_evidence_digest: Sha256Digest
    independent: Literal[True] = True
    deploy_performed: Literal[False] = False

    @model_validator(mode="after")
    def validate_attestation(self) -> MainAttestationManifest:
        if self.reviewer_identity == self.evaluator_identity:
            raise ValueError("reviewer and evaluator attestations must be independent")
        return self


class MainGraduationPlan(MainBound):
    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    package: MainSourcePackageBinding = Field(
        validation_alias=AliasChoices("package", "source_package")
    )
    delta: MainDeltaManifest = Field(validation_alias=AliasChoices("delta", "delta_manifest"))
    composition: MainCompositionArtifact = Field(
        validation_alias=AliasChoices("composition", "composition_artifact")
    )
    policy_epoch: Sha256Digest
    controller_config_digest: Sha256Digest
    release_issuer_binding: MainReleaseIssuerBinding
    evidence_artifacts: list[ArtifactRef] = Field(min_length=1)
    deploy_performed: Literal[False] = False

    @model_validator(mode="after")
    def validate_plan(self) -> MainGraduationPlan:
        if any(
            item.repository_digest != self.repository_digest or item.target_ref != self.target_ref
            for item in (self.package, self.delta, self.composition)
        ):
            raise ValueError("plan child target bindings differ")
        if (
            self.package.operation_id != self.operation_id
            or self.delta.operation_id != self.operation_id
            or self.composition.operation_id != self.operation_id
        ):
            raise ValueError("plan child operation IDs differ")
        if (
            self.delta.package_digest != self.package.package_digest
            or self.composition.package_digest != self.package.package_digest
        ):
            raise ValueError("plan source package binding differs")
        if self.composition.delta_digest != self.delta.delta_digest:
            raise ValueError("plan composition delta differs")
        binding = self.release_issuer_binding
        if (
            binding.operation_id != self.operation_id
            or binding.repository_digest != self.repository_digest
            or binding.target_ref != self.target_ref
            or binding.controller_config_digest != self.controller_config_digest
            or binding.trusted_source_issuer != self.package.source_issuer
            or binding.trusted_source_domain != self.package.source_domain
        ):
            raise ValueError("plan controller authority binding differs")
        refs = {item.digest for item in self.evidence_artifacts}
        if len(refs) != len(self.evidence_artifacts):
            raise ValueError("plan evidence artifacts must be unique")
        return self


class MainGraduationIntent(MainBound):
    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    plan_digest: Sha256Digest
    package_digest: Sha256Digest
    composition_digest: Sha256Digest
    base_commit: GitObject
    base_tree: GitObject
    candidate_commit: GitObject
    candidate_tree: GitObject
    candidate_ref: NonEmptyString
    lease_identity: NonEmptyString
    lease_digest: Sha256Digest
    lease_evidence: MainLeaseEvidence
    lease_evidence_artifact: ArtifactRef
    policy_epoch: Sha256Digest
    intent_digest: Sha256Digest
    state: Literal["intent_recorded"] = "intent_recorded"
    recorded_at: datetime

    _aware_recorded_at = field_validator("recorded_at")(_aware)

    @model_validator(mode="after")
    def validate_intent(self) -> MainGraduationIntent:
        lease_bytes = canonical_bytes(self.lease_evidence)
        if (
            self.lease_evidence.operation_id != self.operation_id
            or self.lease_evidence.repository_digest != self.repository_digest
            or self.lease_evidence.target_ref != self.target_ref
            or self.lease_evidence.identity != self.lease_identity
            or self.lease_evidence.lease_digest != self.lease_digest
            or self.lease_evidence_artifact.role != "main-graduation-lease-evidence"
            or self.lease_evidence_artifact.media_type
            != "application/vnd.avo.main-graduation-lease-evidence+json"
            or self.lease_evidence_artifact.digest != canonical_digest(self.lease_evidence)
            or self.lease_evidence_artifact.size_bytes != len(lease_bytes)
        ):
            raise ValueError("intent lease evidence is not bound")
        if self.intent_digest != canonical_digest(
            self.model_dump(exclude={"intent_digest"}, mode="json")
        ):
            raise ValueError("intent digest mismatch")
        return self


class MainPreparationAuthorization(MainBound):
    """Reversible authorization; it cannot authorize a main mutation."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    plan_digest: Sha256Digest
    intent_digest: Sha256Digest
    package_digest: Sha256Digest
    composition_digest: Sha256Digest
    base_commit: GitObject
    base_tree: GitObject
    candidate_commit: GitObject
    candidate_tree: GitObject
    lease_identity: NonEmptyString
    lease_digest: Sha256Digest
    policy_epoch: Sha256Digest
    authorization_digest: Sha256Digest
    scope: Literal["candidate_publication_pr_preparation_queue_admission"] = (
        "candidate_publication_pr_preparation_queue_admission"
    )
    authorized: Literal[True] = True
    deploy_performed: Literal[False] = False
    authorized_at: datetime

    _aware_authorized_at = field_validator("authorized_at")(_aware)

    @model_validator(mode="after")
    def validate_authorization(self) -> MainPreparationAuthorization:
        if self.authorization_digest != canonical_digest(
            self.model_dump(exclude={"authorization_digest"}, mode="json")
        ):
            raise ValueError("preparation authorization digest mismatch")
        return self


class MainQueueAdmissionObservation(MainBound):
    """One-use, PR-head-only admission proof (never group evidence)."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    preparation_authorization_digest: Sha256Digest
    package_digest: Sha256Digest
    composition_digest: Sha256Digest
    pull_request_number: StrictInt = Field(gt=0)
    pull_request_url: NonEmptyString
    base_commit: GitObject
    base_tree: GitObject
    head_commit: GitObject = Field(validation_alias=AliasChoices("head_commit", "candidate_commit"))
    head_tree: GitObject = Field(validation_alias=AliasChoices("head_tree", "candidate_tree"))
    admission_sha: GitObject = Field(validation_alias=AliasChoices("admission_sha", "pr_head_sha"))
    admission_run_id: NonEmptyString
    admission_nonce: NonEmptyString
    queue_generation_digest: Sha256Digest
    protection_manifest_digest: Sha256Digest
    issuer_identity: NonEmptyString
    release_issuer_app_id: StrictInt = Field(gt=0)
    issuer_isolation_digest: Sha256Digest
    validation_app_id: Literal[15368] = 15368
    check_context: Literal["avo-main-release"] = "avo-main-release"
    check_state: Literal["completed"] = "completed"
    check_conclusion: Literal["success"] = "success"
    release_transition: Literal[False] = False
    one_use: Literal[True] = True
    observed_at: datetime

    _aware_observed_at = field_validator("observed_at")(_aware)

    @model_validator(mode="after")
    def validate_admission(self) -> MainQueueAdmissionObservation:
        if self.admission_sha != self.head_commit:
            raise ValueError("admission success must bind the exact PR head SHA")
        if self.release_issuer_app_id == self.validation_app_id:
            raise ValueError("validation App 15368 cannot issue admission evidence")
        if self.base_commit == self.head_commit:
            raise ValueError("PR head must differ from base")
        if not self.pull_request_url.startswith("https://"):
            raise ValueError("pull request URL must use HTTPS")
        return self


class MainReleaseHoldObservation(MainBound):
    """Distinct pending group-specific hold, created after queue admission."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    preparation_authorization_digest: Sha256Digest
    admission_observation_digest: Sha256Digest
    package_digest: Sha256Digest
    composition_digest: Sha256Digest
    pull_request_number: StrictInt = Field(gt=0)
    group_sha: GitObject
    group_tree: GitObject
    group_parents: list[GitObject] = Field(min_length=1)
    expected_group_parents: list[GitObject] = Field(min_length=1)
    group_topology_digest: Sha256Digest
    base_commit: GitObject
    base_tree: GitObject
    composition_tree: GitObject = Field(
        validation_alias=AliasChoices(
            "composition_tree", "expected_tree", "expected_group_tree", "candidate_tree"
        )
    )
    queue_generation_digest: Sha256Digest
    queue_members: list[StrictInt] = Field(min_length=1, max_length=1)
    max_entries_per_group: Literal[1] = 1
    hold_run_id: NonEmptyString
    hold_nonce: NonEmptyString
    issuer_identity: NonEmptyString
    release_issuer_app_id: StrictInt = Field(gt=0)
    issuer_isolation_digest: Sha256Digest
    check_context: Literal["avo-main-release"] = "avo-main-release"
    check_state: Literal["in_progress"] = "in_progress"
    check_conclusion: Literal["pending"] = "pending"
    validation_app_id: Literal[15368] = 15368
    other_required_checks: MainMergeGroupChecks
    protection_manifest_digest: Sha256Digest
    attestation_manifest_digest: Sha256Digest
    observed_at: datetime

    _aware_observed_at = field_validator("observed_at")(_aware)

    @model_validator(mode="after")
    def validate_hold(self) -> MainReleaseHoldObservation:
        if self.queue_members != [self.pull_request_number]:
            raise ValueError("release group must contain exactly the authorized PR")
        if not self.group_parents or self.group_parents[0] != self.base_commit:
            raise ValueError("release group parent topology must start at the base")
        if len(set(self.group_parents)) != len(self.group_parents):
            raise ValueError("release group parent topology must be complete and unique")
        if self.group_parents != self.expected_group_parents:
            raise ValueError("release group topology differs from provider-bound expectation")
        if self.group_tree != self.composition_tree:
            raise ValueError("release group tree differs from deterministic composition")
        if self.other_required_checks.group_sha != self.group_sha:
            raise ValueError("required checks must bind the exact merge-group SHA")
        if (
            self.other_required_checks.operation_id != self.operation_id
            or self.other_required_checks.repository_digest != self.repository_digest
            or self.other_required_checks.target_ref != self.target_ref
            or self.other_required_checks.package_digest != self.package_digest
            or self.other_required_checks.composition_digest != self.composition_digest
        ):
            raise ValueError("merge-group checks are not hold-bound")
        if any(check.context == "avo-main-release" for check in self.other_required_checks.checks):
            raise ValueError("group hold checks must not reuse the release hold context")
        if self.release_issuer_app_id == self.validation_app_id:
            raise ValueError("validation App 15368 cannot issue release hold evidence")
        return self


class MainReleaseAuthorization(MainBound):
    """Single-use authority consumed only by the isolated release issuer."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    preparation_authorization_digest: Sha256Digest
    admission_observation_digest: Sha256Digest
    hold_observation_digest: Sha256Digest
    package_digest: Sha256Digest
    composition_digest: Sha256Digest
    group_sha: GitObject
    hold_run_id: NonEmptyString
    hold_nonce: NonEmptyString
    queue_generation_digest: Sha256Digest
    lease_identity: NonEmptyString
    lease_digest: Sha256Digest
    policy_epoch: Sha256Digest
    release_issuer_identity: NonEmptyString
    release_issuer_app_id: StrictInt = Field(gt=0)
    issuer_isolation_digest: Sha256Digest
    authorization_digest: Sha256Digest
    one_use: Literal[True] = True
    used: Literal[False] = False
    deploy_performed: Literal[False] = False
    expires_at: datetime
    authorized_at: datetime

    _aware_expires_at = field_validator("expires_at")(_aware)
    _aware_authorized_at = field_validator("authorized_at")(_aware)

    @model_validator(mode="after")
    def validate_release_authorization(self) -> MainReleaseAuthorization:
        if self.expires_at <= self.authorized_at:
            raise ValueError("release authorization must expire after authorization")
        if self.release_issuer_app_id == 15368:
            raise ValueError("validation App 15368 cannot be the isolated release issuer")
        if self.authorization_digest != canonical_digest(
            self.model_dump(exclude={"authorization_digest"}, mode="json")
        ):
            raise ValueError("release authorization digest mismatch")
        return self


class MainReleaseTransitionReceipt(MainBound):
    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    release_authorization_digest: Sha256Digest
    group_sha: GitObject
    hold_run_id: NonEmptyString
    hold_nonce: NonEmptyString
    issuer_identity: NonEmptyString
    release_issuer_app_id: StrictInt = Field(gt=0)
    validation_app_id: Literal[15368] = 15368
    issuer_isolation_digest: Sha256Digest
    outcome: Literal["transitioned", "already_transitioned", "reconciliation_required"]
    transition_count: Literal[1] = 1
    response_digest: Sha256Digest
    observed_at: datetime
    deploy_performed: Literal[False] = False

    _aware_observed_at = field_validator("observed_at")(_aware)

    @model_validator(mode="after")
    def validate_transition(self) -> MainReleaseTransitionReceipt:
        if self.release_issuer_app_id == self.validation_app_id:
            raise ValueError("validation App 15368 cannot transition release hold")
        return self


class MainProviderReceipt(MainBound):
    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    release_authorization_digest: Sha256Digest
    provider_identity: NonEmptyString
    provider_api_version: NonEmptyString
    outcome: Literal["observed", "rejected", "ambiguous"]
    result_commit: GitObject | None = None
    result_tree: GitObject | None = None
    result_parents: list[GitObject] = Field(default_factory=list)
    response_digest: Sha256Digest
    observed_at: datetime
    deploy_performed: Literal[False] = False

    _aware_observed_at = field_validator("observed_at")(_aware)

    @model_validator(mode="after")
    def validate_provider_receipt(self) -> MainProviderReceipt:
        if self.outcome == "observed" and (
            self.result_commit is None or self.result_tree is None or len(self.result_parents) != 1
        ):
            raise ValueError("observed provider success requires exact one-parent result")
        if self.outcome != "observed" and any(
            value is not None for value in (self.result_commit, self.result_tree)
        ):
            raise ValueError("non-success receipt cannot claim result objects")
        return self


class MainReconciliation(MainBound):
    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    state: Literal["pending", "completed", "failed", "reconciliation_required"]
    main_commit: GitObject
    main_tree: GitObject
    main_parents: list[GitObject]
    expected_tree: GitObject
    expected_base_commit: GitObject
    queue_generation_digest: Sha256Digest
    transition_receipt_digest: Sha256Digest | None = None
    deploy_performed: Literal[False] = False

    @model_validator(mode="after")
    def validate_reconciliation(self) -> MainReconciliation:
        if self.state == "completed" and (
            self.main_tree != self.expected_tree or self.main_parents != [self.expected_base_commit]
        ):
            raise ValueError("completed reconciliation is not exact result topology")
        return self


class MainCompletionPackage(MainBound):
    """Final immutable package; its child refs are checked by the journal."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    plan: MainGraduationPlan
    source_package: MainSourcePackageBinding
    delta: MainDeltaManifest
    composition: MainCompositionArtifact
    queue_observation: MainQueueObservation
    protection_manifest: MainProtectionManifest
    attestation_manifest: MainAttestationManifest
    merge_group_checks: MainMergeGroupChecks
    intent: MainGraduationIntent
    release_issuer_binding: MainReleaseIssuerBinding
    preparation_authorization: MainPreparationAuthorization
    admission_observation: MainQueueAdmissionObservation
    hold_observation: MainReleaseHoldObservation
    release_authorization: MainReleaseAuthorization
    transition_receipt: MainReleaseTransitionReceipt
    provider_receipt: MainProviderReceipt
    reconciliation: MainReconciliation
    artifacts: list[ArtifactRef] = Field(min_length=1)
    deploy_performed: Literal[False] = False

    @model_validator(mode="after")
    def validate_completion(self) -> MainCompletionPackage:
        records = (
            self.plan,
            self.source_package,
            self.delta,
            self.composition,
            self.queue_observation,
            self.protection_manifest,
            self.attestation_manifest,
            self.merge_group_checks,
            self.release_issuer_binding,
            self.transition_receipt,
            self.provider_receipt,
            self.reconciliation,
            self.intent,
            self.preparation_authorization,
            self.admission_observation,
            self.hold_observation,
            self.release_authorization,
            self.transition_receipt,
            self.provider_receipt,
            self.reconciliation,
        )
        if any(
            getattr(record, "operation_id", self.operation_id) != self.operation_id
            for record in records
        ):
            raise ValueError("completion child operation IDs differ")
        if self.transition_receipt.outcome not in {"transitioned", "already_transitioned"}:
            raise ValueError("completion requires terminal release transition")
        if self.provider_receipt.outcome != "observed":
            raise ValueError("completion requires an observed provider result")
        if self.reconciliation.state != "completed":
            raise ValueError("completion requires completed reconciliation")
        if self.reconciliation.main_tree != self.composition.candidate_tree:
            raise ValueError("final main tree differs from deterministic composition")
        if self.release_issuer_binding != self.plan.release_issuer_binding:
            raise ValueError("completion issuer binding differs from plan")
        if self.reconciliation.expected_tree != self.composition.candidate_tree:
            raise ValueError("reconciliation expected tree differs from composition")
        if self.reconciliation.main_parents != [self.composition.base_commit]:
            raise ValueError("final main result must have exactly the bound base parent")
        if self.reconciliation.main_commit != self.provider_receipt.result_commit:
            raise ValueError("provider result commit differs from final main result")
        if self.reconciliation.expected_base_commit != self.composition.base_commit:
            raise ValueError("reconciliation expected base differs from composition")
        if self.provider_receipt.result_tree != self.composition.candidate_tree:
            raise ValueError("provider result tree differs from composition")
        if self.provider_receipt.result_parents != [self.composition.base_commit]:
            raise ValueError("provider result must have exactly one bound base parent")
        if self.provider_receipt.release_authorization_digest != canonical_digest(
            self.release_authorization
        ):
            raise ValueError("provider receipt does not bind release authorization")
        if self.reconciliation.transition_receipt_digest != canonical_digest(
            self.transition_receipt
        ):
            raise ValueError("reconciliation does not bind release transition")
        if (
            self.reconciliation.queue_generation_digest
            != self.queue_observation.queue_generation_digest
        ):
            raise ValueError("reconciliation queue generation differs")
        if self.release_authorization.used:
            raise ValueError("completion cannot reuse a release authorization")
        if self.merge_group_checks.group_sha == self.admission_observation.head_commit:
            raise ValueError("PR-head SHA cannot be reused as merge-group SHA")
        for evidence in (
            self.source_package,
            self.delta,
            self.composition,
            self.queue_observation,
            self.protection_manifest,
            self.attestation_manifest,
            self.merge_group_checks,
        ):
            if (
                evidence.repository_digest != self.repository_digest
                or evidence.target_ref != self.target_ref
            ):
                raise ValueError("completion evidence repository/target binding differs")
        if self.merge_group_checks.group_sha != self.hold_observation.group_sha:
            raise ValueError("group checks differ from release hold")
        if self.merge_group_checks.operation_id != self.operation_id:
            raise ValueError("group checks operation differs")
        if self.merge_group_checks.package_digest != self.source_package.package_digest:
            raise ValueError("group checks package differs")
        if self.merge_group_checks.composition_digest != self.composition.composition_digest:
            raise ValueError("group checks composition differs")
        if (
            self.queue_observation.queue_generation_digest
            != self.hold_observation.queue_generation_digest
        ):
            raise ValueError("queue generation differs across evidence")
        if (
            self.protection_manifest.issuer_isolation_digest
            != self.release_authorization.issuer_isolation_digest
        ):
            raise ValueError("release issuer isolation differs across evidence")
        if (
            self.protection_manifest.release_issuer_app_id
            != self.release_authorization.release_issuer_app_id
        ):
            raise ValueError("release issuer app differs across evidence")
        issuer_stages = (
            self.protection_manifest.issuer_isolation_digest,
            self.queue_observation.issuer_isolation_digest,
            self.admission_observation.issuer_isolation_digest,
            self.hold_observation.issuer_isolation_digest,
            self.release_authorization.issuer_isolation_digest,
            self.transition_receipt.issuer_isolation_digest,
        )
        if len(set(issuer_stages)) != 1:
            raise ValueError("release issuer isolation differs across stages")
        if self.release_issuer_binding.isolation_digest != issuer_stages[0]:
            raise ValueError("controller-pinned issuer isolation differs across stages")
        issuer_apps = (
            self.protection_manifest.release_issuer_app_id,
            self.queue_observation.release_issuer_app_id,
            self.admission_observation.release_issuer_app_id,
            self.hold_observation.release_issuer_app_id,
            self.release_authorization.release_issuer_app_id,
            self.transition_receipt.release_issuer_app_id,
        )
        if len(set(issuer_apps)) != 1 or issuer_apps[0] == 15368:
            raise ValueError("release issuer identity is not stable and isolated")
        if self.release_issuer_binding.app_id != issuer_apps[0]:
            raise ValueError("controller-pinned issuer app differs across stages")
        if (
            self.admission_observation.issuer_identity != self.hold_observation.issuer_identity
            or self.hold_observation.issuer_identity
            != self.release_authorization.release_issuer_identity
            or self.release_authorization.release_issuer_identity
            != self.transition_receipt.issuer_identity
        ):
            raise ValueError("release issuer differs across stages")
        if self.release_issuer_binding.issuer_id != self.admission_observation.issuer_identity:
            raise ValueError("controller-pinned issuer differs across stages")
        if (
            self.queue_observation.queue_generation_digest
            != self.admission_observation.queue_generation_digest
        ):
            raise ValueError("queue generation differs at admission")
        if self.queue_observation.expected_base_commit != self.composition.base_commit:
            raise ValueError("queue base differs from composition base")
        if self.queue_observation.expected_base_tree != self.composition.base_tree:
            raise ValueError("queue base tree differs from composition base")
        if (
            self.hold_observation.expected_group_parents
            != self.queue_observation.expected_group_parents
        ):
            raise ValueError("hold topology expectation differs from queue configuration")
        if (
            self.hold_observation.group_topology_digest
            != self.queue_observation.group_topology_digest
        ):
            raise ValueError("hold topology digest differs from queue configuration")
        if (
            self.protection_manifest.isolated_release_issuer
            != self.queue_observation.isolated_release_issuer
            or self.queue_observation.isolated_release_issuer
            != self.admission_observation.issuer_identity
        ):
            raise ValueError("controller-pinned release issuer differs across stages")
        if (
            self.queue_observation.provider_identity != self.protection_manifest.provider_identity
            or self.queue_observation.provider_api_version
            != self.protection_manifest.provider_api_version
            or self.provider_receipt.provider_identity != self.queue_observation.provider_identity
            or self.provider_receipt.provider_api_version
            != self.queue_observation.provider_api_version
        ):
            raise ValueError("provider identity/version differs across main stages")
        if self.admission_observation.base_commit != self.composition.base_commit:
            raise ValueError("admission base differs from composition base")
        if self.admission_observation.head_commit != self.composition.candidate_commit:
            raise ValueError("admission head differs from composed candidate")
        if self.admission_observation.head_tree != self.composition.candidate_tree:
            raise ValueError("admission head tree differs from composed candidate")
        if self.release_authorization.hold_observation_digest != canonical_digest(
            self.hold_observation
        ):
            raise ValueError("release authorization does not bind the pending hold")
        if self.release_authorization.admission_observation_digest != canonical_digest(
            self.admission_observation
        ):
            raise ValueError("release authorization does not bind admission")
        if self.hold_observation.admission_observation_digest != canonical_digest(
            self.admission_observation
        ):
            raise ValueError("group hold does not bind PR-head admission")
        if (
            self.hold_observation.pull_request_number
            != self.admission_observation.pull_request_number
        ):
            raise ValueError("group hold PR differs from admission PR")
        if self.release_authorization.group_sha != self.hold_observation.group_sha:
            raise ValueError("release authorization group differs from pending hold")
        if self.release_authorization.hold_run_id != self.hold_observation.hold_run_id:
            raise ValueError("release authorization hold run differs")
        if self.release_authorization.hold_nonce != self.hold_observation.hold_nonce:
            raise ValueError("release authorization hold nonce differs")
        if (
            self.release_authorization.queue_generation_digest
            != self.hold_observation.queue_generation_digest
        ):
            raise ValueError("release authorization queue generation differs")
        if self.preparation_authorization.intent_digest != canonical_digest(self.intent):
            raise ValueError("preparation authorization does not bind intent")
        if self.preparation_authorization.plan_digest != canonical_digest(self.plan):
            raise ValueError("preparation authorization does not bind plan")
        if self.intent.plan_digest != canonical_digest(self.plan):
            raise ValueError("intent does not bind plan")
        if self.release_authorization.preparation_authorization_digest != canonical_digest(
            self.preparation_authorization
        ):
            raise ValueError("release authorization does not bind preparation authorization")
        if (
            self.source_package != self.plan.package
            or self.delta != self.plan.delta
            or self.composition != self.plan.composition
        ):
            raise ValueError("completion evidence differs from plan children")
        if self.intent.package_digest != self.source_package.package_digest:
            raise ValueError("intent package differs from source package")
        if self.intent.composition_digest != self.composition.composition_digest:
            raise ValueError("intent composition differs from composition artifact")
        if self.preparation_authorization.package_digest != self.source_package.package_digest:
            raise ValueError("preparation authorization package differs")
        if self.preparation_authorization.composition_digest != self.composition.composition_digest:
            raise ValueError("preparation authorization composition differs")
        if self.admission_observation.head_commit == self.hold_observation.group_sha:
            raise ValueError("PR-head admission SHA cannot be reused as group SHA")
        roles = [item.role for item in self.artifacts]
        if len(roles) != len(set(roles)):
            raise ValueError("completion artifact roles must be unique")
        required_roles = {
            "main-graduation-source-package",
            "main-graduation-delta",
            "main-graduation-composition",
            "main-graduation-queue-observation",
            "main-graduation-protection-manifest",
            "main-graduation-attestation-manifest",
            "main-graduation-merge-group-checks",
            "main-graduation-release-issuer-binding",
            "main-graduation-plan",
            "main-graduation-intent",
            "main-graduation-preparation-authorization",
            "main-graduation-queue-admission",
            "main-graduation-release-hold",
            "main-graduation-release-authorization",
            "main-graduation-release-transition",
            "main-graduation-provider-receipt",
            "main-graduation-reconciliation",
        }
        if set(roles) != required_roles:
            raise ValueError("completion artifact closure is incomplete")
        return self


class MainInverseDeltaArtifact(MainBound):
    """Typed inverse of a completed main result; opaque rollback digests are forbidden."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    completion_package_digest: Sha256Digest
    current_main_commit: GitObject
    current_main_tree: GitObject
    inverse_changed_paths: list[NonEmptyString] = Field(min_length=1)
    inverse_tree: GitObject
    policy_epoch: Sha256Digest
    inverse_delta_digest: Sha256Digest
    deploy_performed: Literal[False] = False

    _valid_paths = field_validator("inverse_changed_paths")(_paths)

    @model_validator(mode="after")
    def validate_inverse_delta(self) -> MainInverseDeltaArtifact:
        expected = canonical_digest(self.model_dump(exclude={"inverse_delta_digest"}, mode="json"))
        if self.inverse_delta_digest != expected:
            raise ValueError("inverse delta digest mismatch")
        return self


class MainRollbackAuthorization(MainBound):
    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    completion_package_digest: Sha256Digest
    current_main_commit: GitObject
    current_main_tree: GitObject
    inverse_delta_digest: Sha256Digest
    inverse_delta_artifact_digest: Sha256Digest
    inverse_tree: GitObject
    lease_identity: NonEmptyString
    lease_digest: Sha256Digest
    policy_epoch: Sha256Digest
    authorization_digest: Sha256Digest
    authorized: Literal[True] = True
    deploy_performed: Literal[False] = False
    authorized_at: datetime

    _aware_authorized_at = field_validator("authorized_at")(_aware)

    @model_validator(mode="after")
    def validate_rollback_authorization(self) -> MainRollbackAuthorization:
        if self.authorization_digest != canonical_digest(
            self.model_dump(exclude={"authorization_digest"}, mode="json")
        ):
            raise ValueError("rollback authorization digest mismatch")
        return self


class MainRollbackIntent(MainBound):
    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    completion_package_digest: Sha256Digest
    inverse_delta_digest: Sha256Digest
    inverse_delta_artifact_digest: Sha256Digest
    base_commit: GitObject
    base_tree: GitObject
    current_main_commit: GitObject
    current_main_tree: GitObject
    candidate_commit: GitObject
    candidate_tree: GitObject
    inverse_tree: GitObject
    lease_identity: NonEmptyString
    lease_digest: Sha256Digest
    policy_epoch: Sha256Digest
    intent_digest: Sha256Digest
    recorded_at: datetime

    _aware_recorded_at = field_validator("recorded_at")(_aware)

    @model_validator(mode="after")
    def validate_rollback_intent(self) -> MainRollbackIntent:
        if self.intent_digest != canonical_digest(
            self.model_dump(exclude={"intent_digest"}, mode="json")
        ):
            raise ValueError("rollback intent digest mismatch")
        return self


class EligibilityLedgerStarted(MainBound):
    schema_version: Literal[1] = 1
    activation_digest: Sha256Digest
    controller_config_digest: Sha256Digest
    scheduler_sequence_watermark: StrictInt = Field(ge=0)
    streak: StrictInt = Field(ge=0)
    deploy_performed: Literal[False] = False


class MainGraduationEligibilityRecord(MainBound):
    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    scheduler_sequence: StrictInt = Field(gt=0)
    previous_scheduler_sequence: StrictInt | None = Field(
        default=None,
        validation_alias=AliasChoices("previous_scheduler_sequence", "previous_sequence"),
    )
    scheduler_watermark: StrictInt | None = Field(default=None, ge=0)
    submission_digest: Sha256Digest
    classification: Literal["eligible", "excluded"]
    exclusion_reason: NonEmptyString | None = None
    exclusion_evidence_digest: Sha256Digest | None = None
    ordinary: StrictBool
    nonempty: StrictBool
    terminal_disposition: (
        Literal["success", "failed", "quarantined", "reconciliation_required", "reset"] | None
    ) = None
    disposition_digest: Sha256Digest | None = None
    deploy_performed: Literal[False] = False

    @model_validator(mode="after")
    def validate_eligibility(self) -> MainGraduationEligibilityRecord:
        if self.classification == "eligible" and not (self.ordinary and self.nonempty):
            raise ValueError("only ordinary nonempty submissions are eligible")
        if self.classification == "excluded" and (
            (self.ordinary and self.nonempty)
            or not self.exclusion_reason
            or not self.exclusion_evidence_digest
        ):
            raise ValueError("exclusions require independent reason/evidence")
        if (
            self.classification == "eligible"
            and self.terminal_disposition is not None
            and self.disposition_digest is None
        ):
            raise ValueError("eligible terminal disposition requires evidence digest")
        if (
            self.previous_scheduler_sequence is not None
            and self.scheduler_sequence != self.previous_scheduler_sequence + 1
        ):
            raise ValueError("eligibility scheduler sequence contains a gap")
        if (
            self.scheduler_watermark is not None
            and self.scheduler_sequence <= self.scheduler_watermark
        ):
            raise ValueError("eligibility sequence is before activation watermark")
        return self


class MainGraduationAttempt(MainBound):
    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    scheduler_sequence: StrictInt = Field(gt=0)
    eligibility_record_digest: Sha256Digest
    package_digest: Sha256Digest | None = None
    terminal_disposition: (
        Literal["success", "failed", "quarantined", "reconciliation_required", "reset"] | None
    ) = None
    disposition_digest: Sha256Digest | None = None
    deploy_performed: Literal[False] = False

    @model_validator(mode="after")
    def validate_attempt(self) -> MainGraduationAttempt:
        if self.terminal_disposition is not None and self.disposition_digest is None:
            raise ValueError("terminal attempt requires disposition evidence")
        return self


T = TypeVar("T", bound=StrictModel)


def main_operation_id(**identity: object) -> Sha256Digest:
    """Return a stable operation identity from controller-bound values."""
    return canonical_digest(identity)


def main_record_bytes(record: StrictModel) -> bytes:
    """Canonical wire bytes used for every content-addressed main record."""
    return canonical_bytes(record)


def main_record_digest(record: StrictModel) -> Sha256Digest:
    """Content digest of a canonical main record."""
    return canonical_digest(record)


__all__ = [
    "EligibilityLedgerStarted",
    "MainAttestationManifest",
    "MainCheckObservation",
    "MainCompletionPackage",
    "MainCompositionArtifact",
    "MainDeltaManifest",
    "MainGraduationAttempt",
    "MainGraduationEligibilityRecord",
    "MainGraduationIntent",
    "MainGraduationPlan",
    "MainInverseDeltaArtifact",
    "MainLeaseEvidence",
    "MainMergeGroupChecks",
    "MainPreparationAuthorization",
    "MainProtectionManifest",
    "MainProviderReceipt",
    "MainQueueAdmissionObservation",
    "MainQueueObservation",
    "MainReconciliation",
    "MainReleaseAuthorization",
    "MainReleaseHoldObservation",
    "MainReleaseIssuerBinding",
    "MainReleaseTransitionReceipt",
    "MainRollbackAuthorization",
    "MainRollbackIntent",
    "MainSourcePackageBinding",
    "MainValidationIdentity",
    "main_operation_id",
    "main_record_bytes",
    "main_record_digest",
]
