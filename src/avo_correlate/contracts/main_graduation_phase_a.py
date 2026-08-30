"""Phase-A contracts for the protected-main coordinator boundary.

These records describe the durable protocol around an external write.  They do
not perform a write and intentionally contain no provider client or merge
capability.  A journal can use the records as append-only facts and enforce
create-once semantics with the content-addressed identities below.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator

from avo_correlate.contracts.base import (
    NonEmptyString,
    Sha256Digest,
    require_aware_datetime,
)
from avo_correlate.contracts.main_graduation import GitObject, MainBound
from avo_correlate.domain.canonical import canonical_digest

MainMutationStage = Literal[
    "candidate_publication",
    "pull_request_open",
    "admission_check",
    "queue_enqueue",
    "merge_group_hold",
    "release_transition",
]
MainMutationOutcome = Literal[
    "applied",
    "already_applied",
    "rejected",
    "ambiguous",
    "reconciliation_required",
]

_PARENT_STAGE: dict[MainMutationStage, MainMutationStage | None] = {
    "candidate_publication": None,
    "pull_request_open": "candidate_publication",
    "admission_check": "pull_request_open",
    "queue_enqueue": "admission_check",
    "merge_group_hold": "queue_enqueue",
    "release_transition": "merge_group_hold",
}


def main_target_scope_digest(repository_digest: str, target_ref: str) -> Sha256Digest:
    """Return the stable fence key for one repository target, independent of an attempt."""

    return canonical_digest({"repository_digest": repository_digest, "target_ref": target_ref})


def main_stage_identity_digest(
    operation_id: str,
    stage: MainMutationStage,
    external_key: str,
    *,
    queue_generation_digest: str | None,
    repository_digest: str,
    target_ref: str,
) -> Sha256Digest:
    """Derive a deterministic identity for a stage-specific provider object."""

    return canonical_digest(
        {
            "operation_id": operation_id,
            "stage": stage,
            "external_key": external_key,
            "queue_generation_digest": queue_generation_digest,
            "repository_digest": repository_digest,
            "target_ref": target_ref,
        }
    )


def main_stage_nonce(stage_identity_digest: str) -> Sha256Digest:
    """Derive the nonce used when a provider supports an idempotency nonce."""

    return canonical_digest({"stage_identity_digest": stage_identity_digest})


def main_release_external_key(
    *,
    operation_id: str,
    repository_digest: str,
    target_ref: str,
    authorization_digest: str,
    hold_observation_digest: str,
    group_sha: str,
    hold_run_id: str,
    hold_nonce: str,
    queue_generation_digest: str,
    release_check_context: str,
    release_issuer_app_id: int,
) -> Sha256Digest:
    """Derive the canonical external key for the protected-main release.

    A generic external key is not sufficient for the release transition: the
    provider object must be tied to the exact authorization, held merge-group
    SHA, hold execution, queue generation, and isolated release check.  Keep
    this projection centralized so callers cannot silently omit one of those
    bindings.
    """

    return canonical_digest(
        {
            "operation_id": operation_id,
            "repository_digest": repository_digest,
            "target_ref": target_ref,
            "authorization_digest": authorization_digest,
            "hold_observation_digest": hold_observation_digest,
            "group_sha": group_sha,
            "hold_run_id": hold_run_id,
            "hold_nonce": hold_nonce,
            "queue_generation_digest": queue_generation_digest,
            "release_check_context": release_check_context,
            "release_issuer_app_id": release_issuer_app_id,
        }
    )


def main_release_external_identity_digest(
    *,
    operation_id: str,
    repository_digest: str,
    target_ref: str,
    authorization_digest: str,
    hold_observation_digest: str,
    group_sha: str,
    hold_run_id: str,
    hold_nonce: str,
    queue_generation_digest: str,
    release_check_context: str,
    release_issuer_app_id: int,
) -> Sha256Digest:
    """Derive the generic stage identity from the canonical release key."""

    external_key = main_release_external_key(
        operation_id=operation_id,
        repository_digest=repository_digest,
        target_ref=target_ref,
        authorization_digest=authorization_digest,
        hold_observation_digest=hold_observation_digest,
        group_sha=group_sha,
        hold_run_id=hold_run_id,
        hold_nonce=hold_nonce,
        queue_generation_digest=queue_generation_digest,
        release_check_context=release_check_context,
        release_issuer_app_id=release_issuer_app_id,
    )
    return main_stage_identity_digest(
        operation_id,
        "release_transition",
        external_key,
        queue_generation_digest=queue_generation_digest,
        repository_digest=repository_digest,
        target_ref=target_ref,
    )


class MainExternalIdentity(MainBound):
    """Content-addressed identity of one external object or action."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    stage: MainMutationStage
    external_key: NonEmptyString
    queue_generation_digest: Sha256Digest | None = None
    identity_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_identity(self) -> MainExternalIdentity:
        expected = main_stage_identity_digest(
            self.operation_id,
            self.stage,
            self.external_key,
            queue_generation_digest=self.queue_generation_digest,
            repository_digest=self.repository_digest,
            target_ref=self.target_ref,
        )
        if self.identity_digest != expected:
            raise ValueError("external identity digest mismatch")
        if (
            self.stage
            in {"admission_check", "queue_enqueue", "merge_group_hold", "release_transition"}
            and self.queue_generation_digest is None
        ):
            raise ValueError("queue-bound external identity requires queue generation")
        return self


class MainMutationIntent(MainBound):
    """Append-only intent written before dispatching any external mutation."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    stage: MainMutationStage
    parent_stage: MainMutationStage | None = None
    parent_intent_digest: Sha256Digest | None = None
    parent_receipt: MainMutationReceipt | None = None
    # An ambiguous predecessor remains immutable.  A durable fence
    # resolution may authorize the next stage without rewriting that receipt.
    parent_resolution_digest: Sha256Digest | None = None
    lease_identity: NonEmptyString
    lease_digest: Sha256Digest
    lease_epoch_digest: Sha256Digest
    policy_epoch_digest: Sha256Digest
    controller_config_digest: Sha256Digest
    preparation_authorization_digest: Sha256Digest
    release_authorization_digest: Sha256Digest | None = None
    release_claim_digest: Sha256Digest | None = None
    external_identity: MainExternalIdentity
    request_digest: Sha256Digest
    recorded_at: datetime
    state: Literal["intent_recorded"] = "intent_recorded"
    intent_digest: Sha256Digest

    _aware_recorded_at = field_validator("recorded_at")(require_aware_datetime)

    @model_validator(mode="after")
    def validate_intent(self) -> MainMutationIntent:
        expected_parent = _PARENT_STAGE[self.stage]
        if self.parent_stage != expected_parent:
            raise ValueError("mutation intent has an invalid parent stage")
        if (self.parent_stage is None) != (self.parent_intent_digest is None):
            raise ValueError("parent stage and parent intent must be supplied together")
        if self.parent_stage is None and (
            self.parent_receipt is not None or self.parent_resolution_digest is not None
        ):
            raise ValueError("root mutation intent cannot carry a predecessor resolution")
        if self.parent_stage is not None and (
            (self.parent_receipt is None) == (self.parent_resolution_digest is None)
        ):
            raise ValueError("next mutation intent requires exactly one predecessor proof")
        if self.parent_receipt is not None:
            parent = self.parent_receipt
            if (
                parent.stage != self.parent_stage
                or parent.intent_digest != self.parent_intent_digest
                or parent.operation_id != self.operation_id
                or parent.repository_digest != self.repository_digest
                or parent.target_ref != self.target_ref
                or parent.outcome not in {"applied", "already_applied"}
            ):
                raise ValueError(
                    "mutation intent parent receipt is not a successful exact predecessor"
                )
        external = self.external_identity
        if (
            external.repository_digest != self.repository_digest
            or external.target_ref != self.target_ref
            or external.operation_id != self.operation_id
            or external.stage != self.stage
        ):
            raise ValueError("mutation intent external identity is not bound")
        if self.intent_digest != canonical_digest(
            self.model_dump(exclude={"intent_digest"}, mode="json")
        ):
            raise ValueError("mutation intent digest mismatch")
        if self.stage == "release_transition":
            if self.release_authorization_digest is None or self.release_claim_digest is None:
                raise ValueError("release transition requires authorization and claim")
        elif self.release_authorization_digest is not None or self.release_claim_digest is not None:
            raise ValueError("non-release mutation cannot carry release authority")
        return self


class MainMutationReceipt(MainBound):
    """Create-once provider receipt for exactly one mutation intent."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    stage: MainMutationStage
    intent_digest: Sha256Digest
    parent_intent_digest: Sha256Digest | None = None
    lease_identity: NonEmptyString
    lease_digest: Sha256Digest
    lease_epoch_digest: Sha256Digest
    policy_epoch_digest: Sha256Digest
    controller_config_digest: Sha256Digest
    preparation_authorization_digest: Sha256Digest
    release_authorization_digest: Sha256Digest | None = None
    release_claim_digest: Sha256Digest | None = None
    external_identity: MainExternalIdentity
    outcome: MainMutationOutcome
    dispatch_started: StrictBool
    response_digest: Sha256Digest
    observed_at: datetime
    receipt_digest: Sha256Digest

    _aware_observed_at = field_validator("observed_at")(require_aware_datetime)

    @model_validator(mode="after")
    def validate_receipt(self) -> MainMutationReceipt:
        external = self.external_identity
        if (
            external.repository_digest != self.repository_digest
            or external.target_ref != self.target_ref
            or external.operation_id != self.operation_id
            or external.stage != self.stage
        ):
            raise ValueError("mutation receipt external identity is not bound")
        if (
            self.outcome in {"applied", "already_applied", "ambiguous", "reconciliation_required"}
            and not self.dispatch_started
        ):
            raise ValueError(
                "mutation outcome requires a dispatched or possibly dispatched request"
            )
        if self.outcome == "rejected" and self.dispatch_started:
            raise ValueError("rejected mutation cannot claim dispatch was not prevented")
        if self.stage == "release_transition":
            if self.release_authorization_digest is None or self.release_claim_digest is None:
                raise ValueError("release transition requires authorization and claim")
        elif self.release_authorization_digest is not None or self.release_claim_digest is not None:
            raise ValueError("non-release mutation cannot carry release authority")
        if self.receipt_digest != canonical_digest(
            self.model_dump(exclude={"receipt_digest"}, mode="json")
        ):
            raise ValueError("mutation receipt digest mismatch")
        return self


class MainReleaseClaim(MainBound):
    """Atomic, create-once claim consumed before isolated release dispatch."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    authorization_digest: Sha256Digest
    hold_observation_digest: Sha256Digest
    group_sha: GitObject
    hold_run_id: NonEmptyString
    hold_nonce: NonEmptyString
    queue_generation_digest: Sha256Digest
    lease_identity: NonEmptyString
    lease_digest: Sha256Digest
    lease_epoch_digest: Sha256Digest
    release_issuer_identity: NonEmptyString
    release_issuer_app_id: StrictInt = Field(gt=0)
    issuer_isolation_digest: Sha256Digest
    target_scope_digest: Sha256Digest
    authorization_expires_at: datetime
    lease_expires_at: datetime
    claim_key: Sha256Digest
    claimed_at: datetime
    one_use: Literal[True] = True
    state: Literal["claimed"] = "claimed"
    claim_digest: Sha256Digest

    _aware_claimed_at = field_validator("claimed_at")(require_aware_datetime)
    _aware_authorization_expires_at = field_validator("authorization_expires_at")(
        require_aware_datetime
    )
    _aware_lease_expires_at = field_validator("lease_expires_at")(require_aware_datetime)

    @model_validator(mode="after")
    def validate_claim(self) -> MainReleaseClaim:
        if self.release_issuer_app_id == 15368:
            raise ValueError("validation App 15368 cannot claim release")
        if self.target_scope_digest != main_target_scope_digest(
            self.repository_digest, self.target_ref
        ):
            raise ValueError("release claim target scope mismatch")
        if self.authorization_expires_at > self.lease_expires_at:
            raise ValueError("release authorization cannot outlive the main lease")
        if (
            self.claimed_at >= self.authorization_expires_at
            or self.claimed_at >= self.lease_expires_at
        ):
            raise ValueError("release claim must be created before authority expiry")
        key_values: dict[str, object] = {
            "repository_digest": self.repository_digest,
            "target_ref": self.target_ref,
            "operation_id": self.operation_id,
            "authorization_digest": self.authorization_digest,
            "hold_observation_digest": self.hold_observation_digest,
            "group_sha": self.group_sha,
            "hold_run_id": self.hold_run_id,
            "hold_nonce": self.hold_nonce,
            "queue_generation_digest": self.queue_generation_digest,
            "lease_epoch_digest": self.lease_epoch_digest,
            "lease_digest": self.lease_digest,
            "release_issuer_identity": self.release_issuer_identity,
            "issuer_isolation_digest": self.issuer_isolation_digest,
            "authorization_expires_at": self.authorization_expires_at.isoformat(),
            "lease_expires_at": self.lease_expires_at.isoformat(),
        }
        key_values["release_issuer_app_id"] = self.release_issuer_app_id
        key_values["target_scope_digest"] = self.target_scope_digest
        expected_key = canonical_digest(key_values)
        if self.claim_key != expected_key:
            raise ValueError("release claim key mismatch")
        if self.claim_digest != canonical_digest(
            self.model_dump(exclude={"claim_digest"}, mode="json")
        ):
            raise ValueError("release claim digest mismatch")
        return self


class MainUnresolvedMutationFence(MainBound):
    """Open target-scoped fence created for an ambiguous external mutation."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    stage: MainMutationStage
    intent_digest: Sha256Digest
    source_receipt_digest: Sha256Digest
    external_identity_digest: Sha256Digest
    lease_identity: NonEmptyString
    lease_digest: Sha256Digest
    target_scope_digest: Sha256Digest
    opened_at: datetime
    state: Literal["open"] = "open"
    fence_digest: Sha256Digest

    _aware_opened_at = field_validator("opened_at")(require_aware_datetime)

    @model_validator(mode="after")
    def validate_fence(self) -> MainUnresolvedMutationFence:
        if self.target_scope_digest != main_target_scope_digest(
            self.repository_digest, self.target_ref
        ):
            raise ValueError("mutation fence target scope mismatch")
        if self.fence_digest != canonical_digest(
            self.model_dump(exclude={"fence_digest"}, mode="json")
        ):
            raise ValueError("mutation fence digest mismatch")
        return self


class MainMutationFenceResolution(MainBound):
    """Append-only closure fact for an unresolved mutation fence."""

    schema_version: Literal[1] = 1
    fence_digest: Sha256Digest
    operation_id: Sha256Digest
    intent_digest: Sha256Digest
    external_identity_digest: Sha256Digest
    lease_identity: NonEmptyString
    lease_digest: Sha256Digest
    target_scope_digest: Sha256Digest
    resolved_receipt_digest: Sha256Digest
    authoritative_observation_digest: Sha256Digest
    provider_identity: NonEmptyString
    provider_api_version: NonEmptyString
    outcome: Literal["observed", "not_applied"]
    resolution_digest: Sha256Digest
    resolved_at: datetime

    _aware_resolved_at = field_validator("resolved_at")(require_aware_datetime)

    @model_validator(mode="after")
    def validate_resolution(self) -> MainMutationFenceResolution:
        if self.target_scope_digest != main_target_scope_digest(
            self.repository_digest, self.target_ref
        ):
            raise ValueError("mutation resolution target scope mismatch")
        if self.resolution_digest != canonical_digest(
            self.model_dump(exclude={"resolution_digest"}, mode="json")
        ):
            raise ValueError("mutation fence resolution digest mismatch")
        return self


class MainLeaseEvidenceRecord(MainBound):
    """Public durable lease record returned by the main journal API."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    owner: NonEmptyString
    policy_epoch: Sha256Digest
    lease_epoch_digest: Sha256Digest
    acquired_at: datetime
    expires_at: datetime
    lease_digest: Sha256Digest
    evidence_digest: Sha256Digest

    _aware_acquired_at = field_validator("acquired_at")(require_aware_datetime)
    _aware_expires_at = field_validator("expires_at")(require_aware_datetime)

    @model_validator(mode="after")
    def validate_lease(self) -> MainLeaseEvidenceRecord:
        if self.expires_at <= self.acquired_at:
            raise ValueError("main lease record must expire after acquisition")
        expected_lease_digest = canonical_digest(
            self.model_dump(exclude={"lease_digest", "evidence_digest"}, mode="json")
        )
        if self.lease_digest != expected_lease_digest:
            raise ValueError("main lease record lease digest mismatch")
        if self.evidence_digest != canonical_digest(
            self.model_dump(exclude={"evidence_digest"}, mode="json")
        ):
            raise ValueError("main lease record evidence digest mismatch")
        return self


class MainLeaseEvidenceReadRequest(MainBound):
    """Typed, read-only lookup key for durable main lease evidence."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    lease_digest: Sha256Digest
    requested_at: datetime

    _aware_requested_at = field_validator("requested_at")(require_aware_datetime)


class MainClaimedReleaseTransitionReceipt(MainBound):
    """Release transition receipt that cannot exist without the one-use claim."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    release_authorization_digest: Sha256Digest
    claim_digest: Sha256Digest
    group_sha: GitObject
    hold_run_id: NonEmptyString
    hold_nonce: NonEmptyString
    issuer_identity: NonEmptyString
    release_issuer_app_id: StrictInt = Field(gt=0)
    issuer_isolation_digest: Sha256Digest
    outcome: Literal["transitioned", "already_transitioned", "reconciliation_required"]
    transition_count: Literal[1] = 1
    response_digest: Sha256Digest
    observed_at: datetime
    mutation_receipt_digest: Sha256Digest
    receipt_digest: Sha256Digest
    deploy_performed: Literal[False] = False

    _aware_observed_at = field_validator("observed_at")(require_aware_datetime)

    @model_validator(mode="after")
    def validate_transition(self) -> MainClaimedReleaseTransitionReceipt:
        if self.release_issuer_app_id == 15368:
            raise ValueError("validation App 15368 cannot transition release hold")
        if self.receipt_digest != canonical_digest(
            self.model_dump(exclude={"receipt_digest"}, mode="json")
        ):
            raise ValueError("claimed transition receipt digest mismatch")
        return self


# Resolve the forward reference used to embed the exact durable predecessor
# receipt in a next-stage intent.
MainMutationIntent.model_rebuild()


__all__ = [
    "MainClaimedReleaseTransitionReceipt",
    "MainExternalIdentity",
    "MainLeaseEvidenceReadRequest",
    "MainLeaseEvidenceRecord",
    "MainMutationFenceResolution",
    "MainMutationIntent",
    "MainMutationOutcome",
    "MainMutationReceipt",
    "MainMutationStage",
    "MainReleaseClaim",
    "MainUnresolvedMutationFence",
    "main_release_external_identity_digest",
    "main_release_external_key",
    "main_stage_identity_digest",
    "main_stage_nonce",
    "main_target_scope_digest",
]
