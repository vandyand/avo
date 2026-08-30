from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from avo_correlate.contracts import (
    MainClaimedReleaseTransitionReceipt,
    MainExternalIdentity,
    MainLeaseEvidenceReadRequest,
    MainLeaseEvidenceRecord,
    MainMutationFenceResolution,
    MainMutationIntent,
    MainMutationReceipt,
    MainMutationStage,
    MainReleaseClaim,
    MainUnresolvedMutationFence,
    StrictModel,
    main_stage_identity_digest,
    main_stage_nonce,
    main_target_scope_digest,
)
from avo_correlate.domain.canonical import canonical_digest

NOW = datetime(2026, 1, 1, tzinfo=UTC)
R = "sha256:" + "1" * 64
D = "sha256:" + "2" * 64
D2 = "sha256:" + "3" * 64
BASE = "a" * 40
HEAD = "b" * 40


def external(stage: MainMutationStage = "candidate_publication") -> MainExternalIdentity:
    key = "refs/heads/avo/candidate/op"
    queue = D if stage != "candidate_publication" else None
    identity = main_stage_identity_digest(
        D,
        stage,
        key,
        queue_generation_digest=queue,
        repository_digest=R,
        target_ref="refs/heads/main",
    )
    return MainExternalIdentity(
        repository_digest=R,
        operation_id=D,
        stage=stage,
        external_key=key,
        queue_generation_digest=queue,
        identity_digest=identity,
    )


def digest_model[ModelT: StrictModel](model: type[ModelT], field: str, **values: Any) -> ModelT:
    probe = model.model_construct(**values, **{field: D})  # pyright: ignore[reportArgumentType]
    return model.model_validate(
        {**values, field: canonical_digest(probe.model_dump(exclude={field}, mode="json"))}
    )


def intent() -> MainMutationIntent:
    values = {
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "operation_id": D,
        "stage": "candidate_publication",
        "lease_identity": "avo-controller",
        "lease_digest": D2,
        "lease_epoch_digest": D2,
        "policy_epoch_digest": D2,
        "controller_config_digest": D2,
        "preparation_authorization_digest": D2,
        "external_identity": external(),
        "request_digest": D2,
        "recorded_at": NOW,
    }
    return digest_model(MainMutationIntent, "intent_digest", **values)


def test_deterministic_identities_and_nonce_are_stable() -> None:
    value = main_stage_identity_digest(
        D,
        "admission_check",
        "pr:17",
        queue_generation_digest=D2,
        repository_digest=R,
        target_ref="refs/heads/main",
    )
    assert value == main_stage_identity_digest(
        D,
        "admission_check",
        "pr:17",
        queue_generation_digest=D2,
        repository_digest=R,
        target_ref="refs/heads/main",
    )
    assert value != main_stage_identity_digest(
        D,
        "admission_check",
        "pr:18",
        queue_generation_digest=D2,
        repository_digest=R,
        target_ref="refs/heads/main",
    )
    assert main_stage_nonce(value) == main_stage_nonce(value)
    assert main_target_scope_digest(R, "refs/heads/main") == main_target_scope_digest(
        R, "refs/heads/main"
    )


def test_intent_requires_exact_stage_parent_and_external_binding() -> None:
    record = intent()
    assert record.intent_digest == canonical_digest(
        record.model_dump(exclude={"intent_digest"}, mode="json")
    )
    with pytest.raises(ValidationError, match="parent stage"):
        record.model_copy(update={"parent_stage": "pull_request_open"})
        MainMutationIntent.model_validate(
            {**record.model_dump(), "parent_stage": "pull_request_open"}
        )
    with pytest.raises(ValidationError, match="external identity"):
        MainMutationIntent.model_validate(
            {
                **record.model_dump(),
                "external_identity": external("pull_request_open").model_dump(),
            }
        )


def test_receipt_fails_closed_for_ambiguous_without_dispatch_and_is_content_addressed() -> None:
    values = {
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "operation_id": D,
        "stage": "candidate_publication",
        "intent_digest": intent().intent_digest,
        "lease_identity": "avo-controller",
        "lease_digest": D2,
        "lease_epoch_digest": D2,
        "policy_epoch_digest": D2,
        "controller_config_digest": D2,
        "preparation_authorization_digest": D2,
        "external_identity": external(),
        "outcome": "ambiguous",
        "dispatch_started": True,
        "response_digest": D2,
        "observed_at": NOW,
    }
    receipt = digest_model(MainMutationReceipt, "receipt_digest", **values)
    assert receipt.receipt_digest == canonical_digest(
        receipt.model_dump(exclude={"receipt_digest"}, mode="json")
    )
    with pytest.raises(ValidationError, match="requires a dispatched"):
        MainMutationReceipt.model_validate(
            {
                **receipt.model_dump(),
                "dispatch_started": False,
                "receipt_digest": D,
            }
        )


def test_release_claim_key_binds_authorization_hold_group_lease_and_issuer() -> None:
    values = {
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "operation_id": D,
        "authorization_digest": D2,
        "hold_observation_digest": D,
        "group_sha": HEAD,
        "hold_run_id": "hold-run",
        "hold_nonce": "hold-nonce",
        "queue_generation_digest": D2,
        "lease_identity": "avo-controller",
        "lease_digest": D2,
        "lease_epoch_digest": D2,
        "release_issuer_identity": "isolated-release",
        "release_issuer_app_id": 9002,
        "issuer_isolation_digest": D,
        "target_scope_digest": main_target_scope_digest(R, "refs/heads/main"),
        "authorization_expires_at": NOW.replace(hour=1),
        "lease_expires_at": NOW.replace(hour=2),
        "claimed_at": NOW,
    }
    probe = MainReleaseClaim.model_construct(  # pyright: ignore[reportArgumentType]
        **values,  # pyright: ignore[reportArgumentType]
        claim_key=D,
        claim_digest=D2,  # pyright: ignore[reportArgumentType]
    )
    values["claim_key"] = canonical_digest(
        {
            "repository_digest": R,
            "target_ref": "refs/heads/main",
            "operation_id": D,
            "authorization_digest": D2,
            "hold_observation_digest": D,
            "group_sha": HEAD,
            "hold_run_id": "hold-run",
            "hold_nonce": "hold-nonce",
            "queue_generation_digest": D2,
            "lease_epoch_digest": D2,
            "lease_digest": D2,
            "release_issuer_identity": "isolated-release",
            "release_issuer_app_id": 9002,
            "issuer_isolation_digest": D,
            "target_scope_digest": main_target_scope_digest(R, "refs/heads/main"),
            "authorization_expires_at": NOW.replace(hour=1).isoformat(),
            "lease_expires_at": NOW.replace(hour=2).isoformat(),
        }
    )
    probe = MainReleaseClaim.model_construct(**values, claim_digest=D2)  # pyright: ignore[reportArgumentType]
    values["claim_digest"] = canonical_digest(
        probe.model_dump(exclude={"claim_digest"}, mode="json")
    )
    claim = MainReleaseClaim.model_validate(values)
    assert claim.one_use is True
    with pytest.raises(ValidationError, match="claim key"):
        MainReleaseClaim.model_validate({**values, "claim_key": D})
    with pytest.raises(ValidationError, match="before authority expiry"):
        MainReleaseClaim.model_validate(
            {
                **values,
                "claimed_at": NOW.replace(hour=3),
                "claim_digest": values["claim_digest"],
            }
        )


def test_claimed_transition_receipt_requires_non_validation_issuer_and_claim() -> None:
    receipt_values = {
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "operation_id": D,
        "release_authorization_digest": D2,
        "claim_digest": D,
        "group_sha": HEAD,
        "hold_run_id": "hold-run",
        "hold_nonce": "hold-nonce",
        "issuer_identity": "isolated-release",
        "release_issuer_app_id": 9002,
        "issuer_isolation_digest": D2,
        "outcome": "transitioned",
        "response_digest": D2,
        "observed_at": NOW,
        "mutation_receipt_digest": D2,
    }
    probe = MainClaimedReleaseTransitionReceipt.model_construct(
        **receipt_values,  # pyright: ignore[reportArgumentType]
        receipt_digest=D,  # pyright: ignore[reportArgumentType]
    )
    receipt = MainClaimedReleaseTransitionReceipt.model_validate(
        {
            **receipt_values,
            "receipt_digest": canonical_digest(
                probe.model_dump(exclude={"receipt_digest"}, mode="json")
            ),
        }
    )
    assert receipt.claim_digest == D
    with pytest.raises(ValidationError, match="validation App"):
        MainClaimedReleaseTransitionReceipt.model_validate(
            {**receipt.model_dump(), "release_issuer_app_id": 15368}
        )


def test_target_fence_and_resolution_bind_scope_and_intent() -> None:
    values = {
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "operation_id": D,
        "stage": "candidate_publication",
        "intent_digest": intent().intent_digest,
        "source_receipt_digest": D2,
        "external_identity_digest": external().identity_digest,
        "lease_identity": "avo-controller",
        "lease_digest": D2,
        "target_scope_digest": main_target_scope_digest(R, "refs/heads/main"),
        "opened_at": NOW,
    }
    probe = MainUnresolvedMutationFence.model_construct(  # pyright: ignore[reportArgumentType]
        **values,  # pyright: ignore[reportArgumentType]
        fence_digest=D,  # pyright: ignore[reportArgumentType]
    )
    values["fence_digest"] = canonical_digest(
        probe.model_dump(exclude={"fence_digest"}, mode="json")
    )
    fence = MainUnresolvedMutationFence.model_validate(values)
    resolution_values = {
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "fence_digest": fence.fence_digest,
        "operation_id": D,
        "intent_digest": intent().intent_digest,
        "external_identity_digest": external().identity_digest,
        "lease_identity": "avo-controller",
        "lease_digest": D2,
        "target_scope_digest": main_target_scope_digest(R, "refs/heads/main"),
        "resolved_receipt_digest": D2,
        "authoritative_observation_digest": D,
        "provider_identity": "provider",
        "provider_api_version": "v1",
        "outcome": "observed",
        "observed_outcome": "applied",
        "resolved_at": NOW,
    }
    probe = MainMutationFenceResolution.model_construct(  # pyright: ignore[reportArgumentType]
        **resolution_values,  # pyright: ignore[reportArgumentType]
        resolution_digest=D,  # pyright: ignore[reportArgumentType]
    )
    resolution = MainMutationFenceResolution.model_validate(
        {
            **resolution_values,
            "resolution_digest": canonical_digest(
                probe.model_dump(exclude={"resolution_digest"}, mode="json")
            ),
        }
    )
    assert resolution.fence_digest == fence.fence_digest
    with pytest.raises(ValidationError):
        MainMutationFenceResolution.model_validate(
            {
                **resolution_values,
                "outcome": "reconciliation_required",
                "resolution_digest": resolution.resolution_digest,
            }
        )
    with pytest.raises(ValidationError, match="target scope"):
        MainUnresolvedMutationFence.model_validate({**values, "target_scope_digest": D})


def test_lease_record_and_read_request_are_strict_and_durable() -> None:
    values = {
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "operation_id": D,
        "owner": "avo-controller",
        "policy_epoch": D2,
        "lease_epoch_digest": D2,
        "acquired_at": NOW,
        "expires_at": NOW.replace(hour=2),
    }
    lease_probe = MainLeaseEvidenceRecord.model_construct(
        **values,  # pyright: ignore[reportArgumentType]
        lease_digest=D,
        evidence_digest=D,  # pyright: ignore[reportArgumentType]
    )
    values["lease_digest"] = canonical_digest(
        lease_probe.model_dump(exclude={"lease_digest", "evidence_digest"}, mode="json")
    )
    probe = MainLeaseEvidenceRecord.model_construct(  # pyright: ignore[reportArgumentType]
        **values,  # pyright: ignore[reportArgumentType]
        evidence_digest=D,  # pyright: ignore[reportArgumentType]
    )
    record = MainLeaseEvidenceRecord.model_validate(
        {
            **values,
            "evidence_digest": canonical_digest(
                probe.model_dump(exclude={"evidence_digest"}, mode="json")
            ),
        }
    )
    request = MainLeaseEvidenceReadRequest(
        repository_digest=R,
        target_ref="refs/heads/main",
        operation_id=D,
        lease_digest=record.lease_digest,
        requested_at=NOW,
    )
    assert request.lease_digest == record.lease_digest
    with pytest.raises(ValidationError, match="expire"):
        MainLeaseEvidenceRecord.model_validate(
            {
                **record.model_dump(),
                "expires_at": NOW,
                "evidence_digest": D,
            }
        )
