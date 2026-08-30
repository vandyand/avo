from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
    MainGraduationJournalError,
)
from avo_correlate.contracts import (
    MainClaimedReleaseTransitionReceipt,
    MainCompletionPackage,
    MainMutationFenceResolution,
    MainProviderPostStateObservation,
    MainProviderReceipt,
    MainReconciliation,
    main_release_external_identity_digest,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest
from tests.unit.test_main_graduation_journal_coverage import completion as completion_package

R = "sha256:" + "1" * 64
OP = "sha256:" + "2" * 64
D = "sha256:" + "3" * 64
ALT = "sha256:" + "4" * 64
COMMIT = "a" * 40
TREE = "b" * 40
NOW = datetime(2026, 1, 1, tzinfo=UTC)


def test_main_completion_v1_is_not_accepted_as_c4() -> None:
    with pytest.raises(ValidationError):
        MainCompletionPackage.model_validate({"schema_version": 1})


def test_claimed_transition_requires_exact_mutation_receipt_link() -> None:
    payload = {
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "operation_id": OP,
        "release_authorization_digest": D,
        "claim_digest": D,
        "group_sha": COMMIT,
        "hold_run_id": "run",
        "hold_nonce": "nonce",
        "issuer_identity": "isolated-release",
        "release_issuer_app_id": 9001,
        "issuer_isolation_digest": D,
        "outcome": "transitioned",
        "response_digest": D,
        "observed_at": NOW,
        "receipt_digest": D,
    }
    with pytest.raises(ValidationError, match="mutation_receipt_digest"):
        MainClaimedReleaseTransitionReceipt.model_validate(payload)


def test_provider_post_state_is_content_addressed_and_authoritative() -> None:
    probe = MainProviderPostStateObservation.model_construct(
        repository_digest=R,
        target_ref="refs/heads/main",
        operation_id=OP,
        release_authorization_digest=D,
        provider_identity="provider",
        provider_api_version="v1",
        result_commit=COMMIT,
        result_tree=TREE,
        result_parents=["c" * 40],
        response_digest=D,
        observed_at=NOW,
        authoritative=True,
        observation_digest=D,
    )
    observation = MainProviderPostStateObservation.model_validate(
        {
            **probe.model_dump(mode="json"),
            "observation_digest": canonical_digest(
                probe.model_dump(exclude={"observation_digest"}, mode="json")
            ),
        }
    )
    assert observation.authoritative is True
    with pytest.raises(ValidationError, match="observation digest"):
        MainProviderPostStateObservation.model_validate(
            {**observation.model_dump(mode="json"), "result_tree": COMMIT}
        )


def test_release_external_identity_changes_with_authority_inputs() -> None:
    values: dict[str, Any] = {
        "operation_id": OP,
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "authorization_digest": D,
        "hold_observation_digest": D,
        "group_sha": COMMIT,
        "hold_run_id": "run",
        "hold_nonce": "nonce",
        "queue_generation_digest": D,
        "release_check_context": "avo-main-release",
        "release_issuer_app_id": 9001,
    }
    first = main_release_external_identity_digest(**values)
    assert first == main_release_external_identity_digest(**values)
    assert first != main_release_external_identity_digest(
        operation_id=OP,
        repository_digest=R,
        target_ref="refs/heads/main",
        authorization_digest=D,
        hold_observation_digest=D,
        group_sha=COMMIT,
        hold_run_id="run",
        hold_nonce="other",
        queue_generation_digest=D,
        release_check_context="avo-main-release",
        release_issuer_app_id=9001,
    )


def _post_state() -> MainProviderPostStateObservation:
    values: dict[str, Any] = {
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "operation_id": OP,
        "release_authorization_digest": D,
        "provider_identity": "provider",
        "provider_api_version": "v1",
        "result_commit": COMMIT,
        "result_tree": TREE,
        "result_parents": ["c" * 40],
        "response_digest": D,
        "observed_at": NOW,
        "authoritative": True,
    }
    # The contract hashes its JSON-mode model dump, which normalizes datetimes
    # (rather than hashing the Python datetime object representation).
    digest_input = MainProviderPostStateObservation.model_construct(**values).model_dump(
        mode="json"
    )
    return MainProviderPostStateObservation.model_validate(
        {**values, "observation_digest": canonical_digest(digest_input)}
    )


def test_c4_post_state_requires_injected_authority_verifier(tmp_path: Path) -> None:
    observation = _post_state()
    provider = MainProviderReceipt.model_construct(
        repository_digest=R,
        target_ref="refs/heads/main",
        operation_id=OP,
        release_authorization_digest=D,
        provider_identity="provider",
        provider_api_version="v1",
        outcome="observed",
        result_commit=COMMIT,
        result_tree=TREE,
        result_parents=["c" * 40],
        response_digest=D,
        observed_at=NOW,
    )
    reconciliation = MainReconciliation.model_construct(
        repository_digest=R,
        target_ref="refs/heads/main",
        operation_id=OP,
        state="completed",
        main_commit=COMMIT,
        main_tree=TREE,
        main_parents=["c" * 40],
        expected_tree=TREE,
        expected_base_commit="c" * 40,
        queue_generation_digest=D,
    )
    with pytest.raises(MainGraduationJournalError, match="injected provider post-state"):
        MainGraduationJournal(tmp_path)._verify_provider_post_state_authority(  # pyright: ignore[reportPrivateUsage]
            observation, provider, reconciliation
        )


def _ambiguous_completion_with_resolution(
    *, resolved_at: datetime = NOW
) -> MainCompletionPackage:
    package = completion_package()
    mutation = package.release_transition_mutation_receipt.model_copy(
        update={"outcome": "ambiguous"}
    )
    object.__setattr__(
        mutation,
        "receipt_digest",
        canonical_digest(mutation.model_dump(exclude={"receipt_digest"}, mode="json")),
    )
    claimed = package.claimed_transition_receipt.model_copy(
        update={
            "outcome": "transitioned",
            "mutation_receipt_digest": mutation.receipt_digest,
        }
    )
    object.__setattr__(
        claimed,
        "receipt_digest",
        canonical_digest(claimed.model_dump(exclude={"receipt_digest"}, mode="json")),
    )
    resolution = MainMutationFenceResolution.model_construct(
        repository_digest=package.repository_digest,
        target_ref=package.target_ref,
        fence_digest=package.release_transition_fence_resolution.fence_digest
        if package.release_transition_fence_resolution is not None
        else package.operation_id,
        operation_id=package.operation_id,
        intent_digest=package.release_transition_intent.intent_digest,
        external_identity_digest=package.release_transition_intent.external_identity.identity_digest,
        lease_identity=package.lease_evidence_record.owner,
        lease_digest=package.lease_evidence_record.lease_digest,
        target_scope_digest=package.release_claim.target_scope_digest,
        resolved_receipt_digest=mutation.receipt_digest,
        authoritative_observation_digest=package.provider_post_state_observation.observation_digest,
        provider_identity=package.provider_post_state_observation.provider_identity,
        provider_api_version=package.provider_post_state_observation.provider_api_version,
        outcome="observed",
        observed_outcome="applied",
        resolution_digest=package.operation_id,
        resolved_at=resolved_at,
    )
    object.__setattr__(
        resolution,
        "resolution_digest",
        canonical_digest(resolution.model_dump(exclude={"resolution_digest"}, mode="json")),
    )
    object.__setattr__(
        claimed,
        "mutation_resolution_digest",
        resolution.resolution_digest,
    )
    object.__setattr__(
        claimed,
        "response_digest",
        resolution.authoritative_observation_digest,
    )
    object.__setattr__(claimed, "observed_at", resolution.resolved_at)
    object.__setattr__(
        claimed,
        "receipt_digest",
        canonical_digest(claimed.model_dump(exclude={"receipt_digest"}, mode="json")),
    )
    transition = package.transition_receipt.model_copy(
        update={
            "outcome": "transitioned",
            "response_digest": claimed.response_digest,
            "observed_at": claimed.observed_at,
        }
    )
    reconciliation = package.reconciliation.model_copy(
        update={"transition_receipt_digest": canonical_digest(transition)}
    )
    resolution_payload = canonical_bytes(resolution)
    resolution_ref = ArtifactRef(
        digest=canonical_digest(resolution),
        size_bytes=len(resolution_payload),
        media_type="application/vnd.avo.main-graduation-mutation-fence-resolution+json",
        role="main-graduation-mutation-fence-resolution",
        created_at=NOW,
    )
    return package.model_copy(
        update={
            "transition_receipt": transition,
            "claimed_transition_receipt": claimed,
            "release_transition_mutation_receipt": mutation,
            "release_transition_fence_resolution": resolution,
            "reconciliation": reconciliation,
            "artifacts": [*package.artifacts, resolution_ref],
        }
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("repository_digest", ALT),
        ("target_ref", "refs/heads/other"),
        ("target_scope_digest", ALT),
        ("resolved_at", NOW - timedelta(seconds=1)),
        ("provider_identity", "other-provider"),
        ("provider_api_version", "v2"),
        ("authoritative_observation_digest", ALT),
    ),
)
def test_ambiguous_completion_requires_exact_resolution_bindings(field: str, value: Any) -> None:
    package = _ambiguous_completion_with_resolution()
    assert MainCompletionPackage.validate_completion(package) is package  # pyright: ignore[reportCallIssue]
    resolution = package.release_transition_fence_resolution
    assert resolution is not None
    tampered_resolution = resolution.model_copy(update={field: value})
    tampered = package.model_copy(
        update={"release_transition_fence_resolution": tampered_resolution}
    )
    with pytest.raises(ValueError, match="C4 fence resolution is not bound to release authority"):
        MainCompletionPackage.validate_completion(tampered)  # pyright: ignore[reportCallIssue]


def test_observed_resolution_requires_explicit_terminal_outcome() -> None:
    package = _ambiguous_completion_with_resolution()
    resolution = package.release_transition_fence_resolution
    assert resolution is not None
    tampered = package.model_copy(
        update={
            "release_transition_fence_resolution": resolution.model_copy(
                update={"observed_outcome": None}
            )
        }
    )
    with pytest.raises(ValueError, match="observed fence resolution lacks a terminal outcome"):
        MainCompletionPackage.validate_completion(tampered)  # pyright: ignore[reportCallIssue]


def test_recovered_ambiguity_can_resolve_after_authorization_expiry() -> None:
    package = _ambiguous_completion_with_resolution(
        resolved_at=NOW + timedelta(minutes=6)
    )
    assert MainCompletionPackage.validate_completion(package) is package  # pyright: ignore[reportCallIssue]


def test_not_applied_resolution_cannot_complete() -> None:
    package = _ambiguous_completion_with_resolution()
    resolution = package.release_transition_fence_resolution
    assert resolution is not None
    resolution = resolution.model_copy(update={"outcome": "not_applied", "observed_outcome": None})
    claimed = package.claimed_transition_receipt.model_copy(
        update={"outcome": "reconciliation_required"}
    )
    transition = package.transition_receipt.model_copy(
        update={"outcome": "reconciliation_required"}
    )
    tampered = package.model_copy(
        update={
            "claimed_transition_receipt": claimed,
            "transition_receipt": transition,
            "release_transition_fence_resolution": resolution,
            "reconciliation": package.reconciliation.model_copy(
                update={"transition_receipt_digest": canonical_digest(transition)}
            ),
        }
    )
    with pytest.raises(ValueError, match="completion cannot finalize a not-applied"):
        MainCompletionPackage.validate_completion(tampered)  # pyright: ignore[reportCallIssue]


def _rebound_mutation_chain(
    package: MainCompletionPackage,
    *,
    claim_update: dict[str, Any] | None = None,
    intent_update: dict[str, Any] | None = None,
) -> MainCompletionPackage:
    claim = package.release_claim
    if claim_update:
        claim = claim.model_copy(update=claim_update)
        object.__setattr__(
            claim,
            "claim_digest",
            canonical_digest(claim.model_dump(exclude={"claim_digest"}, mode="json")),
        )
    intent_updates = dict(intent_update or {})
    if claim_update:
        intent_updates["release_claim_digest"] = claim.claim_digest
    intent = package.release_transition_intent.model_copy(update=intent_updates)
    object.__setattr__(
        intent,
        "intent_digest",
        canonical_digest(intent.model_dump(exclude={"intent_digest"}, mode="json")),
    )
    mutation = package.release_transition_mutation_receipt.model_copy(
        update={"intent_digest": intent.intent_digest}
    )
    object.__setattr__(
        mutation,
        "receipt_digest",
        canonical_digest(mutation.model_dump(exclude={"receipt_digest"}, mode="json")),
    )
    claimed = package.claimed_transition_receipt.model_copy(
        update={"mutation_receipt_digest": mutation.receipt_digest}
    )
    object.__setattr__(
        claimed,
        "receipt_digest",
        canonical_digest(claimed.model_dump(exclude={"receipt_digest"}, mode="json")),
    )
    return package.model_copy(
        update={
            "release_claim": claim,
            "release_transition_intent": intent,
            "release_transition_mutation_receipt": mutation,
            "claimed_transition_receipt": claimed,
        }
    )


@pytest.mark.parametrize(
    ("claim_update", "intent_update", "message"),
    (
        ({"claimed_at": NOW - timedelta(seconds=1)}, None, "release claim chronology"),
        (None, {"recorded_at": NOW - timedelta(seconds=1)}, "release mutation chronology"),
        (None, {"recorded_at": NOW + timedelta(minutes=5)}, "release mutation chronology"),
    ),
)
def test_completion_rejects_stale_release_authority_chronology(
    claim_update: dict[str, Any] | None,
    intent_update: dict[str, Any] | None,
    message: str,
) -> None:
    package = _rebound_mutation_chain(
        completion_package(), claim_update=claim_update, intent_update=intent_update
    )
    with pytest.raises(ValueError, match=message):
        MainCompletionPackage.validate_completion(package)  # pyright: ignore[reportCallIssue]


@pytest.mark.parametrize(
    ("observed_at", "valid"),
    ((NOW, True), (NOW + timedelta(minutes=5), False)),
)
def test_completion_release_observations_respect_authorization_window(
    observed_at: datetime, valid: bool
) -> None:
    package = completion_package()
    transition = package.transition_receipt.model_copy(update={"observed_at": observed_at})
    claimed = package.claimed_transition_receipt.model_copy(update={"observed_at": observed_at})
    package = package.model_copy(
        update={"transition_receipt": transition, "claimed_transition_receipt": claimed}
    )
    if valid:
        assert MainCompletionPackage.validate_completion(package) is package  # pyright: ignore[reportCallIssue]
    else:
        with pytest.raises(ValueError, match="release transition chronology"):
            MainCompletionPackage.validate_completion(package)  # pyright: ignore[reportCallIssue]


@pytest.mark.parametrize("field", ("response_digest", "observed_at"))
def test_legacy_transition_observation_cannot_split_from_claimed(field: str) -> None:
    package = completion_package()
    value: Any = D if field == "response_digest" else NOW + timedelta(seconds=1)
    transition = package.transition_receipt.model_copy(update={field: value})
    tampered = package.model_copy(update={"transition_receipt": transition})
    with pytest.raises(ValueError, match="legacy transition observation is not claim-bound"):
        MainCompletionPackage.validate_completion(tampered)  # pyright: ignore[reportCallIssue]
