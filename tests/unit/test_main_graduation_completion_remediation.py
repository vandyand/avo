from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from avo_correlate.contracts import (
    MainClaimedReleaseTransitionReceipt,
    MainCompletionPackage,
    MainProviderPostStateObservation,
    main_release_external_identity_digest,
)
from avo_correlate.domain.canonical import canonical_digest

R = "sha256:" + "1" * 64
OP = "sha256:" + "2" * 64
D = "sha256:" + "3" * 64
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
    values = {
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
    assert first != main_release_external_identity_digest(**{**values, "hold_nonce": "other"})

