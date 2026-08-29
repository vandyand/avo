"""Regression tests for cross-process campaign package addressing."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast

import pytest

from avo_correlate.application.integration_live_rollback_service import (
    LiveIntegrationRollbackService,
    LiveRollbackEvidenceError,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_campaign import (
    campaign_package_bytes,
    verify_campaign_package_artifact,
)
from avo_correlate.contracts.integration_drill import IntegrationRollbackRequest
from avo_correlate.contracts.promotion_policy import PromotionConfig
from tests.unit.test_integration_campaign_contracts import (
    _package,  # pyright: ignore[reportPrivateUsage]
)


def _reference(data: bytes) -> ArtifactRef:
    return ArtifactRef(
        digest="sha256:" + hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
        media_type="application/vnd.avo.integration-campaign+json",
        role="integration-campaign-package",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def test_promotion_policy_set_serialization_is_process_order_independent() -> None:
    first = PromotionConfig(
        evaluation_epoch=1,
        trusted_base_issuers=["base"],
        trusted_reviewer_issuers=["reviewer"],
        trusted_path_issuers=["path"],
        rollback_issuer_ids=["rollback"],
        rollback_limit=1,
        reviewer_domains={"reviewer": "example.test"},
        proposer_domains={"proposer": "example.test"},
        candidate_proposers={"sha256:" + "a" * 64: "proposer"},
        low_gates=frozenset({"zeta", "alpha"}),
        ordinary_gates=frozenset({"omega", "beta"}),
    )
    second = first.model_copy(
        update={
            "low_gates": frozenset({"alpha", "zeta"}),
            "ordinary_gates": frozenset({"beta", "omega"}),
        }
    )
    assert first.model_dump(mode="json") == second.model_dump(mode="json")

    package = _package()
    policy = package.bundle.controller_config.policy
    reordered = package.bundle.controller_config.model_copy(
        update={
            "policy": policy.model_copy(
                update={
                    "low_gates": frozenset(reversed(tuple(policy.low_gates))),
                    "ordinary_gates": frozenset(reversed(tuple(policy.ordinary_gates))),
                }
            )
        }
    )
    reordered_package = package.model_copy(
        update={"bundle": package.bundle.model_copy(update={"controller_config": reordered})}
    )
    assert campaign_package_bytes(package) == campaign_package_bytes(reordered_package)


def test_legacy_gate_permutation_binds_to_durable_digest() -> None:
    package = _package()
    current = campaign_package_bytes(package)
    raw = json.loads(current)
    policy = raw["bundle"]["controller_config"]["policy"]
    policy["low_gates"] = list(reversed(policy["low_gates"]))
    policy["ordinary_gates"] = list(reversed(policy["ordinary_gates"]))
    legacy = json.dumps(raw, separators=(",", ":"), ensure_ascii=False).encode()
    # The legacy bytes remain RFC-8785 canonical; only array ordering differs.
    reference = _reference(legacy)
    assert verify_campaign_package_artifact(package, reference, legacy) == reference.digest
    assert reference.digest != "sha256:" + hashlib.sha256(current).hexdigest()


def test_campaign_package_binding_rejects_unrelated_tampering() -> None:
    package = _package()
    raw = json.loads(campaign_package_bytes(package))
    raw["main_before_commit"] = "b" * 40
    tampered = json.dumps(raw, separators=(",", ":"), ensure_ascii=False).encode()
    with pytest.raises(ValueError, match="campaign package"):
        verify_campaign_package_artifact(package, _reference(tampered), tampered)


def test_live_service_rejects_canary_ref_mixing_before_rollback() -> None:
    canary = _package()
    failed_commit = canary.receipt.applied_result_commit
    failed_tree = canary.receipt.applied_result_tree
    assert failed_commit is not None and failed_tree is not None
    request = IntegrationRollbackRequest.model_construct(
        operation_id="sha256:" + "b" * 64,
        repository_digest=canary.intent.repository_digest,
        target_ref=canary.intent.target_ref,
        main_before_commit="a" * 40,
        failed_integration_head_commit=failed_commit,
        failed_integration_head_tree=failed_tree,
        restore_to_commit=canary.intent.base_commit,
        restore_to_tree=canary.intent.base_tree,
        rollback_candidate_commit="c" * 40,
        rollback_candidate_parent_commit=failed_commit,
        promotion_operation_id="sha256:" + "c" * 64,
    )
    ref = _reference(campaign_package_bytes(canary))
    forged = ref.model_copy(update={"digest": "sha256:" + "f" * 64})
    bundle = SimpleNamespace(
        operation_kind="authorized_rollback",
        rollback_authorization=SimpleNamespace(
            operation_id=request.operation_id,
            canary_operation_id=canary.intent.operation_id,
            canary_package_digest=ref.digest,
        ),
    )
    rollback = SimpleNamespace(calls=0)

    def forbidden_run(*_args: Any, **_kwargs: Any) -> None:
        rollback.calls += 1

    def no_package(_operation_id: str) -> None:
        return None

    rollback.run = forbidden_run
    service = LiveIntegrationRollbackService(
        cast(Any, rollback),
        cast(Any, SimpleNamespace()),
        cast(Any, SimpleNamespace(read_package=no_package)),
        cast(Any, SimpleNamespace()),
        main_head_reader=lambda: request.main_before_commit,
        target_observation_reader=lambda: cast(Any, SimpleNamespace()),
    )
    with pytest.raises(LiveRollbackEvidenceError, match="successful canary"):
        service.run(
            request,
            canary_package=canary,
            canary_package_artifact=forged,
            authorization=cast(Any, SimpleNamespace()),
            bundle=cast(Any, bundle),
            publication=cast(Any, SimpleNamespace()),
            bundle_digest="sha256:" + "d" * 64,
            intent_factory=lambda _lease: cast(Any, object()),
        )
    assert rollback.calls == 0
