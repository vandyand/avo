"""Regression tests for cross-process campaign package addressing."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import pytest

from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_campaign import (
    campaign_package_bytes,
    verify_campaign_package_artifact,
)
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
