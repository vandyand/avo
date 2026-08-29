"""Replay classification regressions for ordinary and rollback bundles."""

# These tests intentionally reuse the canonical promotion fixtures.
# pyright: reportPrivateUsage=false

import json
from pathlib import Path

import pytest

from avo_correlate.domain.canonical import canonical_bytes, canonical_digest
from tests.unit.test_promotion_rollback_service_edges import (
    _evidence,
    _inputs,
    config,
)
from tests.unit.test_promotion_rollback_service_edges import (
    controller as rollback_controller,
)
from tests.unit.test_promotion_service import (
    FakeRepository,
    _config,
    _controller,
    _input,
    bundle_bytes,
)


def _integration_controller(tmp_path: Path):
    repository = FakeRepository()
    repository.state = repository.state.model_copy(update={"target_ref": "refs/heads/integration"})
    return _controller(tmp_path, repository)


def test_ordinary_integration_bundle_with_rollback_availability_replays(
    tmp_path: Path,
) -> None:
    controller = _integration_controller(tmp_path)
    result = controller.dry_run(
        _input(), candidate_root=tmp_path / "candidate", config=_config()
    )
    assert result.bundle.rollback_authorization is None
    assert result.bundle.rollback_operation_id is None
    assert result.bundle.operation_kind == "ordinary_campaign"
    report = controller.replay(result.bundle, bundle_digest=result.bundle_digest)
    assert report.outcome == "would_apply"


def test_legacy_rollback_shape_without_controller_authorization_is_rejected(
    tmp_path: Path,
) -> None:
    controller = _integration_controller(tmp_path)
    result = controller.dry_run(
        _input(), candidate_root=tmp_path / "candidate", config=_config()
    )
    legacy = result.bundle.model_copy(
        update={"operation_kind": None, "rollback_operation_id": None}
    )
    digest = canonical_digest(json.loads(bundle_bytes(legacy)))
    report = controller.replay(legacy, bundle_digest=digest)
    assert report.outcome == "invalid_bundle"
    assert report.errors == ["bundle operation kind is missing"]


def test_wire_legacy_bundle_omitting_kind_fails_before_repository_read(tmp_path: Path) -> None:
    repository = FakeRepository()
    repository.state = repository.state.model_copy(update={"target_ref": "refs/heads/integration"})
    controller = _controller(tmp_path, repository)
    result = controller.dry_run(
        _input(), candidate_root=tmp_path / "candidate", config=_config()
    )
    before_replay = repository.snapshot_count
    wire = json.loads(bundle_bytes(result.bundle))
    del wire["operation_kind"]
    digest = canonical_digest(wire)
    report = controller.replay(canonical_bytes(wire), bundle_digest=digest)
    assert report.outcome == "invalid_bundle"
    assert report.errors == ["bundle operation kind is missing"]
    assert repository.snapshot_count == before_replay


def test_authorized_rollback_bundle_remains_replayable(tmp_path: Path) -> None:
    fixture, preauth, drill, publication, package_ref = _inputs(tmp_path)
    controller, store, candidate = rollback_controller(tmp_path)
    store.put_bytes(
        fixture.canary_bytes,
        media_type=package_ref.media_type,
        role=package_ref.role,
        max_bytes=2_000_000,
    )
    store.put_bytes(
        _evidence(fixture, preauth),
        media_type="application/json",
        role="publication",
        max_bytes=2_000_000,
    )
    result = controller.create_rollback_bundle(
        fixture.operation,
        canary_package=fixture.package,
        canary_package_artifact=package_ref,
        drill_authorization=drill,
        candidate_root=candidate,
        publication=publication,
        config=config(),
    )
    assert result.bundle.rollback_authorization is not None
    assert result.bundle.operation_kind == "authorized_rollback"
    assert controller.replay(result.bundle, bundle_digest=result.bundle_digest).outcome == (
        "would_apply"
    )
    forged_decision = result.bundle.decision.model_copy(
        update={"reason_codes": ["requirements_satisfied"]}
    )
    forged = result.bundle.model_copy(update={"decision": forged_decision})
    with pytest.raises(ValueError, match="authorized rollback kind"):
        type(result.bundle).model_validate(forged.model_dump(mode="json"))


def test_bundle_reason_code_must_match_explicit_operation_kind(tmp_path: Path) -> None:
    controller = _integration_controller(tmp_path)
    result = controller.dry_run(
        _input(), candidate_root=tmp_path / "candidate", config=_config()
    )
    decision = result.bundle.decision.model_copy(update={"reason_codes": ["authorized_rollback"]})
    forged = result.bundle.model_copy(update={"decision": decision})
    with pytest.raises(ValueError, match="ordinary campaign"):
        type(result.bundle).model_validate(forged.model_dump(mode="json"))
