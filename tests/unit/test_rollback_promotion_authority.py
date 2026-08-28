from __future__ import annotations

from pathlib import Path

import pytest

from avo_correlate.adapters.artifacts import FilesystemArtifactStore
from avo_correlate.application.promotion_service import RollbackPromotionAuthorizationJournal
from avo_correlate.contracts.promotion_bundle import RollbackPromotionBundleAuthorization
from avo_correlate.domain.canonical import canonical_digest

D = "sha256:" + "a" * 64
G = "1" * 40


def _authorization(
    reason: str = "restore the known-good tree",
) -> RollbackPromotionBundleAuthorization:
    values = {
        "schema_version": 1,
        "operation_id": D,
        "canary_operation_id": "sha256:" + "c" * 64,
        "canary_package_digest": "sha256:" + "d" * 64,
        "drill_authorization_id": "sha256:" + "e" * 64,
        "repository_digest": "sha256:" + "f" * 64,
        "target_ref": "refs/heads/integration",
        "main_before_commit": G,
        "failed_integration_head_commit": G,
        "failed_integration_head_tree": "2" * 40,
        "restore_to_commit": "3" * 40,
        "restore_to_tree": "4" * 40,
        "rollback_candidate_commit": "5" * 40,
        "rollback_candidate_tree": "4" * 40,
        "rollback_candidate_parent_commit": G,
        "candidate_digest": D,
        "source_tree_digest": D,
        "restore_tree_digest": D,
        "publication_evidence_digest": D,
        "issuer_id": "rollback-controller",
        "reason": reason,
        "authorized": True,
    }
    return RollbackPromotionBundleAuthorization.model_validate(
        {**values, "authorization_id": canonical_digest(values)}
    )


def test_authorization_is_content_addressed_and_aliases_issuer() -> None:
    authorization = _authorization()
    assert authorization.issuer == "rollback-controller"
    assert authorization.authorization_id == canonical_digest(
        authorization.model_dump(exclude={"authorization_id"}, mode="json")
    )


def test_authorization_does_not_choose_the_post_bind_promotion_operation() -> None:
    authorization = _authorization()
    payload = authorization.model_dump(mode="json")
    assert "promotion_operation_id" not in payload


def test_authorization_journal_is_create_once_and_rejects_conflicts(tmp_path: Path) -> None:
    journal = RollbackPromotionAuthorizationJournal(FilesystemArtifactStore(tmp_path))
    authorization = _authorization()
    reference = journal.record(authorization)
    assert journal.record(authorization) == reference
    journal.require(authorization)
    with pytest.raises(ValueError, match="not durably recorded"):
        journal.require(authorization, require_children=True)
    with pytest.raises(ValueError, match="conflicting"):
        journal.record(_authorization("different reason"))
