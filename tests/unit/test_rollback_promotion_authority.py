from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from avo_correlate.adapters.artifacts import FilesystemArtifactStore
from avo_correlate.adapters.git.publisher import PreparedPublication, PublicationPlan
from avo_correlate.application.promotion_service import RollbackPromotionAuthorizationJournal
from avo_correlate.application.rollback_bundle_authority import RollbackBundleAuthority
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_campaign import IntegrationCampaignEvidencePackage
from avo_correlate.contracts.integration_drill import IntegrationRollbackRequest
from avo_correlate.contracts.integration_soak import FailedSoakAttestation
from avo_correlate.contracts.prepublication import RollbackSnapshotRestoreFacts
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


def test_prepublication_authority_rejects_nested_model_construct_before_record() -> None:
    class Journal:
        records = 0

        def record(self, *_args: Any, **_kwargs: Any) -> None:
            self.records += 1

        def read_artifact(self, *_args: Any, **_kwargs: Any) -> bytes:
            raise AssertionError("child reads must not follow semantic rejection")

    operation = IntegrationRollbackRequest.model_construct(
        operation_id=D,
        promotion_operation_id="sha256:" + "b" * 64,
        repository_digest="sha256:" + "c" * 64,
        target_ref="refs/heads/integration",
        main_before_commit=G,
        failed_integration_head_commit=G,
        failed_integration_head_tree=G,
        restore_to_commit=G,
        restore_to_tree=G,
        rollback_candidate_commit="2" * 40,
        rollback_candidate_parent_commit=G,
    )
    plan = PublicationPlan(
        publication_id=D,
        repository_digest=operation.repository_digest,
        expected_remote="https://github.com/acme/widget.git",
        base_commit=G,
        base_tree=G,
        candidate_digest=D,
        candidate_ref="refs/heads/avo/candidate/" + "a" * 32,
        candidate_commit="2" * 40,
        candidate_tree=G,
        controller_publisher_identity="publisher",
        changed_paths=("src/x.py",),
    )
    journal = Journal()
    authority = RollbackBundleAuthority(Any, journal)  # type: ignore[arg-type]
    with pytest.raises((ValueError, TypeError)):
        authority.authorize(
            operation,
            canary_package_artifact=ArtifactRef.model_construct(),
            canary_package=IntegrationCampaignEvidencePackage.model_construct(),
            failed_soak=FailedSoakAttestation.model_construct(),
            facts=RollbackSnapshotRestoreFacts.model_construct(),
            prepared=PreparedPublication(plan, Path("candidate")),
        )
    assert journal.records == 0
