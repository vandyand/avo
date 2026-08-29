"""Durable create-once journal for pre-publication rollback authority."""

from __future__ import annotations

import json
import os

from avo_correlate.adapters.artifacts.filesystem import (
    ArtifactIntegrityError,
    FilesystemArtifactStore,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_campaign import (
    IntegrationCampaignEvidencePackage,
    verify_campaign_package_artifact,
)
from avo_correlate.contracts.prepublication import RollbackPublicationAuthorization
from avo_correlate.domain.canonical import canonical_bytes


class RollbackBundleAuthorityJournal:
    """CAS storage plus one-operation create-once index."""

    def __init__(self, artifact_store: FilesystemArtifactStore) -> None:
        self._store = artifact_store
        self._root = artifact_store.root / "rollback-publication-authorizations"

    def record(
        self,
        authorization: RollbackPublicationAuthorization,
        *,
        canary_package_artifact: ArtifactRef,
        publication_plan_artifact: ArtifactRef,
    ) -> ArtifactRef:
        payload = canonical_bytes(authorization)
        reference = self._store.put_bytes(
            payload,
            media_type="application/vnd.avo.rollback-publication-authorization+json",
            role="rollback-publication-authorization",
            max_bytes=2_000_000,
        )
        self._root.mkdir(parents=True, exist_ok=True)
        # Operation identity, rather than authorization identity, is the
        # create-once key: a second authority for one rollback must conflict.
        index = self._root / authorization.operation_id.removeprefix("sha256:")
        value = canonical_bytes({
            "authorization": authorization.model_dump(mode="json"),
            "artifact": reference.model_dump(mode="json"),
            "canary_package_artifact": canary_package_artifact.model_dump(mode="json"),
            "publication_plan_artifact": publication_plan_artifact.model_dump(mode="json"),
        })
        try:
            with index.open("xb") as handle:
                handle.write(value)
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError:
            try:
                existing = json.loads(index.read_bytes())
                old = RollbackPublicationAuthorization.model_validate(existing["authorization"])
                old_ref = ArtifactRef.model_validate(existing["artifact"])
                old_canary = ArtifactRef.model_validate(existing["canary_package_artifact"])
                old_plan = ArtifactRef.model_validate(existing["publication_plan_artifact"])
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ValueError("rollback publication authorization index is malformed") from exc
            if (
                old != authorization
                or old_canary != canary_package_artifact
                or old_plan != publication_plan_artifact
            ):
                raise ValueError("conflicting rollback publication authorization") from None
            if self._store.read_bytes(old_ref) != payload:
                raise ValueError("rollback publication authorization artifact is corrupt") from None
            return old_ref
        return reference

    def require(self, authorization: RollbackPublicationAuthorization) -> None:
        index = self._root / authorization.operation_id.removeprefix("sha256:")
        try:
            raw = index.read_bytes()
            value = json.loads(raw)
            if canonical_bytes(value) != raw:
                raise ValueError("authorization index is not canonical JSON")
            existing = RollbackPublicationAuthorization.model_validate(value["authorization"])
            if existing != authorization:
                raise ValueError("authorization differs from durable authority")
            reference = ArtifactRef.model_validate(value["artifact"])
            if (
                reference.role != "rollback-publication-authorization"
                or reference.media_type
                != "application/vnd.avo.rollback-publication-authorization+json"
            ):
                raise ValueError("authorization artifact metadata is malformed")
            if self._store.read_bytes(reference) != canonical_bytes(authorization):
                raise ValueError("authorization artifact differs from durable authority")
            canary_reference = ArtifactRef.model_validate(value["canary_package_artifact"])
            if (
                canary_reference.role != "integration-campaign-package"
                or canary_reference.media_type != "application/vnd.avo.integration-campaign+json"
                or canary_reference.digest != authorization.canary_package_digest
            ):
                raise ValueError("durable canary child metadata differs from authority")
            canary_data = self._store.read_bytes(canary_reference)
            canary_raw = json.loads(canary_data, object_pairs_hook=_strict_object_pairs)
            canary = IntegrationCampaignEvidencePackage.model_validate(canary_raw)
            verify_campaign_package_artifact(canary, canary_reference, canary_data)
            if canary.intent.operation_id != authorization.canary_operation_id:
                raise ValueError("durable canary child operation differs from authority")
            plan_reference = ArtifactRef.model_validate(value["publication_plan_artifact"])
            if (
                plan_reference.role != "candidate-publication-plan"
                or plan_reference.media_type
                != "application/vnd.avo.candidate-publication+json"
            ):
                raise ValueError("durable publication plan child metadata is malformed")
            plan_data = self._store.read_bytes(plan_reference)
            plan_raw = json.loads(plan_data, object_pairs_hook=_strict_object_pairs)
            if canonical_bytes(plan_raw) != plan_data:
                raise ValueError("durable publication plan child is not canonical")
            from avo_correlate.adapters.git.publisher import FilesystemPublicationJournal

            plan = FilesystemPublicationJournal._plan_from_payload(  # pyright: ignore[reportPrivateUsage]
                plan_raw
            )
            if plan.publication_id != authorization.publication_plan_digest:
                raise ValueError("durable publication plan differs from authority")
            if (
                plan.repository_digest != authorization.repository_digest
                or plan.base_commit != authorization.failed_integration_head_commit
                or plan.base_tree != authorization.failed_integration_head_tree
                or plan.candidate_commit != authorization.rollback_candidate_commit
                or plan.candidate_tree != authorization.rollback_candidate_tree
                or plan.candidate_digest != authorization.candidate_digest
                or plan.candidate_ref != authorization.candidate_ref
                or list(plan.changed_paths) != authorization.changed_paths
            ):
                raise ValueError("durable publication plan topology differs from authority")
        except (
            ArtifactIntegrityError,
            OSError,
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            raise ValueError("rollback publication authorization is not durably recorded") from exc

    def read_artifact(self, reference: ArtifactRef) -> bytes:
        """Read a referenced authority artifact with content-address verification."""

        return self._store.read_bytes(reference)


def _strict_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, item in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = item
    return result


RollbackPublicationAuthorizationJournal = RollbackBundleAuthorityJournal

__all__ = [
    "RollbackBundleAuthorityJournal",
    "RollbackPublicationAuthorizationJournal",
]
