"""Durable create-once journal for pre-publication rollback authority."""

from __future__ import annotations

import json
import os

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.contracts.base import ArtifactRef
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
        index = self._root / authorization.authorization_id.removeprefix("sha256:")
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
        index = self._root / authorization.authorization_id.removeprefix("sha256:")
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
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("rollback publication authorization is not durably recorded") from exc

    def read_artifact(self, reference: ArtifactRef) -> bytes:
        """Read a referenced authority artifact with content-address verification."""

        return self._store.read_bytes(reference)


RollbackPublicationAuthorizationJournal = RollbackBundleAuthorityJournal

__all__ = [
    "RollbackBundleAuthorityJournal",
    "RollbackPublicationAuthorizationJournal",
]
