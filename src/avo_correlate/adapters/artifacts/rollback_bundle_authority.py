"""Durable create-once journal for pre-publication rollback authority."""

from __future__ import annotations

import hashlib
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
from avo_correlate.contracts.integration_soak import FailedSoakAttestation
from avo_correlate.contracts.prepublication import RollbackPublicationAuthorization
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest


class RollbackBundleAuthorityJournal:
    """CAS storage plus one-operation create-once index."""

    def __init__(self, artifact_store: FilesystemArtifactStore) -> None:
        self._store = artifact_store
        self._root = artifact_store.root / "rollback-publication-authorizations"

    def read_authorization(
        self, operation_id: str
    ) -> RollbackPublicationAuthorization | None:
        """Read an indexed authorization without requiring child objects.

        Recovery uses this narrow read to materialize a publication plan into
        the authority store before performing the full durable-child check.
        """

        index = self._root / operation_id.removeprefix("sha256:")
        if not index.is_file():
            return None
        try:
            raw = index.read_bytes()
            value = json.loads(raw)
            if canonical_bytes(value) != raw:
                raise ValueError("authorization index is not canonical JSON")
            authorization = RollbackPublicationAuthorization.model_validate(value["authorization"])
            if authorization.operation_id != operation_id:
                raise ValueError("authorization operation ID differs from index")
            return authorization
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("rollback publication authorization index is malformed") from exc

    def read_failed_soak_data(
        self, authorization: RollbackPublicationAuthorization
    ) -> bytes | None:
        """Read the exact provider child from a durable authorization, if present."""

        index = self._root / authorization.operation_id.removeprefix("sha256:")
        try:
            raw = index.read_bytes()
            value = json.loads(raw)
            if canonical_bytes(value) != raw:
                raise ValueError("authorization index is not canonical JSON")
            if "failed_soak_artifact" not in value:
                return None
            reference = ArtifactRef.model_validate(value["failed_soak_artifact"])
            data = self._store.read_bytes(reference)
            parsed = json.loads(data, object_pairs_hook=_strict_object_pairs)
            if (
                reference.role != "integration-drill-soak"
                or reference.media_type != "application/vnd.avo.integration-drill-soak+json"
                or canonical_bytes(parsed) != data
                or canonical_digest(parsed) != reference.digest
            ):
                raise ValueError("durable failed soak child is corrupt")
            return data
        except (
            ArtifactIntegrityError,
            OSError,
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            raise ValueError("durable failed soak child is malformed") from exc

    def read_canary_package(
        self, authorization: RollbackPublicationAuthorization
    ) -> IntegrationCampaignEvidencePackage:
        """Read and verify the exact canary package bound to an authority."""

        index = self._root / authorization.operation_id.removeprefix("sha256:")
        try:
            raw = index.read_bytes()
            value = json.loads(raw)
            if canonical_bytes(value) != raw:
                raise ValueError("authorization index is not canonical JSON")
            reference = ArtifactRef.model_validate(value["canary_package_artifact"])
            if (
                reference.role != "integration-campaign-package"
                or reference.media_type != "application/vnd.avo.integration-campaign+json"
                or reference.digest != authorization.canary_package_digest
            ):
                raise ValueError("durable canary child metadata differs from authority")
            data = self._store.read_bytes(reference)
            parsed = json.loads(data, object_pairs_hook=_strict_object_pairs)
            package = IntegrationCampaignEvidencePackage.model_validate(parsed)
            verify_campaign_package_artifact(package, reference, data)
            if package.intent.operation_id != authorization.canary_operation_id:
                raise ValueError("durable canary child operation differs from authority")
            return package
        except (
            ArtifactIntegrityError,
            OSError,
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            raise ValueError("durable canary package child is malformed") from exc

    def read_publication_plan_artifact(
        self, authorization: RollbackPublicationAuthorization
    ) -> ArtifactRef:
        """Return the exact plan reference retained by the authority index."""

        index = self._root / authorization.operation_id.removeprefix("sha256:")
        try:
            raw = index.read_bytes()
            value = json.loads(raw)
            if canonical_bytes(value) != raw:
                raise ValueError("authorization index is not canonical JSON")
            return ArtifactRef.model_validate(value["publication_plan_artifact"])
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("durable publication plan reference is malformed") from exc

    def recovery_bridge_exists(
        self, authorization: RollbackPublicationAuthorization
    ) -> bool:
        """Report only physical bridge presence; malformed bridges are not absent."""

        bridge = self._root / f"{authorization.operation_id.removeprefix('sha256:')}.bridge"
        if bridge.exists() and not bridge.is_file():
            raise ValueError("rollback recovery bridge has invalid type")
        return bridge.is_file()

    def record(
        self,
        authorization: RollbackPublicationAuthorization,
        *,
        canary_package_artifact: ArtifactRef,
        publication_plan_artifact: ArtifactRef,
        publication_plan_data: bytes | None = None,
        failed_soak_data: bytes | None = None,
    ) -> ArtifactRef:
        if publication_plan_data is not None:
            if (
                publication_plan_artifact.role != "candidate-publication-plan"
                or publication_plan_artifact.media_type
                != "application/vnd.avo.candidate-publication+json"
                or publication_plan_artifact.size_bytes != len(publication_plan_data)
                or publication_plan_artifact.digest
                != f"sha256:{hashlib.sha256(publication_plan_data).hexdigest()}"
            ):
                raise ValueError("publication plan artifact metadata or digest is invalid")
            self._store.put_bytes(
                publication_plan_data,
                media_type=publication_plan_artifact.media_type,
                role=publication_plan_artifact.role,
                max_bytes=2_000_000,
            )
        failed_soak_artifact: ArtifactRef | None = None
        if failed_soak_data is not None:
            failed_soak_artifact = self._store.put_bytes(
                failed_soak_data,
                media_type="application/vnd.avo.integration-drill-soak+json",
                role="integration-drill-soak",
                max_bytes=2_000_000,
            )
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
            **({"failed_soak_artifact": failed_soak_artifact.model_dump(mode="json")}
               if failed_soak_artifact is not None else {}),
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
                or (
                    failed_soak_artifact is not None
                    and existing.get("failed_soak_artifact") is not None
                    and ArtifactRef.model_validate(existing["failed_soak_artifact"])
                    != failed_soak_artifact
                )
            ):
                raise ValueError("conflicting rollback publication authorization") from None
            if self._store.read_bytes(old_ref) != payload:
                raise ValueError("rollback publication authorization artifact is corrupt") from None
            return old_ref
        return reference

    def record_recovery_bridge(
        self,
        authorization: RollbackPublicationAuthorization,
        *,
        legacy_failed_soak_data: bytes,
        fresh_failed_soak_data: bytes,
        publication_plan_artifact: ArtifactRef,
        publication_plan_data: bytes,
    ) -> None:
        """Durably bridge an exact old attestation to fresh revalidation.

        The indexed authorization is immutable.  The sidecar records the raw
        index digest and both provider observations so a restart can recover
        without recomputing identity from a moving freshness cutoff.
        """

        if (
            publication_plan_artifact.role != "candidate-publication-plan"
            or publication_plan_artifact.media_type
            != "application/vnd.avo.candidate-publication+json"
            or publication_plan_artifact.size_bytes != len(publication_plan_data)
            or publication_plan_artifact.digest
            != f"sha256:{hashlib.sha256(publication_plan_data).hexdigest()}"
        ):
            raise ValueError("recovery plan artifact metadata or digest is invalid")
        local_plan_ref = self._store.put_bytes(
            publication_plan_data,
            media_type=publication_plan_artifact.media_type,
            role=publication_plan_artifact.role,
            max_bytes=2_000_000,
        )
        legacy_soak_ref = self._store.put_bytes(
            legacy_failed_soak_data,
            media_type="application/vnd.avo.integration-drill-soak+json",
            role="integration-drill-soak",
            max_bytes=2_000_000,
        )
        fresh_soak_ref = self._store.put_bytes(
            fresh_failed_soak_data,
            media_type="application/vnd.avo.integration-drill-soak+json",
            role="integration-drill-soak",
            max_bytes=2_000_000,
        )
        index = self._root / authorization.operation_id.removeprefix("sha256:")
        index_raw = index.read_bytes()
        bridge = self._root / f"{authorization.operation_id.removeprefix('sha256:')}.bridge"
        payload = canonical_bytes(
            {
                "schema_version": 1,
                "authorization_id": authorization.authorization_id,
                "legacy_index_digest": f"sha256:{hashlib.sha256(index_raw).hexdigest()}",
                "legacy_failed_soak_artifact": legacy_soak_ref.model_dump(mode="json"),
                "fresh_failed_soak_artifact": fresh_soak_ref.model_dump(mode="json"),
                "publication_plan_artifact": publication_plan_artifact.model_dump(mode="json"),
                "materialized_publication_plan_artifact": local_plan_ref.model_dump(mode="json"),
            }
        )
        try:
            with bridge.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError:
            self.require_recovery_bridge(authorization)

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
            if "failed_soak_artifact" in value:
                soak_reference = ArtifactRef.model_validate(value["failed_soak_artifact"])
                if (
                    soak_reference.role != "integration-drill-soak"
                    or soak_reference.media_type
                    != "application/vnd.avo.integration-drill-soak+json"
                ):
                    raise ValueError("durable failed soak child metadata is malformed")
                soak_data = self._store.read_bytes(soak_reference)
                soak_raw = json.loads(soak_data, object_pairs_hook=_strict_object_pairs)
                soak = FailedSoakAttestation.model_validate(soak_raw)
                if (
                    canonical_bytes(soak_raw) != soak_data
                    or soak_reference.digest != canonical_digest(soak_raw)
                    or soak.attestation_id != authorization.failed_soak_attestation_id
                    or canonical_digest(soak) != authorization.failed_soak_attestation_digest
                ):
                    raise ValueError("durable failed soak child differs from authority")
            else:
                self.require_recovery_bridge(authorization)
        except (
            ArtifactIntegrityError,
            OSError,
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            raise ValueError("rollback publication authorization is not durably recorded") from exc

    def require_recovery_bridge(self, authorization: RollbackPublicationAuthorization) -> None:
        """Verify the immutable bridge used when provider freshness moves."""

        bridge = self._root / f"{authorization.operation_id.removeprefix('sha256:')}.bridge"
        index = self._root / authorization.operation_id.removeprefix("sha256:")
        try:
            raw = bridge.read_bytes()
            value = json.loads(raw)
            if canonical_bytes(value) != raw:
                raise ValueError("recovery bridge is not canonical JSON")
            if (
                value["authorization_id"] != authorization.authorization_id
                or value["legacy_index_digest"]
                != f"sha256:{hashlib.sha256(index.read_bytes()).hexdigest()}"
            ):
                raise ValueError("recovery bridge does not bind the authority index")
            legacy_ref = ArtifactRef.model_validate(value["legacy_failed_soak_artifact"])
            soak_data = self._store.read_bytes(legacy_ref)
            legacy_raw = json.loads(soak_data, object_pairs_hook=_strict_object_pairs)
            if (
                legacy_ref.role != "integration-drill-soak"
                or legacy_ref.media_type != "application/vnd.avo.integration-drill-soak+json"
                or canonical_bytes(legacy_raw) != soak_data
                or canonical_digest(legacy_raw) != legacy_ref.digest
            ):
                raise ValueError("recovery bridge soak artifact is corrupt")
            legacy = FailedSoakAttestation.model_validate(legacy_raw)
            if (
                legacy.attestation_id != authorization.failed_soak_attestation_id
                or canonical_digest(legacy) != authorization.failed_soak_attestation_digest
            ):
                raise ValueError("recovery bridge does not preserve exact attestation")
            fresh_ref = ArtifactRef.model_validate(value["fresh_failed_soak_artifact"])
            fresh_data = self._store.read_bytes(fresh_ref)
            fresh_raw = json.loads(fresh_data, object_pairs_hook=_strict_object_pairs)
            fresh = FailedSoakAttestation.model_validate(fresh_raw)
            if (
                fresh_ref.role != "integration-drill-soak"
                or fresh_ref.media_type != "application/vnd.avo.integration-drill-soak+json"
                or canonical_bytes(fresh_raw) != fresh_data
                or canonical_digest(fresh_raw) != fresh_ref.digest
                or fresh.repository_digest != authorization.repository_digest
                or fresh.integration_ref != authorization.target_ref
                or fresh.integration_commit != authorization.failed_integration_head_commit
                or fresh.integration_tree != authorization.failed_integration_head_tree
                or fresh.integration_parent_commit != authorization.restore_to_commit
                or fresh.restore_commit != authorization.restore_to_commit
                or fresh.restore_tree != authorization.restore_to_tree
                or fresh.main_commit != authorization.main_before_commit
                or fresh.model_dump(
                    exclude={"freshness_cutoff", "attestation_id"}, mode="json"
                )
                != legacy.model_dump(
                    exclude={"freshness_cutoff", "attestation_id"}, mode="json"
                )
            ):
                raise ValueError("recovery bridge fresh soak artifact is corrupt")
            plan_ref = ArtifactRef.model_validate(value["publication_plan_artifact"])
            if (
                plan_ref.role != "candidate-publication-plan"
                or plan_ref.media_type != "application/vnd.avo.candidate-publication+json"
            ):
                raise ValueError("recovery bridge plan differs from authority")
            plan_data = self._store.read_bytes(plan_ref)
            plan_raw = json.loads(plan_data, object_pairs_hook=_strict_object_pairs)
            if canonical_bytes(plan_raw) != plan_data:
                raise ValueError("recovery bridge plan is not canonical")
            from avo_correlate.adapters.git.publisher import FilesystemPublicationJournal

            plan = FilesystemPublicationJournal._plan_from_payload(  # pyright: ignore[reportPrivateUsage]
                plan_raw
            )
            if plan.publication_id != authorization.publication_plan_digest:
                raise ValueError("recovery bridge plan differs from authority")
            local_plan_ref = ArtifactRef.model_validate(
                value["materialized_publication_plan_artifact"]
            )
            if local_plan_ref.digest != plan_ref.digest:
                raise ValueError("recovery bridge plan materialization differs from authority")
            if self._store.read_bytes(local_plan_ref) != plan_data:
                raise ValueError("recovery bridge plan materialization is corrupt")
        except (
            ArtifactIntegrityError,
            OSError,
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            raise ValueError("rollback recovery bridge is not durably recorded") from exc

    def read_recovery_bridge_legacy_soak_data(
        self, authorization: RollbackPublicationAuthorization
    ) -> bytes:
        """Read the exact legacy observation after validating its bridge."""

        self.require_recovery_bridge(authorization)
        bridge = self._root / f"{authorization.operation_id.removeprefix('sha256:')}.bridge"
        value = json.loads(bridge.read_bytes())
        reference = ArtifactRef.model_validate(value["legacy_failed_soak_artifact"])
        return self._store.read_bytes(reference)

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
