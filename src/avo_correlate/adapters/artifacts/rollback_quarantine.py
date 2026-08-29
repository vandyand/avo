"""Create-once terminal quarantine for abandoned rollback operations."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from pathlib import Path

from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.prepublication import (
    RollbackOperationQuarantine,
    RollbackPublicationAuthorization,
    RollbackRemoteAbsenceObservation,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest


class RollbackOperationQuarantineJournal:
    """Local-only, create-once terminal fence keyed by rollback operation."""

    def __init__(self, state_root: Path) -> None:
        self._root = state_root.resolve() / "rollback-quarantine"

    def read(self, operation_id: str) -> RollbackOperationQuarantine | None:
        path = self._path(operation_id)
        if path.is_symlink():
            raise ValueError("rollback operation quarantine is a symlink")
        if not path.is_file():
            return None
        try:
            data = path.read_bytes()
            raw = json.loads(data, object_pairs_hook=_strict_object_pairs)
            if canonical_bytes(raw) != data:
                raise ValueError("quarantine record is not canonical")
            record = RollbackOperationQuarantine.model_validate(raw)
            if record.operation_id != operation_id:
                raise ValueError("quarantine operation ID differs from path")
            return record
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("rollback operation quarantine is malformed") from exc

    def create_for_authorization(
        self,
        authorization: RollbackPublicationAuthorization,
        *,
        authorization_index_data: bytes,
        canary_package_artifact: ArtifactRef,
        publication_plan_artifact: ArtifactRef,
        reason: str,
        absence_verifier: Callable[[str, str, str], object],
    ) -> RollbackOperationQuarantine:
        """Verify remote absence, then write only the quarantine record."""

        authorization = RollbackPublicationAuthorization.model_validate_json(
            canonical_bytes(authorization)
        )
        canary_package_artifact = ArtifactRef.model_validate_json(
            canonical_bytes(canary_package_artifact)
        )
        publication_plan_artifact = ArtifactRef.model_validate_json(
            canonical_bytes(publication_plan_artifact)
        )
        try:
            index_raw = json.loads(
                authorization_index_data, object_pairs_hook=_strict_object_pairs
            )
            if canonical_bytes(index_raw) != authorization_index_data:
                raise ValueError("authorization index is not canonical")
            indexed = RollbackPublicationAuthorization.model_validate(
                index_raw["authorization"]
            )
            if indexed != authorization:
                raise ValueError("authorization index differs from authority")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("authorization index is malformed") from exc
        if canary_package_artifact.digest != authorization.canary_package_digest:
            raise ValueError("quarantine canary differs from authority")
        if (
            publication_plan_artifact.role != "candidate-publication-plan"
            or publication_plan_artifact.media_type
            != "application/vnd.avo.candidate-publication+json"
        ):
            raise ValueError("quarantine publication plan reference is malformed")
        absence = absence_verifier(
            authorization.candidate_ref,
            authorization.rollback_candidate_commit,
            authorization.failed_integration_head_commit,
        )
        if not isinstance(absence, RollbackRemoteAbsenceObservation):
            raise TypeError("absence verifier returned an invalid observation")
        absence = RollbackRemoteAbsenceObservation.model_validate_json(canonical_bytes(absence))
        if (
            absence.repository_digest != authorization.repository_digest
            or absence.candidate_ref != authorization.candidate_ref
            or absence.candidate_commit != authorization.rollback_candidate_commit
            or absence.base_commit != authorization.failed_integration_head_commit
        ):
            raise ValueError("remote absence observation differs from authority")
        values = {
            "schema_version": 1,
            "operation_id": authorization.operation_id,
            "authorization_id": authorization.authorization_id,
            "authorization_index_digest": "sha256:"
            + hashlib.sha256(authorization_index_data).hexdigest(),
            "canary_operation_id": authorization.canary_operation_id,
            "canary_package_digest": canary_package_artifact.digest,
            "publication_plan_digest": authorization.publication_plan_digest,
            "publication_plan_artifact_digest": publication_plan_artifact.digest,
            "candidate_ref": authorization.candidate_ref,
            "candidate_commit": authorization.rollback_candidate_commit,
            "candidate_parent_commit": authorization.rollback_candidate_parent_commit,
            "reason": reason,
            "remote_absence": absence.model_dump(mode="json"),
        }
        record = RollbackOperationQuarantine.model_validate(
            {**values, "quarantine_id": canonical_digest(values)}
        )
        path = self._path(record.operation_id)
        self._root.mkdir(parents=True, exist_ok=True)
        payload = canonical_bytes(record)
        try:
            with path.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError:
            existing = self.read(record.operation_id)
            if existing != record:
                raise ValueError("conflicting rollback operation quarantine") from None
            if existing is None:
                raise ValueError("rollback operation quarantine disappeared") from None
            return existing
        return record

    def _path(self, operation_id: str) -> Path:
        if len(operation_id) != 71 or not operation_id.startswith("sha256:"):
            raise ValueError("quarantine operation ID is malformed")
        if any(char not in "0123456789abcdef" for char in operation_id[7:]):
            raise ValueError("quarantine operation ID is malformed")
        return self._root / f"{operation_id[7:]}.json"


def _strict_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


__all__ = ["RollbackOperationQuarantineJournal"]
