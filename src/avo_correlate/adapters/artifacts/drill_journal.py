"""Create-once filesystem journal for AVO-004.6 drill evidence."""

from __future__ import annotations

import errno
import json
import os
from pathlib import Path
from typing import Any

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_drill import (
    IntegrationDrillCaseResult,
    IntegrationDrillPlan,
    IntegrationDrillPromotionEvidenceManifest,
    IntegrationDrillResult,
    IntegrationDrillRollbackAuthorization,
    IntegrationDrillRollbackIntent,
    IntegrationDrillRollbackReceipt,
    IntegrationDrillSoakObservation,
)
from avo_correlate.domain.canonical import canonical_bytes


class DrillJournalError(RuntimeError):
    pass


class DrillRecordConflictError(DrillJournalError):
    pass


_MODELS: dict[str, Any] = {
    "plan": IntegrationDrillPlan,
    "case": IntegrationDrillCaseResult,
    "soak": IntegrationDrillSoakObservation,
    "rollback-intent": IntegrationDrillRollbackIntent,
    "rollback-authorization": IntegrationDrillRollbackAuthorization,
    "rollback-receipt": IntegrationDrillRollbackReceipt,
    "promotion-evidence-manifest": IntegrationDrillPromotionEvidenceManifest,
    "result": IntegrationDrillResult,
}


class IntegrationDrillJournal:
    def __init__(
        self,
        root: Path,
        *,
        artifact_store: FilesystemArtifactStore | None = None,
        max_record_bytes: int = 8 * 1024 * 1024,
    ):
        if max_record_bytes <= 0:
            raise ValueError("max_record_bytes must be positive")
        self._root = root.resolve()
        self._indexes = self._root / "integration-drill-index"
        self._store = artifact_store or FilesystemArtifactStore(self._root / "artifacts")
        self._max = max_record_bytes

    @property
    def root(self):
        return self._root

    def delete_artifact(self, digest: str) -> bool:
        """Test/recovery seam for removing an object before verification."""
        return self._store.delete(digest)

    def _id(self, record: Any, kind: str) -> str:
        if kind == "case":
            return record.operation_id + f"-{record.case_id}"
        return record.operation_id

    def _record(self, kind: str, record: Any) -> ArtifactRef:
        data = canonical_bytes(record)
        ref = self._store.put_bytes(
            data,
            media_type=f"application/vnd.avo.integration-drill-{kind}+json",
            role=f"integration-drill-{kind}",
            max_bytes=self._max,
        )
        _sync_directory(self._store.path_for_digest(ref.digest).parent)
        key = self._id(record, kind)
        index = self._indexes / kind / f"{key.removeprefix('sha256:')}.json"
        index.parent.mkdir(parents=True, exist_ok=True)
        payload = canonical_bytes(ref)
        try:
            with index.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            _sync_directory(index.parent)
        except FileExistsError:
            try:
                old = ArtifactRef.model_validate(json.loads(index.read_text(encoding="utf-8")))
                old_data = self._store.read_bytes(old)
            except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
                raise DrillJournalError("malformed drill index") from exc
            if old.digest != ref.digest or old_data != data:
                raise DrillRecordConflictError(f"conflicting {kind} record") from None
            return old
        return ref

    def _read(self, kind: str, key: str) -> tuple[Any, ArtifactRef] | None:
        index = self._indexes / kind / f"{key.removeprefix('sha256:')}.json"
        if not index.is_file():
            return None
        try:
            ref = ArtifactRef.model_validate(json.loads(index.read_text(encoding="utf-8")))
            if (
                ref.role != f"integration-drill-{kind}"
                or ref.media_type != f"application/vnd.avo.integration-drill-{kind}+json"
                or ref.size_bytes > self._max
            ):
                raise ValueError("artifact metadata mismatch")
            data = self._store.read_bytes(ref)
            parsed = json.loads(data.decode("utf-8"))
            if canonical_bytes(parsed) != data:
                raise ValueError("noncanonical record")
            record: Any = _MODELS[kind].model_validate(parsed)
        except (
            OSError,
            RuntimeError,
            ValueError,
            TypeError,
            UnicodeError,
            json.JSONDecodeError,
        ) as exc:
            raise DrillJournalError(f"malformed or unverifiable drill {kind}") from exc
        if self._id(record, kind) != key:
            raise DrillRecordConflictError("drill record identity does not match index")
        return record, ref

    def record_plan(self, record: IntegrationDrillPlan) -> ArtifactRef:
        return self._record("plan", record)

    def read_plan(self, operation_id: str) -> tuple[IntegrationDrillPlan, ArtifactRef] | None:
        return self._read("plan", operation_id)

    def record_case_result(self, record: IntegrationDrillCaseResult) -> ArtifactRef:
        return self._record("case", record)

    def read_case_result(
        self, operation_id: str, case_id: int
    ) -> tuple[IntegrationDrillCaseResult, ArtifactRef] | None:
        return self._read("case", f"{operation_id}-{case_id}")

    def record_soak_observation(self, record: IntegrationDrillSoakObservation) -> ArtifactRef:
        return self._record("soak", record)

    def read_soak_observation(
        self, operation_id: str
    ) -> tuple[IntegrationDrillSoakObservation, ArtifactRef] | None:
        return self._read("soak", operation_id)

    def record_rollback_intent(self, record: IntegrationDrillRollbackIntent) -> ArtifactRef:
        return self._record("rollback-intent", record)

    def read_rollback_intent(
        self, operation_id: str
    ) -> tuple[IntegrationDrillRollbackIntent, ArtifactRef] | None:
        return self._read("rollback-intent", operation_id)

    def record_rollback_authorization(
        self, record: IntegrationDrillRollbackAuthorization
    ) -> ArtifactRef:
        return self._record("rollback-authorization", record)

    def read_rollback_authorization(
        self, operation_id: str
    ) -> tuple[IntegrationDrillRollbackAuthorization, ArtifactRef] | None:
        return self._read("rollback-authorization", operation_id)

    def record_rollback_receipt(self, record: IntegrationDrillRollbackReceipt) -> ArtifactRef:
        return self._record("rollback-receipt", record)

    def read_rollback_receipt(
        self, operation_id: str
    ) -> tuple[IntegrationDrillRollbackReceipt, ArtifactRef] | None:
        return self._read("rollback-receipt", operation_id)

    def record_promotion_evidence_manifest(
        self, record: IntegrationDrillPromotionEvidenceManifest
    ) -> ArtifactRef:
        return self._record("promotion-evidence-manifest", record)

    def read_promotion_evidence_manifest(
        self, operation_id: str
    ) -> tuple[IntegrationDrillPromotionEvidenceManifest, ArtifactRef] | None:
        return self._read("promotion-evidence-manifest", operation_id)

    def record_result(self, record: IntegrationDrillResult) -> ArtifactRef:
        return self._record("result", record)

    record_aggregate_result = record_result

    def read_result(self, operation_id: str) -> tuple[IntegrationDrillResult, ArtifactRef] | None:
        return self._read("result", operation_id)

    read_aggregate_result = read_result


def _sync_directory(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        if os.name == "nt" and exc.errno in {
            errno.EINVAL,
            errno.EACCES,
            errno.ENOTSUP,
            errno.EOPNOTSUPP,
        }:
            return
        raise
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


__all__ = ["DrillJournalError", "DrillRecordConflictError", "IntegrationDrillJournal"]
