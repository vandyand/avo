"""Durable content-addressed records for campaign completion recovery."""

from __future__ import annotations

import errno
import json
import os
import re
from pathlib import Path
from typing import TypeVar, cast

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_campaign import (
    CampaignCompletionPlan,
    CampaignFinalEvidenceRecord,
    IntegrationCampaignEvidencePackage,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

RecordT = TypeVar(
    "RecordT",
    CampaignCompletionPlan,
    CampaignFinalEvidenceRecord,
    IntegrationCampaignEvidencePackage,
)
_SHA256_ID = re.compile(r"^sha256:[0-9a-f]{64}$")


class CampaignJournalError(RuntimeError):
    """A campaign record is missing, malformed, or conflicts with history."""


class CampaignCompletionJournal:
    """Atomic operation indexes over immutable plan and package artifacts.

    The plan index is published before provider promotion.  The package index is
    published only after all post-merge checks pass.  Both indexes are
    create-once and therefore make retries idempotent while rejecting tampering.
    """

    def __init__(
        self, root: Path, *, artifact_store: FilesystemArtifactStore | None = None
    ) -> None:
        self._root = root.resolve()
        self._indexes = self._root / "campaign-completion-index"
        self._store = artifact_store or FilesystemArtifactStore(self._root / "artifacts")

    @property
    def root(self) -> Path:
        return self._root

    def record_plan(self, plan: CampaignCompletionPlan) -> ArtifactRef:
        return self._record("plan", plan.operation_id, plan)

    def read_plan(self, operation_id: str) -> tuple[CampaignCompletionPlan, ArtifactRef] | None:
        return self._read("plan", operation_id, CampaignCompletionPlan)

    def list_plan_operations(self) -> tuple[str, ...]:
        """Return every durably indexed plan identity in deterministic order.

        Startup recovery must discover plans without consulting the current
        checkout.  Treat a malformed filename/index as a hard journal error;
        silently skipping it could make a restart select the wrong campaign.
        """
        directory = self._indexes / "plan"
        if not directory.is_dir():
            return ()
        operation_ids: list[str] = []
        for index in sorted(directory.glob("*.json")):
            if index.name != index.name.lower() or len(index.stem) != 64:
                raise CampaignJournalError("campaign plan index identity is malformed")
            operation_id = f"sha256:{index.stem}"
            if any(char not in "0123456789abcdef" for char in index.stem):
                raise CampaignJournalError("campaign plan index identity is malformed")
            loaded = self.read_plan(operation_id)
            if loaded is None:
                raise CampaignJournalError("campaign plan index disappeared during recovery")
            operation_ids.append(operation_id)
        return tuple(operation_ids)

    def record_final_evidence(self, evidence: CampaignFinalEvidenceRecord) -> ArtifactRef:
        return self._record("final-evidence", evidence.operation_id, evidence)

    def read_final_evidence(
        self, operation_id: str
    ) -> tuple[CampaignFinalEvidenceRecord, ArtifactRef] | None:
        return self._read("final-evidence", operation_id, CampaignFinalEvidenceRecord)

    def record_package(self, package: IntegrationCampaignEvidencePackage) -> ArtifactRef:
        return self._record("package", package.intent.operation_id, package)

    def read_package(
        self, operation_id: str
    ) -> tuple[IntegrationCampaignEvidencePackage, ArtifactRef] | None:
        return self._read("package", operation_id, IntegrationCampaignEvidencePackage)

    def _record(self, kind: str, operation_id: str, record: RecordT) -> ArtifactRef:
        _check_operation_id(operation_id)
        try:
            data = canonical_bytes(record)
            if kind == "package":
                # Re-parse the canonical wire form so nested model_construct()
                # instances cannot bypass campaign-package validation.
                record = cast(
                    RecordT,
                    IntegrationCampaignEvidencePackage.model_validate_json(data),
                )
                data = canonical_bytes(record)
                _verify_package_children(
                    cast(IntegrationCampaignEvidencePackage, record), self._store
                )
        except (TypeError, ValueError, OSError) as exc:
            raise CampaignJournalError(f"malformed campaign {kind}") from exc
        reference = self._store.put_bytes(
            data,
            media_type=(
                "application/vnd.avo.integration-campaign-plan+json"
                if kind == "plan"
                else "application/vnd.avo.integration-campaign-final-evidence+json"
                if kind == "final-evidence"
                else "application/vnd.avo.integration-campaign+json"
            ),
            role=f"integration-campaign-{kind}",
            max_bytes=8 * 1024 * 1024,
        )
        # Publish the index only after the content-addressed object directory has
        # been flushed; otherwise a crash can leave a durable index to a missing
        # plan/package object.
        _sync_directory(self._store.path_for_digest(reference.digest).parent)
        index = self._indexes / kind / f"{operation_id.removeprefix('sha256:')}.json"
        index.parent.mkdir(parents=True, exist_ok=True)
        payload = canonical_bytes(reference)
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
                raise CampaignJournalError("campaign record index is malformed") from exc
            if old.digest != reference.digest or old_data != data:
                raise CampaignJournalError(
                    f"conflicting {kind} for operation {operation_id}"
                ) from None
            return old
        except OSError as exc:
            raise CampaignJournalError("campaign record was not durably indexed") from exc
        return reference

    def _read(
        self, kind: str, operation_id: str, model: type[RecordT]
    ) -> tuple[RecordT, ArtifactRef] | None:
        _check_operation_id(operation_id)
        index = self._indexes / kind / f"{operation_id.removeprefix('sha256:')}.json"
        if not index.is_file():
            return None
        try:
            reference = ArtifactRef.model_validate(
                json.loads(index.read_text(encoding="utf-8"), object_pairs_hook=_strict_pairs)
            )
            expected_role = f"integration-campaign-{kind}"
            if reference.role != expected_role:
                raise ValueError("campaign record role does not match index")
            data = self._store.read_bytes(reference)
            raw = json.loads(data.decode("utf-8"), object_pairs_hook=_strict_pairs)
            if canonical_bytes(raw) != data:
                raise ValueError("campaign record is not canonical JSON")
            record = model.model_validate(raw)
            if kind == "package":
                _verify_package_children(
                    cast(IntegrationCampaignEvidencePackage, record), self._store
                )
        except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
            raise CampaignJournalError(f"malformed or unverifiable campaign {kind}") from exc
        if kind == "plan":
            record_id: str = cast(CampaignCompletionPlan, record).operation_id
        elif kind == "final-evidence":
            record_id = cast(CampaignFinalEvidenceRecord, record).operation_id
        else:
            package = cast(IntegrationCampaignEvidencePackage, record)
            record_id = package.intent.operation_id
        if record_id != operation_id:
            raise CampaignJournalError("campaign record operation ID does not match index")
        return record, reference


__all__ = ["CampaignCompletionJournal", "CampaignJournalError"]


def _sync_directory(path: Path) -> None:
    """Flush an index directory where the platform exposes directory fsync."""
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        if os.name == "nt" and exc.errno in {22, 13, 95, errno.ENOTSUP}:
            return
        raise
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _check_operation_id(operation_id: str) -> None:
    if _SHA256_ID.fullmatch(operation_id) is None:
        raise ValueError("operation_id must be a SHA-256 digest")


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _verify_package_children(
    package: IntegrationCampaignEvidencePackage, store: FilesystemArtifactStore
) -> None:
    """Verify every externally referenced campaign child before returning it."""

    lease_reference = package.lease_evidence_artifact
    lease_payload = canonical_bytes(package.lease_evidence)
    if (
        lease_reference.digest != canonical_digest(package.lease_evidence)
        or lease_reference.size_bytes != len(lease_payload)
    ):
        raise ValueError("campaign lease evidence reference is not content-bound")
    if store.read_bytes(lease_reference) != lease_payload:
        raise ValueError("campaign lease evidence is missing or tampered")

    for reference in package.evidence_artifacts:
        data = store.read_bytes(reference)
        raw = json.loads(data.decode("utf-8"), object_pairs_hook=_strict_pairs)
        if canonical_bytes(raw) != data or canonical_digest(raw) != reference.digest:
            raise ValueError("campaign evidence artifact is missing or tampered")
