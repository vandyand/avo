"""Create-once content-addressed journal for protected-main graduation."""

from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
from typing import Any, cast

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.contracts.base import ArtifactRef, StrictModel
from avo_correlate.contracts.main_graduation import (
    EligibilityLedgerStarted,
    MainAttestationManifest,
    MainCompletionPackage,
    MainCompositionArtifact,
    MainDeltaManifest,
    MainGraduationAttempt,
    MainGraduationEligibilityRecord,
    MainGraduationIntent,
    MainGraduationPlan,
    MainMergeGroupChecks,
    MainPreparationAuthorization,
    MainProtectionManifest,
    MainProviderReceipt,
    MainQueueAdmissionObservation,
    MainQueueObservation,
    MainReconciliation,
    MainReleaseAuthorization,
    MainReleaseHoldObservation,
    MainReleaseTransitionReceipt,
    MainRollbackAuthorization,
    MainRollbackIntent,
    MainSourcePackageBinding,
)
from avo_correlate.domain.canonical import canonical_bytes


class MainGraduationJournalError(RuntimeError):
    """An indexed record is missing, malformed, tampered, or conflicting."""


class MainGraduationRecordConflictError(MainGraduationJournalError):
    """A create-once key was already bound to different canonical bytes."""


_MODELS: dict[str, type[StrictModel]] = {
    "ledger-started": EligibilityLedgerStarted,
    "plan": MainGraduationPlan,
    "source-package": MainSourcePackageBinding,
    "delta": MainDeltaManifest,
    "composition": MainCompositionArtifact,
    "queue": MainQueueObservation,
    "protection": MainProtectionManifest,
    "attestations": MainAttestationManifest,
    "merge-group-checks": MainMergeGroupChecks,
    "intent": MainGraduationIntent,
    "preparation-authorization": MainPreparationAuthorization,
    "queue-admission": MainQueueAdmissionObservation,
    "release-hold": MainReleaseHoldObservation,
    "release-authorization": MainReleaseAuthorization,
    "release-transition": MainReleaseTransitionReceipt,
    "provider-receipt": MainProviderReceipt,
    "reconciliation": MainReconciliation,
    "rollback-authorization": MainRollbackAuthorization,
    "rollback-intent": MainRollbackIntent,
    "attempt": MainGraduationAttempt,
    "eligibility": MainGraduationEligibilityRecord,
    "completion": MainCompletionPackage,
}


def _digest_bytes(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _operation_id(record: Any) -> str:
    value = getattr(record, "operation_id", None)
    if value is None:
        value = getattr(record, "activation_digest", None)
    if value is None:
        value = getattr(record, "submission_digest", None)
    if value is None:
        raise ValueError("main graduation record lacks a SHA-256 operation identity")
    if len(value) != 71 or not _is_digest(value):
        raise ValueError("main graduation record lacks a SHA-256 operation identity")
    return value


def _is_digest(value: str) -> bool:
    return value.startswith("sha256:") and all(char in "0123456789abcdef" for char in value[7:])


def _check_digest(value: str) -> None:
    if len(value) != 71 or not _is_digest(value):
        raise ValueError("journal key must be a SHA-256 digest")


class MainGraduationJournal:
    """Persist one canonical record per operation/ledger key using ``xb`` indexes."""

    def __init__(
        self,
        root: Path,
        *,
        artifact_store: FilesystemArtifactStore | None = None,
        max_record_bytes: int = 32 * 1024 * 1024,
    ) -> None:
        if max_record_bytes <= 0:
            raise ValueError("max_record_bytes must be positive")
        self._root = root.resolve()
        self._indexes = self._root / "main-graduation-index"
        self._store = artifact_store or FilesystemArtifactStore(self._root / "artifacts")
        self._max = max_record_bytes

    @property
    def root(self) -> Path:
        return self._root

    def delete_artifact(self, digest: str) -> bool:
        """Recovery/test seam; indexed reads still fail closed after deletion."""
        return self._store.delete(digest)

    def _record(self, kind: str, record: StrictModel) -> ArtifactRef:
        model = _MODELS.get(kind)
        if model is None:
            raise ValueError(f"unknown main graduation record kind: {kind}")
        try:
            data = canonical_bytes(record)
            # Reparse to ensure nested model_construct() values cannot bypass
            # semantic validators at the journal boundary.
            checked = model.model_validate_json(data)
            data = canonical_bytes(checked)
            operation_id = _operation_id(checked)
            if kind == "completion":
                self._materialize_children(cast(MainCompletionPackage, checked))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise MainGraduationJournalError(f"invalid main graduation {kind}") from exc
        reference = self._store.put_bytes(
            data,
            media_type=f"application/vnd.avo.main-graduation-{kind}+json",
            role=f"main-graduation-{kind}",
            max_bytes=self._max,
        )
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
                old = self._read_reference(index)
                old_data = self._store.read_bytes(old)
            except (OSError, ValueError, RuntimeError, TypeError, json.JSONDecodeError) as exc:
                raise MainGraduationJournalError("main graduation index is malformed") from exc
            if old.digest != reference.digest or old_data != data:
                raise MainGraduationRecordConflictError(
                    f"conflicting main graduation {kind} for {operation_id}"
                ) from None
            return old
        except OSError as exc:
            raise MainGraduationJournalError("main graduation record was not indexed") from exc
        return reference

    def _read_reference(self, index: Path) -> ArtifactRef:
        try:
            if index.stat().st_size > self._max:
                raise ValueError("main graduation index is too large")
            return ArtifactRef.model_validate(json.loads(index.read_text(encoding="utf-8")))
        except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
            raise MainGraduationJournalError("main graduation index is malformed") from exc

    def _read(self, kind: str, key: str) -> tuple[StrictModel, ArtifactRef] | None:
        _check_digest(key)
        index = self._indexes / kind / f"{key.removeprefix('sha256:')}.json"
        if not index.is_file():
            return None
        try:
            reference = self._read_reference(index)
            if (
                reference.role != f"main-graduation-{kind}"
                or reference.media_type != f"application/vnd.avo.main-graduation-{kind}+json"
                or reference.size_bytes > self._max
            ):
                raise ValueError("main graduation artifact metadata mismatch")
            data = self._store.read_bytes(reference)
            parsed = json.loads(data.decode("utf-8"))
            if canonical_bytes(parsed) != data:
                raise ValueError("main graduation record is not canonical JSON")
            record = _MODELS[kind].model_validate(parsed)
            if kind == "completion":
                self._verify_children(cast(MainCompletionPackage, record))
            if _operation_id(record) != key:
                raise MainGraduationRecordConflictError(
                    "main graduation identity does not match index"
                )
            return record, reference
        except MainGraduationRecordConflictError:
            raise
        except (
            OSError,
            RuntimeError,
            ValueError,
            TypeError,
            UnicodeError,
            json.JSONDecodeError,
        ) as exc:
            raise MainGraduationJournalError(
                f"malformed or unverifiable main graduation {kind}"
            ) from exc

    @staticmethod
    def _child_values(package: MainCompletionPackage) -> dict[str, StrictModel]:
        return {
            "main-graduation-plan": package.plan,
            "main-graduation-intent": package.intent,
            "main-graduation-preparation-authorization": package.preparation_authorization,
            "main-graduation-queue-admission": package.admission_observation,
            "main-graduation-release-hold": package.hold_observation,
            "main-graduation-release-authorization": package.release_authorization,
            "main-graduation-release-transition": package.transition_receipt,
            "main-graduation-provider-receipt": package.provider_receipt,
            "main-graduation-reconciliation": package.reconciliation,
        }

    def _materialize_children(self, package: MainCompletionPackage) -> None:
        references = {item.role: item for item in package.artifacts}
        values = self._child_values(package)
        if set(references) != set(values):
            raise MainGraduationJournalError("completion child artifacts are incomplete")
        for role, value in values.items():
            expected = references[role]
            payload = canonical_bytes(value)
            if (
                expected.role != role
                or expected.media_type != f"application/vnd.avo.{role}+json"
                or expected.digest != _digest_bytes(payload)
                or expected.size_bytes != len(payload)
            ):
                raise MainGraduationJournalError(
                    f"completion child artifact is not content-bound: {role}"
                )
            stored = self._store.put_bytes(
                payload,
                media_type=expected.media_type,
                role=expected.role,
                max_bytes=self._max,
            )
            try:
                read_back = self._store.read_bytes(expected)
            except (OSError, RuntimeError, ValueError) as exc:
                raise MainGraduationJournalError(
                    f"completion child artifact is unreadable: {role}"
                ) from exc
            if (
                stored.digest != expected.digest
                or stored.role != role
                or stored.media_type != expected.media_type
                or read_back != payload
            ):
                raise MainGraduationJournalError(
                    f"completion child artifact metadata mismatch: {role}"
                )

    def _verify_children(self, package: MainCompletionPackage) -> None:
        references = {item.role: item for item in package.artifacts}
        values = self._child_values(package)
        if set(references) != set(values):
            raise MainGraduationJournalError("completion child artifacts are incomplete")
        for role, value in values.items():
            expected = references[role]
            if expected.role != role or expected.media_type != f"application/vnd.avo.{role}+json":
                raise MainGraduationJournalError(
                    f"completion child artifact metadata mismatch: {role}"
                )
            try:
                data = self._store.read_bytes(expected)
            except (OSError, RuntimeError, ValueError) as exc:
                raise MainGraduationJournalError(
                    f"completion child artifact is unreadable: {role}"
                ) from exc
            if data != canonical_bytes(value) or expected.digest != _digest_bytes(data):
                raise MainGraduationJournalError(
                    f"completion child artifact contents mismatch: {role}"
                )

    def record(self, kind: str, record: StrictModel) -> ArtifactRef:
        return self._record(kind, record)

    def read(self, kind: str, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read(kind, operation_id)

    def record_ledger_started(self, record: EligibilityLedgerStarted) -> ArtifactRef:
        return self._record("ledger-started", record)

    def read_ledger_started(self, activation_digest: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("ledger-started", activation_digest)

    def record_plan(self, record: MainGraduationPlan) -> ArtifactRef:
        return self._record("plan", record)

    def read_plan(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("plan", operation_id)

    def record_source_package(self, record: MainSourcePackageBinding) -> ArtifactRef:
        return self._record("source-package", record)

    def read_source_package(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("source-package", operation_id)

    def record_delta(self, record: MainDeltaManifest) -> ArtifactRef:
        return self._record("delta", record)

    def read_delta(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("delta", operation_id)

    def record_composition(self, record: MainCompositionArtifact) -> ArtifactRef:
        return self._record("composition", record)

    def read_composition(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("composition", operation_id)

    def record_queue_observation(self, record: MainQueueObservation) -> ArtifactRef:
        return self._record("queue", record)

    def read_queue_observation(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("queue", operation_id)

    def record_protection_manifest(self, record: MainProtectionManifest) -> ArtifactRef:
        return self._record("protection", record)

    def read_protection_manifest(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("protection", operation_id)

    def record_attestation_manifest(self, record: MainAttestationManifest) -> ArtifactRef:
        return self._record("attestations", record)

    def read_attestation_manifest(
        self, operation_id: str
    ) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("attestations", operation_id)

    def record_merge_group_checks(self, record: MainMergeGroupChecks) -> ArtifactRef:
        return self._record("merge-group-checks", record)

    def read_merge_group_checks(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("merge-group-checks", operation_id)

    def record_intent(self, record: MainGraduationIntent) -> ArtifactRef:
        return self._record("intent", record)

    def read_intent(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("intent", operation_id)

    def record_preparation_authorization(self, record: MainPreparationAuthorization) -> ArtifactRef:
        return self._record("preparation-authorization", record)

    def read_preparation_authorization(
        self, operation_id: str
    ) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("preparation-authorization", operation_id)

    def record_queue_admission(self, record: MainQueueAdmissionObservation) -> ArtifactRef:
        return self._record("queue-admission", record)

    def read_queue_admission(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("queue-admission", operation_id)

    def record_release_hold(self, record: MainReleaseHoldObservation) -> ArtifactRef:
        return self._record("release-hold", record)

    def read_release_hold(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("release-hold", operation_id)

    def record_release_authorization(self, record: MainReleaseAuthorization) -> ArtifactRef:
        return self._record("release-authorization", record)

    def read_release_authorization(
        self, operation_id: str
    ) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("release-authorization", operation_id)

    def record_release_transition(self, record: MainReleaseTransitionReceipt) -> ArtifactRef:
        return self._record("release-transition", record)

    def read_release_transition(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("release-transition", operation_id)

    def record_provider_receipt(self, record: MainProviderReceipt) -> ArtifactRef:
        return self._record("provider-receipt", record)

    def read_provider_receipt(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("provider-receipt", operation_id)

    def record_reconciliation(self, record: MainReconciliation) -> ArtifactRef:
        return self._record("reconciliation", record)

    def read_reconciliation(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("reconciliation", operation_id)

    def record_rollback_authorization(self, record: MainRollbackAuthorization) -> ArtifactRef:
        return self._record("rollback-authorization", record)

    def read_rollback_authorization(
        self, operation_id: str
    ) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("rollback-authorization", operation_id)

    def record_rollback_intent(self, record: MainRollbackIntent) -> ArtifactRef:
        return self._record("rollback-intent", record)

    def read_rollback_intent(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("rollback-intent", operation_id)

    def record_attempt(self, record: MainGraduationAttempt) -> ArtifactRef:
        return self._record("attempt", record)

    def read_attempt(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("attempt", operation_id)

    def record_eligibility(self, record: MainGraduationEligibilityRecord) -> ArtifactRef:
        return self._record("eligibility", record)

    def read_eligibility(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("eligibility", operation_id)

    def record_completion(self, record: MainCompletionPackage) -> ArtifactRef:
        return self._record("completion", record)

    def read_completion(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("completion", operation_id)

    record_package = record_completion
    read_package = read_completion


def _sync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
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
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "MainGraduationJournal",
    "MainGraduationJournalError",
    "MainGraduationRecordConflictError",
]
