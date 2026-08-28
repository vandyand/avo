"""Create-once durable journal for hosted-live rollback completion packages."""

from __future__ import annotations

import errno
import json
import os
from pathlib import Path

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_live_rollback_completion import (
    LiveRollbackCompletionPackage,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest


class LiveRollbackCompletionJournalError(RuntimeError):
    """A completion package is missing, malformed, or conflicting."""


class LiveRollbackCompletionJournal:
    """Atomically index one immutable completion per rollback operation."""

    def __init__(
        self,
        root: Path,
        *,
        artifact_store: FilesystemArtifactStore | None = None,
        max_package_bytes: int = 32 * 1024 * 1024,
    ) -> None:
        if max_package_bytes <= 0:
            raise ValueError("max_package_bytes must be positive")
        self._root = root.resolve()
        self._indexes = self._root / "live-rollback-completion-index"
        self._store = artifact_store or FilesystemArtifactStore(self._root / "artifacts")
        self._max = max_package_bytes

    def record_package(self, package: LiveRollbackCompletionPackage) -> ArtifactRef:
        if package.cleanup_outcome.outcome != "cleaned":
            raise LiveRollbackCompletionJournalError(
                "completion cannot be indexed before durable cleanup"
            )
        data = canonical_bytes(package)
        self._materialize_children(package)
        reference = self._store.put_bytes(
            data,
            media_type="application/vnd.avo.integration-live-rollback-completion+json",
            role="integration-live-rollback-completion-package",
            max_bytes=self._max,
        )
        _sync_directory(self._store.path_for_digest(reference.digest).parent)
        index = self._indexes / "package" / f"{package.operation_id.removeprefix('sha256:')}.json"
        index.parent.mkdir(parents=True, exist_ok=True)
        try:
            with index.open("xb") as handle:
                handle.write(canonical_bytes(reference))
                handle.flush()
                os.fsync(handle.fileno())
            _sync_directory(index.parent)
        except FileExistsError:
            old = self._read_reference(index)
            try:
                old_data = self._store.read_bytes(old)
            except (OSError, ValueError, RuntimeError) as exc:
                raise LiveRollbackCompletionJournalError(
                    "live rollback completion package is unreadable"
                ) from exc
            if old.digest != reference.digest or old_data != data:
                raise LiveRollbackCompletionJournalError(
                    f"conflicting live rollback completion for {package.operation_id}; "
                    "unreachable object retained for forensic reconciliation"
                ) from None
            return old
        except OSError as exc:
            raise LiveRollbackCompletionJournalError(
                "live rollback completion was not durably indexed"
            ) from exc
        return reference

    def _materialize_children(self, package: LiveRollbackCompletionPackage) -> None:
        """Install and read back every child named by the outer package.

        A digest in a package is not evidence that its object exists.  Child
        records are therefore installed in this journal's store before the
        outer index can become visible.  ``put_bytes`` also verifies an
        existing same-digest object, so a corrupt object fails closed.
        """

        values: dict[str, object] = {
            "integration-live-rollback-package": package.core_package,
            "candidate-publication-plan": package.publication_plan,
            "candidate-publication-outcome": package.publication_outcome,
            "candidate-publication-evidence": package.publication_evidence,
            "integration-provider-observation": package.provider_observation,
            "integration-provider-reconciliation": package.provider_reconciliation,
            "trusted-check-manifest": package.check_manifest,
            "protection-manifest": package.protection_manifest,
            "workflow-evidence": package.workflow_evidence,
            "synthetic-validation-plan": package.validation_plan,
            "synthetic-validation-authorization": package.validation_authorization,
            "synthetic-validation-outcome": package.validation_outcome,
            "synthetic-validation-cleanup-proof": package.cleanup_proof,
            "synthetic-validation-cleanup": package.cleanup_outcome,
        }
        references = {reference.role: reference for reference in package.artifacts}
        if set(references) != set(values):
            raise LiveRollbackCompletionJournalError("completion child artifacts are incomplete")
        for role, value in values.items():
            expected = references[role]
            payload = canonical_bytes(value)
            if (
                expected.digest != canonical_digest(value)
                or expected.size_bytes != len(payload)
            ):
                raise LiveRollbackCompletionJournalError(
                    f"completion child artifact is not content-bound: {role}"
                )
            try:
                stored = self._store.put_bytes(
                    payload,
                    media_type=expected.media_type,
                    role=expected.role,
                    max_bytes=self._max,
                )
                read_back = self._store.read_bytes(expected)
            except (OSError, RuntimeError, ValueError) as exc:
                raise LiveRollbackCompletionJournalError(
                    f"completion child artifact is missing or tampered: {role}"
                ) from exc
            if (
                stored.digest != expected.digest
                or stored.role != expected.role
                or stored.media_type != expected.media_type
                or stored.size_bytes != expected.size_bytes
                or read_back != payload
            ):
                raise LiveRollbackCompletionJournalError(
                    f"completion child artifact metadata or contents mismatch: {role}"
                )
        self._verify_children(package)

    def _verify_children(self, package: LiveRollbackCompletionPackage) -> None:
        values = self._child_values(package)
        references = {reference.role: reference for reference in package.artifacts}
        if set(references) != set(values):
            raise LiveRollbackCompletionJournalError("completion child artifacts are incomplete")
        for role, value in values.items():
            expected = references[role]
            try:
                payload = self._store.read_bytes(expected)
            except (OSError, RuntimeError, ValueError) as exc:
                raise LiveRollbackCompletionJournalError(
                    f"completion child artifact is missing or tampered: {role}"
                ) from exc
            if payload != canonical_bytes(value) or canonical_digest(value) != expected.digest:
                raise LiveRollbackCompletionJournalError(
                    f"completion child artifact contents mismatch: {role}"
                )

    @staticmethod
    def _child_values(package: LiveRollbackCompletionPackage) -> dict[str, object]:
        return {
            "integration-live-rollback-package": package.core_package,
            "candidate-publication-plan": package.publication_plan,
            "candidate-publication-outcome": package.publication_outcome,
            "candidate-publication-evidence": package.publication_evidence,
            "integration-provider-observation": package.provider_observation,
            "integration-provider-reconciliation": package.provider_reconciliation,
            "trusted-check-manifest": package.check_manifest,
            "protection-manifest": package.protection_manifest,
            "workflow-evidence": package.workflow_evidence,
            "synthetic-validation-plan": package.validation_plan,
            "synthetic-validation-authorization": package.validation_authorization,
            "synthetic-validation-outcome": package.validation_outcome,
            "synthetic-validation-cleanup-proof": package.cleanup_proof,
            "synthetic-validation-cleanup": package.cleanup_outcome,
        }

    def read_package(
        self, operation_id: str
    ) -> tuple[LiveRollbackCompletionPackage, ArtifactRef] | None:
        _check_digest(operation_id)
        index = self._indexes / "package" / f"{operation_id.removeprefix('sha256:')}.json"
        if not index.is_file():
            return None
        try:
            reference = self._read_reference(index)
            if (
                reference.role != "integration-live-rollback-completion-package"
                or reference.media_type
                != "application/vnd.avo.integration-live-rollback-completion+json"
                or reference.size_bytes > self._max
            ):
                raise ValueError("live completion package metadata mismatch")
            data = self._store.read_bytes(reference)
            parsed = json.loads(data.decode("utf-8"))
            if canonical_bytes(parsed) != data:
                raise ValueError("live completion package is not canonical JSON")
            package = LiveRollbackCompletionPackage.model_validate(parsed)
            self._verify_children(package)
        except (
            OSError,
            RuntimeError,
            ValueError,
            TypeError,
            UnicodeError,
            json.JSONDecodeError,
        ) as exc:
            raise LiveRollbackCompletionJournalError(
                "malformed or unverifiable live completion package"
            ) from exc
        if package.operation_id != operation_id:
            raise LiveRollbackCompletionJournalError(
                "live completion identity does not match index"
            )
        return package, reference

    def _read_reference(self, index: Path) -> ArtifactRef:
        try:
            if index.stat().st_size > self._max:
                raise ValueError("live completion index is too large")
            return ArtifactRef.model_validate(json.loads(index.read_text(encoding="utf-8")))
        except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
            raise LiveRollbackCompletionJournalError("live completion index is malformed") from exc


def _check_digest(value: str) -> None:
    if (
        len(value) != 71
        or not value.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in value[7:])
    ):
        raise ValueError("operation_id must be a SHA-256 digest")


def _sync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        if os.name == "nt" and exc.errno in {errno.EINVAL, errno.EACCES, errno.ENOTSUP}:
            return
        raise
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = ["LiveRollbackCompletionJournal", "LiveRollbackCompletionJournalError"]
