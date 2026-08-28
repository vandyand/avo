"""Create-once durable storage for live rollback evidence packages."""

from __future__ import annotations

import errno
import json
import os
from pathlib import Path

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_live_rollback import LiveRollbackEvidencePackage
from avo_correlate.domain.canonical import canonical_bytes


class LiveRollbackJournalError(RuntimeError):
    """A live rollback package is missing, malformed, or conflicting."""


class LiveRollbackJournal:
    """Atomically index one immutable package per rollback operation."""

    def __init__(
        self,
        root: Path,
        *,
        artifact_store: FilesystemArtifactStore | None = None,
        max_package_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        if max_package_bytes <= 0:
            raise ValueError("max_package_bytes must be positive")
        self._root = root.resolve()
        self._indexes = self._root / "live-rollback-index"
        self._store = artifact_store or FilesystemArtifactStore(self._root / "artifacts")
        self._max = max_package_bytes

    @property
    def root(self) -> Path:
        return self._root

    def record_package(self, package: LiveRollbackEvidencePackage) -> ArtifactRef:
        data = canonical_bytes(package)
        reference = self._store.put_bytes(
            data,
            media_type="application/vnd.avo.integration-live-rollback+json",
            role="integration-live-rollback-package",
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
                raise LiveRollbackJournalError("live rollback package is unreadable") from exc
            if old.digest != reference.digest or old_data != data:
                raise LiveRollbackJournalError(
                    f"conflicting live rollback package for {package.operation_id}"
                ) from None
            return old
        except OSError as exc:
            raise LiveRollbackJournalError("live rollback package was not durably indexed") from exc
        return reference

    def read_package(
        self, operation_id: str
    ) -> tuple[LiveRollbackEvidencePackage, ArtifactRef] | None:
        _check_digest(operation_id)
        index = self._indexes / "package" / f"{operation_id.removeprefix('sha256:')}.json"
        if not index.is_file():
            return None
        try:
            reference = self._read_reference(index)
            if (
                reference.role != "integration-live-rollback-package"
                or reference.media_type != "application/vnd.avo.integration-live-rollback+json"
                or reference.size_bytes > self._max
            ):
                raise ValueError("live rollback package metadata mismatch")
            data = self._store.read_bytes(reference)
            parsed = json.loads(data.decode("utf-8"))
            if canonical_bytes(parsed) != data:
                raise ValueError("live rollback package is not canonical JSON")
            package = LiveRollbackEvidencePackage.model_validate(parsed)
        except (
            OSError,
            RuntimeError,
            ValueError,
            TypeError,
            UnicodeError,
            json.JSONDecodeError,
        ) as exc:
            raise LiveRollbackJournalError(
                "malformed or unverifiable live rollback package"
            ) from exc
        if package.operation_id != operation_id:
            raise LiveRollbackJournalError("live rollback package identity does not match index")
        return package, reference

    def list_operations(self) -> tuple[str, ...]:
        directory = self._indexes / "package"
        if not directory.is_dir():
            return ()
        operations: list[str] = []
        for index in sorted(directory.glob("*.json")):
            if len(index.stem) != 64 or index.stem != index.stem.lower():
                raise LiveRollbackJournalError("live rollback package index identity is malformed")
            operation_id = f"sha256:{index.stem}"
            _check_digest(operation_id)
            loaded = self.read_package(operation_id)
            if loaded is None:
                raise LiveRollbackJournalError("live rollback package index disappeared")
            operations.append(operation_id)
        return tuple(operations)

    def _read_reference(self, index: Path) -> ArtifactRef:
        try:
            if index.stat().st_size > self._max:
                raise ValueError("live rollback package index is too large")
            return ArtifactRef.model_validate(json.loads(index.read_text(encoding="utf-8")))
        except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
            raise LiveRollbackJournalError("live rollback package index is malformed") from exc


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


__all__ = ["LiveRollbackJournal", "LiveRollbackJournalError"]
