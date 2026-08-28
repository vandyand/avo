"""Atomic, content-addressed local artifact storage."""

import hashlib
import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from avo_correlate.contracts.base import ArtifactRef

_MAX_INSTALL_RACE_ATTEMPTS = 8


class ArtifactTooLargeError(ValueError):
    pass


class ArtifactIntegrityError(RuntimeError):
    pass


class FilesystemArtifactStore:
    def __init__(self, root: Path, *, clock: Callable[[], datetime] | None = None) -> None:
        self._root = root.resolve()
        self._objects = self._root / "objects" / "sha256"
        self._temporary = self._root / "temporary"
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def root(self) -> Path:
        """The storage root used for controller isolation checks."""

        return self._root

    def put_bytes(
        self,
        data: bytes,
        *,
        media_type: str,
        role: str,
        max_bytes: int,
    ) -> ArtifactRef:
        self._objects.mkdir(parents=True, exist_ok=True)
        self._temporary.mkdir(parents=True, exist_ok=True)
        if len(data) > max_bytes:
            raise ArtifactTooLargeError(f"artifact exceeds {max_bytes} bytes")
        hex_digest = hashlib.sha256(data).hexdigest()
        digest = f"sha256:{hex_digest}"
        destination = self._path_for_hex(hex_digest)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = self._temporary / f"{uuid4()}.partial"
        try:
            with temporary.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            _install_or_reuse(destination, temporary, hex_digest, digest)
        finally:
            temporary.unlink(missing_ok=True)
        return ArtifactRef(
            digest=digest,
            size_bytes=len(data),
            media_type=media_type,
            role=role,
            created_at=self._clock(),
        )

    def read_bytes(self, reference: ArtifactRef, *, verify: bool = True) -> bytes:
        hex_digest = reference.digest.removeprefix("sha256:")
        path = self._path_for_hex(hex_digest)
        data = path.read_bytes()
        if len(data) != reference.size_bytes:
            raise ArtifactIntegrityError(f"artifact size mismatch: {reference.digest}")
        if verify and hashlib.sha256(data).hexdigest() != hex_digest:
            raise ArtifactIntegrityError(f"artifact digest mismatch: {reference.digest}")
        return data

    def exists(self, digest: str) -> bool:
        return self._path_for_hex(digest.removeprefix("sha256:")).is_file()

    def path_for_digest(self, digest: str) -> Path:
        return self._path_for_hex(digest.removeprefix("sha256:"))

    def delete(self, digest: str) -> bool:
        path = self.path_for_digest(digest)
        if not path.exists():
            return False
        path.unlink()
        return True

    def cleanup_temporary(self) -> int:
        removed = 0
        for path in self._temporary.glob("*.partial"):
            path.unlink(missing_ok=True)
            removed += 1
        return removed

    def _path_for_hex(self, hex_digest: str) -> Path:
        if len(hex_digest) != 64 or any(char not in "0123456789abcdef" for char in hex_digest):
            raise ValueError("invalid SHA-256 digest")
        return self._objects / hex_digest[:2] / hex_digest[2:]

    @staticmethod
    def _digest_file(path: Path) -> str:
        return _compute_digest(path)


def _install_or_reuse(
    destination: Path, temporary: Path, hex_digest: str, digest: str
) -> None:
    """Install one object or verify the winner of a same-digest race.

    Windows can report ``PermissionError`` when a concurrent writer wins the
    destination rename.  A bounded verify-after-race loop makes insertion
    idempotent without sleeping or treating a partial winner as valid.
    """
    last_error: OSError | ArtifactIntegrityError | None = None
    for _ in range(_MAX_INSTALL_RACE_ATTEMPTS):
        if destination.exists():
            try:
                actual = _compute_digest(destination)
            except OSError as exc:
                last_error = exc
                continue
            if actual == hex_digest:
                temporary.unlink(missing_ok=True)
                return
            last_error = ArtifactIntegrityError(
                f"existing object failed verification: {digest}"
            )
            continue
        try:
            os.replace(temporary, destination)
            return
        except (FileExistsError, PermissionError) as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise ArtifactIntegrityError(f"object could not be installed: {digest}")


def _compute_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()
