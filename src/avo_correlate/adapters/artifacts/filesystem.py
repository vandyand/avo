"""Atomic, content-addressed local artifact storage."""

import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from avo_correlate.contracts.base import ArtifactRef


class ArtifactTooLargeError(ValueError):
    pass


class ArtifactIntegrityError(RuntimeError):
    pass


class FilesystemArtifactStore:
    def __init__(self, root: Path) -> None:
        self._root = root.resolve()
        self._objects = self._root / "objects" / "sha256"
        self._temporary = self._root / "temporary"

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
            if destination.exists():
                if self._digest_file(destination) != hex_digest:
                    raise ArtifactIntegrityError(f"existing object failed verification: {digest}")
                temporary.unlink()
            else:
                os.replace(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
        return ArtifactRef(
            digest=digest,
            size_bytes=len(data),
            media_type=media_type,
            role=role,
            created_at=datetime.now(UTC),
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
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()
