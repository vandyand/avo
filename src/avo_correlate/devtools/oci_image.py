"""Fail-closed verification of reviewed OCI images for local Docker execution.

An OCI manifest digest is evidence about the image that was reviewed.  Docker's
local image ID is a config digest and is a different namespace.  This module
checks the former and returns the latter only as an execution reference.
"""

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class ImageVerificationError(RuntimeError):
    """Raised when an image cannot be tied to the reviewed OCI manifest."""


@dataclass(frozen=True, slots=True)
class VerifiedImageReference:
    """The reviewed evidence digest and the immutable local Docker reference."""

    reviewed_manifest: str
    execution_reference: str


def resolve_verified_image(
    image: str,
    expected_manifest: str,
    *,
    metadata_file: Path | str | None = None,
    docker_executable: str = "docker",
) -> VerifiedImageReference:
    """Verify ``image`` and return its local config ID for Docker execution.

    Without BuildKit metadata, a local Docker image must expose exactly one
    RepoDigest and it must match ``expected_manifest``.  When ``metadata_file``
    is supplied, its ``containerimage.digest`` must match instead; any
    RepoDigest reported by Docker is still checked for conflicts.  Neither
    source is inferred from candidate-controlled input.
    """

    _require_digest(expected_manifest, "expected reviewed manifest")
    if not image.strip():
        raise ImageVerificationError("image reference is empty")

    try:
        completed = subprocess.run(
            [docker_executable, "image", "inspect", image, "--format", "{{json .}}"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
            check=False,
            shell=False,
        )
    except OSError as exc:
        raise ImageVerificationError(f"cannot execute docker image inspect for {image!r}") from exc
    if completed.returncode:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        suffix = f": {detail}" if detail else ""
        raise ImageVerificationError(
            f"docker image inspect failed for {image!r} (exit {completed.returncode}){suffix}"
        )

    inspected = _parse_json_object(completed.stdout, "docker inspect output")
    execution_reference = inspected.get("Id")
    if not isinstance(execution_reference, str) or not _DIGEST_RE.fullmatch(
        execution_reference
    ):
        raise ImageVerificationError("docker inspect returned no valid immutable image ID")

    repo_digests = _repo_digests(inspected.get("RepoDigests"))
    if metadata_file is not None:
        metadata_manifest = _read_buildkit_manifest(Path(metadata_file))
        if metadata_manifest != expected_manifest:
            raise ImageVerificationError(
                "BuildKit metadata manifest "
                f"{metadata_manifest} does not match reviewed manifest {expected_manifest}"
            )
        if repo_digests and set(repo_digests) != {expected_manifest}:
            raise ImageVerificationError("Docker RepoDigests conflict with BuildKit metadata")
    else:
        unique_repo_digests = set(repo_digests)
        if len(unique_repo_digests) != 1:
            reason = "missing" if not repo_digests else "ambiguous"
            raise ImageVerificationError(f"{reason} RepoDigest evidence")
        if unique_repo_digests != {expected_manifest}:
            raise ImageVerificationError("Docker RepoDigest does not match the reviewed manifest")

    return VerifiedImageReference(
        reviewed_manifest=expected_manifest,
        execution_reference=execution_reference,
    )


def _repo_digests(value: object) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ImageVerificationError("docker inspect returned malformed RepoDigests")
    digests: list[str] = []
    for item in cast(list[object], value):
        if not isinstance(item, str):
            raise ImageVerificationError("docker inspect returned malformed RepoDigests")
        repository, separator, digest = item.rpartition("@")
        if not separator or not repository or not _DIGEST_RE.fullmatch(digest):
            raise ImageVerificationError("docker inspect returned malformed RepoDigest")
        digests.append(digest)
    return digests


def _read_buildkit_manifest(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ImageVerificationError(f"cannot read BuildKit metadata file: {path}") from exc
    metadata = _parse_json_object(raw, "BuildKit metadata")
    digest = metadata.get("containerimage.digest")
    if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
        raise ImageVerificationError("BuildKit metadata lacks a valid containerimage.digest")
    return digest


def _parse_json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise ImageVerificationError(f"malformed {label}") from exc
    if not isinstance(parsed, dict):
        raise ImageVerificationError(f"{label} must be a JSON object")
    return cast(dict[str, Any], parsed)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _require_digest(value: str, label: str) -> None:
    if not _DIGEST_RE.fullmatch(value):
        raise ImageVerificationError(f"{label} is not a valid sha256 digest")
