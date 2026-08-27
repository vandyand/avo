"""Fail-closed verification of reviewed OCI images for local Docker execution.

An OCI manifest digest is evidence about the image that was reviewed. Docker
engines expose either that manifest or its config digest as the local image ID.
This module binds both namespaces and returns the engine-local ID only as an
execution reference.
"""

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_DOCKER_SCHEMA2_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v2+json"


class ImageVerificationError(RuntimeError):
    """Raised when an image cannot be tied to the reviewed OCI manifest."""


@dataclass(frozen=True, slots=True)
class VerifiedImageReference:
    """Reviewed equivalence target and immutable local Docker reference.

    ``reviewed_manifest`` remains the pre-reviewed target used by the existing
    evaluation schema. ``verified_digest`` and ``verification_basis`` identify
    what this local inspection directly established. A config basis proves
    executable content equivalence, not exact manifest serialization.
    """

    reviewed_manifest: str
    execution_reference: str
    verified_digest: str
    verification_basis: Literal["manifest", "config"]


def resolve_verified_image(
    image: str,
    expected_manifest: str,
    expected_config: str,
    *,
    metadata_file: Path | str | None = None,
    docker_executable: str = "docker",
) -> VerifiedImageReference:
    """Verify ``image`` and return its immutable local ID for Docker execution.

    Without BuildKit metadata, a local Docker image must expose exactly one
    RepoDigest and it must match ``expected_manifest``. When ``metadata_file``
    is supplied, its digest may identify either reviewed manifest or expected
    config, with the config exporter requiring its explicit config digest.
    Neither source is inferred from candidate-controlled input.
    """

    _require_digest(expected_manifest, "expected reviewed manifest")
    _require_digest(expected_config, "expected image config")
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
    if not isinstance(execution_reference, str) or execution_reference not in {
        expected_manifest,
        expected_config,
    }:
        raise ImageVerificationError("docker inspect returned no valid immutable image ID")

    _validate_descriptor(inspected.get("Descriptor"), expected_manifest, expected_config)
    repo_digests = _repo_digests(inspected.get("RepoDigests"))
    verification_basis: Literal["manifest", "config"]
    verified_digest: str
    if metadata_file is not None:
        if any(digest != expected_manifest for digest in repo_digests):
            raise ImageVerificationError("Docker RepoDigest conflicts with reviewed manifest")
        metadata_digest, metadata_config = _read_buildkit_metadata(
            Path(metadata_file), expected_config
        )
        if metadata_config is not None and metadata_config != expected_config:
            raise ImageVerificationError("BuildKit metadata config does not match expected config")
        if metadata_digest == expected_manifest:
            verification_basis = "manifest"
            verified_digest = expected_manifest
        elif metadata_digest == expected_config:
            if metadata_config != expected_config or execution_reference != expected_config:
                raise ImageVerificationError(
                    "config-only BuildKit metadata lacks expected config evidence"
                )
            verification_basis = "config"
            verified_digest = expected_config
        else:
            raise ImageVerificationError("BuildKit metadata digest is not reviewed evidence")
    else:
        unique_repo_digests = set(repo_digests)
        if len(unique_repo_digests) != 1:
            reason = "missing" if not repo_digests else "ambiguous"
            raise ImageVerificationError(f"{reason} RepoDigest evidence")
        if unique_repo_digests != {expected_manifest}:
            raise ImageVerificationError("Docker RepoDigest does not match the reviewed manifest")
        verification_basis = "manifest"
        verified_digest = expected_manifest

    return VerifiedImageReference(
        reviewed_manifest=expected_manifest,
        execution_reference=execution_reference,
        verified_digest=verified_digest,
        verification_basis=verification_basis,
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


def _read_buildkit_metadata(path: Path, expected_config: str) -> tuple[str, str | None]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ImageVerificationError(f"cannot read BuildKit metadata file: {path}") from exc
    metadata = _parse_json_object(raw, "BuildKit metadata")
    digest = metadata.get("containerimage.digest")
    if not isinstance(digest, str) or not _DIGEST_RE.fullmatch(digest):
        raise ImageVerificationError("BuildKit metadata lacks a valid containerimage.digest")
    config_digest = metadata.get("containerimage.config.digest")
    if config_digest is not None and (
        not isinstance(config_digest, str) or not _DIGEST_RE.fullmatch(config_digest)
    ):
        raise ImageVerificationError("BuildKit metadata has an invalid config digest")
    _validate_buildkit_descriptor(
        metadata.get("containerimage.descriptor"), digest, expected_config
    )
    return digest, config_digest


def _validate_buildkit_descriptor(
    value: object, metadata_digest: str, expected_config: str
) -> None:
    if value is None:
        return
    if not isinstance(value, dict):
        raise ImageVerificationError("BuildKit metadata descriptor is malformed")
    descriptor = cast(dict[object, object], value)
    digest = descriptor.get("digest")
    if digest != metadata_digest:
        raise ImageVerificationError("BuildKit metadata descriptor digest conflicts with digest")
    media_type = descriptor.get("mediaType")
    if media_type != _DOCKER_SCHEMA2_MEDIA_TYPE:
        raise ImageVerificationError("BuildKit metadata descriptor is not Docker schema2")
    annotations = descriptor.get("annotations")
    if annotations is None:
        return
    if not isinstance(annotations, dict):
        raise ImageVerificationError("BuildKit metadata descriptor annotations are malformed")
    config_digest = cast(dict[object, object], annotations).get("config.digest")
    if config_digest is not None and config_digest != expected_config:
        raise ImageVerificationError(
            "BuildKit metadata descriptor config digest does not match expected config"
        )


def _validate_descriptor(value: object, expected_manifest: str, expected_config: str) -> None:
    if value is None:
        return
    if not isinstance(value, dict):
        raise ImageVerificationError("docker inspect returned malformed Descriptor")
    descriptor = cast(dict[object, object], value)
    digest = descriptor.get("digest")
    if digest is not None and digest != expected_manifest:
        raise ImageVerificationError(
            "Docker Descriptor digest does not match the reviewed manifest"
        )
    media_type = descriptor.get("mediaType")
    if media_type is not None and media_type != _DOCKER_SCHEMA2_MEDIA_TYPE:
        raise ImageVerificationError("Docker Descriptor has an unsupported media type")
    annotations = descriptor.get("annotations")
    if annotations is None:
        return
    if not isinstance(annotations, dict):
        raise ImageVerificationError("Docker Descriptor annotations are malformed")
    config_digest = cast(dict[object, object], annotations).get("config.digest")
    if config_digest is not None and config_digest != expected_config:
        raise ImageVerificationError(
            "Docker Descriptor config digest does not match expected config"
        )


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
