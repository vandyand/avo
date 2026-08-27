import json
import subprocess
from pathlib import Path

import pytest

from avo_correlate.devtools.oci_image import (
    ImageVerificationError,
    resolve_verified_image,
)

EXPECTED = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
CONFIG = "sha256:" + "c" * 64


def _inspect_result(
    *, repo_digests: list[str] | None = None, **extra: object
) -> subprocess.CompletedProcess[bytes]:
    payload: dict[str, object] = {
        "Id": CONFIG,
        "RepoDigests": repo_digests if repo_digests is not None else [f"repo@{EXPECTED}"],
    }
    payload.update(extra)
    return subprocess.CompletedProcess(
        args=["docker"],
        returncode=0,
        stdout=json.dumps(payload).encode(),
        stderr=b"",
    )


def _successful_inspect(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
    return _inspect_result()


def test_repo_digest_verification_returns_local_config_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(subprocess, "run", _successful_inspect)

    result = resolve_verified_image("reference:tag", EXPECTED, expected_config=CONFIG)

    assert result.reviewed_manifest == EXPECTED
    assert result.execution_reference == CONFIG
    assert result.verified_digest == EXPECTED
    assert result.verification_basis == "manifest"


def test_buildkit_metadata_verification_works_without_repo_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    metadata = tmp_path / "metadata.json"
    metadata.write_text(
        json.dumps(
            {
                "containerimage.digest": EXPECTED,
                "containerimage.descriptor": {
                    "digest": EXPECTED,
                    "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                    "annotations": {"config.digest": CONFIG},
                },
            }
        ),
        encoding="utf-8",
    )

    def inspect(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return _inspect_result(repo_digests=[])

    monkeypatch.setattr(subprocess, "run", inspect)

    result = resolve_verified_image(
        "reference:tag", EXPECTED, expected_config=CONFIG, metadata_file=metadata
    )

    assert result.execution_reference == CONFIG
    assert result.verified_digest == EXPECTED
    assert result.verification_basis == "manifest"


def test_buildkit_config_exporter_requires_matching_config_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    metadata = tmp_path / "metadata.json"
    metadata.write_text(
        json.dumps(
            {
                "containerimage.digest": CONFIG,
                "containerimage.config.digest": CONFIG,
                "containerimage.descriptor": {
                    "digest": CONFIG,
                    "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                    "annotations": {"config.digest": CONFIG},
                },
            }
        ),
        encoding="utf-8",
    )

    def inspect(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return _inspect_result(repo_digests=[])

    monkeypatch.setattr(subprocess, "run", inspect)

    result = resolve_verified_image(
        "reference:tag", EXPECTED, expected_config=CONFIG, metadata_file=metadata
    )

    assert result.reviewed_manifest == EXPECTED
    assert result.execution_reference == CONFIG
    assert result.verified_digest == CONFIG
    assert result.verification_basis == "config"


def test_config_exporter_without_config_evidence_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    metadata = tmp_path / "metadata.json"
    metadata.write_text(json.dumps({"containerimage.digest": CONFIG}), encoding="utf-8")
    monkeypatch.setattr(subprocess, "run", _successful_inspect)

    with pytest.raises(ImageVerificationError, match="config-only"):
        resolve_verified_image(
            "reference:tag", EXPECTED, expected_config=CONFIG, metadata_file=metadata
        )


def test_config_mismatch_fails_even_when_manifest_evidence_matches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def inspect(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return _inspect_result(repo_digests=[], Id=OTHER)

    monkeypatch.setattr(subprocess, "run", inspect)

    with pytest.raises(ImageVerificationError, match="image ID"):
        resolve_verified_image("reference:tag", EXPECTED, expected_config=CONFIG)


def test_metadata_and_descriptor_conflicts_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    metadata = tmp_path / "metadata.json"
    metadata.write_text(
        json.dumps(
            {
                "containerimage.digest": EXPECTED,
                "containerimage.config.digest": OTHER,
            }
        ),
        encoding="utf-8",
    )

    def inspect(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return _inspect_result(
            repo_digests=[f"repo@{OTHER}"],
            Descriptor={
                "digest": OTHER,
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "annotations": {"config.digest": OTHER},
            },
        )

    monkeypatch.setattr(subprocess, "run", inspect)

    with pytest.raises(ImageVerificationError):
        resolve_verified_image(
            "reference:tag", EXPECTED, expected_config=CONFIG, metadata_file=metadata
        )


@pytest.mark.parametrize(
    "descriptor",
    [
        {"digest": OTHER},
        {"mediaType": "application/octet-stream"},
        {"annotations": {"config.digest": OTHER}},
    ],
)
def test_malformed_or_mismatched_descriptor_fails(
    descriptor: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    def inspect(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return _inspect_result(Descriptor=descriptor)

    monkeypatch.setattr(subprocess, "run", inspect)

    with pytest.raises(ImageVerificationError, match="Descriptor"):
        resolve_verified_image("reference:tag", EXPECTED, expected_config=CONFIG)


@pytest.mark.parametrize(
    ("repo_digests", "metadata", "message"),
    [
        ([f"repo@{OTHER}"], None, "does not match"),
        ([f"repo@{EXPECTED}", f"other@{OTHER}"], None, "ambiguous"),
        ([], None, "missing"),
    ],
)
def test_manifest_evidence_mismatch_ambiguity_and_missing_fail_closed(
    repo_digests: list[str],
    metadata: str | None,
    message: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata_file = None
    if metadata is not None:
        metadata_file = tmp_path / "metadata.json"
        metadata_file.write_text(metadata, encoding="utf-8")

    def inspect(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return _inspect_result(repo_digests=repo_digests)

    monkeypatch.setattr(subprocess, "run", inspect)

    with pytest.raises(ImageVerificationError, match=message):
        resolve_verified_image(
            "reference:tag", EXPECTED, expected_config=CONFIG, metadata_file=metadata_file
        )


def test_malformed_buildkit_metadata_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    metadata = tmp_path / "metadata.json"
    metadata.write_text("{not-json", encoding="utf-8")

    def inspect(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return _inspect_result(repo_digests=[])

    monkeypatch.setattr(subprocess, "run", inspect)

    with pytest.raises(ImageVerificationError, match="malformed"):
        resolve_verified_image(
            "reference:tag", EXPECTED, expected_config=CONFIG, metadata_file=metadata
        )


@pytest.mark.parametrize(
    "descriptor",
    [
        "not-an-object",
        {"digest": OTHER, "mediaType": "application/vnd.docker.distribution.manifest.v2+json"},
        {"digest": EXPECTED, "mediaType": "application/vnd.oci.image.manifest.v1+json"},
        {
            "digest": EXPECTED,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "annotations": {"config.digest": OTHER},
        },
    ],
)
def test_buildkit_descriptor_conflicts_and_malformed_values_fail(
    descriptor: object, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    metadata = tmp_path / "metadata.json"
    metadata.write_text(
        json.dumps({"containerimage.digest": EXPECTED, "containerimage.descriptor": descriptor}),
        encoding="utf-8",
    )
    monkeypatch.setattr(subprocess, "run", _successful_inspect)

    with pytest.raises(ImageVerificationError, match=r"descriptor|Descriptor"):
        resolve_verified_image(
            "reference:tag", EXPECTED, expected_config=CONFIG, metadata_file=metadata
        )


def test_valid_metadata_cannot_override_conflicting_repo_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    metadata = tmp_path / "metadata.json"
    metadata.write_text(json.dumps({"containerimage.digest": EXPECTED}), encoding="utf-8")

    def inspect(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return _inspect_result(repo_digests=[f"repo@{OTHER}"])

    monkeypatch.setattr(subprocess, "run", inspect)

    with pytest.raises(ImageVerificationError, match="conflict"):
        resolve_verified_image(
            "reference:tag", EXPECTED, expected_config=CONFIG, metadata_file=metadata
        )


def test_inspect_command_failure_is_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    def command_failure(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            args=["docker"], returncode=1, stdout=b"", stderr=b"not found"
        )

    monkeypatch.setattr(subprocess, "run", command_failure)

    with pytest.raises(ImageVerificationError, match="inspect failed"):
        resolve_verified_image("reference:tag", EXPECTED, expected_config=CONFIG)
