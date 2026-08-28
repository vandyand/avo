from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from avo_correlate.adapters.artifacts import FilesystemArtifactStore
from avo_correlate.adapters.artifacts.filesystem import (
    ArtifactIntegrityError,
    ArtifactTooLargeError,
)


def test_round_trip_and_content_deduplication(tmp_path: Path) -> None:
    store = FilesystemArtifactStore(tmp_path)
    first = store.put_bytes(b"evidence", media_type="text/plain", role="test", max_bytes=100)
    second = store.put_bytes(b"evidence", media_type="text/plain", role="test", max_bytes=100)
    assert first.digest == second.digest
    assert store.read_bytes(first) == b"evidence"
    assert store.exists(first.digest)
    assert not list((tmp_path / "temporary").iterdir())


def test_size_limit_is_enforced_before_write(tmp_path: Path) -> None:
    store = FilesystemArtifactStore(tmp_path)
    with pytest.raises(ArtifactTooLargeError):
        store.put_bytes(b"large", media_type="text/plain", role="test", max_bytes=2)
    assert not list((tmp_path / "temporary").iterdir())


def test_tampering_is_detected(tmp_path: Path) -> None:
    store = FilesystemArtifactStore(tmp_path)
    reference = store.put_bytes(b"safe", media_type="text/plain", role="test", max_bytes=100)
    paths = [path for path in (tmp_path / "objects" / "sha256").rglob("*") if path.is_file()]
    assert len(paths) == 1
    paths[0].write_bytes(b"evil")
    with pytest.raises(ArtifactIntegrityError):
        store.read_bytes(reference)


def test_same_digest_concurrent_insertion_is_idempotent(tmp_path: Path) -> None:
    store = FilesystemArtifactStore(tmp_path)
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [
            pool.submit(
                store.put_bytes,
                b"concurrent-evidence",
                media_type="text/plain",
                role="test",
                max_bytes=100,
            )
            for _ in range(8)
        ]
        references = [future.result() for future in futures]
    assert {reference.digest for reference in references} == {
        references[0].digest
    }
    assert store.read_bytes(references[0]) == b"concurrent-evidence"
    assert not list((tmp_path / "temporary").iterdir())
