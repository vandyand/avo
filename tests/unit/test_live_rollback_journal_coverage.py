"""Focused branch coverage for the live rollback journal adapter."""

# These tests intentionally exercise private durability seams and reuse the
# comprehensive historical fixture; keep those test-only diagnostics local.
# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownVariableType=false

import errno
import json
from pathlib import Path
from typing import Any

import pytest

import avo_correlate.adapters.artifacts.live_rollback_journal as journal_module
from avo_correlate.adapters.artifacts.live_rollback_journal import (
    LiveRollbackJournal,
    LiveRollbackJournalError,
)
from tests.unit.test_integration_live_rollback import _package_fixture


def test_constructor_rejects_nonpositive_limit(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="positive"):
        LiveRollbackJournal(tmp_path, max_package_bytes=0)


def test_record_read_list_and_idempotent_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = _package_fixture()
    journal = LiveRollbackJournal(tmp_path)

    monkeypatch.setattr(
        journal_module.LiveRollbackEvidencePackage,
        "model_validate",
        classmethod(lambda cls, _data: package),
    )

    reference = journal.record_package(package)
    assert journal.record_package(package) == reference
    loaded = journal.read_package(package.operation_id)
    assert loaded is not None
    assert loaded[0] == package
    assert loaded[1] == reference
    assert journal.list_operations() == (package.operation_id,)
    assert journal.read_package("sha256:" + "b" * 64) is None
    assert LiveRollbackJournal(tmp_path / "other").list_operations() == ()


@pytest.mark.parametrize("operation_id", ["", "sha256:bad", "sha256:" + "G" * 64])
def test_read_rejects_malformed_operation_identity(
    tmp_path: Path, operation_id: str
) -> None:
    with pytest.raises(ValueError, match="SHA-256"):
        LiveRollbackJournal(tmp_path).read_package(operation_id)


def test_conflict_keeps_content_addressed_object(tmp_path: Path) -> None:
    package = _package_fixture()
    journal = LiveRollbackJournal(tmp_path)
    journal.record_package(package)
    conflicting = package.model_copy(update={"main_after_commit": "2" * 40})
    with pytest.raises(LiveRollbackJournalError, match="unreachable"):
        journal.record_package(conflicting)


def test_existing_index_with_missing_object_fails_closed(tmp_path: Path) -> None:
    package = _package_fixture()
    journal = LiveRollbackJournal(tmp_path)
    journal.record_package(package)
    index = tmp_path / "live-rollback-index" / "package" / (
        package.operation_id.removeprefix("sha256:") + ".json"
    )
    old = json.loads(index.read_text(encoding="utf-8"))
    old["digest"] = "sha256:" + "f" * 64
    index.write_text(json.dumps(old), encoding="utf-8")
    with pytest.raises(LiveRollbackJournalError, match="unreadable"):
        journal.record_package(package)


def test_record_wraps_store_and_index_os_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = _package_fixture()
    journal = LiveRollbackJournal(tmp_path)

    def fail_store(*args: Any, **kwargs: Any) -> Any:
        raise OSError("store unavailable")

    monkeypatch.setattr(journal._store, "put_bytes", fail_store)
    with pytest.raises(OSError, match="store unavailable"):
        journal.record_package(package)

    journal = LiveRollbackJournal(tmp_path / "index-error")
    original_open = Path.open

    def fail_index_open(path: Path, *args: Any, **kwargs: Any) -> Any:
        if path.name == package.operation_id.removeprefix("sha256:") + ".json":
            raise OSError("index unavailable")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_index_open)
    with pytest.raises(LiveRollbackJournalError, match="durably indexed"):
        journal.record_package(package)


@pytest.mark.parametrize(
    "metadata",
    [
        {"role": "wrong"},
        {"media_type": "application/octet-stream"},
        {"size_bytes": 10**9},
    ],
)
def test_read_rejects_reference_metadata_tampering(
    tmp_path: Path, metadata: dict[str, object]
) -> None:
    package = _package_fixture()
    journal = LiveRollbackJournal(tmp_path)
    journal.record_package(package)
    index = tmp_path / "live-rollback-index" / "package" / (
        package.operation_id.removeprefix("sha256:") + ".json"
    )
    ref = json.loads(index.read_text(encoding="utf-8"))
    ref.update(metadata)
    index.write_text(json.dumps(ref), encoding="utf-8")
    with pytest.raises(LiveRollbackJournalError, match="malformed"):
        journal.read_package(package.operation_id)


def test_read_rejects_noncanonical_and_identity_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = _package_fixture()
    journal = LiveRollbackJournal(tmp_path)
    reference = journal.record_package(package)
    # The stored package is valid JSON, but a fake store can expose a noncanonical encoding.
    class NonCanonicalStore:
        def read_bytes(self, _reference: object) -> bytes:
            return b'{"b": 1, "a": 2}'

    monkeypatch.setattr(journal, "_store", NonCanonicalStore())
    with pytest.raises(LiveRollbackJournalError, match="malformed"):
        journal.read_package(package.operation_id)

    # Rebuild a real journal and point an alias index at a package with another identity.
    journal = LiveRollbackJournal(tmp_path / "identity")
    journal.record_package(package)
    alias = "sha256:" + "b" * 64
    alias_index = journal.root / "live-rollback-index" / "package" / ("b" * 64 + ".json")
    source = journal.root / "live-rollback-index" / "package" / (
        package.operation_id.removeprefix("sha256:") + ".json"
    )
    alias_index.write_bytes(source.read_bytes())
    monkeypatch.setattr(
        journal_module.LiveRollbackEvidencePackage,
        "model_validate",
        classmethod(lambda cls, _data: package),
    )
    with pytest.raises(LiveRollbackJournalError, match="identity"):
        journal.read_package(alias)
    assert reference.digest.startswith("sha256:")


def test_list_rejects_malformed_or_disappearing_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = LiveRollbackJournal(tmp_path)
    directory = tmp_path / "live-rollback-index" / "package"
    directory.mkdir(parents=True)
    (directory / "ABC.json").write_text("{}", encoding="utf-8")
    with pytest.raises(LiveRollbackJournalError, match="identity"):
        journal.list_operations()

    (directory / "ABC.json").unlink()
    package = _package_fixture()
    journal.record_package(package)
    monkeypatch.setattr(journal, "read_package", lambda _operation: None)
    with pytest.raises(LiveRollbackJournalError, match="disappeared"):
        journal.list_operations()


def test_reference_parser_and_sync_error_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = LiveRollbackJournal(tmp_path, max_package_bytes=8)
    index = tmp_path / "index.json"
    index.write_text("x" * 9, encoding="utf-8")
    with pytest.raises(LiveRollbackJournalError, match="malformed"):
        journal._read_reference(index)

    def fail_open(*args: Any, **kwargs: Any) -> Any:
        raise OSError(errno.EINVAL, "directory fsync unsupported")

    monkeypatch.setattr(journal_module.os, "name", "nt")
    monkeypatch.setattr(journal_module.os, "open", fail_open)
    journal_module._sync_directory(tmp_path)

    def unsupported_error(*args: Any, **kwargs: Any) -> Any:
        raise OSError(errno.EIO, "directory fsync failed")

    monkeypatch.setattr(journal_module.os, "name", "posix")
    monkeypatch.setattr(journal_module.os, "open", unsupported_error)
    with pytest.raises(OSError, match="directory fsync failed"):
        journal_module._sync_directory(tmp_path)

    closed: list[int] = []
    monkeypatch.setattr(journal_module.os, "name", "posix")
    monkeypatch.setattr(journal_module.os, "open", lambda *_args, **_kwargs: 7)
    monkeypatch.setattr(journal_module.os, "fsync", lambda descriptor: None)
    monkeypatch.setattr(journal_module.os, "close", closed.append)
    journal_module._sync_directory(tmp_path)
    assert closed == [7]
