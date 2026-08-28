"""Focused branch coverage for the hosted completion journal adapter."""

# These tests intentionally exercise private durability seams and reuse the
# comprehensive historical fixture; keep those test-only diagnostics local.
# pyright: reportPrivateUsage=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false, reportUnknownVariableType=false

import errno
import json
from pathlib import Path
from typing import Any

import pytest

import avo_correlate.adapters.artifacts.live_rollback_completion_journal as journal_module
from avo_correlate.adapters.artifacts.live_rollback_completion_journal import (
    LiveRollbackCompletionJournal,
    LiveRollbackCompletionJournalError,
)
from tests.unit.test_integration_live_rollback_completion import _completion_fixture


def _validated_journal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    package: Any,
) -> LiveRollbackCompletionJournal:
    # The historical fixture intentionally uses model_construct for Phase-A records.
    # Replace only the outer reparse hooks so these adapter tests can exercise durable
    # storage and recovery paths independently of the contract fixture's provenance.
    monkeypatch.setattr(
        journal_module.LiveRollbackCompletionPackage,
        "model_validate_json",
        classmethod(lambda cls, _data: package),
    )
    monkeypatch.setattr(
        journal_module.LiveRollbackCompletionPackage,
        "model_validate",
        classmethod(lambda cls, _data: package),
    )
    return LiveRollbackCompletionJournal(tmp_path)


def test_constructor_rejects_nonpositive_limit(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="positive"):
        LiveRollbackCompletionJournal(tmp_path, max_package_bytes=0)


def test_record_read_and_idempotent_replay(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    package = _completion_fixture()
    journal = _validated_journal(tmp_path, monkeypatch, package)
    reference = journal.record_package(package)
    assert journal.record_package(package) == reference
    loaded = journal.read_package(package.operation_id)
    assert loaded is not None
    assert loaded[0] == package
    assert loaded[1] == reference
    assert (
        LiveRollbackCompletionJournal(tmp_path / "missing").read_package(package.operation_id)
        is None
    )


def test_record_wraps_semantic_validation_and_cleanup_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = _completion_fixture()
    monkeypatch.setattr(
        journal_module.LiveRollbackCompletionPackage,
        "model_validate_json",
        classmethod(lambda cls, _data: (_ for _ in ()).throw(TypeError("bad model"))),
    )
    with pytest.raises(LiveRollbackCompletionJournalError, match="semantic"):
        LiveRollbackCompletionJournal(tmp_path).record_package(package)

    pending = package.model_copy(
        update={
            "cleanup_outcome": package.cleanup_outcome.model_copy(
                update={"outcome": "created"}
            )
        }
    )
    journal = _validated_journal(tmp_path / "pending", monkeypatch, pending)
    with pytest.raises(LiveRollbackCompletionJournalError, match="cleanup"):
        journal.record_package(pending)


def test_index_write_error_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    package = _completion_fixture()
    journal = _validated_journal(tmp_path, monkeypatch, package)
    original_open = Path.open

    def fail_index_open(path: Path, *args: Any, **kwargs: Any) -> Any:
        if path.name == package.operation_id.removeprefix("sha256:") + ".json":
            raise OSError("index unavailable")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_index_open)
    with pytest.raises(LiveRollbackCompletionJournalError, match="durably indexed"):
        journal.record_package(package)


def test_conflict_and_unreadable_existing_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = _completion_fixture()
    journal = _validated_journal(tmp_path, monkeypatch, package)
    journal.record_package(package)
    conflicting = package.model_copy(update={"main_after_commit": "2" * 40})
    monkeypatch.setattr(
        journal_module.LiveRollbackCompletionPackage,
        "model_validate_json",
        classmethod(lambda cls, _data: conflicting),
    )
    with pytest.raises(LiveRollbackCompletionJournalError, match="conflicting"):
        journal.record_package(conflicting)

    reference_file = tmp_path / "live-rollback-completion-index" / "package" / (
        package.operation_id.removeprefix("sha256:") + ".json"
    )
    ref = json.loads(reference_file.read_text(encoding="utf-8"))
    ref["digest"] = "sha256:" + "f" * 64
    reference_file.write_text(json.dumps(ref), encoding="utf-8")
    monkeypatch.setattr(
        journal_module.LiveRollbackCompletionPackage,
        "model_validate_json",
        classmethod(lambda cls, _data: package),
    )
    with pytest.raises(LiveRollbackCompletionJournalError, match="unreadable"):
        journal.record_package(package)


def test_materialization_rejects_incomplete_and_unbound_children(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = _completion_fixture()
    missing = package.model_copy(update={"artifacts": package.artifacts[:-1]})
    journal = _validated_journal(tmp_path / "missing", monkeypatch, missing)
    with pytest.raises(LiveRollbackCompletionJournalError, match="incomplete"):
        journal.record_package(missing)

    unbound_ref = package.artifacts[0].model_copy(update={"size_bytes": 1})
    unbound = package.model_copy(update={"artifacts": [unbound_ref, *package.artifacts[1:]]})
    journal = _validated_journal(tmp_path / "unbound", monkeypatch, unbound)
    with pytest.raises(LiveRollbackCompletionJournalError, match="content-bound"):
        journal.record_package(unbound)


class _FailingStore:
    def put_bytes(self, *_args: Any, **_kwargs: Any) -> Any:
        raise OSError("store failed")

    def read_bytes(self, _reference: object) -> bytes:
        raise OSError("read failed")


def test_materialization_and_outer_store_errors_are_wrapped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = _completion_fixture()
    journal = _validated_journal(tmp_path / "child", monkeypatch, package)
    monkeypatch.setattr(journal, "_store", _FailingStore())
    with pytest.raises(LiveRollbackCompletionJournalError, match="child artifact"):
        journal.record_package(package)

    journal = _validated_journal(tmp_path / "outer", monkeypatch, package)
    real_put = journal._store.put_bytes
    calls = 0

    def fail_outer(data: bytes, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        if calls == 15:
            raise OSError("outer store failed")
        return real_put(data, **kwargs)

    monkeypatch.setattr(journal._store, "put_bytes", fail_outer)
    with pytest.raises(OSError, match="outer store failed"):
        journal.record_package(package)


def test_materialization_rejects_stored_metadata_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = _completion_fixture()
    journal = _validated_journal(tmp_path, monkeypatch, package)
    real_put = journal._store.put_bytes
    calls = 0

    def wrong_metadata(data: bytes, **kwargs: Any) -> Any:
        nonlocal calls
        calls += 1
        stored = real_put(data, **kwargs)
        if calls == 1:
            return stored.model_copy(update={"role": "wrong-role"})
        return stored

    monkeypatch.setattr(journal._store, "put_bytes", wrong_metadata)
    with pytest.raises(LiveRollbackCompletionJournalError, match="metadata"):
        journal.record_package(package)


def test_verify_children_rejects_missing_and_mismatched_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = _completion_fixture()
    journal = _validated_journal(tmp_path, monkeypatch, package)

    class MissingStore:
        def read_bytes(self, _reference: object) -> bytes:
            raise OSError("missing child")

    monkeypatch.setattr(journal, "_store", MissingStore())
    with pytest.raises(LiveRollbackCompletionJournalError, match="missing or tampered"):
        journal._verify_children(package)

    class WrongStore:
        def read_bytes(self, _reference: object) -> bytes:
            return b"wrong payload"

    monkeypatch.setattr(journal, "_store", WrongStore())
    with pytest.raises(LiveRollbackCompletionJournalError, match="contents mismatch"):
        journal._verify_children(package)

    incomplete = package.model_copy(update={"artifacts": package.artifacts[:-1]})
    with pytest.raises(LiveRollbackCompletionJournalError, match="incomplete"):
        journal._verify_children(incomplete)


def test_read_rejects_reference_metadata_and_malformed_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = _completion_fixture()
    journal = _validated_journal(tmp_path, monkeypatch, package)
    journal.record_package(package)
    index = tmp_path / "live-rollback-completion-index" / "package" / (
        package.operation_id.removeprefix("sha256:") + ".json"
    )
    reference = json.loads(index.read_text(encoding="utf-8"))
    reference["role"] = "wrong"
    index.write_text(json.dumps(reference), encoding="utf-8")
    with pytest.raises(LiveRollbackCompletionJournalError, match="malformed"):
        journal.read_package(package.operation_id)

    # Restore the index and expose noncanonical bytes through a small store proxy.
    journal = _validated_journal(tmp_path / "payload", monkeypatch, package)
    journal.record_package(package)
    class NonCanonicalStore:
        def read_bytes(self, _reference: object) -> bytes:
            return b'{"b": 1, "a": 2}'

    monkeypatch.setattr(journal, "_store", NonCanonicalStore())
    with pytest.raises(LiveRollbackCompletionJournalError, match="malformed"):
        journal.read_package(package.operation_id)


def test_read_identity_and_child_tamper_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = _completion_fixture()
    journal = _validated_journal(tmp_path, monkeypatch, package)
    journal.record_package(package)
    monkeypatch.setattr(
        journal_module.LiveRollbackCompletionPackage,
        "model_validate",
        classmethod(
            lambda cls, _data: package.model_copy(
                update={"operation_id": "sha256:" + "b" * 64}
            )
        ),
    )
    with pytest.raises(LiveRollbackCompletionJournalError, match="identity"):
        journal.read_package(package.operation_id)

    monkeypatch.setattr(
        journal_module.LiveRollbackCompletionPackage,
        "model_validate",
        classmethod(lambda cls, _data: package),
    )
    monkeypatch.setattr(
        journal,
        "_verify_children",
        lambda _package: (_ for _ in ()).throw(ValueError("tamper")),
    )
    with pytest.raises(LiveRollbackCompletionJournalError, match="malformed"):
        journal.read_package(package.operation_id)


@pytest.mark.parametrize("operation_id", ["", "sha256:bad", "sha256:" + "G" * 64])
def test_read_rejects_malformed_operation_identity(tmp_path: Path, operation_id: str) -> None:
    with pytest.raises(ValueError, match="SHA-256"):
        LiveRollbackCompletionJournal(tmp_path).read_package(operation_id)


def test_reference_parser_and_sync_platform_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = LiveRollbackCompletionJournal(tmp_path, max_package_bytes=8)
    index = tmp_path / "index.json"
    index.write_text("x" * 9, encoding="utf-8")
    with pytest.raises(LiveRollbackCompletionJournalError, match="malformed"):
        journal._read_reference(index)

    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    with pytest.raises(LiveRollbackCompletionJournalError, match="malformed"):
        journal._read_reference(malformed)

    original_name = journal_module.os.name
    monkeypatch.setattr(journal_module.os, "name", "nt")

    def unsupported_open(*_args: Any, **_kwargs: Any) -> Any:
        raise OSError(errno.EINVAL, "directory fsync unsupported")

    monkeypatch.setattr(journal_module.os, "open", unsupported_open)
    journal_module._sync_directory(tmp_path)
    monkeypatch.setattr(journal_module.os, "name", original_name)

    def unsupported_error(*_args: Any, **_kwargs: Any) -> Any:
        raise OSError(errno.EIO, "directory fsync failed")

    monkeypatch.setattr(journal_module.os, "name", "posix")
    monkeypatch.setattr(journal_module.os, "open", unsupported_error)
    with pytest.raises(OSError, match="directory fsync failed"):
        journal_module._sync_directory(tmp_path)

    closed: list[int] = []
    monkeypatch.setattr(journal_module.os, "name", "posix")
    monkeypatch.setattr(journal_module.os, "open", lambda *_args, **_kwargs: 11)
    monkeypatch.setattr(journal_module.os, "fsync", lambda descriptor: None)
    monkeypatch.setattr(journal_module.os, "close", closed.append)
    journal_module._sync_directory(tmp_path)
    assert closed == [11]
