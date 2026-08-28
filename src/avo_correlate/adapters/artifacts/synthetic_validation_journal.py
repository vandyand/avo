"""Durable create-once journal for synthetic validation operations."""

from __future__ import annotations

import errno
import json
import os
from pathlib import Path
from typing import TypeVar
from uuid import uuid4

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.synthetic_validation import (
    SyntheticValidationAttempt,
    SyntheticValidationCreateAuthorization,
    SyntheticValidationOutcome,
    SyntheticValidationPlan,
)
from avo_correlate.domain.canonical import canonical_bytes

RecordT = TypeVar(
    "RecordT",
    SyntheticValidationPlan,
    SyntheticValidationOutcome,
    SyntheticValidationAttempt,
    SyntheticValidationCreateAuthorization,
)


class SyntheticValidationJournalError(RuntimeError):
    """A synthetic-validation record is missing, malformed, or conflicts."""


class SyntheticValidationJournal:
    """Content-addressed immutable plan/outcome records with create-once indexes."""

    def __init__(
        self, root: Path, *, artifact_store: FilesystemArtifactStore | None = None
    ) -> None:
        self._root = root.resolve()
        self._indexes = self._root / "synthetic-validation-index"
        self._store = artifact_store or FilesystemArtifactStore(self._root / "artifacts")

    @property
    def root(self) -> Path:
        return self._root

    def record_plan(self, plan: SyntheticValidationPlan) -> ArtifactRef:
        return self._record("plan", plan.operation_id, plan)

    def read_plan(self, operation_id: str) -> tuple[SyntheticValidationPlan, ArtifactRef] | None:
        return self._read("plan", operation_id, SyntheticValidationPlan)

    def record_outcome(self, outcome: SyntheticValidationOutcome) -> ArtifactRef:
        return self._record("outcome", outcome.operation_id, outcome)

    def read_outcome(
        self, operation_id: str
    ) -> tuple[SyntheticValidationOutcome, ArtifactRef] | None:
        return self._read("outcome", operation_id, SyntheticValidationOutcome)

    def record_attempt(self, attempt: SyntheticValidationAttempt) -> ArtifactRef:
        return self._record("attempt", attempt.operation_id, attempt)

    def read_attempt(
        self, operation_id: str
    ) -> tuple[SyntheticValidationAttempt, ArtifactRef] | None:
        return self._read("attempt", operation_id, SyntheticValidationAttempt)

    def claim_create_authorization(
        self, authorization: SyntheticValidationCreateAuthorization
    ) -> bool:
        """Atomically claim the one pre-create authorization for an operation."""
        operation_id = authorization.operation_id
        if not _is_digest(operation_id):
            raise ValueError("operation_id must be a SHA-256 digest")
        data = canonical_bytes(authorization)
        claim = self._indexes / "authorization" / f"{operation_id[7:]}.claim"
        claim.parent.mkdir(parents=True, exist_ok=True)
        try:
            # Directory creation is the atomic reservation.  The record is
            # written only by its owner, so losers never race artifact
            # insertion or observe a partially written JSON claim.
            claim.mkdir()
            record_path = claim / "record.json"
            partial_path = claim / "record.partial"
            with partial_path.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(partial_path, record_path)
            _sync_directory(claim)
            _sync_directory(claim.parent)
        except FileExistsError:
            record_path = claim / "record.json"
            if not record_path.is_file():
                return False
            try:
                existing_data = _read_limited(record_path)
                parsed = json.loads(existing_data.decode("utf-8"))
                if canonical_bytes(parsed) != existing_data:
                    raise ValueError("authorization claim is not canonical JSON")
                existing = SyntheticValidationCreateAuthorization.model_validate(parsed)
            except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
                raise SyntheticValidationJournalError(
                    "synthetic validation authorization claim is malformed"
                ) from exc
            if existing != authorization:
                raise SyntheticValidationJournalError(
                    f"conflicting synthetic validation authorization for operation {operation_id}"
                ) from None
            return False
        except OSError as exc:
            raise SyntheticValidationJournalError(
                "synthetic validation authorization claim was not indexed"
            ) from exc

        # Only the claim owner inserts the content-addressed artifact.  The
        # claim remains after final indexing as durable pre-create evidence;
        # if this process crashes before indexing, readers still see the
        # authorization and refuse to replay the provider mutation.
        self._record_authorization_after_claim(authorization)
        return True

    def read_create_authorization(
        self, operation_id: str
    ) -> (
        SyntheticValidationCreateAuthorization
        | tuple[SyntheticValidationCreateAuthorization, ArtifactRef]
        | None
    ):
        indexed = self._read(
            "authorization", operation_id, SyntheticValidationCreateAuthorization
        )
        if indexed is not None:
            return indexed
        claim = self._indexes / "authorization" / f"{operation_id[7:]}.claim"
        record_path = claim / "record.json"
        if not record_path.is_file():
            return None
        try:
            data = _read_limited(record_path)
            parsed = json.loads(data.decode("utf-8"))
            if canonical_bytes(parsed) != data:
                raise ValueError("authorization claim is not canonical JSON")
            authorization = SyntheticValidationCreateAuthorization.model_validate(parsed)
        except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
            raise SyntheticValidationJournalError(
                "synthetic validation authorization claim is malformed"
            ) from exc
        if authorization.operation_id != operation_id:
            raise SyntheticValidationJournalError(
                "authorization claim operation ID does not match index"
            )
        return authorization

    def record_cleanup(self, outcome: SyntheticValidationOutcome) -> ArtifactRef:
        return self._record("cleanup", outcome.operation_id, outcome)

    def read_cleanup(
        self, operation_id: str
    ) -> tuple[SyntheticValidationOutcome, ArtifactRef] | None:
        return self._read("cleanup", operation_id, SyntheticValidationOutcome)

    # ``receipt`` names are useful to callers used to provider mutation journals.
    record_receipt = record_outcome
    read_receipt = read_outcome
    record_result = record_outcome
    read_result = read_outcome

    def _record(self, kind: str, operation_id: str, record: RecordT) -> ArtifactRef:
        reference, _ = self._record_once(kind, operation_id, record)
        return reference

    def _record_once(
        self, kind: str, operation_id: str, record: RecordT
    ) -> tuple[ArtifactRef, bool]:
        if not _is_digest(operation_id):
            raise ValueError("operation_id must be a SHA-256 digest")
        data = canonical_bytes(record)
        reference = self._store.put_bytes(
            data,
            media_type="application/vnd.avo.synthetic-validation+json",
            role=f"synthetic-validation-{kind}",
            max_bytes=2 * 1024 * 1024,
        )
        _sync_directory(self._store.path_for_digest(reference.digest).parent)
        index = self._indexes / kind / f"{operation_id[7:]}.json"
        index.parent.mkdir(parents=True, exist_ok=True)
        # Keep the temporary basename short: nested Windows campaign roots
        # can otherwise exceed MAX_PATH when the 64-hex operation filename is
        # repeated alongside a UUID.
        temporary = index.parent / f".tmp-{uuid4().hex}.partial"
        try:
            # Publish only after the complete index payload is durable.  A
            # direct ``open('xb')`` lets Windows losers observe an empty file
            # while the winner is still writing it.
            with temporary.open("xb") as handle:
                handle.write(canonical_bytes(reference))
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary, index)
        except FileExistsError:
            try:
                old = ArtifactRef.model_validate(json.loads(_read_limited(index).decode("utf-8")))
                if (
                    old.role != f"synthetic-validation-{kind}"
                    or old.media_type != "application/vnd.avo.synthetic-validation+json"
                ):
                    raise ValueError("record metadata does not match journal kind")
                old_data = self._store.read_bytes(old)
            except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
                raise SyntheticValidationJournalError(
                    "synthetic validation index is malformed"
                ) from exc
            if old.digest != reference.digest or old_data != data:
                raise SyntheticValidationJournalError(
                    f"conflicting synthetic validation {kind} for operation {operation_id}"
                ) from None
            return old, False
        except OSError as exc:
            raise SyntheticValidationJournalError(
                "synthetic validation record was not indexed"
            ) from exc
        finally:
            temporary.unlink(missing_ok=True)
        _sync_directory(index.parent)
        return reference, True
        raise SyntheticValidationJournalError("synthetic validation index state is ambiguous")

    def _record_authorization_after_claim(
        self, authorization: SyntheticValidationCreateAuthorization
    ) -> ArtifactRef:
        """Persist the claimed authorization; its directory is single-writer."""
        operation_id = authorization.operation_id
        data = canonical_bytes(authorization)
        reference = self._store.put_bytes(
            data,
            media_type="application/vnd.avo.synthetic-validation+json",
            role="synthetic-validation-authorization",
            max_bytes=2 * 1024 * 1024,
        )
        index = self._indexes / "authorization" / f"{operation_id[7:]}.json"
        index.parent.mkdir(parents=True, exist_ok=True)
        try:
            with index.open("xb") as handle:
                handle.write(canonical_bytes(reference))
                handle.flush()
                os.fsync(handle.fileno())
            _sync_directory(index.parent)
        except OSError as exc:
            raise SyntheticValidationJournalError(
                "synthetic validation authorization was not indexed"
            ) from exc
        return reference

    def _read(
        self, kind: str, operation_id: str, model: type[RecordT]
    ) -> tuple[RecordT, ArtifactRef] | None:
        if not _is_digest(operation_id):
            raise ValueError("operation_id must be a SHA-256 digest")
        index = self._indexes / kind / f"{operation_id[7:]}.json"
        if not index.is_file():
            return None
        try:
            reference = ArtifactRef.model_validate(json.loads(_read_limited(index).decode("utf-8")))
            if (
                reference.role != f"synthetic-validation-{kind}"
                or reference.media_type != "application/vnd.avo.synthetic-validation+json"
            ):
                raise ValueError("record metadata does not match journal kind")
            data = self._store.read_bytes(reference)
            parsed = json.loads(data.decode("utf-8"))
            if canonical_bytes(parsed) != data:
                raise ValueError("record is not canonical JSON")
            record = model.model_validate(parsed)
        except (
            OSError,
            RuntimeError,
            ValueError,
            TypeError,
            UnicodeError,
            json.JSONDecodeError,
        ) as exc:
            raise SyntheticValidationJournalError(
                f"malformed or unverifiable synthetic validation {kind}"
            ) from exc
        record_id = record.operation_id
        if record_id != operation_id:
            raise SyntheticValidationJournalError("record operation ID does not match index")
        return record, reference


def _is_digest(value: str) -> bool:
    return len(value) == 71 and value.startswith("sha256:") and all(
        char in "0123456789abcdef" for char in value[7:]
    )


def _read_limited(path: Path, maximum: int = 2 * 1024 * 1024) -> bytes:
    if path.stat().st_size > maximum:
        raise ValueError("journal record exceeds configured content limit")
    return path.read_bytes()


def _sync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        if os.name == "nt" and exc.errno in {
            errno.EINVAL,
            errno.EACCES,
            errno.ENOTSUP,
            errno.EOPNOTSUPP,
        }:
            return
        raise
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = ["SyntheticValidationJournal", "SyntheticValidationJournalError"]
