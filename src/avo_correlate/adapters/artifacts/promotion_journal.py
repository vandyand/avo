"""Durable, single-writer journal for protected integration promotion.

This adapter deliberately has no recovery authority: an expired lease is still
an occupied lease until its owner releases it (or an operator removes it).
That makes ambiguous provider calls visible to the service instead of silently
allowing a second mutation.
"""

from __future__ import annotations

import errno
import json
import os
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TypeVar, cast

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_promotion import (
    IntegrationPromotionIntent,
    IntegrationPromotionReceipt,
    PromotionLeaseEvidence,
    PromotionMutationAuthorization,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest


class PromotionJournalError(RuntimeError):
    """Base error for an unsafe or conflicting journal operation."""


class PromotionLeaseConflictError(PromotionJournalError):
    """A repository/target lease is occupied, malformed, or cannot be released."""


class PromotionRecordConflictError(PromotionJournalError):
    """An operation was previously recorded with different canonical content."""


@dataclass(frozen=True, slots=True)
class PromotionLease:
    operation_id: str
    repository_digest: str
    target_ref: str
    identity: str
    acquired_at: datetime
    expires_at: datetime
    digest: str


RecordT = TypeVar(
    "RecordT",
    IntegrationPromotionIntent,
    IntegrationPromotionReceipt,
    PromotionMutationAuthorization,
    PromotionLeaseEvidence,
)


class IntegrationPromotionJournal:
    """Filesystem-backed leases and content-addressed intent/receipt records.

    ``root`` is supplied by the caller and is resolved once; this class does
    not discover or widen its trust boundary. ``acquire_lease`` and
    ``release_lease`` are the controller-exclusive fencing operations.
    ``record_intent`` must complete before the provider merge call, while
    ``record_receipt`` stores the immutable observation afterward.
    """

    def __init__(
        self, root: Path, *, artifact_store: FilesystemArtifactStore | None = None,
        max_record_bytes: int = 2_000_000,
    ) -> None:
        if max_record_bytes <= 0:
            raise ValueError("max_record_bytes must be positive")
        self._root = root.resolve()
        self._leases = self._root / "promotion-leases"
        self._records = self._root / "promotion-record-index"
        self._store = artifact_store or FilesystemArtifactStore(self._root / "artifacts")
        self._max_record_bytes = max_record_bytes

    @property
    def root(self) -> Path:
        return self._root

    def acquire_lease(
        self, repository_digest: str, target_ref: str, operation_id: str, *,
        lease_seconds: int, now: datetime | None = None,
    ) -> PromotionLease:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        self._check_digest(repository_digest, "repository_digest")
        self._check_digest(operation_id, "operation_id")
        if not target_ref or target_ref.strip() != target_ref:
            raise ValueError("target_ref must be non-empty and trimmed")
        acquired = self._aware(now or datetime.now(UTC))
        expires = acquired + timedelta(seconds=lease_seconds)
        identity = secrets.token_urlsafe(32)
        payload = {
            "schema_version": 1, "operation_id": operation_id,
            "repository_digest": repository_digest, "target_ref": target_ref,
            "identity": identity,
            "acquired_at": _canonical_timestamp(acquired),
            "expires_at": _canonical_timestamp(expires),
        }
        lease_digest = canonical_digest(payload)
        key = canonical_digest(
            {"repository_digest": repository_digest, "target_ref": target_ref}
        ).removeprefix("sha256:")
        path = self._leases / f"{key}.json"
        document = {**payload, "digest": lease_digest}
        # Operation IDs are durable idempotency keys.  Refuse to mint a new
        # identity for one that already has immutable evidence; doing this
        # before creating the live lease also avoids leaving an occupied lease
        # behind on a reuse conflict.
        if self.read_lease_evidence(operation_id) is not None:
            raise PromotionLeaseConflictError(
                "operation already has durable promotion lease evidence"
            )
        try:
            self._exclusive_write(path, canonical_bytes(document))
        except FileExistsError as exc:
            raise PromotionLeaseConflictError(
                "promotion lease is occupied; expired or malformed leases are not auto-broken"
            ) from exc
        except OSError as exc:
            raise PromotionJournalError(
                "promotion lease creation is not durably recorded; reconciliation required"
            ) from exc
        evidence = PromotionLeaseEvidence(
            operation_id=operation_id,
            repository_digest=repository_digest,
            target_ref=target_ref,
            identity=identity,
            acquired_at=acquired,
            expires_at=expires,
            digest=lease_digest,
        )
        lease = PromotionLease(
            operation_id, repository_digest, target_ref, identity, acquired, expires, lease_digest
        )
        # The evidence is immutable and indexed by operation ID.  It is
        # persisted before any provider mutation and remains after the
        # ephemeral lease file is released.
        try:
            self.record_lease_evidence(evidence)
        except (OSError, ValueError, RuntimeError) as exc:
            try:
                self.release_lease(lease)
            except (OSError, ValueError, RuntimeError) as cleanup_exc:
                raise PromotionJournalError(
                    "promotion lease evidence failed and lease cleanup was not confirmed; "
                    "operator reconciliation required"
                ) from cleanup_exc
            raise PromotionJournalError(
                "promotion lease evidence is not durably recorded; reconciliation required"
            ) from exc
        return lease

    def release_lease(self, lease: PromotionLease) -> None:
        key = canonical_digest(
            {"repository_digest": lease.repository_digest, "target_ref": lease.target_ref}
        ).removeprefix("sha256:")
        path = self._leases / f"{key}.json"
        try:
            document = json.loads(self._read_limited(path).decode("utf-8"))
            expected = self._lease_from_document(document)
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise PromotionLeaseConflictError("lease is missing or malformed") from exc
        if (
            expected.identity,
            expected.digest,
            expected.repository_digest,
            expected.target_ref,
        ) != (
            lease.identity, lease.digest, lease.repository_digest, lease.target_ref
        ):
            raise PromotionLeaseConflictError("lease identity or digest does not match")
        try:
            path.unlink()
        except FileNotFoundError as exc:
            raise PromotionLeaseConflictError("lease disappeared before release") from exc
        try:
            _sync_directory(path.parent)
        except OSError as exc:
            # The unlink already happened.  Do not pretend the lease is still
            # held; callers must reconcile the resulting on-disk state.
            raise PromotionJournalError(
                "lease was removed but directory durability could not be confirmed; "
                "reconciliation required"
            ) from exc

    def read_lease(self, repository_digest: str, target_ref: str) -> PromotionLease | None:
        """Read and verify a lease, including an expired lease, for recovery."""
        self._check_digest(repository_digest, "repository_digest")
        if not target_ref or target_ref.strip() != target_ref:
            raise ValueError("target_ref must be non-empty and trimmed")
        key = canonical_digest(
            {"repository_digest": repository_digest, "target_ref": target_ref}
        ).removeprefix("sha256:")
        path = self._leases / f"{key}.json"
        if not path.is_file():
            return None
        try:
            document = json.loads(self._read_limited(path).decode("utf-8"))
            lease = self._lease_from_document(document)
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise PromotionLeaseConflictError("lease is malformed") from exc
        if (lease.repository_digest, lease.target_ref) != (repository_digest, target_ref):
            raise PromotionLeaseConflictError("lease scope does not match its key")
        return lease

    def release_matching_lease(
        self,
        repository_digest: str,
        target_ref: str,
        operation_id: str,
        identity: str,
        digest: str,
    ) -> bool:
        """Release only an exactly matching lease; return false when absent."""
        lease = self.read_lease(repository_digest, target_ref)
        if lease is None:
            return False
        if (lease.operation_id, lease.identity, lease.digest) != (operation_id, identity, digest):
            raise PromotionLeaseConflictError("lease recovery bindings do not match")
        self.release_lease(lease)
        return True

    def assert_current(self, lease: PromotionLease, *, now: datetime | None = None) -> None:
        """Verify that ``lease`` still owns the exact live on-disk lease."""
        key = canonical_digest(
            {"repository_digest": lease.repository_digest, "target_ref": lease.target_ref}
        ).removeprefix("sha256:")
        path = self._leases / f"{key}.json"
        try:
            document = json.loads(self._read_limited(path).decode("utf-8"))
            current = self._lease_from_document(document)
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise PromotionLeaseConflictError("lease is missing or malformed") from exc
        if current != lease:
            raise PromotionLeaseConflictError("lease identity or digest does not match")
        if current.expires_at <= self._aware(now or datetime.now(UTC)):
            raise PromotionLeaseConflictError("promotion lease has expired")

    def record_intent(self, intent: IntegrationPromotionIntent) -> ArtifactRef:
        return self._record("intent", intent.operation_id, intent)

    def record_receipt(self, receipt: IntegrationPromotionReceipt) -> ArtifactRef:
        return self._record("receipt", receipt.operation_id, receipt)

    def record_lease_evidence(self, evidence: PromotionLeaseEvidence) -> ArtifactRef:
        """Persist lease identity/timestamps independently of the live lease file."""
        return self._record("lease-evidence", evidence.operation_id, evidence)

    def record_mutation_authorization(
        self, authorization: PromotionMutationAuthorization
    ) -> ArtifactRef:
        return self._record("mutation-authorization", authorization.operation_id, authorization)

    def read_intent(
        self, operation_id: str
    ) -> tuple[IntegrationPromotionIntent, ArtifactRef] | None:
        return self._read("intent", operation_id, IntegrationPromotionIntent)

    def read_receipt(
        self, operation_id: str
    ) -> tuple[IntegrationPromotionReceipt, ArtifactRef] | None:
        return self._read("receipt", operation_id, IntegrationPromotionReceipt)

    def read_lease_evidence(
        self, operation_id: str
    ) -> tuple[PromotionLeaseEvidence, ArtifactRef] | None:
        """Read lease evidence after release, verifying its content address."""
        return self._read("lease-evidence", operation_id, PromotionLeaseEvidence)

    def read_mutation_authorization(
        self, operation_id: str
    ) -> tuple[PromotionMutationAuthorization, ArtifactRef] | None:
        return self._read("mutation-authorization", operation_id, PromotionMutationAuthorization)

    def read_lease_evidence_ref(self, operation_id: str) -> ArtifactRef | None:
        """Return the durable evidence reference for campaign evidence packaging."""
        evidence = self.read_lease_evidence(operation_id)
        return evidence[1] if evidence is not None else None

    # Explicit aliases make service reconciliation call sites self-documenting.
    persist_intent = record_intent
    persist_receipt = record_receipt
    persist_lease_evidence = record_lease_evidence
    persist_mutation_authorization = record_mutation_authorization

    def _record(self, kind: str, operation_id: str, record: RecordT) -> ArtifactRef:
        data = canonical_bytes(record)
        artifact = self._store.put_bytes(
            data, media_type="application/vnd.avo.integration-promotion+json",
            role=f"promotion-{kind}", max_bytes=self._max_record_bytes,
        )
        # ``FilesystemArtifactStore`` makes the object contents durable; sync
        # its containing directory before publishing the index that points to
        # the object.  This is especially important for lease evidence because
        # it must remain readable after the live lease entry is removed.
        _sync_directory(self._store.path_for_digest(artifact.digest).parent)
        index = self._records / kind / f"{operation_id.removeprefix('sha256:')}.json"
        reference = artifact.model_dump(mode="json")
        try:
            self._exclusive_write(index, canonical_bytes(reference))
        except FileExistsError:
            try:
                old = ArtifactRef.model_validate(
                    json.loads(self._read_limited(index).decode("utf-8"))
                )
                if (
                    old.role != f"promotion-{kind}"
                    or old.media_type != "application/vnd.avo.integration-promotion+json"
                ):
                    raise ValueError("existing promotion record artifact metadata is malformed")
                old_data = self._store.read_bytes(old)
            except (
                OSError,
                RuntimeError,
                ValueError,
                TypeError,
                json.JSONDecodeError,
            ) as exc:
                raise PromotionRecordConflictError(
                    "existing promotion record index is malformed"
                ) from exc
            if old.digest != artifact.digest or old_data != data:
                raise PromotionRecordConflictError(
                    f"conflicting {kind} for operation {operation_id}"
                ) from None
            return old
        return artifact

    def _read(
        self, kind: str, operation_id: str, model: type[RecordT]
    ) -> tuple[RecordT, ArtifactRef] | None:
        self._check_digest(operation_id, "operation_id")
        index = self._records / kind / f"{operation_id.removeprefix('sha256:')}.json"
        if not index.is_file():
            return None
        try:
            reference = ArtifactRef.model_validate(
                json.loads(self._read_limited(index).decode("utf-8"))
            )
            if (
                reference.role != f"promotion-{kind}"
                or reference.media_type != "application/vnd.avo.integration-promotion+json"
            ):
                raise ValueError("record artifact metadata does not match its journal kind")
            if reference.size_bytes > self._max_record_bytes:
                raise ValueError("record exceeds configured content limit")
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
            raise PromotionJournalError(f"malformed or unverifiable {kind} record") from exc
        if record.operation_id != operation_id:
            raise PromotionRecordConflictError(f"{kind} operation ID does not match index")
        return record, reference

    def _read_limited(self, path: Path) -> bytes:
        """Read journal JSON without allowing an unbounded hostile file."""
        if path.stat().st_size > self._max_record_bytes:
            raise ValueError("journal record exceeds configured content limit")
        return path.read_bytes()

    @staticmethod
    def _check_digest(value: str, name: str) -> None:
        if (
            len(value) != 71
            or not value.startswith("sha256:")
            or any(c not in "0123456789abcdef" for c in value[7:])
        ):
            raise ValueError(f"{name} must be a SHA-256 digest")

    @staticmethod
    def _aware(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value.astimezone(UTC)

    @classmethod
    def _lease_from_document(cls, document: object) -> PromotionLease:
        if not isinstance(document, dict) or "digest" not in document:
            raise ValueError("malformed lease")
        raw = dict(cast(dict[str, object], document))
        digest = raw.pop("digest", None)
        if not isinstance(digest, str) or canonical_digest(raw) != digest:
            raise ValueError("lease digest mismatch")
        required = {
            "schema_version", "operation_id", "repository_digest", "target_ref",
            "identity", "acquired_at", "expires_at",
        }
        if set(raw) != required:
            raise ValueError("malformed lease fields")
        if raw["schema_version"] != 1:
            raise ValueError("malformed lease value")
        raw_values = tuple(raw[name] for name in (
            "operation_id", "repository_digest", "target_ref", "identity",
            "acquired_at", "expires_at",
        ))
        if not all(
            isinstance(value, str)
            for value in raw_values
        ):
            raise ValueError("malformed lease value")
        operation_id, repository_digest, target_ref, identity, acquired_at, expires_at = cast(
            tuple[str, str, str, str, str, str], raw_values
        )
        cls._check_digest(repository_digest, "repository_digest")
        cls._check_digest(operation_id, "operation_id")
        return PromotionLease(
            operation_id, repository_digest, target_ref, identity,
            cls._aware(datetime.fromisoformat(acquired_at)),
            cls._aware(datetime.fromisoformat(expires_at)), digest,
        )

    @staticmethod
    def _exclusive_write(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        _sync_directory(path.parent)


def _sync_directory(path: Path) -> None:
    """Durably publish a directory entry where the platform supports it.

    POSIX filesystems must be able to fsync the containing directory; failure
    is propagated so callers fail closed.  Windows commonly does not expose
    directory handles through ``os.open``.  Its documented unsupported cases
    are treated as the platform's best available durability, while any
    successfully opened directory is still fsynced and failures propagate.
    """
    flags = os.O_RDONLY
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags | directory_flag)
    except OSError as exc:
        unsupported = {errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EACCES}
        if os.name == "nt" and exc.errno in unsupported:
            return
        raise
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "IntegrationPromotionJournal", "PromotionJournalError", "PromotionLease",
    "PromotionLeaseConflictError", "PromotionRecordConflictError",
]


def _canonical_timestamp(value: datetime) -> str:
    """Use Pydantic's canonical UTC spelling for lease digest stability."""
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
