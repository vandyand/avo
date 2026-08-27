"""CAS commit, durable references, and conservative garbage collection."""

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.adapters.persistence.database import Database
from avo_correlate.adapters.persistence.models import (
    ArtifactMetadataRow,
    ArtifactReferenceRow,
    DeletionTombstoneRow,
    EventRow,
    OutboxRow,
    RunRow,
)
from avo_correlate.contracts.base import ArtifactRef


class ArtifactMetadataConflict(RuntimeError):
    pass


class ArtifactService:
    def __init__(self, database: Database, store: FilesystemArtifactStore) -> None:
        self._database = database
        self._store = store

    def put_bytes(
        self,
        data: bytes,
        *,
        run_id: str,
        owner_type: str,
        owner_id: str,
        media_type: str,
        role: str,
        retention_class: str,
        max_bytes: int,
        actor_id: str,
    ) -> ArtifactRef:
        reference = self._store.put_bytes(
            data, media_type=media_type, role=role, max_bytes=max_bytes
        )
        now = datetime.now(UTC)
        with self._database.session() as session:
            run = session.get(RunRow, run_id)
            if run is None:
                raise LookupError(f"run not found: {run_id}")
            metadata = session.get(ArtifactMetadataRow, reference.digest)
            if metadata is None:
                session.add(
                    ArtifactMetadataRow(
                        digest=reference.digest,
                        size_bytes=reference.size_bytes,
                        media_type=reference.media_type,
                        role=reference.role,
                        created_at=reference.created_at,
                        verified_at=reference.created_at,
                    )
                )
                session.flush()
            elif (
                metadata.size_bytes != reference.size_bytes
                or metadata.media_type != reference.media_type
            ):
                raise ArtifactMetadataConflict("digest has incompatible metadata")
            existing = session.scalar(
                select(ArtifactReferenceRow).where(
                    ArtifactReferenceRow.digest == reference.digest,
                    ArtifactReferenceRow.owner_type == owner_type,
                    ArtifactReferenceRow.owner_id == owner_id,
                    ArtifactReferenceRow.role == role,
                )
            )
            if existing is not None:
                return reference
            session.add(
                ArtifactReferenceRow(
                    reference_id=str(uuid4()),
                    digest=reference.digest,
                    run_id=run_id,
                    owner_type=owner_type,
                    owner_id=owner_id,
                    role=role,
                    retention_class=retention_class,
                    created_at=now,
                )
            )
            self._append_event(
                session,
                run,
                actor_id=actor_id,
                digest=reference.digest,
                owner_type=owner_type,
                owner_id=owner_id,
                now=now,
            )
        return reference

    def collect_unreferenced(self, *, grace_seconds: int, reason: str) -> list[str]:
        """Delete old, unreferenced bytes; active references are never considered."""
        cutoff = datetime.now(UTC) - timedelta(seconds=grace_seconds)
        removed: list[str] = []
        with self._database.session() as session:
            candidates = list(
                session.scalars(
                    select(ArtifactMetadataRow).where(
                        ArtifactMetadataRow.created_at < cutoff,
                        ~select(ArtifactReferenceRow)
                        .where(ArtifactReferenceRow.digest == ArtifactMetadataRow.digest)
                        .exists(),
                    )
                )
            )
            for metadata in candidates:
                bytes_removed = self._store.delete(metadata.digest)
                outcome = "removed" if bytes_removed else "already_absent"
                session.add(
                    DeletionTombstoneRow(
                        tombstone_id=str(uuid4()),
                        digest=metadata.digest,
                        outcome=outcome,
                        reason=reason,
                        created_at=datetime.now(UTC),
                    )
                )
                session.delete(metadata)
                removed.append(metadata.digest)
        return removed

    @staticmethod
    def _append_event(
        session: Session,
        run: RunRow,
        *,
        actor_id: str,
        digest: str,
        owner_type: str,
        owner_id: str,
        now: datetime,
    ) -> None:
        event_id = str(uuid4())
        run.revision += 1
        run.event_sequence += 1
        run.updated_at = now
        payload = json.dumps(
            {"digest": digest, "owner_type": owner_type, "owner_id": owner_id},
            sort_keys=True,
            separators=(",", ":"),
        )
        session.add(
            EventRow(
                event_id=event_id,
                run_id=run.run_id,
                sequence=run.event_sequence,
                event_type="artifact.committed",
                actor_id=actor_id,
                payload_json=payload,
                created_at=now,
            )
        )
        session.flush()
        session.add(
            OutboxRow(
                outbox_id=str(uuid4()),
                event_id=event_id,
                topic="run.events",
                payload_json=payload,
                created_at=now,
            )
        )
