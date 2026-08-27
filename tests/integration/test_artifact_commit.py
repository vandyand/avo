from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import func, select

from avo_correlate.adapters.artifacts import FilesystemArtifactStore
from avo_correlate.adapters.persistence import Database
from avo_correlate.adapters.persistence.models import (
    ArtifactMetadataRow,
    ArtifactReferenceRow,
    DeletionTombstoneRow,
)
from avo_correlate.application.artifact_service import ArtifactService
from avo_correlate.application.query_service import QueryService
from avo_correlate.application.run_service import RunService
from tests.conftest import experiment_spec


def test_artifact_object_metadata_reference_and_event_commit(tmp_path: Path) -> None:
    database = Database(tmp_path / "state.db")
    database.initialize()
    runs = RunService(database)
    runs.create_experiment(experiment_spec())
    runs.create_run("experiment-1", actor_id="tester", run_id="run-1")
    service = ArtifactService(database, FilesystemArtifactStore(tmp_path / "artifacts"))
    first = service.put_bytes(
        b"evidence",
        run_id="run-1",
        owner_type="candidate",
        owner_id="candidate-1",
        media_type="application/octet-stream",
        role="patch",
        retention_class="candidate-evidence",
        max_bytes=1_000,
        actor_id="worker",
    )
    second = service.put_bytes(
        b"evidence",
        run_id="run-1",
        owner_type="candidate",
        owner_id="candidate-1",
        media_type="application/octet-stream",
        role="patch",
        retention_class="candidate-evidence",
        max_bytes=1_000,
        actor_id="worker",
    )
    assert first.digest == second.digest
    metadata = QueryService(database).artifact(first.digest)
    assert metadata.size_bytes == len(b"evidence")
    with database.session() as session:
        assert session.scalar(select(func.count()).select_from(ArtifactReferenceRow)) == 1
    assert [event.event_type for event in runs.list_events("run-1")] == [
        "run.created",
        "artifact.committed",
    ]


def test_artifact_collection_removes_only_old_unreferenced_objects(tmp_path: Path) -> None:
    database = Database(tmp_path / "state.db")
    database.initialize()
    store = FilesystemArtifactStore(tmp_path / "artifacts")
    service = ArtifactService(database, store)
    reference = store.put_bytes(
        b"orphan", media_type="application/octet-stream", role="temporary", max_bytes=100
    )
    with database.session() as session:
        session.add(
            ArtifactMetadataRow(
                digest=reference.digest,
                size_bytes=reference.size_bytes,
                media_type=reference.media_type,
                role=reference.role,
                created_at=datetime.now(UTC) - timedelta(days=2),
                verified_at=reference.created_at,
            )
        )
    assert service.collect_unreferenced(grace_seconds=60, reason="retention") == [
        reference.digest
    ]
    assert not store.exists(reference.digest)
    with database.session() as session:
        tombstone = session.scalar(select(DeletionTombstoneRow))
        assert tombstone is not None
        assert tombstone.outcome == "removed"


def test_artifact_commit_rejects_missing_run(tmp_path: Path) -> None:
    database = Database(tmp_path / "state.db")
    database.initialize()
    service = ArtifactService(database, FilesystemArtifactStore(tmp_path / "artifacts"))
    with pytest.raises(LookupError, match="run not found"):
        service.put_bytes(
            b"unowned",
            run_id="missing",
            owner_type="candidate",
            owner_id="candidate-1",
            media_type="application/octet-stream",
            role="patch",
            retention_class="candidate-evidence",
            max_bytes=1_000,
            actor_id="worker",
        )
