from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.experiment import ReviewPolicy, WorkspaceSpec
from avo_correlate.contracts.runtime import EconomicUsageRecord, ReconciliationCaseRecord

DIGEST = "sha256:" + ("a" * 64)


def test_artifact_requires_timezone_aware_timestamp() -> None:
    with pytest.raises(ValidationError):
        ArtifactRef(
            digest=DIGEST,
            size_bytes=1,
            media_type="text/plain",
            role="test",
            created_at=datetime(2026, 1, 1),
        )
    artifact = ArtifactRef(
        digest=DIGEST,
        size_bytes=1,
        media_type="text/plain",
        role="test",
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert artifact.schema_version == 1


@pytest.mark.parametrize(
    "path",
    ["../secret", "/etc/passwd", "C:/secret", r"folder\file", "a//b", "./a"],
)
def test_workspace_rejects_unsafe_manifest_paths(path: str) -> None:
    with pytest.raises(ValidationError):
        WorkspaceSpec(
            source_uri="https://example.invalid/repository",
            source_revision="abc",
            source_tree_digest=DIGEST,
            allowed_paths=[path],
            forbidden_paths=["private"],
            required_paths=["pyproject.toml"],
            max_file_bytes=10,
            max_tree_bytes=20,
        )


def test_required_review_requires_approval() -> None:
    with pytest.raises(ValidationError):
        ReviewPolicy(required=True, approvals_required=0)


def test_runtime_economics_and_reconciliation_are_internally_consistent() -> None:
    with pytest.raises(ValidationError, match="price_table_digest"):
        EconomicUsageRecord(billing_mode="subscription", cost_source="price_table")
    with pytest.raises(ValidationError, match="charged cost"):
        EconomicUsageRecord(billing_mode="metered", cost_source="provider")
    with pytest.raises(ValidationError, match="open reconciliation"):
        ReconciliationCaseRecord(
            reconciliation_id="case-1",
            run_id="run-1",
            activity_id="activity-1",
            reason="ambiguous",
            state="open",
            resolution="retry",
            opened_at=datetime.now(UTC),
        )
    with pytest.raises(ValidationError, match="requires resolution"):
        ReconciliationCaseRecord(
            reconciliation_id="case-1",
            run_id="run-1",
            activity_id="activity-1",
            reason="ambiguous",
            state="resolved",
            opened_at=datetime.now(UTC),
        )
