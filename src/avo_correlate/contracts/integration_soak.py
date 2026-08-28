"""Provider-owned attestation for the base-controlled integration soak."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Literal

from pydantic import Field, field_validator, model_validator

from avo_correlate.contracts.base import (
    Sha256Digest,
    StrictModel,
    require_aware_datetime,
)
from avo_correlate.domain.canonical import canonical_digest

_GIT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
SOAK_WORKFLOW_PATH = ".github/workflows/integration-soak.yml"
SOAK_WORKFLOW_VARIABLE = "AVO_TRUSTED_SOAK_WORKFLOW_SHA256"
SOAK_CONTEXT = "avo integration soak"
SOAK_APP_ID = 15368
SOAK_MARKER = "AVO-Live-Rollback-Marker: fail-soak"
SOAK_MARKER_PATH = "src/avo_correlate/live_rollback_marker.txt"
# GitHub stores the candidate file as one UTF-8 marker line terminated by LF.
# Keep the exact bytes and digest in the contract so the workflow and provider
# have one authority-safe trigger definition.
SOAK_MARKER_BLOB_DIGEST = "sha256:84e940a02be358b4d7abc4d6fb1b83b723adce8fbd0feaa8c193919a0e28a318"


def _git(value: str, label: str) -> str:
    if _GIT.fullmatch(value) is None:
        raise ValueError(f"{label} is malformed")
    return value


class FailedSoakAttestation(StrictModel):
    """An authenticated, read-only observation of the deterministic failed soak.

    Every identity in this record is read from GitHub.  In particular,
    ``restore_commit`` is the exact sole parent of ``integration_commit`` and
    its tree is read from the parent commit, rather than supplied by a caller.
    """

    schema_version: Literal[1] = 1
    attestation_id: Sha256Digest
    repository_digest: Sha256Digest
    integration_ref: Literal["refs/heads/integration"] = "refs/heads/integration"
    integration_commit: str
    integration_tree: str
    integration_parent_commit: str
    restore_commit: str
    restore_tree: str
    main_ref: Literal["refs/heads/main"] = "refs/heads/main"
    main_commit: str
    check_run_id: int = Field(gt=0)
    workflow_id: int = Field(gt=0)
    workflow_run_id: int = Field(gt=0)
    context: Literal["avo integration soak"] = SOAK_CONTEXT
    app_id: Literal[15368] = SOAK_APP_ID
    status: Literal["completed"] = "completed"
    conclusion: Literal["failure"] = "failure"
    completed_at: datetime
    freshness_cutoff: datetime
    marker_path: Literal["src/avo_correlate/live_rollback_marker.txt"] = SOAK_MARKER_PATH
    marker_blob_digest: Sha256Digest = SOAK_MARKER_BLOB_DIGEST
    workflow_path: Literal[".github/workflows/integration-soak.yml"] = SOAK_WORKFLOW_PATH
    workflow_blob_digest: Sha256Digest
    repository_variables_digest: Sha256Digest

    @property
    def observation_id(self) -> Sha256Digest:
        """Compatibility name for consumers that index observations."""
        return self.attestation_id

    @property
    def integration_head_commit(self) -> str:
        return self.integration_commit

    @property
    def integration_head_tree(self) -> str:
        return self.integration_tree

    @property
    def main_head_commit(self) -> str:
        return self.main_commit

    @property
    def check_id(self) -> int:
        return self.check_run_id

    @property
    def run_id(self) -> int:
        return self.workflow_run_id

    _aware_completed_at = field_validator("completed_at")(require_aware_datetime)
    _aware_freshness_cutoff = field_validator("freshness_cutoff")(require_aware_datetime)

    @model_validator(mode="after")
    def validate_attestation(self) -> FailedSoakAttestation:
        for name in (
            "integration_commit",
            "integration_tree",
            "integration_parent_commit",
            "restore_commit",
            "restore_tree",
            "main_commit",
        ):
            _git(getattr(self, name), name)
        if self.integration_parent_commit != self.restore_commit:
            raise ValueError("restore commit must be the exact integration parent")
        if self.completed_at < self.freshness_cutoff:
            raise ValueError("failed soak check is stale")
        if self.completed_at > datetime.now(UTC):
            raise ValueError("failed soak check is future-dated")
        if self.workflow_blob_digest != self.repository_variables_digest:
            raise ValueError("soak workflow and repository-variable evidence differ")
        if self.marker_path != SOAK_MARKER_PATH:
            raise ValueError("soak marker path is not trusted")
        if self.marker_blob_digest != SOAK_MARKER_BLOB_DIGEST:
            raise ValueError("soak marker content is not trusted")
        expected = canonical_digest(self.model_dump(exclude={"attestation_id"}, mode="json"))
        if self.attestation_id != expected:
            raise ValueError("failed soak attestation ID mismatch")
        return self


__all__ = [
    "SOAK_APP_ID",
    "SOAK_CONTEXT",
    "SOAK_MARKER",
    "SOAK_MARKER_BLOB_DIGEST",
    "SOAK_MARKER_PATH",
    "SOAK_WORKFLOW_PATH",
    "SOAK_WORKFLOW_VARIABLE",
    "FailedSoakAttestation",
]
