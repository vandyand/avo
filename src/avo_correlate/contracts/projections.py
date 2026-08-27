"""Stable read projections for operator inspection."""

from datetime import datetime
from typing import Any, Literal

from avo_correlate.contracts.base import (
    NonEmptyString,
    NonNegativeInt,
    Sha256Digest,
    StrictModel,
)


class SessionProjection(StrictModel):
    schema_version: Literal[1] = 1
    session_id: NonEmptyString
    run_id: NonEmptyString
    state: NonEmptyString
    request: dict[str, Any]
    result: dict[str, Any] | None
    attempts: list[dict[str, Any]]


class CandidateProjection(StrictModel):
    schema_version: Literal[1] = 1
    candidate_id: NonEmptyString
    run_id: NonEmptyString
    state: NonEmptyString
    manifest: dict[str, Any]
    evaluations: list[dict[str, Any]]
    admission: dict[str, Any] | None
    policy_decisions: list[dict[str, Any]]
    reviews: list[dict[str, Any]]


class ArtifactMetadataProjection(StrictModel):
    schema_version: Literal[1] = 1
    digest: Sha256Digest
    size_bytes: NonNegativeInt
    media_type: NonEmptyString
    role: NonEmptyString
    created_at: datetime
    verified_at: datetime


class SessionRuntimeProjection(StrictModel):
    schema_version: Literal[1] = 1
    session_id: NonEmptyString
    run_id: NonEmptyString
    session_state: NonEmptyString
    invocations: list[dict[str, Any]]
    reconciliations: list[dict[str, Any]]
