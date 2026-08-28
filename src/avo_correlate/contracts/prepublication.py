"""Typed contracts for the rollback publication pre-authorization fence."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import AliasChoices, Field, StrictInt, field_validator, model_validator

from avo_correlate.contracts.base import NonEmptyString, Sha256Digest, StrictModel
from avo_correlate.domain.canonical import canonical_digest

_GIT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
SOAK_ISSUER_ID = "github-app:15368/integration-soak"


def _git(value: str) -> str:
    if not _GIT.fullmatch(value):
        raise ValueError("Git object ID is malformed")
    return value


def _path(value: str) -> str:
    if (
        not value
        or value.startswith(("/", "\\"))
        or ".." in value.replace("\\", "/").split("/")
    ):
        raise ValueError("changed path is unsafe")
    return value


class RollbackPublicationAuthorityConfig(StrictModel):
    """Fixed trust configuration; none of these values come from a canary."""

    schema_version: Literal[1] = 1
    repository_digest: Sha256Digest
    target_ref: Literal["refs/heads/integration"] = "refs/heads/integration"
    soak_issuer_id: NonEmptyString = Field(
        default=SOAK_ISSUER_ID,
        validation_alias=AliasChoices("soak_issuer_id", "soak_issuer")
    )
    soak_app_id: StrictInt = Field(
        default=15368,
        validation_alias=AliasChoices("soak_app_id", "soak_app")
    )
    soak_context: NonEmptyString
    soak_workflow_path: NonEmptyString
    base_issuer_id: NonEmptyString
    path_issuer_id: NonEmptyString
    controller_identity: NonEmptyString
    publisher_identity: NonEmptyString
    trusted_config_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_digest(self) -> RollbackPublicationAuthorityConfig:
        values = self.model_dump(mode="json")
        supplied = values.pop("trusted_config_digest")
        if canonical_digest(values) != supplied:
            raise ValueError("trusted authority configuration digest mismatch")
        if self.controller_identity == self.publisher_identity:
            raise ValueError("controller and publisher identities must be separate")
        if self.soak_issuer_id != SOAK_ISSUER_ID:
            raise ValueError("soak issuer must be the fixed GitHub App/check identity")
        if self.soak_app_id != 15368:
            raise ValueError("soak app is not the fixed GitHub App")
        return self


class RollbackSnapshotRestoreFacts(StrictModel):
    """Authenticated failed-head and restore topology supplied by the observer."""

    repository_digest: Sha256Digest
    target_ref: Literal["refs/heads/integration"] = "refs/heads/integration"
    failed_head_commit: str
    failed_head_tree: str
    failed_head_parents: list[str] = Field(min_length=1, max_length=1)
    restore_commit: str
    restore_tree: str

    @model_validator(mode="after")
    def validate_topology(self) -> RollbackSnapshotRestoreFacts:
        values = [
            self.failed_head_commit,
            self.failed_head_tree,
            *self.failed_head_parents,
            self.restore_commit,
            self.restore_tree,
        ]
        for value in values:
            _git(value)
        if self.failed_head_parents != [self.restore_commit]:
            raise ValueError("restore commit is not the immediate sole parent")
        return self


class RollbackPublicationAuthorization(StrictModel):
    """Durable, content-addressed authority created before candidate push."""

    schema_version: Literal[1] = 1
    operation_id: Sha256Digest
    canary_operation_id: Sha256Digest
    canary_package_digest: Sha256Digest
    repository_digest: Sha256Digest
    target_ref: Literal["refs/heads/integration"] = "refs/heads/integration"
    main_before_commit: str
    failed_integration_head_commit: str
    failed_integration_head_tree: str
    restore_to_commit: str
    restore_to_tree: str
    rollback_candidate_commit: str
    rollback_candidate_tree: str
    rollback_candidate_parent_commit: str
    candidate_digest: Sha256Digest
    candidate_ref: NonEmptyString
    changed_paths: list[NonEmptyString] = Field(min_length=1)
    publication_plan_digest: Sha256Digest
    publication_evidence_digest: Sha256Digest
    failed_soak_attestation_id: Sha256Digest
    failed_soak_attestation_digest: Sha256Digest
    authority_config_digest: Sha256Digest
    controller_identity: NonEmptyString
    publisher_identity: NonEmptyString
    issuer_id: NonEmptyString
    reason: NonEmptyString
    authorized: Literal[True] = True
    authorization_id: Sha256Digest

    @field_validator("changed_paths")
    @classmethod
    def sorted_paths(cls, values: list[str]) -> list[str]:
        if values != sorted(values, key=lambda value: (value.casefold(), value)):
            raise ValueError("changed paths must be sorted")
        if len({value.casefold() for value in values}) != len(values):
            raise ValueError("changed paths must be unique")
        return values

    @model_validator(mode="after")
    def validate_authorization(self) -> RollbackPublicationAuthorization:
        for value in (
            self.main_before_commit, self.failed_integration_head_commit,
            self.failed_integration_head_tree, self.restore_to_commit,
            self.restore_to_tree, self.rollback_candidate_commit,
            self.rollback_candidate_tree, self.rollback_candidate_parent_commit,
        ):
            _git(value)
        for value in self.changed_paths:
            _path(value)
        if self.rollback_candidate_parent_commit != self.failed_integration_head_commit:
            raise ValueError("rollback candidate parent differs from failed head")
        if self.rollback_candidate_tree != self.restore_to_tree:
            raise ValueError("rollback candidate tree differs from restore tree")
        if self.rollback_candidate_commit == self.restore_to_commit:
            raise ValueError("rollback candidate must be a new commit")
        if self.authorization_id != canonical_digest(
            self.model_dump(exclude={"authorization_id"}, mode="json")
        ):
            raise ValueError("rollback publication authorization digest mismatch")
        return self


__all__ = [
    "SOAK_ISSUER_ID",
    "RollbackPublicationAuthorityConfig",
    "RollbackPublicationAuthorization",
    "RollbackSnapshotRestoreFacts",
]
