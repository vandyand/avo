"""Contracts for bounded, schema-constrained model inference."""

from typing import Literal, TypeVar

from avo_correlate.contracts.base import NonEmptyString, Sha256Digest, StrictModel
from avo_correlate.contracts.budgets import UsageRecord


class StructuredInferenceContext(StrictModel):
    """Stable identity and operation metadata for one structured inference."""

    schema_version: Literal[1] = 1
    run_id: NonEmptyString
    session_id: NonEmptyString
    activity_id: NonEmptyString
    operation_id: NonEmptyString
    operation_version: NonEmptyString


OutputT = TypeVar("OutputT", bound=StrictModel)


class StructuredInferenceResult[OutputT: StrictModel](StrictModel):
    """A validated output plus the provider evidence needed to replay it."""

    schema_version: Literal[1] = 1
    output: OutputT
    usage: UsageRecord
    invocation_id: NonEmptyString
    provider_request_id: str | None = None
    provider_model_revision: str | None = None
    finish_reason: NonEmptyString
    output_artifact_digest: Sha256Digest
