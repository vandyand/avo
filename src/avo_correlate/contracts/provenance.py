"""Machine-readable provenance export and verification reports."""

from typing import Any, Literal

from pydantic import Field

from avo_correlate.contracts.base import NonEmptyString, Sha256Digest, StrictModel


class ProvenanceExport(StrictModel):
    schema_version: Literal[1] = 1
    format: Literal["avo-lineage-json-v1"] = "avo-lineage-json-v1"
    run_id: NonEmptyString
    manifest: dict[str, Any]
    manifest_digest: Sha256Digest


class VerificationReport(StrictModel):
    schema_version: Literal[1] = 1
    verified: bool
    checks: list[NonEmptyString] = Field(min_length=1)
    errors: list[NonEmptyString] = Field(default_factory=list[NonEmptyString])
