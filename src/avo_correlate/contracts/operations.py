"""Operational validation, dry-run, and benchmark records."""

from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import Literal

from pydantic import Field, field_validator

from avo_correlate.contracts.base import (
    NonEmptyString,
    PositiveInt,
    Sha256Digest,
    StrictModel,
    require_aware_datetime,
)


class CheckStatus(StrEnum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


class DoctorCheck(StrictModel):
    name: NonEmptyString
    status: CheckStatus
    detail: NonEmptyString
    next_action: NonEmptyString | None = None


class DoctorReport(StrictModel):
    schema_version: Literal[1] = 1
    overall: CheckStatus
    checks: list[DoctorCheck] = Field(min_length=1)


class ValidationCheck(StrictModel):
    schema_version: Literal[1] = 1
    check_id: NonEmptyString
    outcome: Literal["pass", "warn", "fail"]
    detail: NonEmptyString


class DryRunReport(StrictModel):
    schema_version: Literal[1] = 1
    experiment_id: NonEmptyString
    spec_digest: Sha256Digest
    outcome: Literal["ready", "blocked"]
    checks: list[ValidationCheck] = Field(min_length=1)


class ReferenceScenarioResult(StrictModel):
    schema_version: Literal[1] = 1
    run_id: NonEmptyString
    session_id: NonEmptyString
    candidate_id: NonEmptyString
    admission_id: NonEmptyString
    final_state: Literal["completed"]
    provenance_digest: Sha256Digest
    provenance_verified: Literal[True] = True


class PlatformOverheadReport(StrictModel):
    schema_version: Literal[1] = 1
    hardware_class: NonEmptyString
    execution_image_digest: Sha256Digest
    trial_count: PositiveInt
    wall_clock_ms: Decimal = Field(ge=0)
    workload_ms: Decimal = Field(ge=0)
    platform_overhead_ms: Decimal = Field(ge=0)
    measured_at: datetime

    _aware_measured = field_validator("measured_at")(require_aware_datetime)
