"""Sandbox execution boundary records."""

from datetime import datetime
from typing import Literal

from pydantic import Field, field_validator, model_validator

from avo_correlate.contracts.base import (
    NonEmptyString,
    NonNegativeInt,
    PositiveInt,
    Sha256Digest,
    StrictModel,
    require_aware_datetime,
)


class SandboxMount(StrictModel):
    schema_version: Literal[1] = 1
    source_digest: Sha256Digest
    target: NonEmptyString
    read_only: bool = True


class SandboxExecutionSpec(StrictModel):
    schema_version: Literal[1] = 1
    execution_id: NonEmptyString
    image_digest: Sha256Digest
    command: list[NonEmptyString] = Field(min_length=1)
    working_directory: NonEmptyString = "/workspace"
    environment: dict[str, str] = Field(default_factory=dict)
    mounts: list[SandboxMount] = Field(default_factory=list[SandboxMount])
    network_enabled: bool = False
    timeout_seconds: PositiveInt
    termination_grace_seconds: PositiveInt = 5
    cpu_limit: str = "1.0"
    memory_bytes: PositiveInt
    pids_limit: PositiveInt = 128
    output_bytes_limit: PositiveInt

    @model_validator(mode="after")
    def deny_unsafe_environment(self) -> "SandboxExecutionSpec":
        forbidden = {"DOCKER_HOST", "SSH_AUTH_SOCK", "AWS_SECRET_ACCESS_KEY"}
        if forbidden.intersection(self.environment):
            raise ValueError("sandbox environment contains a protected host variable")
        return self


class SandboxExecutionResult(StrictModel):
    schema_version: Literal[1] = 1
    execution_id: NonEmptyString
    outcome: Literal["succeeded", "failed", "timed_out", "output_limit", "policy_blocked"]
    exit_code: int | None
    stdout_digest: Sha256Digest
    stderr_digest: Sha256Digest
    stdout_bytes: NonNegativeInt
    stderr_bytes: NonNegativeInt
    started_at: datetime
    completed_at: datetime

    _aware_started = field_validator("started_at")(require_aware_datetime)
    _aware_completed = field_validator("completed_at")(require_aware_datetime)
