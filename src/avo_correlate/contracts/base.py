"""Common immutable schema primitives."""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator

Sha256Digest = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
NonEmptyString = Annotated[str, StringConstraints(min_length=1, strip_whitespace=True)]
NonNegativeInt = Annotated[int, Field(ge=0)]
PositiveInt = Annotated[int, Field(gt=0)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


def require_aware_datetime(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value


class ArtifactRef(StrictModel):
    schema_version: Literal[1] = 1
    digest: Sha256Digest
    size_bytes: NonNegativeInt
    media_type: NonEmptyString
    role: NonEmptyString
    created_at: datetime

    _aware_created_at = field_validator("created_at")(require_aware_datetime)


class ActorRef(StrictModel):
    schema_version: Literal[1] = 1
    actor_type: Literal["human", "service", "harness", "evaluator"]
    actor_id: NonEmptyString


class VersionedComponentRef(StrictModel):
    schema_version: Literal[1] = 1
    component_id: NonEmptyString
    component_version: NonEmptyString
    package_digest: Sha256Digest
    capability_manifest_digest: Sha256Digest
