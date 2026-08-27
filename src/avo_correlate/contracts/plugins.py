"""Signed plugin capability manifests and compatibility declarations."""

from typing import Any, Literal

from pydantic import Field

from avo_correlate.contracts.base import NonEmptyString, Sha256Digest, StrictModel


class PluginCapabilityManifest(StrictModel):
    schema_version: Literal[1] = 1
    plugin_id: NonEmptyString
    plugin_version: NonEmptyString
    package_digest: Sha256Digest
    source_digest: Sha256Digest
    supported_contract_versions: list[NonEmptyString] = Field(min_length=1)
    supported_schema_versions: list[int] = Field(min_length=1)
    operating_systems: list[NonEmptyString] = Field(min_length=1)
    architectures: list[NonEmptyString] = Field(min_length=1)
    required_executables: list[NonEmptyString] = Field(default_factory=list)
    network_access: Literal["none", "control-plane-only", "brokered"]
    configuration_schema: dict[str, Any]
    side_effects: list[NonEmptyString] = Field(default_factory=list)
    security_classification: NonEmptyString
    health_check: list[NonEmptyString] = Field(min_length=1)
    license: NonEmptyString


class SignedPluginManifest(StrictModel):
    schema_version: Literal[1] = 1
    manifest: PluginCapabilityManifest
    signature_algorithm: Literal["hmac-sha256"]
    signer_key_id: NonEmptyString
    signature_hex: NonEmptyString
