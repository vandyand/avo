"""Signed manifest verification and explicit compatibility checks."""

import hashlib
import hmac
from collections.abc import Mapping

from avo_correlate.contracts.plugins import (
    PluginCapabilityManifest,
    SignedPluginManifest,
)
from avo_correlate.domain.canonical import canonical_bytes


class PluginCompatibilityError(ValueError):
    pass


def sign_plugin_manifest(
    manifest: PluginCapabilityManifest, *, key_id: str, signing_key: bytes
) -> SignedPluginManifest:
    if len(signing_key) < 32:
        raise ValueError("plugin signing key must contain at least 32 bytes")
    signature = hmac.digest(signing_key, canonical_bytes(manifest), hashlib.sha256).hex()
    return SignedPluginManifest(
        manifest=manifest,
        signature_algorithm="hmac-sha256",
        signer_key_id=key_id,
        signature_hex=signature,
    )


def verify_plugin_manifest(
    signed: SignedPluginManifest,
    *,
    trusted_keys: Mapping[str, bytes],
    required_contract: str,
    required_schema_version: int,
    operating_system: str,
    architecture: str,
) -> PluginCapabilityManifest:
    key = trusted_keys.get(signed.signer_key_id)
    if key is None:
        raise PluginCompatibilityError("plugin signer is not trusted")
    expected = hmac.digest(
        key, canonical_bytes(signed.manifest), hashlib.sha256
    ).hex()
    if not hmac.compare_digest(expected, signed.signature_hex):
        raise PluginCompatibilityError("plugin manifest signature is invalid")
    manifest = signed.manifest
    if required_contract not in manifest.supported_contract_versions:
        raise PluginCompatibilityError("plugin does not support the required contract")
    if required_schema_version not in manifest.supported_schema_versions:
        raise PluginCompatibilityError("plugin does not support the required schema")
    if operating_system not in manifest.operating_systems:
        raise PluginCompatibilityError("plugin does not support this operating system")
    if architecture not in manifest.architectures:
        raise PluginCompatibilityError("plugin does not support this architecture")
    return manifest
