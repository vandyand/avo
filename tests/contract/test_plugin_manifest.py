import pytest

from avo_correlate.application.plugin_registry import (
    PluginCompatibilityError,
    sign_plugin_manifest,
    verify_plugin_manifest,
)
from avo_correlate.contracts.plugins import PluginCapabilityManifest
from tests.conftest import DIGEST_A, DIGEST_B


def manifest() -> PluginCapabilityManifest:
    return PluginCapabilityManifest(
        plugin_id="reference-evaluator",
        plugin_version="1.0.0",
        package_digest=DIGEST_A,
        source_digest=DIGEST_B,
        supported_contract_versions=["AuthoritativeEvaluator/1"],
        supported_schema_versions=[1],
        operating_systems=["linux"],
        architectures=["x86_64"],
        required_executables=["docker"],
        network_access="none",
        configuration_schema={"type": "object", "additionalProperties": False},
        side_effects=["writes:/output"],
        security_classification="trusted-team-sandbox",
        health_check=["python", "/app/entrypoint.py", "--health"],
        license="Proprietary",
    )


def test_signed_manifest_proves_compatibility() -> None:
    signed = sign_plugin_manifest(manifest(), key_id="release-1", signing_key=b"k" * 32)
    verified = verify_plugin_manifest(
        signed,
        trusted_keys={"release-1": b"k" * 32},
        required_contract="AuthoritativeEvaluator/1",
        required_schema_version=1,
        operating_system="linux",
        architecture="x86_64",
    )
    assert verified.plugin_id == "reference-evaluator"


def test_signing_key_must_meet_the_minimum_strength() -> None:
    with pytest.raises(ValueError, match="at least 32 bytes"):
        sign_plugin_manifest(manifest(), key_id="release-1", signing_key=b"too-short")


def test_untrusted_manifest_signer_fails_closed() -> None:
    signed = sign_plugin_manifest(manifest(), key_id="release-1", signing_key=b"k" * 32)

    with pytest.raises(PluginCompatibilityError, match="signer is not trusted"):
        verify_plugin_manifest(
            signed,
            trusted_keys={},
            required_contract="AuthoritativeEvaluator/1",
            required_schema_version=1,
            operating_system="linux",
            architecture="x86_64",
        )


def test_each_incompatible_manifest_dimension_fails_closed() -> None:
    signed = sign_plugin_manifest(manifest(), key_id="release-1", signing_key=b"k" * 32)
    trusted = {"release-1": b"k" * 32}

    with pytest.raises(PluginCompatibilityError, match="required contract"):
        verify_plugin_manifest(
            signed,
            trusted_keys=trusted,
            required_contract="AuthoritativeEvaluator/2",
            required_schema_version=1,
            operating_system="linux",
            architecture="x86_64",
        )
    with pytest.raises(PluginCompatibilityError, match="required schema"):
        verify_plugin_manifest(
            signed,
            trusted_keys=trusted,
            required_contract="AuthoritativeEvaluator/1",
            required_schema_version=2,
            operating_system="linux",
            architecture="x86_64",
        )
    with pytest.raises(PluginCompatibilityError, match="operating system"):
        verify_plugin_manifest(
            signed,
            trusted_keys=trusted,
            required_contract="AuthoritativeEvaluator/1",
            required_schema_version=1,
            operating_system="windows",
            architecture="x86_64",
        )
    with pytest.raises(PluginCompatibilityError, match="architecture"):
        verify_plugin_manifest(
            signed,
            trusted_keys=trusted,
            required_contract="AuthoritativeEvaluator/1",
            required_schema_version=1,
            operating_system="linux",
            architecture="aarch64",
        )


def test_tampered_or_incompatible_manifest_fails_closed() -> None:
    signed = sign_plugin_manifest(manifest(), key_id="release-1", signing_key=b"k" * 32)
    tampered = signed.model_copy(
        update={"manifest": signed.manifest.model_copy(update={"plugin_version": "forged"})}
    )
    with pytest.raises(PluginCompatibilityError, match="signature"):
        verify_plugin_manifest(
            tampered,
            trusted_keys={"release-1": b"k" * 32},
            required_contract="AuthoritativeEvaluator/1",
            required_schema_version=1,
            operating_system="linux",
            architecture="x86_64",
        )
