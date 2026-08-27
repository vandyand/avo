"""Provision a host-local signed AVO Codex profile without copying credentials."""

import argparse
import hashlib
import os
import secrets
from pathlib import Path

from avo_correlate.adapters.harness.codex import (
    codex_permission_contract,
    strict_agent_completion_schema,
)
from avo_correlate.application.plugin_registry import sign_plugin_manifest
from avo_correlate.contracts.plugins import PluginCapabilityManifest
from avo_correlate.contracts.runtime import HarnessRuntimeProfile
from avo_correlate.domain.canonical import canonical_digest


def _digest_file(path: Path) -> str:
    with path.open("rb") as source:
        return "sha256:" + hashlib.file_digest(source, "sha256").hexdigest()


def _write_private_new(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--codex-executable", type=Path, required=True)
    parser.add_argument("--codex-home", type=Path, required=True)
    parser.add_argument("--private-tmpdir", type=Path, required=True)
    parser.add_argument("--canary-root", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--trusted-key", type=Path, required=True)
    parser.add_argument("--profile-id", default="codex-live-wsl-v6")
    parser.add_argument("--model", default="gpt-5.6-sol")
    return parser.parse_args()


def main() -> None:
    arguments = _arguments()
    executable = arguments.codex_executable.resolve(strict=True)
    codex_home = arguments.codex_home.resolve(strict=True)
    private_tmpdir = arguments.private_tmpdir.resolve()
    canary_root = arguments.canary_root.resolve()
    profile_path = arguments.profile.resolve()
    key_path = arguments.trusted_key.resolve()
    if profile_path.exists():
        raise SystemExit(f"refusing to overwrite existing profile: {profile_path}")
    if key_path.exists():
        signing_key = key_path.read_bytes()
        if len(signing_key) < 32:
            raise SystemExit("existing trusted key is shorter than 32 bytes")
    else:
        signing_key = secrets.token_bytes(32)
        _write_private_new(key_path, signing_key)
    if (
        private_tmpdir == Path(private_tmpdir.anchor)
        or private_tmpdir == Path.home()
        or private_tmpdir == codex_home
        or private_tmpdir.is_relative_to(codex_home)
    ):
        raise SystemExit("private TMPDIR must be narrow and outside CODEX_HOME")
    private_tmpdir.mkdir(parents=True, exist_ok=True)
    os.chmod(private_tmpdir, 0o700)
    canary_root.mkdir(parents=True, exist_ok=True)
    os.chmod(canary_root, 0o700)
    manifest = PluginCapabilityManifest(
        plugin_id="openai-codex",
        plugin_version="0.147.0",
        package_digest=_digest_file(executable),
        source_digest=canonical_digest(
            {"python_sdk": "openai-codex==0.147.0", "cli": "codex-cli 0.149.1"}
        ),
        supported_contract_versions=["HarnessRuntimeProfile.v1"],
        supported_schema_versions=[1],
        operating_systems=["linux"],
        architectures=["x86_64"],
        required_executables=[str(executable)],
        network_access="control-plane-only",
        configuration_schema={
            "required": [
                "isolated_codex_home",
                "private_tmpdir",
                "codex_executable",
                "canary_root",
            ]
        },
        side_effects=["workspace_write", "provider_thread"],
        security_classification="sandboxed-coding-agent",
        health_check=["permission-canaries", "chatgpt-account"],
        license="Apache-2.0",
    )
    signed = sign_plugin_manifest(
        manifest,
        key_id="avo-local-codex-live-v1",
        signing_key=signing_key,
    )
    runtime_profile = HarnessRuntimeProfile(
        profile_id=arguments.profile_id,
        plugin=signed,
        transport="sdk",
        requested_model=arguments.model,
        authentication_class="subscription",
        credential_profile_ref=None,
        permission_profile_digest=canonical_digest(codex_permission_contract()),
        development_evaluator_id="development",
        max_wall_time_seconds=900,
        max_turns=20,
        completion_schema_digest=canonical_digest(strict_agent_completion_schema()),
        configuration={
            "isolated_codex_home": str(codex_home),
            "private_tmpdir": str(private_tmpdir),
            "codex_executable": str(executable),
            "canary_root": str(canary_root),
        },
    )
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    _write_private_new(profile_path, runtime_profile.model_dump_json(indent=2).encode())
    print(f"profile={profile_path}")
    print(f"trusted_key={key_path}")
    print(f"codex_executable={executable}")
    print(f"codex_home={codex_home}")
    print(f"private_tmpdir={private_tmpdir}")


if __name__ == "__main__":
    main()
