import base64
import hashlib
from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime
from typing import cast

import pytest

from avo_correlate.adapters.hosted_git import (
    GitHubEvidenceSnapshot,
    GitHubIntegrationProvider,
    GitHubProtectionPolicy,
    github_repository_digest,
)
from avo_correlate.adapters.hosted_git.github import JsonBody, JsonObject, JsonTransport, JsonValue
from avo_correlate.domain.canonical import canonical_digest

D = github_repository_digest("acme", "widget")
A = "a" * 40
B = "b" * 40
C = "c" * 40


def provider(transport: JsonTransport) -> GitHubIntegrationProvider:
    return GitHubIntegrationProvider(
        owner="acme",
        repo="widget",
        repository_digest=D,
        target_ref="refs/heads/integration",
        trusted_checks=(("ci", 15368),),
        protection_checks=(("ci", 15368),),
        freshness_cutoff=datetime(2026, 1, 1, tzinfo=UTC),
        protection_policy=GitHubProtectionPolicy(),
        token="memory-only-token",
        transport=transport,
    )


def repository() -> dict[str, JsonValue]:
    return cast(JsonObject, {
        "full_name": "acme/widget",
        "name": "widget",
        "owner": {"login": "acme"},
    })


def test_workflow_authority_hashes_exact_blob_and_variable() -> None:
    blob = b"workflow\r\n"
    expected = hashlib.sha256(blob).hexdigest()
    encoded = base64.b64encode(blob).decode()

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, body
        assert headers["Authorization"] == "Bearer memory-only-token"
        if url.endswith("/repos/acme/widget"):
            return 200, repository()
        if "/contents/.github/workflows/synthetic-validation.yml?ref=" in url:
            return 200, {
                "type": "file",
                "path": ".github/workflows/synthetic-validation.yml",
                "encoding": "base64",
                "content": encoded,
            }
        if url.endswith("/actions/variables/AVO_TRUSTED_WORKFLOW_SHA256"):
            return 200, {"name": "AVO_TRUSTED_WORKFLOW_SHA256", "value": expected}
        raise AssertionError(url)

    result = provider(transport).observe_workflow_authority(A)
    assert result.source_commit == A
    assert result.workflow_blob_digest == "sha256:" + expected
    assert result.repository_variables_digest == result.workflow_blob_digest


def test_workflow_authority_rejects_wrong_pin_and_path() -> None:
    blob = base64.b64encode(b"workflow").decode()

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, body, headers
        if url.endswith("/repos/acme/widget"):
            return 200, repository()
        if "/contents/" in url:
            return 200, {
                "type": "file",
                "path": ".github/workflows/synthetic-validation.yml",
                "encoding": "base64",
                "content": blob,
            }
        return 200, {"name": "AVO_TRUSTED_WORKFLOW_SHA256", "value": "0" * 64}

    with pytest.raises(ValueError, match="does not match"):
        provider(transport).observe_workflow_authority(A)
    with pytest.raises(ValueError, match="outside"):
        provider(transport).observe_workflow_authority(A, workflow_path="ci.yml")


@pytest.mark.parametrize(
    ("update", "message"),
    [
        ({"type": "directory"}, "identity or encoding"),
        ({"path": "other.yml"}, "identity or encoding"),
        ({"encoding": "utf-8"}, "identity or encoding"),
        ({"content": "not base64"}, "not valid base64"),
        ({"name": "OTHER"}, "identity mismatch"),
        ({"value": "Z" * 64}, "lowercase SHA-256"),
    ],
)
def test_workflow_authority_rejects_malformed_content_or_variable(
    update: dict[str, str], message: str
) -> None:
    blob = base64.b64encode(b"workflow").decode()

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, body, headers
        if url.endswith("/repos/acme/widget"):
            return 200, repository()
        if "/contents/" in url:
            payload: JsonObject = {
                "type": "file",
                "path": ".github/workflows/synthetic-validation.yml",
                "encoding": "base64",
                "content": blob,
            }
            if "name" not in update and "value" not in update:
                payload.update(cast(JsonObject, update))
            return 200, payload
        expected = hashlib.sha256(b"workflow").hexdigest()
        variable: JsonObject = {"name": "AVO_TRUSTED_WORKFLOW_SHA256", "value": expected}
        if "name" in update or "value" in update:
            variable.update(cast(JsonObject, update))
        return 200, variable

    with pytest.raises(ValueError, match=message):
        provider(transport).observe_workflow_authority(A)


def test_live_rollback_manifests_are_typed_and_source_bound() -> None:
    check_manifest = {
        "schema_version": 1,
        "trusted_checks": [{"context": "ci", "app_id": 15368}],
        "runs": [
            {
                "name": "ci",
                "app_id": 15368,
                "head_sha": C,
                "status": "completed",
                "conclusion": "success",
                "completed_at": "2026-02-01T00:00:00Z",
            }
        ],
    }
    protection = {
        "required_status_checks": {
            "strict": True,
            "checks": [{"context": "ci", "app_id": 15368}],
        },
        "required_pull_request_reviews": {
            "required_approving_review_count": 0,
            "dismiss_stale_reviews": True,
            "require_last_push_approval": False,
        },
        "enforce_admins": True,
        "required_linear_history": True,
        "required_conversation_resolution": True,
        "allow_force_pushes": False,
        "allow_deletions": False,
        "lock_branch": False,
    }
    snapshot = GitHubEvidenceSnapshot(
        synthetic_merge_commit=C,
        synthetic_merge_tree=B,
        protection_evidence_digest=canonical_digest(protection),
        check_evidence_manifest_digest=canonical_digest(check_manifest),
        protection_evidence=cast(JsonObject, protection),
        check_evidence_manifest=cast(JsonObject, check_manifest),
    )

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, url, body, headers
        return 200, repository()

    checks = provider(transport)
    check, protection_manifest = checks.live_rollback_manifests(
        snapshot, protection_source_commit=A
    )
    assert check.source_commit == C
    assert check.check_entries[0].app_id == 15368
    assert protection_manifest.source_commit == A
    assert protection_manifest.protection_entries[0].app_id == 15368
    assert protection_manifest.protection_entries[0].enforced


def _snapshot_with_runs(runs: list[JsonObject]) -> GitHubEvidenceSnapshot:
    manifest: JsonObject = {
        "schema_version": 1,
        "trusted_checks": [{"context": "ci", "app_id": 15368}],
        "runs": cast(JsonValue, runs),
    }
    protection: JsonObject = {
        "required_status_checks": {
            "strict": True,
            "checks": [{"context": "ci", "app_id": 15368}],
        },
        "required_pull_request_reviews": {
            "required_approving_review_count": 0,
            "dismiss_stale_reviews": True,
            "require_last_push_approval": False,
        },
        "enforce_admins": True,
        "required_linear_history": True,
        "required_conversation_resolution": True,
        "allow_force_pushes": False,
        "allow_deletions": False,
        "lock_branch": False,
    }
    return GitHubEvidenceSnapshot(
        synthetic_merge_commit=C,
        synthetic_merge_tree=B,
        protection_evidence_digest=canonical_digest(protection),
        check_evidence_manifest_digest=canonical_digest(manifest),
        protection_evidence=protection,
        check_evidence_manifest=manifest,
    )


def _run(name: str) -> JsonObject:
    return {
        "name": name,
        "app_id": 15368,
        "head_sha": C,
        "status": "completed",
        "conclusion": "success",
        "completed_at": "2026-02-01T00:00:00Z",
    }


def test_live_rollback_manifests_rejects_unexpected_and_duplicate_runs() -> None:
    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, url, body, headers
        return 200, repository()

    checks = provider(transport)
    with pytest.raises(ValueError, match="unexpected trusted check"):
        checks.live_rollback_manifests(
            _snapshot_with_runs([_run("ci"), _run("other")]),
            protection_source_commit=A,
        )
    with pytest.raises(ValueError, match="duplicate trusted check"):
        checks.live_rollback_manifests(
            _snapshot_with_runs([_run("ci"), _run("ci")]),
            protection_source_commit=A,
        )


def test_live_rollback_manifests_rejects_duplicate_declarations() -> None:
    snapshot = _snapshot_with_runs([_run("ci")])
    manifest = snapshot.check_evidence_manifest
    manifest["trusted_checks"] = cast(
        JsonValue,
        [
            {"context": "ci", "app_id": 15368},
            {"context": "ci", "app_id": 15368},
        ],
    )
    snapshot = replace(
        snapshot,
        check_evidence_manifest_digest=canonical_digest(manifest),
    )

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, url, body, headers
        return 200, repository()

    with pytest.raises(ValueError, match="duplicate trusted check declaration"):
        provider(transport).live_rollback_manifests(snapshot, protection_source_commit=A)


def test_live_rollback_manifests_rejects_wrong_target_and_digests() -> None:
    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, url, body, headers
        return 200, repository()

    checks = provider(transport)
    snapshot = _snapshot_with_runs([_run("ci")])
    with pytest.raises(ValueError, match="target ref"):
        checks.live_rollback_manifests(
            snapshot, protection_source_commit=A, target_ref="refs/heads/other"
        )
    with pytest.raises(ValueError, match="manifest digest"):
        checks.live_rollback_manifests(
            replace(snapshot, check_evidence_manifest_digest="sha256:" + "f" * 64),
            protection_source_commit=A,
        )


def test_live_rollback_manifests_rejects_noncanonical_protection_evidence() -> None:
    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, url, body, headers
        return 200, repository()

    snapshot = _snapshot_with_runs([_run("ci")])
    protection = dict(snapshot.protection_evidence)
    protection["allow_deletions"] = True
    changed = replace(
        snapshot,
        protection_evidence=protection,
        protection_evidence_digest=canonical_digest(protection),
    )
    with pytest.raises(ValueError, match="protection evidence"):
        provider(transport).live_rollback_manifests(changed, protection_source_commit=A)


@pytest.mark.parametrize(
    ("run_update", "message"),
    [
        ({"head_sha": A}, "completed successfully"),
        ({"status": "queued"}, "completed successfully"),
        ({"conclusion": "failure"}, "completed successfully"),
        ({"completed_at": "not-a-time"}, "timestamp is malformed"),
        ({"completed_at": "2026-02-01T00:00:00"}, "timezone-aware"),
        ({"completed_at": "2099-02-01T00:00:00Z"}, "future-dated"),
        ({"completed_at": "2025-02-01T00:00:00Z"}, "stale"),
    ],
)
def test_live_rollback_manifests_rejects_unusable_check_runs(
    run_update: dict[str, JsonValue], message: str
) -> None:
    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, url, body, headers
        return 200, repository()

    run = {**_run("ci"), **run_update}
    with pytest.raises(ValueError, match=message):
        provider(transport).live_rollback_manifests(
            _snapshot_with_runs([run]), protection_source_commit=A
        )
