import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, cast

# Tests intentionally exercise provider parsing internals for fail-closed coverage.
# pyright: reportPrivateUsage=false
import pytest

import avo_correlate.adapters.hosted_git.github as github_module
from avo_correlate.adapters.hosted_git.github import (
    GitHubIntegrationProvider,
    GitHubProtectionPolicy,
    GitHubRejected,
    GitHubTransportError,
    JsonBody,
    JsonObject,
    JsonTransport,
    JsonValue,
    github_repository_digest,
)
from avo_correlate.contracts.integration_campaign import campaign_marker_digest
from avo_correlate.contracts.integration_promotion import (
    IntegrationPromotionIntent,
    IntegrationPromotionPreconditionError,
    integration_operation_id,
)
from avo_correlate.domain.canonical import canonical_digest

D = github_repository_digest("acme", "widget")
G = "a" * 40
H = "b" * 40
C = "c" * 40


def valid_intent(**updates: object) -> IntegrationPromotionIntent:
    values: dict[str, Any] = {
        "repository_digest": D,
        "controller_lease_digest": D,
        "controller_lease_identity": "controller",
        "candidate_ref": "refs/heads/candidate/x",
        "target_ref": "refs/heads/integration",
        "base_commit": G,
        "base_tree": G,
        "candidate_commit": H,
        "candidate_tree": H,
        "candidate_repository_digest": D,
        "candidate_head_ref": "refs/heads/candidate/x",
        "candidate_head_commit": H,
        "candidate_head_tree": H,
        "target_repository_digest": D,
        "target_base_ref": "refs/heads/integration",
        "target_base_commit": G,
        "target_base_tree": G,
        "synthetic_merge_commit": C,
        "synthetic_merge_tree": H,
        "bundle_digest": D,
        "candidate_digest": D,
        "controller_config_digest": D,
        "publication_evidence_digest": D,
        "protection_evidence_digest": D,
        "evidence_manifest_digest": D,
        "check_evidence_manifest_digest": D,
        "pull_request_number": 7,
        "pull_request_url": "https://github.com/acme/widget/pull/7",
        "provider_identity": "github",
        "provider_api_version": "2022-11-28",
        "merge_method": "squash",
        "state": "intent_recorded",
    }
    values.update(updates)
    identity = {
        key: str(values[key])
        for key in (
            "repository_digest",
            "candidate_ref",
            "target_ref",
            "base_commit",
            "candidate_commit",
            "bundle_digest",
            "candidate_digest",
            "publication_evidence_digest",
            "provider_identity",
            "provider_api_version",
            "merge_method",
        )
    }
    identity.update(
        pull_request_number=str(values["pull_request_number"]),
        candidate_head_commit=str(values["candidate_head_commit"]),
        target_base_commit=str(values["target_base_commit"]),
        synthetic_merge_commit=str(values["synthetic_merge_commit"]),
    )
    values["operation_id"] = integration_operation_id(**identity)
    return IntegrationPromotionIntent.model_validate(values)


def provider_for_intent(
    intent: IntegrationPromotionIntent, transport: JsonTransport
) -> GitHubIntegrationProvider:
    return GitHubIntegrationProvider(
        owner="acme",
        repo="widget",
        repository_digest=D,
        target_ref=intent.target_ref,
        trusted_checks=(("ci", 7),),
        protection_checks=(("ci", 7),),
        freshness_cutoff=datetime(2026, 1, 1, tzinfo=UTC),
        protection_policy=GitHubProtectionPolicy(required_approving_review_count=0),
        transport=transport,
    )


def full_protection() -> JsonObject:
    return {
        "required_status_checks": {
            "strict": True,
            "contexts": ["ci"],
            "checks": [{"context": "ci", "app_id": 7}],
        },
        "required_pull_request_reviews": {
            "required_approving_review_count": 0,
            "dismiss_stale_reviews": True,
            "require_last_push_approval": False,
        },
        "enforce_admins": {"enabled": True},
        "required_linear_history": {"enabled": True},
        "required_conversation_resolution": {"enabled": True},
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
        "lock_branch": {"enabled": False},
    }


def full_protection_digest() -> str:
    return canonical_digest(
        {
            "required_status_checks": {
                "strict": True,
                "checks": [{"context": "ci", "app_id": 7}],
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
    )


def observation_responses(
    intent: IntegrationPromotionIntent, *, draft: bool | None = False
) -> dict[str, JsonValue]:
    protection: JsonValue = full_protection()
    check: JsonObject = {
        "id": 99,
        "name": "ci",
        "app": {"id": 7, "slug": "github-actions"},
        "head_sha": C,
        "status": "completed",
        "conclusion": "success",
        "completed_at": "2026-02-01T00:00:00Z",
        "details_url": "https://ci.example/99",
        "external_id": "run-99",
    }
    checks: JsonValue = {"total_count": 1, "check_runs": [check]}
    pull: JsonObject = {
        "number": 7,
        "html_url": intent.pull_request_url,
        "body": (
            "Automated campaign candidate.\n"
            f"AVO-Campaign-Marker: {campaign_marker_digest(intent)}\n"
        ),
        "state": "open",
        "draft": draft,
        "base": {"ref": "integration", "sha": G, "repo": {"full_name": "acme/widget"}},
        "head": {"ref": "candidate/x", "sha": H, "repo": {"full_name": "acme/widget"}},
        "merge_commit_sha": C,
    }
    values: dict[str, JsonValue] = {
        "pull": pull,
        "protection": protection,
        "checks": checks,
        "base_commit": {"sha": G, "tree": {"sha": G}, "parents": []},
        "head_commit": {"sha": H, "tree": {"sha": H}, "parents": [{"sha": G}]},
        "synthetic_commit": {"sha": C, "tree": {"sha": H}, "parents": [{"sha": G}]},
    }
    values["protection_digest"] = full_protection_digest()
    values["check_digest"] = canonical_digest(
        {
            "schema_version": 1,
            "synthetic_sha": C,
            "synthetic_tree": H,
            "protection_evidence_digest": full_protection_digest(),
            "provider_identity": "github",
            "provider_api_version": "2022-11-28",
            "trusted_checks": [{"context": "ci", "app_id": 7}],
            "freshness_cutoff": "2026-01-01T00:00:00Z",
            "total_count": 1,
            "page_count": 1,
            "runs": [
                {
                    "id": 99,
                    "name": "ci",
                    "app_id": 7,
                    "head_sha": C,
                    "app_slug": "github-actions",
                    "status": "completed",
                    "conclusion": "success",
                    "completed_at": "2026-02-01T00:00:00Z",
                }
            ],
        }
    )
    return values


def provider(
    *,
    target_ref: str = "refs/heads/integration",
    token: str | None = None,
    transport: JsonTransport | None = None,
) -> GitHubIntegrationProvider:
    if transport is None:
        return GitHubIntegrationProvider(
            owner="acme",
            repo="widget",
            repository_digest=D,
            target_ref=target_ref,
            trusted_checks=(("ci", 7),),
            protection_checks=(("ci", 7),),
            freshness_cutoff=datetime(2026, 1, 1, tzinfo=UTC),
            protection_policy=GitHubProtectionPolicy(required_approving_review_count=0),
            token=token,
        )
    return GitHubIntegrationProvider(
        owner="acme",
        repo="widget",
        repository_digest=D,
        target_ref=target_ref,
        trusted_checks=(("ci", 7),),
        protection_checks=(("ci", 7),),
        freshness_cutoff=datetime(2026, 1, 1, tzinfo=UTC),
        protection_policy=GitHubProtectionPolicy(required_approving_review_count=0),
        token=token,
        transport=transport,
    )


def test_requires_full_heads_target_ref() -> None:
    with pytest.raises(ValueError):
        provider(target_ref="integration")


def test_requires_repository_digest_bound_to_configured_repository() -> None:
    with pytest.raises(ValueError, match="repository digest"):
        GitHubIntegrationProvider(
            owner="acme",
            repo="widget",
            repository_digest="sha256:" + "f" * 64,
            target_ref="refs/heads/integration",
            trusted_checks=(("ci", 7),),
            protection_checks=(("ci", 7),),
            freshness_cutoff=datetime(2026, 1, 1, tzinfo=UTC),
        )


def test_public_target_observation_parses_github_git_commit_shape() -> None:
    sha = "a" * 40
    tree = "b" * 40
    parent = "c" * 40

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del body, headers
        if url.endswith("/git/ref/heads/integration"):
            return 200, {"object": {"sha": sha}}
        if url.endswith("/git/commits/" + sha):
            return 200, {"sha": sha, "tree": {"sha": tree}, "parents": [{"sha": parent}]}
        if url.endswith("/protection"):
            return 200, full_protection()
        raise AssertionError(f"unexpected request: {method} {url}")

    observed = provider(transport=transport).observe_integration("refs/heads/integration")
    assert observed.commit == sha
    assert observed.tree == tree
    assert observed.first_parent_commit == parent


def test_public_observation_rejects_case_changed_git_ref() -> None:
    with pytest.raises(ValueError, match="configured integration ref"):
        provider().observe_integration("refs/heads/Integration")


def test_transport_receives_api_version_and_auth_without_fallback() -> None:
    calls: list[tuple[str, str, JsonBody | None, Mapping[str, str]]] = []

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        calls.append((method, url, body, headers))
        return 200, {}

    configured = provider(token="secret", transport=transport)
    sha = "a" * 40

    def fake_response(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        calls.append((method, url, body, headers))
        if url.endswith("/git/ref/heads/integration"):
            return 200, {"object": {"sha": sha}}
        if url.endswith("/git/commits/" + sha):
            return 200, {"sha": sha, "tree": {"sha": sha}, "parents": []}
        if url.endswith("/protection"):
            return 200, full_protection()
        return 200, {}

    configured = provider(token="secret", transport=fake_response)
    configured.observe_integration("refs/heads/integration")
    assert calls[0][3]["Authorization"] == "Bearer secret"
    assert calls[0][3]["X-GitHub-Api-Version"] == configured.provider_api_version


def test_observe_requires_explicit_false_draft_field() -> None:
    base_intent = valid_intent()
    responses = observation_responses(base_intent)
    intent = valid_intent(
        protection_evidence_digest=responses["protection_digest"],
        check_evidence_manifest_digest=responses["check_digest"],
    )

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, body, headers
        if url.endswith("/pulls/7"):
            pull = responses["pull"]
            assert isinstance(pull, dict)
            return 200, {key: value for key, value in pull.items() if key != "draft"}
        if url.endswith("/git/commits/" + G):
            return 200, responses["base_commit"]
        if url.endswith("/git/commits/" + H):
            return 200, responses["head_commit"]
        if url.endswith("/git/commits/" + C):
            return 200, responses["synthetic_commit"]
        if "/check-runs?" in url:
            return 200, responses["checks"]
        if url.endswith("/protection"):
            return 200, responses["protection"]
        raise AssertionError(url)

    with pytest.raises(ValueError, match="identity/state"):
        provider_for_intent(intent, transport).observe(intent)


def test_merge_revalidates_pr_and_does_not_put_after_head_drift() -> None:
    initial = valid_intent()
    responses = observation_responses(initial)
    intent = valid_intent(
        protection_evidence_digest=responses["protection_digest"],
        check_evidence_manifest_digest=responses["check_digest"],
    )
    pr_reads = 0
    put_calls = 0

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        nonlocal pr_reads, put_calls
        del headers
        if url.endswith("/pulls/7"):
            pr_reads += 1
            pull = responses["pull"]
            assert isinstance(pull, dict)
            if pr_reads == 2:
                head = pull["head"]
                assert isinstance(head, dict)
                return 200, {**pull, "head": {**head, "sha": G}}
            return 200, pull
        if url.endswith("/git/ref/heads/integration"):
            return 200, {"object": {"sha": G}}
        if method == "PUT":
            put_calls += 1
            raise AssertionError("merge must not be requested after final revalidation drift")
        if url.endswith("/git/commits/" + G):
            return 200, responses["base_commit"]
        if url.endswith("/git/commits/" + H):
            return 200, responses["head_commit"]
        if url.endswith("/git/commits/" + C):
            return 200, responses["synthetic_commit"]
        if "/check-runs?" in url:
            return 200, responses["checks"]
        if url.endswith("/protection"):
            return 200, responses["protection"]
        raise AssertionError(url)

    provider_instance = provider_for_intent(intent, transport)
    provider_instance.observe(intent)
    with pytest.raises(ValueError, match="commit drift"):
        provider_instance.merge(intent, lease_guard=lambda: None)
    assert pr_reads == 2
    assert put_calls == 0


def _observation_transport(
    intent: IntegrationPromotionIntent,
    responses: dict[str, JsonValue],
    *,
    pull_updates: dict[str, JsonValue] | None = None,
    check_runs: list[JsonValue] | None = None,
    protection: JsonValue | None = None,
) -> tuple[JsonTransport, list[tuple[str, str, JsonBody | None, Mapping[str, str]]]]:
    calls: list[tuple[str, str, JsonBody | None, Mapping[str, str]]] = []

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        calls.append((method, url, body, headers))
        if url.endswith("/pulls/7"):
            pull = responses["pull"]
            assert isinstance(pull, dict)
            if pull_updates:
                pull = {**pull, **pull_updates}
            return 200, pull
        if url.endswith("/git/ref/heads/integration"):
            return 200, {"object": {"sha": G}}
        if url.endswith("/git/commits/" + G):
            return 200, responses["base_commit"]
        if url.endswith("/git/commits/" + H):
            return 200, responses["head_commit"]
        if url.endswith("/git/commits/" + C):
            return 200, responses["synthetic_commit"]
        if "/check-runs?" in url:
            default_checks = responses["checks"]
            assert isinstance(default_checks, dict)
            default_runs = default_checks["check_runs"]
            assert isinstance(default_runs, list)
            selected = check_runs if check_runs is not None else default_runs
            return 200, {"total_count": len(selected), "check_runs": selected}
        if url.endswith("/protection"):
            value = protection if protection is not None else responses["protection"]
            if "/branches/main/" in url:
                assert isinstance(value, dict)
                reviews = value["required_pull_request_reviews"]
                assert isinstance(reviews, dict)
                value = cast(
                    JsonValue,
                    {
                        **value,
                        "required_pull_request_reviews": {
                            **reviews,
                            "required_approving_review_count": 1,
                        },
                    },
                )
            return 200, value
        raise AssertionError(f"unexpected request: {method} {url}")

    del intent
    return transport, calls


def _bound_intent_and_responses() -> tuple[IntegrationPromotionIntent, dict[str, JsonValue]]:
    unbound = valid_intent()
    responses = observation_responses(unbound)
    intent = valid_intent(
        protection_evidence_digest=responses["protection_digest"],
        check_evidence_manifest_digest=responses["check_digest"],
    )
    return intent, responses


def test_observe_returns_exact_bound_provider_observation() -> None:
    intent, responses = _bound_intent_and_responses()
    transport, _ = _observation_transport(intent, responses)
    observed = provider_for_intent(intent, transport).observe(intent)
    assert observed.model_dump(exclude_none=True) == {
        "schema_version": 1,
        "repository_digest": D,
        "pull_request_number": 7,
        "pull_request_url": intent.pull_request_url,
        "candidate_repository_digest": D,
        "target_repository_digest": D,
        "base_ref": intent.target_ref,
        "base_commit": G,
        "base_tree": G,
        "head_ref": intent.candidate_ref,
        "head_commit": H,
        "candidate_tree": H,
        "synthetic_merge_commit": C,
        "synthetic_merge_tree": H,
        "protection_evidence_digest": responses["protection_digest"],
        "check_evidence_manifest_digest": responses["check_digest"],
        "provider_identity": "github",
        "provider_api_version": "2022-11-28",
        "open_state": "open",
        "draft": False,
    }


@pytest.mark.parametrize(
    ("check_update", "message"),
    [
        ({"app": {"id": 8, "slug": "github-actions"}}, "required trusted checks"),
        ({"name": "other"}, "required trusted checks"),
        ({"head_sha": H}, "duplicate, incomplete"),
        ({"status": "queued"}, "duplicate, incomplete"),
        ({"conclusion": "failure"}, "duplicate, incomplete"),
        ({"completed_at": "2025-01-01T00:00:00Z"}, "stale"),
        ({"completed_at": "2099-01-01T00:00:00Z"}, "future"),
    ],
)
def test_observe_rejects_untrusted_or_stale_check_evidence(
    check_update: dict[str, JsonValue], message: str
) -> None:
    intent, responses = _bound_intent_and_responses()
    raw = responses["checks"]
    assert isinstance(raw, dict) and isinstance(raw["check_runs"], list)
    check = raw["check_runs"][0]
    assert isinstance(check, dict)
    transport, _ = _observation_transport(
        intent, responses, check_runs=[{**check, **check_update}]
    )
    with pytest.raises(ValueError, match=message):
        provider_for_intent(intent, transport).observe(intent)


def test_observe_rejects_duplicate_trusted_check() -> None:
    intent, responses = _bound_intent_and_responses()
    raw = responses["checks"]
    assert isinstance(raw, dict) and isinstance(raw["check_runs"], list)
    check = raw["check_runs"][0]
    assert isinstance(check, dict)
    transport, _ = _observation_transport(intent, responses, check_runs=[check, check])
    with pytest.raises(ValueError, match="duplicate"):
        provider_for_intent(intent, transport).observe(intent)


def test_observe_rejects_protection_digest_drift() -> None:
    intent, responses = _bound_intent_and_responses()
    transport, _ = _observation_transport(intent, responses, protection={"required": False})
    with pytest.raises(ValueError, match=r"evidence|protection"):
        provider_for_intent(intent, transport).observe(intent)


@pytest.mark.parametrize(
    "pull_update",
    [
        {"base": {"ref": "other", "sha": G, "repo": {"full_name": "acme/widget"}}},
        {"head": {"ref": "candidate/x", "sha": H, "repo": {"full_name": "fork/widget"}}},
        {"head": {"ref": "candidate/x", "sha": G, "repo": {"full_name": "acme/widget"}}},
        {"base": {"ref": "integration", "sha": H, "repo": {"full_name": "acme/widget"}}},
        {"html_url": "https://github.com/acme/widget/pull/8"},
        {"number": 8},
        {"state": "closed"},
        {"draft": True},
    ],
)
def test_observe_rejects_pr_retarget_fork_head_base_url_or_state_drift(
    pull_update: dict[str, JsonValue],
) -> None:
    intent, responses = _bound_intent_and_responses()
    transport, _ = _observation_transport(intent, responses, pull_updates=pull_update)
    with pytest.raises(ValueError):
        provider_for_intent(intent, transport).observe(intent)


@pytest.mark.parametrize(
    "body",
    [
        "",
        "AVO-Campaign-Marker: sha256:" + "f" * 64,
        "AVO-Campaign-Marker: sha256:" + "f" * 64 + " trailing-text",
        "prefix AVO-Campaign-Marker: sha256:" + "f" * 64,
    ],
)
def test_observe_rejects_missing_wrong_or_near_match_campaign_marker(body: str) -> None:
    intent, responses = _bound_intent_and_responses()
    transport, _ = _observation_transport(intent, responses, pull_updates={"body": body})
    with pytest.raises(ValueError, match=r"campaign marker|identity/state|missing body"):
        provider_for_intent(intent, transport).observe(intent)


def test_merge_success_parses_squash_result_and_sends_one_put() -> None:
    intent, responses = _bound_intent_and_responses()
    result = "d" * 40
    result_tree = H
    result_parent = G
    transport, calls = _observation_transport(intent, responses)

    def wrapped(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        if method == "PUT":
            calls.append((method, url, body, headers))
            assert body == {"sha": H, "merge_method": "squash"}
            return 200, {
                "merged": True,
                "sha": result,
                "message": "Pull Request successfully merged",
            }
        if url.endswith("/git/commits/" + result):
            return 200, {
                "sha": result,
                "tree": {"sha": result_tree},
                "parents": [{"sha": result_parent}],
            }
        return transport(method, url, body, headers)

    merged = provider_for_intent(intent, wrapped).merge(intent, lease_guard=lambda: None)
    assert merged.outcome == "applied"
    assert merged.result_commit == result
    assert merged.result_tree == result_tree
    assert merged.first_parent_commit == result_parent
    puts = [call for call in calls if call[0] == "PUT"]
    assert len(puts) == 1


def test_merge_runs_lease_guard_after_full_target_observation_before_put() -> None:
    intent, responses = _bound_intent_and_responses()
    transport, calls = _observation_transport(intent, responses)
    result = "d" * 40

    def wrapped(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        if method == "PUT":
            calls.append((method, url, body, headers))
            return 200, {"merged": True, "sha": result}
        if url.endswith("/git/commits/" + result):
            return 200, {
                "sha": result,
                "tree": {"sha": H},
                "parents": [{"sha": G}],
            }
        return transport(method, url, body, headers)

    guard_positions: list[int] = []

    def guard() -> None:
        guard_positions.append(len(calls))
        assert calls[-1][0] == "GET"

    merged = provider_for_intent(intent, wrapped).merge(intent, lease_guard=guard)
    assert merged.outcome == "applied"
    assert guard_positions == [len(calls) - 1]
    assert calls[guard_positions[0]][0] == "PUT"
    assert [call[0] for call in calls].count("PUT") == 1


@pytest.mark.parametrize("field", ["approval", "admins"])
def test_merge_fails_closed_when_main_race_containment_protection_is_weak(
    field: str,
) -> None:
    intent, responses = _bound_intent_and_responses()
    transport, calls = _observation_transport(intent, responses)
    main = full_protection()
    if field == "approval":
        reviews = main["required_pull_request_reviews"]
        assert isinstance(reviews, dict)
        main["required_pull_request_reviews"] = {
            **reviews,
            "required_approving_review_count": 0,
        }
    else:
        admins = main["enforce_admins"]
        assert isinstance(admins, dict)
        main["enforce_admins"] = {**admins, "enabled": False}

    def weak_main(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        if "/branches/main/protection" in url:
            return 200, main
        return transport(method, url, body, headers)

    with pytest.raises(IntegrationPromotionPreconditionError, match=r"main branch protection"):
        provider_for_intent(intent, weak_main).merge(intent, lease_guard=lambda: None)
    assert [call[0] for call in calls].count("PUT") == 0


def test_merge_maps_main_protection_transport_failure_to_precondition() -> None:
    intent, responses = _bound_intent_and_responses()
    transport, calls = _observation_transport(intent, responses)

    def unavailable_main(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        if "/branches/main/protection" in url:
            raise GitHubTransportError("main protection unavailable")
        return transport(method, url, body, headers)

    with pytest.raises(IntegrationPromotionPreconditionError, match="main protection unavailable"):
        provider_for_intent(intent, unavailable_main).merge(intent, lease_guard=lambda: None)
    assert [call[0] for call in calls].count("PUT") == 0


def test_merge_rejects_external_two_parent_result() -> None:
    intent, responses = _bound_intent_and_responses()
    transport, _calls = _observation_transport(intent, responses)
    result = "d" * 40
    put_calls = 0

    def external_merge(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        nonlocal put_calls
        if method == "PUT":
            put_calls += 1
            return 200, {"merged": True, "sha": result}
        if url.endswith("/git/commits/" + result):
            return 200, {
                "sha": result,
                "tree": {"sha": H},
                "parents": [{"sha": G}, {"sha": "e" * 40}],
            }
        return transport(method, url, body, headers)

    with pytest.raises(ValueError, match="parent topology"):
        provider_for_intent(intent, external_merge).merge(intent, lease_guard=lambda: None)
    assert put_calls == 1


def test_merge_rejects_exact_target_head_drift_without_put() -> None:
    intent, responses = _bound_intent_and_responses()
    transport, calls = _observation_transport(intent, responses)

    def drifted_target(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        if url.endswith("/git/ref/heads/integration"):
            return 200, {"object": {"sha": H}}
        return transport(method, url, body, headers)

    with pytest.raises(ValueError, match="target head"):
        provider_for_intent(intent, drifted_target).merge(intent, lease_guard=lambda: None)
    assert [call[0] for call in calls].count("PUT") == 0


@pytest.mark.parametrize("status", [409, 405, 422])
def test_merge_maps_authoritative_rejections(status: int) -> None:
    intent, responses = _bound_intent_and_responses()
    transport, _ = _observation_transport(intent, responses)

    def rejecting(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        if method == "PUT":
            return status, {"message": "merge rejected"}
        return transport(method, url, body, headers)

    merged = provider_for_intent(intent, rejecting).merge(intent, lease_guard=lambda: None)
    assert merged.outcome == "rejected"
    assert merged.error is not None


@pytest.mark.parametrize("failure", [500, "exception"])
def test_merge_maps_server_or_transport_failure_to_ambiguity(failure: int | str) -> None:
    intent, responses = _bound_intent_and_responses()
    transport, _ = _observation_transport(intent, responses)

    def failing(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        if method == "PUT":
            if failure == "exception":
                raise OSError("connection reset")
            assert isinstance(failure, int)
            return failure, {"message": "server unavailable"}
        return transport(method, url, body, headers)

    merged = provider_for_intent(intent, failing).merge(intent, lease_guard=lambda: None)
    assert merged.outcome == "ambiguous"
    assert merged.error is not None


def test_merge_rejects_malformed_success_response() -> None:
    intent, responses = _bound_intent_and_responses()
    transport, _ = _observation_transport(intent, responses)

    def malformed(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        if method == "PUT":
            return 200, {"merged": True}
        return transport(method, url, body, headers)

    with pytest.raises(ValueError, match="merge response"):
        provider_for_intent(intent, malformed).merge(intent, lease_guard=lambda: None)


def _reconciliation_responses(
    intent: IntegrationPromotionIntent, *, merged: bool = True
) -> dict[str, JsonValue]:
    pull: JsonObject = {
        "number": 7,
        "html_url": intent.pull_request_url,
        "body": (
            "Merged campaign candidate.\n"
            f"AVO-Campaign-Marker: {campaign_marker_digest(intent)}\n"
        ),
        "state": "closed" if merged else "open",
        "merged": merged,
        "base": {"ref": "integration", "repo": {"full_name": "acme/widget"}},
        "head": {"ref": "candidate/x", "sha": H, "repo": {"full_name": "acme/widget"}},
    }
    if merged:
        pull["merge_commit_sha"] = "d" * 40
    return {
        "pull": pull,
        "ref": {"object": {"sha": C if merged else G}},
        "commit": {
            "sha": C if merged else G,
            "tree": {"sha": H if merged else G},
            "parents": [{"sha": G}],
        },
        "protection": full_protection(),
    }


@pytest.mark.parametrize("merged", [True, False])
def test_reconcile_returns_exact_merged_or_unmerged_state(merged: bool) -> None:
    intent, _ = _bound_intent_and_responses()
    responses = _reconciliation_responses(intent, merged=merged)

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, body, headers
        if url.endswith("/pulls/7"):
            return 200, responses["pull"]
        if "/git/ref/heads/integration" in url:
            return 200, responses["ref"]
        if url.endswith("/git/commits/" + (C if merged else G)):
            return 200, responses["commit"]
        if url.endswith("/protection"):
            return 200, responses["protection"]
        raise AssertionError(url)

    reconciliation = provider_for_intent(intent, transport).reconcile(intent)
    assert reconciliation.merged is merged
    assert reconciliation.state == ("closed" if merged else "open")
    assert reconciliation.merge_commit == (("d" * 40) if merged else None)
    assert reconciliation.target_head_commit == (C if merged else G)


def test_reconcile_rejects_external_two_parent_merge() -> None:
    intent, _ = _bound_intent_and_responses()
    responses = _reconciliation_responses(intent, merged=True)
    commit = responses["commit"]
    assert isinstance(commit, dict)
    responses["commit"] = {**commit, "parents": [{"sha": G}, {"sha": "e" * 40}]}

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, body, headers
        if url.endswith("/pulls/7"):
            return 200, responses["pull"]
        if "/git/ref/heads/integration" in url:
            return 200, responses["ref"]
        if url.endswith("/git/commits/" + C):
            return 200, responses["commit"]
        if url.endswith("/protection"):
            return 200, responses["protection"]
        raise AssertionError(url)

    with pytest.raises(ValueError, match="parent topology"):
        provider_for_intent(intent, transport).reconcile(intent)


@pytest.mark.parametrize(
    "head_update",
    [
        {"ref": "other", "sha": H, "repo": {"full_name": "acme/widget"}},
        {"sha": G, "repo": {"full_name": "acme/widget"}},
        {"ref": "candidate/x", "repo": {"full_name": "acme/widget"}},
        {"ref": "candidate/x", "sha": H, "repo": {"full_name": "fork/widget"}},
    ],
)
def test_reconcile_rejects_merged_head_binding_drift_or_missing_fields(
    head_update: dict[str, JsonValue],
) -> None:
    intent, _ = _bound_intent_and_responses()
    responses = _reconciliation_responses(intent, merged=True)
    pull = responses["pull"]
    assert isinstance(pull, dict)
    responses["pull"] = {**pull, "head": head_update}

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, body, headers
        if url.endswith("/pulls/7"):
            return 200, responses["pull"]
        if "/git/ref/heads/integration" in url:
            return 200, responses["ref"]
        if url.endswith("/git/commits/" + C):
            return 200, responses["commit"]
        if url.endswith("/protection"):
            return 200, responses["protection"]
        raise AssertionError(url)

    with pytest.raises(ValueError):
        provider_for_intent(intent, transport).reconcile(intent)


def test_reconcile_rejects_campaign_marker_drift() -> None:
    intent, _ = _bound_intent_and_responses()
    responses = _reconciliation_responses(intent, merged=True)
    pull = responses["pull"]
    assert isinstance(pull, dict)
    responses["pull"] = {**pull, "body": "AVO-Campaign-Marker: sha256:" + "f" * 64}

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, body, headers
        if url.endswith("/pulls/7"):
            return 200, responses["pull"]
        if "/git/ref/heads/integration" in url:
            return 200, responses["ref"]
        if url.endswith("/git/commits/" + C):
            return 200, responses["commit"]
        if url.endswith("/protection"):
            return 200, responses["protection"]
        raise AssertionError(url)

    with pytest.raises(ValueError, match=r"campaign marker|reconciliation binding"):
        provider_for_intent(intent, transport).reconcile(intent)


@pytest.mark.parametrize(
    "pull_update",
    [
        {"number": 8},
        {"html_url": "https://github.com/acme/widget/pull/8"},
        {"base": {"ref": "other", "repo": {"full_name": "acme/widget"}}},
        {"base": {"ref": "integration", "repo": {"full_name": "fork/widget"}}},
        {"head": {"ref": "candidate/x", "sha": H, "repo": {"full_name": "fork/widget"}}},
        {"head": {"ref": "other", "sha": H, "repo": {"full_name": "acme/widget"}}},
        {"head": {"ref": "candidate/x", "sha": G, "repo": {"full_name": "acme/widget"}}},
    ],
)
def test_reconcile_rejects_identity_ref_repository_or_head_drift(
    pull_update: dict[str, JsonValue],
) -> None:
    intent, _ = _bound_intent_and_responses()
    responses = _reconciliation_responses(intent, merged=False)
    pull = responses["pull"]
    assert isinstance(pull, dict)
    responses["pull"] = {**pull, **pull_update}

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, body, headers
        if url.endswith("/pulls/7"):
            return 200, responses["pull"]
        if "/git/ref/heads/integration" in url:
            return 200, responses["ref"]
        if url.endswith("/git/commits/" + G):
            return 200, responses["commit"]
        if url.endswith("/protection"):
            return 200, responses["protection"]
        raise AssertionError(url)

    with pytest.raises(
        ValueError, match=r"reconciliation binding|head reconciliation|repository mismatch"
    ):
        provider_for_intent(intent, transport).reconcile(intent)


@pytest.mark.parametrize(
    ("section", "key", "value"),
    [
        ("required_status_checks", "strict", False),
        ("required_pull_request_reviews", "required_approving_review_count", 1),
        ("required_pull_request_reviews", "dismiss_stale_reviews", False),
        ("required_pull_request_reviews", "require_last_push_approval", True),
        ("enforce_admins", "enabled", False),
        ("required_linear_history", "enabled", False),
        ("required_conversation_resolution", "enabled", False),
        ("allow_force_pushes", "enabled", True),
        ("allow_deletions", "enabled", True),
        ("lock_branch", "enabled", True),
    ],
)
def test_protection_evidence_rejects_weak_or_dangerous_policy(
    section: str, key: str, value: JsonValue
) -> None:
    protection = full_protection()
    nested = protection[section]
    assert isinstance(nested, dict)
    nested[key] = value

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, body, headers
        if url.endswith("/git/ref/heads/integration"):
            return 200, {"object": {"sha": G}}
        if url.endswith("/git/commits/" + G):
            return 200, {"sha": G, "tree": {"sha": G}, "parents": []}
        if url.endswith("/protection"):
            return 200, protection
        raise AssertionError(url)

    with pytest.raises(ValueError, match=r"protection|trusted"):
        provider(transport=transport).observe_integration("refs/heads/integration")


def test_protection_evidence_requires_exact_context_and_app_allowlist() -> None:
    protection = full_protection()
    status = protection["required_status_checks"]
    assert isinstance(status, dict)
    status["checks"] = [{"context": "ci", "app_id": 7}, {"context": "other", "app_id": 8}]

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, body, headers
        if url.endswith("/git/ref/heads/integration"):
            return 200, {"object": {"sha": G}}
        if url.endswith("/git/commits/" + G):
            return 200, {"sha": G, "tree": {"sha": G}, "parents": []}
        if url.endswith("/protection"):
            return 200, protection
        raise AssertionError(url)

    with pytest.raises(ValueError, match=r"required checks|contexts"):
        provider(transport=transport).observe_integration("refs/heads/integration")


def test_protection_checks_are_separate_from_exact_synthetic_checks() -> None:
    protection = full_protection()
    synthetic = _check_run(99, "synthetic-ci", 9)

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, body, headers
        if url.endswith("/protection"):
            return 200, protection
        if "/check-runs?" in url:
            return 200, {"total_count": 1, "check_runs": [synthetic]}
        raise AssertionError(url)

    configured = GitHubIntegrationProvider(
        owner="acme",
        repo="widget",
        repository_digest=D,
        target_ref="refs/heads/integration",
        trusted_checks=(("synthetic-ci", 9),),
        protection_checks=(("ci", 7),),
        freshness_cutoff=datetime(2026, 1, 1, tzinfo=UTC),
        protection_policy=GitHubProtectionPolicy(required_approving_review_count=0),
        transport=transport,
    )
    snapshot = configured._evidence_snapshot(C, H)  # type: ignore[reportPrivateUsage]
    assert snapshot.protection_evidence["required_status_checks"] == {
        "strict": True,
        "checks": [{"context": "ci", "app_id": 7}],
    }
    assert snapshot.check_evidence_manifest["trusted_checks"] == [
        {"context": "synthetic-ci", "app_id": 9}
    ]


def test_non_success_transport_status_fails_closed() -> None:
    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, url, body, headers
        return 302, {}

    with pytest.raises(GitHubTransportError, match="unexpected status"):
        provider(transport=transport).observe_integration("refs/heads/integration")


def test_protection_policy_is_typed_and_configurable_for_integration_approvals() -> None:
    protection = full_protection()
    reviews = protection["required_pull_request_reviews"]
    assert isinstance(reviews, dict)
    reviews["required_approving_review_count"] = 1

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, body, headers
        if url.endswith("/git/ref/heads/integration"):
            return 200, {"object": {"sha": G}}
        if url.endswith("/git/commits/" + G):
            return 200, {"sha": G, "tree": {"sha": G}, "parents": []}
        if url.endswith("/protection"):
            return 200, protection
        raise AssertionError(url)

    configured = provider(transport=transport)
    with pytest.raises(ValueError, match="approval count"):
        configured.observe_integration("refs/heads/integration")
    configured_one = GitHubIntegrationProvider(
        owner="acme",
        repo="widget",
        repository_digest=D,
        target_ref="refs/heads/integration",
        trusted_checks=(("ci", 7),),
        protection_checks=(("ci", 7),),
        freshness_cutoff=datetime(2026, 1, 1, tzinfo=UTC),
        protection_policy=GitHubProtectionPolicy(required_approving_review_count=1),
        transport=transport,
    )
    observed = configured_one.observe_integration("refs/heads/integration")
    assert observed.protection_evidence_digest != full_protection_digest()


def _check_run(
    run_id: int, name: str, app_id: int, *, completed_at: str | None = "2026-02-01T00:00:00Z"
) -> JsonObject:
    run: JsonObject = {
        "id": run_id,
        "name": name,
        "app": {"id": app_id, "slug": "github-actions"},
        "head_sha": C,
        "status": "completed",
        "conclusion": "success",
    }
    if completed_at is not None:
        run["completed_at"] = completed_at
    return run


def _page_payload(total_count: int, items: list[JsonObject]) -> JsonObject:
    typed_items: list[JsonValue] = list(items)
    return {"total_count": total_count, "check_runs": typed_items}


def _check_manifest_digest() -> str:
    return canonical_digest(
        {
            "schema_version": 1,
            "synthetic_sha": C,
            "synthetic_tree": H,
            "protection_evidence_digest": full_protection_digest(),
            "provider_identity": "github",
            "provider_api_version": "2022-11-28",
            "trusted_checks": [{"context": "ci", "app_id": 7}],
            "freshness_cutoff": "2026-01-01T00:00:00Z",
            "total_count": 101,
            "page_count": 2,
            "runs": [
                {
                    "id": 99,
                    "name": "ci",
                    "app_id": 7,
                    "head_sha": C,
                    "app_slug": "github-actions",
                    "status": "completed",
                    "conclusion": "success",
                    "completed_at": "2026-02-01T00:00:00Z",
                }
            ],
        }
    )


def _paginated_observation_transport(
    intent: IntegrationPromotionIntent,
    responses: dict[str, JsonValue],
    pages: list[list[JsonObject]],
    totals: list[int] | None = None,
) -> tuple[JsonTransport, list[str]]:
    calls: list[str] = []
    declared_totals = totals if totals is not None else [101] * len(pages)

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, body, headers
        if url.endswith("/pulls/7"):
            return 200, responses["pull"]
        if url.endswith("/git/commits/" + G):
            return 200, responses["base_commit"]
        if url.endswith("/git/commits/" + H):
            return 200, responses["head_commit"]
        if url.endswith("/git/commits/" + C):
            return 200, responses["synthetic_commit"]
        if "/check-runs?" in url:
            calls.append(url)
            page = int(url.rsplit("page=", 1)[1])
            return 200, _page_payload(declared_totals[page - 1], pages[page - 1])
        if url.endswith("/protection"):
            return 200, responses["protection"]
        raise AssertionError(url)

    del intent
    return transport, calls


def test_check_evidence_uses_bounded_total_count_pagination_and_self_describing_manifest() -> None:
    all_runs = [_check_run(99, "ci", 7)] + [
        _check_run(1000 + index, f"other-{index}", 8) for index in range(100)
    ]
    pages = [all_runs[:100], all_runs[100:]]
    intent = valid_intent(
        protection_evidence_digest=full_protection_digest(),
        check_evidence_manifest_digest=_check_manifest_digest(),
    )
    responses = observation_responses(intent)
    transport, calls = _paginated_observation_transport(intent, responses, pages)
    observed = provider_for_intent(intent, transport).observe(intent)
    assert len(calls) == 2
    assert "per_page=100&page=1" in calls[0]
    assert "per_page=100&page=2" in calls[1]
    assert observed.check_evidence_manifest_digest == _check_manifest_digest()


def test_check_evidence_rejects_inconsistent_or_duplicate_pages() -> None:
    first = [_check_run(99, "ci", 7)] + [_check_run(1000 + i, f"other-{i}", 8) for i in range(99)]
    intent = valid_intent()
    responses = observation_responses(intent)
    transport, _ = _paginated_observation_transport(
        intent, responses, [first[:-1], first[-1:]]
    )

    with pytest.raises(ValueError, match="inconsistent"):
        provider_for_intent(intent, transport).observe(intent)

    duplicate_pages = [first, [_check_run(99, "ci", 7)]]
    duplicate_transport, _ = _paginated_observation_transport(
        intent, responses, duplicate_pages
    )

    with pytest.raises(ValueError, match="duplicate"):
        provider_for_intent(intent, duplicate_transport).observe(intent)


def test_check_evidence_requires_completed_at_and_does_not_fallback_to_updated_at() -> None:
    check = _check_run(99, "ci", 7, completed_at=None)
    check["updated_at"] = "2026-02-01T00:00:00Z"
    intent = valid_intent()
    responses = observation_responses(intent)
    transport, _ = _paginated_observation_transport(intent, responses, [[check]], [1])

    with pytest.raises(ValueError, match="completed_at"):
        provider_for_intent(intent, transport).observe(intent)


def test_token_is_not_exposed_in_repr_or_error() -> None:
    secret = "super-secret-token"
    configured = provider(token=secret)
    assert secret not in repr(configured)
    with pytest.raises(ValueError) as caught:
        configured.observe(valid_intent(repository_digest="sha256:" + "f" * 64))
    assert secret not in str(caught.value)


def test_create_pull_request_binds_same_repo_refs_and_candidate_sha() -> None:
    intent, responses = _bound_intent_and_responses()
    pull = responses["pull"]
    assert isinstance(pull, dict)
    calls: list[tuple[str, str, JsonBody | None]] = []

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del headers
        calls.append((method, url, body))
        if method == "POST" and url.endswith("/pulls"):
            return 201, pull
        raise AssertionError((method, url))

    created = provider_for_intent(intent, transport).create_pull_request(
        intent.candidate_ref,
        intent.candidate_commit,
        base_commit=intent.base_commit,
        title="Automated candidate",
        body="candidate body",
    )
    assert created.number == intent.pull_request_number
    assert created.base_ref == intent.target_ref
    assert created.head_ref == intent.candidate_ref
    assert calls[0][2] == {
        "title": "Automated candidate",
        "head": "candidate/x",
        "base": "integration",
        "body": "candidate body",
        "draft": False,
    }


def test_create_pull_request_rejects_target_base_drift() -> None:
    intent, responses = _bound_intent_and_responses()
    pull = responses["pull"]
    assert isinstance(pull, dict)
    base = pull["base"]
    assert isinstance(base, dict)
    drifted: JsonObject = dict(pull)
    drifted["base"] = {**base, "sha": "d" * 40}

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, url, body, headers
        return 201, drifted

    with pytest.raises(ValueError, match="repository/ref/commit mismatch"):
        provider_for_intent(intent, transport).create_pull_request(
            intent.candidate_ref,
            intent.candidate_commit,
            base_commit=intent.base_commit,
            title="Automated candidate",
            body="candidate body",
        )


def test_open_or_reconcile_reuses_exact_existing_pull_request_without_post() -> None:
    intent, responses = _bound_intent_and_responses()
    calls: list[str] = []

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del body, headers
        calls.append(method)
        assert "pulls?state=open" in url
        return 200, [responses["pull"]]

    binding = provider_for_intent(intent, transport).open_or_reconcile_pull_request(
        intent.candidate_ref,
        intent.candidate_commit,
        base_commit=intent.base_commit,
        title="Automated candidate",
        body="candidate body",
    )
    assert binding.number == intent.pull_request_number
    assert calls == ["GET"]


def test_open_or_reconcile_observes_once_after_ambiguous_post() -> None:
    intent, responses = _bound_intent_and_responses()
    calls: list[str] = []

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del body, headers
        calls.append(method)
        if calls == ["GET"]:
            return 200, []
        if method == "POST":
            raise GitHubTransportError("lost acknowledgement")
        assert "pulls?state=open" in url
        return 200, [responses["pull"]]

    binding = provider_for_intent(intent, transport).open_or_reconcile_pull_request(
        intent.candidate_ref,
        intent.candidate_commit,
        base_commit=intent.base_commit,
        title="Automated candidate",
        body="candidate body",
    )
    assert binding.number == intent.pull_request_number
    assert calls == ["GET", "POST", "GET"]


def test_update_and_verify_campaign_marker_are_single_bounded_body_operations() -> None:
    intent, responses = _bound_intent_and_responses()
    pull = responses["pull"]
    assert isinstance(pull, dict)
    calls: list[str] = []

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del headers
        if method == "GET" and url.endswith("/pulls/7"):
            calls.append("GET")
            return 200, pull
        if method == "PATCH" and url.endswith("/pulls/7"):
            calls.append("PATCH")
            assert body == {
                "body": "candidate body\nAVO-Campaign-Marker: "
                + campaign_marker_digest(intent)
            }
            return 200, {**pull, "body": body["body"] if body else ""}
        raise AssertionError((method, url))

    updated = provider_for_intent(intent, transport).update_campaign_marker(
        intent, body="candidate body\nAVO-Campaign-Marker: invalid"
    )
    assert updated.body.endswith(campaign_marker_digest(intent))
    assert calls == ["GET", "PATCH"]


def test_discover_pull_request_evidence_returns_only_sanitized_allowlisted_fields() -> None:
    intent, responses = _bound_intent_and_responses()

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, body, headers
        if url.endswith("/pulls/7"):
            return 200, responses["pull"]
        if url.endswith("/git/commits/" + C):
            return 200, responses["synthetic_commit"]
        if "/check-runs?" in url:
            return 200, responses["checks"]
        if url.endswith("/protection"):
            return 200, responses["protection"]
        raise AssertionError(url)

    discovery = provider_for_intent(intent, transport).discover_pull_request_evidence(
        intent.pull_request_number,
        candidate_ref=intent.candidate_ref,
        candidate_commit=intent.candidate_commit,
        base_commit=intent.base_commit,
        campaign_marker=campaign_marker_digest(intent),
    )
    assert discovery.synthetic_merge_commit == C
    assert discovery.synthetic_merge_tree == H
    assert discovery.evidence.check_evidence_manifest_digest == responses["check_digest"]
    assert discovery.evidence.protection_evidence_digest == responses["protection_digest"]
    assert "details_url" not in json.dumps(discovery.evidence.raw_evidence)
    assert "external_id" not in json.dumps(discovery.evidence.raw_evidence)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"owner": "acme/x"}, "repository binding"),
        ({"api_base": "http://api.github.com"}, "API base"),
        ({"trusted_checks": (("ci", 7), ("ci", 7))}, "unique"),
        ({"protection_checks": (("ci", 7), ("ci", 7))}, "unique"),
        ({"freshness_cutoff": datetime(2026, 1, 1)}, "timezone"),
        ({"trusted_checks": (("", 7),)}, "non-empty"),
        ({"protection_checks": (("", 7),)}, "non-empty"),
        ({"trusted_checks": (("ci", -1),)}, "non-negative"),
        ({"protection_checks": (("ci", -1),)}, "non-negative"),
    ],
)
def test_provider_constructor_rejects_malformed_configuration(
    kwargs: dict[str, Any], message: str
) -> None:
    values: dict[str, Any] = {
        "owner": "acme",
        "repo": "widget",
        "repository_digest": D,
        "target_ref": "refs/heads/integration",
        "trusted_checks": (("ci", 7),),
        "protection_checks": (("ci", 7),),
        "freshness_cutoff": datetime(2026, 1, 1, tzinfo=UTC),
    }
    values.update(kwargs)
    with pytest.raises(ValueError, match=message):
        GitHubIntegrationProvider(**values)


def test_provider_requires_explicit_protection_checks() -> None:
    with pytest.raises(TypeError):
        GitHubIntegrationProvider(  # pyright: ignore[reportCallIssue]
            owner="acme",
            repo="widget",
            repository_digest=D,
            target_ref="refs/heads/integration",
            trusted_checks=(("ci", 7),),
            freshness_cutoff=datetime(2026, 1, 1, tzinfo=UTC),
        )


@pytest.mark.parametrize(
    "value",
    [
        "refs/heads/",
        "refs/heads/main",
        "refs/heads/master",
        "refs/heads/production-hotfix",
        "refs/heads/deploy-now",
        "refs/heads/bad..name",
        "refs/heads/bad:name",
    ],
)
def test_branch_scope_rejects_non_integration_refs(value: str) -> None:
    with pytest.raises(ValueError):
        provider()._branch(value, "candidate ref")


def test_json_and_git_shape_helpers_fail_closed_on_malformed_values() -> None:
    with pytest.raises(ValueError, match="malformed JSON"):
        github_module._json_value({1: "not a string key"})
    with pytest.raises(ValueError, match="malformed JSON"):
        github_module._json_value(object())
    with pytest.raises(ValueError, match="malformed Git commit"):
        GitHubIntegrationProvider._commit_parts({"sha": G, "tree": {"sha": H}})
    with pytest.raises(ValueError, match="Git parent"):
        GitHubIntegrationProvider._commit_parts(
            {"sha": G, "tree": {"sha": H}, "parents": [{}]}
        )
    with pytest.raises(ValueError, match="campaign marker"):
        provider()._marker_line("invalid")


@pytest.mark.parametrize("status", [500, 400, 199])
def test_call_maps_server_rejection_and_unexpected_statuses(status: int) -> None:
    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, url, body, headers
        return status, {}

    expected = GitHubTransportError if status in {500, 199} else GitHubRejected
    with pytest.raises(expected):
        provider(transport=transport)._call("GET", "health")

    def failing(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, url, body, headers
        raise OSError("socket closed")

    with pytest.raises(GitHubTransportError, match="transport failure"):
        provider(transport=failing)._call("GET", "health")


def test_find_open_pull_request_handles_empty_oversized_multiple_and_bad_number() -> None:
    intent = valid_intent()
    responses = observation_responses(intent)

    def transport_for(value: JsonValue) -> JsonTransport:
        def transport(
            method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
        ) -> tuple[int, JsonValue]:
            del method, url, body, headers
            return 200, value

        return transport

    configured = provider_for_intent(intent, transport_for([]))
    assert configured._find_open_pull_request(intent.candidate_ref, H, G) is None
    with pytest.raises(ValueError, match="multiple"):
        provider_for_intent(
            intent, transport_for([responses["pull"], responses["pull"]])
        )._find_open_pull_request(
            intent.candidate_ref, H, G
        )
    with pytest.raises(ValueError, match="oversized"):
        provider_for_intent(
            intent, transport_for([responses["pull"]] * 101)
        )._find_open_pull_request(
            intent.candidate_ref, H, G
        )
    bad_pull: JsonObject = dict(cast(JsonObject, responses["pull"]))
    bad_pull["number"] = 0
    with pytest.raises(ValueError, match="number"):
        provider_for_intent(intent, transport_for([bad_pull]))._find_open_pull_request(
            intent.candidate_ref, H, G
        )


def test_open_or_reconcile_does_not_repeat_post_when_recovery_is_absent() -> None:
    intent = valid_intent()
    calls: list[str] = []

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del url, body, headers
        calls.append(method)
        if method == "POST":
            raise GitHubTransportError("lost acknowledgement")
        return 200, []

    with pytest.raises(GitHubTransportError):
        provider_for_intent(intent, transport).open_or_reconcile_pull_request(
            intent.candidate_ref, H, base_commit=G, title="title", body="body"
        )
    assert calls == ["GET", "POST", "GET"]


VALIDATION_REF = "refs/heads/avo/validation/" + "d" * 64


def test_validation_ref_read_resolves_exact_commit_and_tree() -> None:
    calls: list[tuple[str, str, JsonBody | None]] = []

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del headers
        calls.append((method, url, body))
        if method == "GET" and url.endswith(
            "/git/ref/heads/avo%2Fvalidation%2F" + "d" * 64
        ):
            return 200, cast(
                JsonValue, {"ref": VALIDATION_REF, "object": {"type": "commit", "sha": C}}
            )
        if method == "GET" and url.endswith("/git/commits/" + C):
            return 200, cast(JsonValue, {"sha": C, "tree": {"sha": H}, "parents": []})
        raise AssertionError(url)

    assert provider(transport=transport).read_validation_ref(D, VALIDATION_REF) == {
        "commit": C,
        "tree": H,
    }
    assert [item[0] for item in calls] == ["GET", "GET"]


def test_synthetic_validation_observation_never_reads_checks() -> None:
    intent = valid_intent()
    responses = observation_responses(intent)
    calls: list[str] = []

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del body, headers
        calls.append(url)
        if method != "GET":
            raise AssertionError("validation observation must be read-only")
        if url.endswith("/pulls/7"):
            return 200, responses["pull"]
        for name, key in (
            (G, "base_commit"),
            (H, "head_commit"),
            (C, "synthetic_commit"),
        ):
            if url.endswith("/git/commits/" + name):
                return 200, responses[key]
        raise AssertionError(url)

    observation = provider_for_intent(intent, transport).observe_synthetic_validation(
        7,
        candidate_ref=intent.candidate_ref,
        candidate_commit=H,
        base_commit=G,
    )
    assert observation.base_tree == G
    assert observation.head_tree == H
    assert observation.synthetic_commit == C
    assert observation.synthetic_tree == H
    assert not any("check-runs" in url or "protection" in url for url in calls)


def test_validation_ref_create_delete_have_exact_shape_and_scope() -> None:
    calls: list[tuple[str, str, JsonBody | None]] = []

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del headers
        calls.append((method, url, body))
        if method == "POST":
            return 201, cast(
                JsonValue, {"ref": VALIDATION_REF, "object": {"type": "commit", "sha": C}}
            )
        return 204, cast(JsonValue, {})

    configured = provider(transport=transport)
    configured.create_validation_ref(D, VALIDATION_REF, C)
    configured.delete_validation_ref(D, VALIDATION_REF)
    assert calls[0] == (
        "POST",
        configured.api_base + "/repos/acme/widget/git/refs",
        {"ref": VALIDATION_REF, "sha": C},
    )
    assert calls[1] == (
        "DELETE",
        configured.api_base
        + "/repos/acme/widget/git/refs/heads/avo%2Fvalidation%2F"
        + "d" * 64,
        None,
    )


@pytest.mark.parametrize("method", ["read", "create", "delete"])
def test_validation_ref_rejects_wrong_binding_before_transport(method: str) -> None:
    calls = 0

    def transport(*args: object, **kwargs: object) -> tuple[int, JsonValue]:
        nonlocal calls
        calls += 1
        raise AssertionError("transport must not be called")

    configured = provider(transport=transport)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        if method == "read":
            configured.read_validation_ref("sha256:" + "e" * 64, VALIDATION_REF)
        elif method == "create":
            configured.create_validation_ref(D, "refs/heads/main", C)
        else:
            configured.delete_validation_ref(D, "refs/heads/deploy")
    assert calls == 0


def test_merge_lease_guard_failure_happens_before_mutating_put() -> None:
    intent, responses = _bound_intent_and_responses()
    transport, calls = _observation_transport(intent, responses)
    with pytest.raises(IntegrationPromotionPreconditionError, match="lease expired"):
        provider_for_intent(intent, transport).merge(
            intent, lease_guard=lambda: (_ for _ in ()).throw(RuntimeError("lease expired"))
        )
    assert [call[0] for call in calls].count("PUT") == 0


@pytest.mark.parametrize(
    ("protection_update", "message"),
    [
        ({"required_status_checks": {"strict": True}}, "required checks"),
        ({"required_status_checks": {"strict": True, "checks": "ci"}}, "required checks"),
        (
            {
                "required_status_checks": {
                    "strict": True,
                    "checks": [{"context": "ci", "app_id": 7}],
                    "contexts": [1],
                }
            },
            "contexts",
        ),
        (
            {
                "required_status_checks": {
                    "strict": True,
                    "checks": [{"context": "ci", "app_id": 7}],
                    "contexts": ["other"],
                }
            },
            "contexts",
        ),
        ({"required_pull_request_reviews": {"required_approving_review_count": 0}}, "reviews"),
    ],
)
def test_protection_evidence_rejects_malformed_sections(
    protection_update: dict[str, JsonValue], message: str
) -> None:
    protection = full_protection()
    for key, value in protection_update.items():
        protection[key] = value

    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, body, headers
        if url.endswith("/git/ref/heads/integration"):
            return 200, {"object": {"sha": G}}
        if url.endswith("/git/commits/" + G):
            return 200, {"sha": G, "tree": {"sha": G}, "parents": []}
        return 200, protection

    with pytest.raises(ValueError, match=message):
        provider(transport=transport).observe_integration("refs/heads/integration")


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (_page_payload(10001, []), "exceeds"),
        ({"total_count": 1, "check_runs": {}}, "malformed"),
        ({"total_count": 1, "check_runs": [{"id": 1}]}, "missing name"),
    ],
)
def test_check_evidence_rejects_bounded_or_malformed_pages(
    payload: JsonObject, message: str
) -> None:
    def transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, body, headers
        if url.endswith("/protection"):
            return 200, full_protection()
        return 200, payload

    with pytest.raises(ValueError, match=message):
        provider(transport=transport)._evidence_snapshot(C, H)  # type: ignore[reportPrivateUsage]


def test_check_evidence_rejects_changed_total_and_malformed_timestamp() -> None:
    calls = 0

    def changing(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        nonlocal calls
        del method, body, headers
        if url.endswith("/protection"):
            return 200, full_protection()
        calls += 1
        runs = [_check_run(99, "ci", 7)] + [
            _check_run(i, f"other-{i}", 8) for i in range(99)
        ]
        return 200, _page_payload(101 if calls == 1 else 100, runs)

    with pytest.raises(ValueError, match="changed"):
        provider(transport=changing)._evidence_snapshot(C, H)  # type: ignore[reportPrivateUsage]

    malformed = _check_run(99, "ci", 7, completed_at="not-a-date")

    def timestamp_transport(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        del method, body, headers
        if url.endswith("/protection"):
            return 200, full_protection()
        return 200, _page_payload(1, [malformed])

    with pytest.raises(ValueError, match="timestamp"):
        provider(transport=timestamp_transport)._evidence_snapshot(C, H)  # type: ignore[reportPrivateUsage]
