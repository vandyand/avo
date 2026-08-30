from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import cast

import pytest

from avo_correlate.adapters.hosted_git.github import (
    JsonBody,
    JsonObject,
    JsonTransport,
    JsonValue,
    github_repository_digest,
)
from avo_correlate.adapters.hosted_git.protected_main import (
    MainGraduationAttester,
    ProtectedMainProvider,
    ProtectedMainProviderError,
)
from avo_correlate.contracts.main_graduation import (
    MainCheckObservation,
    MainQueueAdmissionObservation,
    MainReleaseAuthorization,
    MainReleaseHoldObservation,
    MainReleaseIssuerBinding,
)

A = "a" * 40
B = "b" * 40
C = "c" * 40
D = "d" * 40
E = "e" * 40
G = "f" * 40
ISOLATION = "sha256:" + "1" * 64
NOW = "2026-08-29T12:00:00Z"


class FakeTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, JsonBody | None]] = []
        self.pr: dict[str, JsonValue] = {
            "number": 7,
            "html_url": "https://github.com/avo/repo/pull/7",
            "state": "open",
            "merged": False,
            "draft": False,
            "base": {"ref": "main", "sha": A, "repo": {"full_name": "avo/repo"}},
            "head": {
                "ref": "refs/heads/avo/candidate/" + "1" * 64,
                "sha": D,
                "repo": {"full_name": "avo/repo"},
            },
        }
        self.queue_config: dict[str, JsonValue] = {
            "maximumEntriesToBuild": 1,
            "maximumEntriesToMerge": 1,
            "mergeMethod": "SQUASH",
            "mergingStrategy": "ALLGREEN",
        }
        self.ruleset: JsonObject = {
            "id": 42,
            "name": "protected-main",
            "source_type": "Repository",
            "source": "avo/repo",
            "target": "branch",
            "enforcement": "active",
            "bypass_actors": [],
            "conditions": {"ref_name": {"include": ["refs/heads/main"], "exclude": []}},
            "rules": [{
                "type": "merge_queue",
                "parameters": {
                    "max_entries_to_merge": 1,
                    "merge_method": "SQUASH",
                    "grouping_strategy": "ALLGREEN",
                },
            }],
        }
        self.ruleset_page: list[JsonObject] = [{"id": 42}]
        self.protection_contexts: list[str] = ["unit-validation", "avo-main-release"]
        self.protection_checks: list[JsonObject] = [
            {"context": "unit-validation", "app_id": 15368},
            {"context": "avo-main-release", "app_id": 9001},
        ]
        self.runs: list[JsonObject] = []

    def __call__(
        self, method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        self.calls.append((method, url, body))
        assert headers.get("Authorization") == "Bearer token"
        if url.endswith("/graphql"):
            assert method == "POST"
            assert body is not None and "query" in body and "variables" in body
            query = body["query"]
            assert isinstance(query, str) and "mergeQueue(branch: $branch)" in query
            return 200, {
                "data": {
                    "repository": {
                        "mergeQueue": {
                            "id": "MQ_1",
                            "configuration": self.queue_config,
                            "entries": {
                                "totalCount": 1,
                                "nodes": [
                                    {
                                        "id": "MQE_1",
                                        "position": 1,
                                        "state": "QUEUED",
                                        "solo": True,
                                        "pullRequest": {"number": 7},
                                        "baseCommit": {"oid": A},
                                        "headCommit": {"oid": D},
                                    }
                                ],
                            },
                        }
                    }
                }
            }
        prefix = "https://api.github.com/repos/avo/repo"
        if url == prefix:
            return 200, {"full_name": "avo/repo"}
        if url == prefix + "/pulls/7":
            return 200, self.pr
        if url == prefix + "/branches/main/protection":
            return 200, cast(JsonValue, {
                "required_status_checks": {
                    "contexts": self.protection_contexts,
                    "checks": self.protection_checks,
                }
            })
        if url == prefix + "/rulesets?includes_parents=true&targets=branch&per_page=100&page=1":
            return 200, cast(JsonValue, self.ruleset_page)
        if url == prefix + "/rulesets/42":
            return 200, self.ruleset
        if url == prefix + "/git/ref/heads/main":
            return 200, {"ref": "refs/heads/main", "object": {"type": "commit", "sha": A}}
        if "/git/commits/" in url:
            sha = url.rsplit("/", 1)[-1]
            topology = {A: (C, [B]), D: (E, [A]), G: (E, [A, D])}
            tree, parents = topology[sha]
            return 200, {
                "sha": sha,
                "tree": {"sha": tree},
                "parents": [{"sha": parent} for parent in parents],
            }
        if "/check-runs" in url:
            return 200, cast(JsonValue, {"check_runs": self.runs})
        raise AssertionError(f"unexpected endpoint: {method} {url}")


def provider(fake: JsonTransport) -> ProtectedMainProvider:
    return ProtectedMainProvider(
        "avo",
        "repo",
        github_repository_digest("avo", "repo"),
        release_issuer_identity="isolated-release",
        release_issuer_app_id=9001,
        issuer_isolation_digest=ISOLATION,
        trusted_check_contexts=("unit-validation",),
        token="token",
        transport=fake,
    )


def check(
    sha: str = G, *, app_id: int = 15368, name: str = "unit-validation", **kwargs: str
) -> JsonObject:
    value: JsonObject = {
        "id": 1,
        "name": name,
        "head_sha": sha,
        "status": "completed",
        "conclusion": "success",
        "app": {"id": app_id},
        "completed_at": NOW,
    }
    value.update(kwargs)
    return value


def test_graphql_queue_is_official_endpoint_and_binds_singleton_entry() -> None:
    fake = FakeTransport()
    main = provider(fake)
    base = main.observe_main()
    queue = main.observe_queue(base)
    assert queue.expected_group_parents == [A, D]
    assert any(method == "POST" and url.endswith("/graphql") for method, url, _ in fake.calls)
    assert not any("merge-queue" in url for _, url, _ in fake.calls)


def test_graphql_queue_can_be_observed_before_enqueue_without_inventing_group_topology() -> None:
    fake = FakeTransport()
    fake.queue_config = dict(fake.queue_config)
    original = fake

    def empty(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        status, payload = original(method, url, body, headers)
        if url.endswith("/graphql"):
            data = cast(dict[str, JsonValue], payload)
            repository = cast(
                dict[str, JsonValue], cast(dict[str, JsonValue], data["data"])["repository"]
            )
            queue = cast(dict[str, JsonValue], repository["mergeQueue"])
            queue["entries"] = {"totalCount": 0, "nodes": []}
        return status, payload

    queue = provider(cast(JsonTransport, empty)).observe_queue()
    assert queue.expected_group_parents == [A]


@pytest.mark.parametrize(
    ("field", "value"),
    [("maximumEntriesToMerge", 2), ("mergeMethod", "MERGE"), ("mergingStrategy", "HEADGREEN")],
)
def test_queue_rejects_unsafe_graphql_configuration(field: str, value: JsonValue) -> None:
    fake = FakeTransport()
    fake.queue_config[field] = value
    with pytest.raises(ProtectedMainProviderError):
        provider(fake).observe_queue()


RULESET_MUTATIONS: list[dict[str, JsonValue]] = [
    {"enforcement": "disabled"},
    {"enforcement": "evaluate"},
    {"bypass_actors": [{}]},
    {"bypass_actors": None},
    {"rules": []},
    {"conditions": {"ref_name": {"include": ["refs/heads/dev"], "exclude": []}}},
]


@pytest.mark.parametrize("mutation", RULESET_MUTATIONS)
def test_protection_requires_active_full_ruleset_without_bypass(
    mutation: dict[str, JsonValue]
) -> None:
    fake = FakeTransport()
    fake.ruleset.update(mutation)
    with pytest.raises(ProtectedMainProviderError):
        provider(fake).observe_protection()


def test_ruleset_page_bounds_fail_closed() -> None:
    fake = FakeTransport()
    fake.ruleset_page = [{"id": index + 1} for index in range(101)]
    with pytest.raises(ProtectedMainProviderError):
        provider(fake).observe_protection()


@pytest.mark.parametrize(
    "contexts,checks",
    [
        (["unit-validation"], [{"context": "unit-validation", "app_id": 15368}]),
        (
            ["unit-validation", "avo-main-release"],
            [
                {"context": "unit-validation", "app_id": 15368},
                {"context": "avo-main-release", "app_id": 15368},
            ],
        ),
        (
            ["unit-validation", "avo-main-release", "extra"],
            [
                {"context": "unit-validation", "app_id": 15368},
                {"context": "avo-main-release", "app_id": 9001},
                {"context": "extra", "app_id": 15368},
            ],
        ),
    ],
)
def test_protection_requires_validation_contexts_plus_isolated_release(
    contexts: list[str], checks: list[JsonObject]
) -> None:
    fake = FakeTransport()
    fake.protection_contexts = contexts
    fake.protection_checks = checks
    with pytest.raises(ProtectedMainProviderError):
        provider(fake).observe_protection()


def test_queue_rejects_graphql_errors_and_missing_queue() -> None:
    fake = FakeTransport()

    def broken(
        method: str, url: str, body: JsonBody | None, headers: Mapping[str, str]
    ) -> tuple[int, JsonValue]:
        if url.endswith("/graphql"):
            return 200, {"errors": [{"message": "forbidden"}], "data": None}
        return fake(method, url, body, headers)

    with pytest.raises(ProtectedMainProviderError):
        ProtectedMainProvider(
            "avo", "repo", github_repository_digest("avo", "repo"),
            release_issuer_identity="isolated-release", release_issuer_app_id=9001,
            issuer_isolation_digest=ISOLATION, trusted_check_contexts=("unit-validation",),
            token="token", transport=cast(JsonTransport, broken),
        ).observe_queue()


@pytest.mark.parametrize("url", [
    "https://github.com/avo/repo/pull/7/extra",
    "https://github.com/avo/repo/pull/70",
    "https://github.com/other/repo/pull/7",
])
def test_pull_request_url_is_exact(url: str) -> None:
    fake = FakeTransport()
    fake.pr["html_url"] = url
    with pytest.raises(ProtectedMainProviderError):
        provider(fake).observe_pull_request(7)


@pytest.mark.parametrize(
    "field,value", [("number", 8), ("state", "closed"), ("draft", True), ("merged", True)]
)
def test_pull_request_identity_state_substitution_is_rejected(field: str, value: JsonValue) -> None:
    fake = FakeTransport()
    fake.pr[field] = value
    with pytest.raises(ProtectedMainProviderError):
        provider(fake).observe_pull_request(7)


def test_merge_group_requires_authenticated_event_and_rechecks_commit_topology() -> None:
    fake = FakeTransport()
    main = provider(fake)
    queue = main.observe_queue()
    event: JsonObject = {
        "merge_group": {
            "head_sha": G,
            "tree_sha": E,
            "parents": [{"sha": A}, {"sha": D}],
            "pull_request_numbers": [7],
            "queue_generation_digest": queue.queue_generation_digest,
        }
    }
    group = main.observe_merge_group(G, event=event, queue=queue, pull_request_number=7)
    assert group.group_parents == (A, D)
    assert group.group_tree == E
    with pytest.raises(ProtectedMainProviderError):
        main.observe_merge_group(G)
    event["merge_group"]["pull_request_numbers"] = [7, 8]  # type: ignore[index]
    with pytest.raises(ProtectedMainProviderError):
        main.observe_merge_group(G, event=event, queue=queue)


@pytest.mark.parametrize("mutation", [
    {"head_sha": D}, {"queue_generation_digest": "sha256:" + "9" * 64},
    {"parents": [{"sha": A}]}, {"tree_sha": C},
])
def test_merge_group_event_substitution_is_rejected(mutation: dict[str, JsonValue]) -> None:
    fake = FakeTransport()
    main = provider(fake)
    queue = main.observe_queue()
    event: JsonObject = {
        "head_sha": G,
        "tree_sha": E,
        "parents": [{"sha": A}, {"sha": D}],
        "pull_request_numbers": [7],
        "queue_generation_digest": queue.queue_generation_digest,
    }
    event.update(mutation)
    with pytest.raises(ProtectedMainProviderError):
        main.observe_merge_group(G, event=event, queue=queue, pull_request_number=7)


@pytest.mark.parametrize("mutation", [
    {"head_sha": D}, {"app": {"id": 9001}}, {"status": "in_progress"},
    {"conclusion": "failure"}, {"completed_at": "2099-01-01T00:00:00Z"},
])
def test_check_run_exact_sha_app_state_and_freshness(mutation: dict[str, JsonValue]) -> None:
    fake = FakeTransport()
    run = check()
    run.update(mutation)
    hold = check(sha=G, name="avo-main-release", app_id=9001)
    hold["id"] = 2
    hold["status"] = "in_progress"
    hold["conclusion"] = None
    fake.runs = [run, hold]
    with pytest.raises(ProtectedMainProviderError):
        provider(fake).observe_merge_group_checks(
            G, operation_id="sha256:" + "2" * 64, package_digest="sha256:" + "3" * 64,
            composition_digest="sha256:" + "4" * 64, config_digest="sha256:" + "5" * 64,
            freshness_cutoff=datetime(2026, 1, 1, tzinfo=UTC),
        )


def test_check_run_duplicate_context_run_id_nonce_and_release_role_are_rejected() -> None:
    fake = FakeTransport()
    first = check()
    second = check(name="other")
    second["id"] = 1
    fake.runs = [first, second]
    with pytest.raises(ProtectedMainProviderError):
        provider(fake).observe_check_runs(G)
    fake.runs = [check(name="avo-main-release", app_id=9001)]
    with pytest.raises(ProtectedMainProviderError):
        provider(fake).observe_merge_group_checks(
            G, operation_id="sha256:" + "2" * 64, package_digest="sha256:" + "3" * 64,
            composition_digest="sha256:" + "4" * 64, config_digest="sha256:" + "5" * 64,
            freshness_cutoff=datetime(2026, 1, 1, tzinfo=UTC),
        )


@pytest.mark.parametrize("timestamp", ["2026-01-01T00:00:00Z", "2099-01-01T00:00:00Z"])
def test_pr_head_admission_check_honors_freshness_cutoff_and_future_rejection(
    timestamp: str,
) -> None:
    fake = FakeTransport()
    fake.runs = [check(sha=D, name="avo-main-release", app_id=9001, completed_at=timestamp)]
    cutoff = datetime(2026, 6, 1, tzinfo=UTC)
    with pytest.raises(ProtectedMainProviderError):
        provider(fake).observe_pr_head_admission_check(D, freshness_cutoff=cutoff)


def test_group_hold_check_is_exact_isolated_pending_run() -> None:
    fake = FakeTransport()
    hold = check(sha=G, name="avo-main-release", app_id=9001)
    hold["status"] = "in_progress"
    hold["conclusion"] = None
    fake.runs = [hold]
    observed = provider(fake).observe_group_hold_check(
        G, freshness_cutoff=datetime(2026, 1, 1, tzinfo=UTC)
    )
    assert observed.run_id == "1"
    fake.runs = [check(sha=G, name="avo-main-release", app_id=15368)]
    with pytest.raises(ProtectedMainProviderError):
        provider(fake).observe_group_hold_check(
            G, freshness_cutoff=datetime(2026, 1, 1, tzinfo=UTC)
        )


def test_merge_group_checks_separate_validation_checks_from_release_hold() -> None:
    fake = FakeTransport()
    validation = check(sha=G)
    hold = check(sha=G, name="avo-main-release", app_id=9001)
    hold["id"] = 2
    hold["status"] = "in_progress"
    hold["conclusion"] = None
    fake.runs = [validation, hold]
    observed = provider(fake).observe_merge_group_checks(
        G,
        operation_id="sha256:" + "2" * 64,
        package_digest="sha256:" + "3" * 64,
        composition_digest="sha256:" + "4" * 64,
        config_digest="sha256:" + "5" * 64,
        freshness_cutoff=datetime(2026, 1, 1, tzinfo=UTC),
    )
    assert [item.context for item in observed.checks] == ["unit-validation"]


def test_provider_has_no_enqueue_or_merge_authority() -> None:
    fake = FakeTransport()
    main = provider(fake)
    assert not hasattr(main, "enqueue")
    assert not hasattr(main, "merge")
    assert all(method == "GET" for method, _, _ in fake.calls)


def test_release_attestation_rejects_caller_supplied_identity_string() -> None:
    attester = MainGraduationAttester(provider(FakeTransport()))
    with pytest.raises(ProtectedMainProviderError):
        attester.attest_release(
            cast(MainReleaseAuthorization, None),
            cast(MainReleaseHoldObservation, None),
            cast(MainReleaseIssuerBinding, "isolated-release"),
        )


def test_admission_attester_binds_issuer_isolation_and_pr_head_role() -> None:
    fake = FakeTransport()
    main = provider(fake)
    pr = main.observe_pull_request(7)
    queue = main.observe_queue()
    admission = MainQueueAdmissionObservation.model_construct(
        repository_digest=main.repository_digest,
        target_ref="refs/heads/main",
        operation_id=queue.operation_id,
        preparation_authorization_digest="sha256:" + "6" * 64,
        package_digest="sha256:" + "7" * 64,
        composition_digest="sha256:" + "8" * 64,
        pull_request_number=7,
        pull_request_url=pr.url,
        base_commit=A,
        base_tree=C,
        head_commit=D,
        head_tree=E,
        admission_sha=D,
        admission_run_id="admission-run",
        admission_nonce="admission-nonce",
        queue_generation_digest=queue.queue_generation_digest,
        protection_manifest_digest=queue.protection_manifest_digest,
        issuer_identity=main.release_issuer_identity,
        release_issuer_app_id=main.release_issuer_app_id,
        issuer_isolation_digest="sha256:" + "9" * 64,
        validation_app_id=15368,
        check_context="avo-main-release",
        check_state="completed",
        check_conclusion="success",
        release_transition=False,
        one_use=True,
        observed_at=datetime.now(UTC),
    )
    check_value = MainCheckObservation.model_construct(
        name="avo-main-release", context="avo-main-release", app_id=9001, sha=D,
        status="completed", conclusion="success", run_id="admission-run", nonce="admission-nonce",
        observed_at=datetime.now(UTC),
    )
    with pytest.raises(ProtectedMainProviderError):
        MainGraduationAttester(main).attest_admission(
            admission,
            pr,
            queue,
            admission_check=check_value,
            freshness_cutoff=datetime(2026, 1, 1, tzinfo=UTC),
        )

    admission = admission.model_copy(
        update={"issuer_isolation_digest": main.issuer_isolation_digest}
    )
    check_value = check_value.model_copy(update={"run_id": "different-run"})
    with pytest.raises(ProtectedMainProviderError):
        MainGraduationAttester(main).attest_admission(
            admission,
            pr,
            queue,
            admission_check=check_value,
            freshness_cutoff=datetime(2026, 1, 1, tzinfo=UTC),
        )
