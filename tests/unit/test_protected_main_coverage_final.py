"""Final focused coverage for the protected-main provider boundary.

The tests in this module exercise the remaining fail-closed branches without
adding production seams or replacing the authenticated transport fixture.
"""
# pyright: reportPrivateUsage=false

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest

from avo_correlate.adapters.hosted_git.protected_main import (
    MainGraduationAttester,
    ProtectedMainProvider,
    ProtectedMainProviderError,
)
from avo_correlate.contracts.main_graduation import (
    MainCheckObservation,
    MainReleaseHoldObservation,
)
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.test_protected_main_adversarial import (
    A,
    C,
    D,
    FakeTransport,
    G,
    check,
    provider,
    signed_webhook,
)
from tests.unit.test_protected_main_coverage import _authorization, _transition
from tests.unit.test_protected_main_coverage_more import _valid_admission

FRESH = datetime(2026, 1, 1, tzinfo=UTC)


def _hold_inputs() -> tuple[Any, Any, Any, Any, Any, Any, MainCheckObservation]:
    """Return internally consistent admission, group, queue, hold, and check."""
    fake = FakeTransport()
    fake.runs = [
        check(name="unit-validation"),
        check(name="avo-main-release", app_id=9001, status="in_progress", conclusion="pending"),
    ]
    main = provider(fake)
    pr = main.observe_pull_request(7)
    queue = main.observe_queue()
    body, headers = signed_webhook(delivery="final-coverage-group")
    group = main.observe_merge_group(
        G,
        webhook_body=body,
        webhook_headers=headers,
        queue=queue,
        pull_request_number=7,
    )
    admission = _valid_admission(main, pr, queue)
    from tests.unit.test_protected_main_coverage import _hold_payload

    source = MainReleaseHoldObservation.model_validate(_hold_payload())
    hold = source.model_copy(
        update={
            "repository_digest": main.repository_digest,
            "operation_id": queue.operation_id,
            "preparation_authorization_digest": admission.preparation_authorization_digest,
            "admission_observation_digest": canonical_digest(admission),
            "package_digest": admission.package_digest,
            "composition_digest": admission.composition_digest,
            "pull_request_number": 7,
            "group_sha": group.group_sha,
            "group_tree": group.group_tree,
            "group_parents": list(group.group_parents),
            "expected_group_parents": list(group.group_parents),
            "group_topology_digest": queue.group_topology_digest,
            "base_commit": queue.expected_base_commit,
            "base_tree": queue.expected_base_tree,
            "composition_tree": group.group_tree,
            "queue_generation_digest": queue.queue_generation_digest,
            "queue_members": [7],
            "hold_run_id": "hold-run",
            "hold_nonce": "hold-nonce",
            "issuer_identity": main.release_issuer_identity,
            "release_issuer_app_id": main.release_issuer_app_id,
            "issuer_isolation_digest": main.issuer_isolation_digest,
            "other_required_checks": source.other_required_checks.model_copy(
                update={
                    "operation_id": queue.operation_id,
                    "package_digest": admission.package_digest,
                    "composition_digest": admission.composition_digest,
                    "group_sha": group.group_sha,
                }
            ),
            "merge_group_receipt": group.webhook_receipt,
            "protection_manifest_digest": queue.protection_manifest_digest,
            "observed_at": datetime.now(UTC),
        }
    )
    hold_check = MainCheckObservation.model_construct(
        name="avo-main-release",
        context="avo-main-release",
        app_id=9001,
        sha=G,
        status="in_progress",
        conclusion="pending",
        run_id="hold-run",
        nonce="hold-nonce",
        observed_at=datetime.now(UTC),
    )
    return main, pr, queue, group, admission, hold, hold_check


def test_constructor_and_transport_guards_cover_configuration_edges() -> None:
    digest = provider(FakeTransport()).repository_digest
    kwargs: dict[str, Any] = {
        "release_issuer_identity": "isolated-release",
        "release_issuer_app_id": 9001,
        "issuer_isolation_digest": "sha256:" + "1" * 64,
        "trusted_check_contexts": ("unit-validation",),
        "token": "token",
        "transport": FakeTransport(),
    }
    for update in [
        {"owner": "", "repo": "repo"},
        {"owner": "avo/evil"},
        {"repository_digest": "sha256:" + "0" * 64},
        {"release_issuer_identity": " "},
        {"release_issuer_app_id": 0},
        {"trusted_validation_app_id": 42},
        {"release_issuer_app_id": 15368},
        {"token": None},
        {"api_base": "http://localhost"},
        {"trusted_check_contexts": ()},
    ]:
        values = {"owner": "avo", "repo": "repo", "repository_digest": digest, **kwargs}
        values.update(update)
        with pytest.raises(ValueError):
            ProtectedMainProvider(**cast(Any, values))

    no_transport = ProtectedMainProvider(
        "avo", "repo", digest, **{key: value for key, value in kwargs.items() if key != "transport"}
    )
    with pytest.raises(ProtectedMainProviderError):
        no_transport.observe_repository()


def test_provider_rejects_malformed_low_level_values_and_transport_statuses() -> None:
    import avo_correlate.adapters.hosted_git.protected_main as module

    with pytest.raises(ProtectedMainProviderError):
        module._bool({}, "flag", "test")
    with pytest.raises(ProtectedMainProviderError):
        module._items(["not-an-object"], "test")
    for value in ["", "not-a-sha"]:
        with pytest.raises(ProtectedMainProviderError):
            module._git(value, "test")
    with pytest.raises(ProtectedMainProviderError):
        module._digest("bad", "test")
    for value in [None, "not-a-date", "2026-01-01T00:00:00"]:
        with pytest.raises(ProtectedMainProviderError):
            module._parse_timestamp(value, "test")

    class StatusTransport:
        def __init__(self, status: int) -> None:
            self.status = status

        def __call__(self, method: str, url: str, body: Any, headers: Any) -> tuple[int, Any]:
            return self.status, {}

    digest = provider(FakeTransport()).repository_digest
    for status, expected in [(401, ProtectedMainProviderError), (302, ProtectedMainProviderError)]:
        main = ProtectedMainProvider(
            "avo",
            "repo",
            digest,
            release_issuer_identity="x",
            release_issuer_app_id=9001,
            issuer_isolation_digest="sha256:" + "1" * 64,
            trusted_check_contexts=("x",),
            token="token",
            transport=StatusTransport(status),
        )
        with pytest.raises(expected):
            main.observe_repository()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("full_name", "other/repo"),
        ("ref", "refs/heads/other"),
        ("object", {"type": "tag", "sha": A}),
    ],
)
def test_repository_and_ref_identity_rejections(field: str, value: Any) -> None:
    class MutatingTransport(FakeTransport):
        def __init__(self, target: str, replacement: Any) -> None:
            super().__init__()
            self.target = target
            self.replacement = replacement

        def __call__(self, method: str, url: str, body: Any, headers: Any) -> tuple[int, Any]:
            if url.endswith(self.target):
                if self.target.endswith("/repos/avo/repo"):
                    return 200, {"full_name": self.replacement}
                if self.target.endswith("/git/ref/heads/main"):
                    return 200, {"ref": self.replacement, "object": self.replacement}
            return super().__call__(method, url, body, headers)

    if field == "full_name":
        fake = MutatingTransport("/repos/avo/repo", value)
        with pytest.raises(ProtectedMainProviderError):
            provider(fake).observe_repository()
    else:
        fake = MutatingTransport("/git/ref/heads/main", value)
        with pytest.raises(ProtectedMainProviderError):
            provider(fake).observe_ref()


def test_pull_request_optional_bindings_and_identity_rejections() -> None:
    main = provider(FakeTransport())
    pr = main.observe_pull_request(7, expected_head_ref="refs/heads/avo/candidate/" + "1" * 64)
    assert pr.head_commit == D
    for kwargs in [
        {"expected_base_commit": D},
        {"expected_head_ref": "refs/heads/other"},
        {"expected_head_commit": A},
        {"expected_url": "https://github.com/avo/repo/pull/8"},
    ]:
        with pytest.raises(ProtectedMainProviderError):
            main.observe_pull_request(7, **kwargs)
    for number in [0, -1, True]:
        with pytest.raises(ProtectedMainProviderError):
            main.observe_pull_request(number)


@pytest.mark.parametrize(
    "mutation",
    [
        "contexts",
        "checks",
        "wrong_app",
        "missing_ruleset",
        "bypass",
        "wrong_target",
        "inactive",
        "wrong_queue",
        "duplicate_merge_queue",
    ],
)
def test_protection_ruleset_and_queue_configuration_rejections(mutation: str) -> None:
    fake = FakeTransport()
    if mutation == "contexts":
        fake.protection_contexts = ["unit-validation"]
    elif mutation == "checks":
        fake.protection_checks = [{"context": "unit-validation", "app_id": 15368}]
    elif mutation == "wrong_app":
        fake.protection_checks[0]["app_id"] = 42
    elif mutation == "missing_ruleset":
        fake.effective_rules = []
    elif mutation == "bypass":
        fake.ruleset["bypass_actors"] = [{"actor": "admin"}]
    elif mutation == "wrong_target":
        fake.ruleset["target"] = "~DEFAULT_BRANCH"
    elif mutation == "inactive":
        fake.ruleset["enforcement"] = "disabled"
    elif mutation == "wrong_queue":
        cast(Any, fake.ruleset)["rules"][0]["parameters"]["merge_method"] = "MERGE"
    else:
        cast(Any, fake.ruleset)["rules"].append(cast(Any, fake.ruleset)["rules"][0])
    with pytest.raises(ProtectedMainProviderError):
        provider(fake).observe_protection()


@pytest.mark.parametrize(
    "mutation",
    [
        {"maximumEntriesToMerge": 2},
        {"mergeMethod": "MERGE"},
        {"mergingStrategy": "HEAD"},
    ],
)
def test_queue_configuration_rejections(mutation: dict[str, Any]) -> None:
    fake = FakeTransport()
    fake.queue_config.update(mutation)
    with pytest.raises(ProtectedMainProviderError):
        provider(fake).observe_queue()


def test_attest_admission_rejects_each_binding_and_check_edge() -> None:
    fake = FakeTransport()
    main = provider(fake)
    pr = main.observe_pull_request(7)
    queue = main.observe_queue()
    admission = _valid_admission(main, pr, queue)
    valid = MainCheckObservation.model_construct(
        name="avo-main-release",
        context="avo-main-release",
        app_id=9001,
        sha=D,
        status="completed",
        conclusion="success",
        run_id="admission-run",
        nonce="admission-nonce",
        observed_at=datetime.now(UTC),
    )
    attester = MainGraduationAttester(main)
    assert attester.attest_admission(
        admission, pr, queue, admission_check=valid, freshness_cutoff=FRESH
    )
    changes = [
        {"repository_digest": "sha256:" + "0" * 64},
        {"pull_request_number": 8},
        {"base_commit": D},
        {"admission_sha": A},
        {"queue_generation_digest": "sha256:" + "0" * 64},
        {"operation_id": "sha256:" + "0" * 64},
        {"issuer_identity": "other"},
        {"validation_app_id": 42},
        {"release_transition": True},
    ]
    for change in changes:
        with pytest.raises(ProtectedMainProviderError):
            attester.attest_admission(
                admission.model_copy(update=change),
                pr,
                queue,
                admission_check=valid,
                freshness_cutoff=FRESH,
            )
    for check_change in [
        {"sha": A},
        {"context": "other"},
        {"app_id": 15368},
        {"status": "queued"},
        {"conclusion": "failure"},
        {"run_id": "other"},
        {"nonce": "other"},
        {"observed_at": datetime(2020, 1, 1, tzinfo=UTC)},
    ]:
        with pytest.raises(ProtectedMainProviderError):
            attester.attest_admission(
                admission,
                pr,
                queue,
                admission_check=valid.model_copy(update=check_change),
                freshness_cutoff=FRESH,
            )
    with pytest.raises(ProtectedMainProviderError):
        attester.attest_admission(
            admission, pr, queue, admission_check=valid, freshness_cutoff=datetime(2026, 1, 1)
        )


def test_attest_hold_success_and_all_rejection_groups() -> None:
    main, _pr, queue, group, admission, hold, hold_check = _hold_inputs()
    attester = MainGraduationAttester(main)
    # model_copy does not add a provider attribute; the helper's explicit call
    # below keeps the production attester boundary visible and deterministic.
    assert (
        attester.attest_hold(
            hold, admission, group, queue, hold_check=hold_check, freshness_cutoff=FRESH
        )
        is hold
    )
    changes = [
        {"repository_digest": "sha256:" + "0" * 64},
        {"target_ref": "refs/heads/other"},
        {"admission_observation_digest": "sha256:" + "0" * 64},
        {"group_sha": A},
        {"group_tree": C},
        {"group_parents": [A]},
        {"queue_generation_digest": "sha256:" + "0" * 64},
        {"queue_members": [8]},
        {"pull_request_number": 8},
        {"check_state": "completed"},
        {"validation_app_id": 42},
        {"operation_id": "sha256:" + "0" * 64},
        {"hold_run_id": "admission-run"},
        {"hold_nonce": "admission-nonce"},
    ]
    for change in changes:
        with pytest.raises(ProtectedMainProviderError):
            attester.attest_hold(
                hold.model_copy(update=change),
                admission,
                group,
                queue,
                hold_check=hold_check,
                freshness_cutoff=FRESH,
            )
    for check_change in [
        {"sha": A},
        {"context": "other"},
        {"app_id": 15368},
        {"status": "completed"},
        {"conclusion": "success"},
        {"run_id": "other"},
        {"nonce": "other"},
        {"observed_at": datetime(2020, 1, 1, tzinfo=UTC)},
        {"observed_at": datetime.now(UTC) + timedelta(days=1)},
    ]:
        with pytest.raises(ProtectedMainProviderError):
            attester.attest_hold(
                hold,
                admission,
                group,
                queue,
                hold_check=hold_check.model_copy(update=check_change),
                freshness_cutoff=FRESH,
            )
    with pytest.raises(ProtectedMainProviderError):
        attester.attest_hold(
            hold,
            admission,
            group,
            queue,
            hold_check=hold_check,
            freshness_cutoff=datetime(2026, 1, 1),
        )


def test_attest_merge_group_checks_wrong_check_and_duplicate_context() -> None:
    from tests.unit.test_protected_main_coverage_more import _check

    fake = FakeTransport()
    fake.runs = [
        _check(),
        _check(
            name="avo-main-release", app_id=9001, status="in_progress", conclusion=None, run_id=2
        ),
    ]
    main = provider(fake)
    queue = main.observe_queue()
    body, headers = signed_webhook(delivery="final-check-group")
    group = main.observe_merge_group(
        G, webhook_body=body, webhook_headers=headers, queue=queue, pull_request_number=7
    )
    checks = main.observe_merge_group_checks(
        G,
        operation_id="sha256:" + "2" * 64,
        package_digest="sha256:" + "3" * 64,
        composition_digest="sha256:" + "4" * 64,
        config_digest="sha256:" + "5" * 64,
        freshness_cutoff=FRESH,
    )
    attester = MainGraduationAttester(main)
    for update in [{"sha": A}, {"app_id": 42}, {"status": "queued"}, {"conclusion": "failure"}]:
        with pytest.raises(ProtectedMainProviderError):
            attester.attest_merge_group_checks(
                checks.model_copy(update={"checks": [checks.checks[0].model_copy(update=update)]}),
                group,
            )
    with pytest.raises(ProtectedMainProviderError):
        attester.attest_merge_group_checks(
            checks.model_copy(update={"checks": [checks.checks[0], checks.checks[0]]}), group
        )


@pytest.mark.parametrize("outcome", ["transitioned", "already_transitioned"])
def test_release_attestation_transition_success_and_rejections(outcome: str) -> None:
    fake = FakeTransport()
    run = check(sha=G, name="avo-main-release", app_id=9001)
    run["id"] = 12
    run["external_id"] = "hold-nonce"
    fake.runs = [run]
    main = provider(fake)
    auth = _authorization()
    hold = MainReleaseHoldObservation.model_construct(
        repository_digest=auth.repository_digest,
        target_ref="refs/heads/main",
        group_sha=G,
        hold_run_id="12",
        hold_nonce="hold-nonce",
    )
    transition = _transition(auth, outcome=outcome)
    attester = MainGraduationAttester(main)
    assert attester.attest_release(auth, hold, transition) is transition
    for update in [
        {"repository_digest": "sha256:" + "0" * 64},
        {"target_ref": "refs/heads/other"},
        {"issuer_identity": "other"},
        {"release_issuer_app_id": 15368},
        {"issuer_isolation_digest": "sha256:" + "0" * 64},
        {"outcome": "reconciliation_required"},
        {"operation_id": "sha256:" + "0" * 64},
        {"group_sha": A},
        {"hold_run_id": "other"},
        {"hold_nonce": "other"},
    ]:
        with pytest.raises(ProtectedMainProviderError):
            attester.attest_release(auth, hold, transition.model_copy(update=update))
    with pytest.raises(ProtectedMainProviderError):
        attester.attest_release(auth, hold, None)
    for runs in [[], [run, dict(run, id=13, external_id="other")]]:
        fake.runs = runs
        with pytest.raises(ProtectedMainProviderError):
            attester.attest_release(auth, hold, transition)
    for update in [
        {"head_sha": A},
        {"app": {"id": 15368}},
        {"status": "queued"},
        {"conclusion": "failure"},
        {"id": 13},
        {"external_id": "other"},
    ]:
        fake.runs = cast(Any, [dict(run, **update)])
        with pytest.raises(ProtectedMainProviderError):
            attester.attest_release(auth, hold, transition)


def test_alias_exports_are_identity_preserving() -> None:
    import avo_correlate.adapters.hosted_git.protected_main as module

    assert module.ProtectedMainGitHubProvider is module.ProtectedMainProvider
    assert module.MainProtectedProvider is module.ProtectedMainProvider
    assert module.ProtectedMainAttester is module.MainGraduationAttester
    assert module.MainProviderAttester is module.MainGraduationAttester
    assert module.ProtectedMainAttestationAdapter is module.MainGraduationAttester
    assert "ProtectedMainProvider" in module.__all__
