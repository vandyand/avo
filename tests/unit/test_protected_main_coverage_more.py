"""High-yield success paths for the protected-main provider and attester."""
# pyright: reportPrivateUsage=false

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import pytest

from avo_correlate.adapters.hosted_git.github import JsonObject
from avo_correlate.adapters.hosted_git.protected_main import (
    MainGraduationAttester,
    ProtectedMainProviderError,
)
from avo_correlate.contracts.main_graduation import (
    MainCheckObservation,
    MainProviderReceipt,
    MainQueueAdmissionObservation,
    MainReleaseHoldObservation,
)
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.test_protected_main_adversarial import (
    A,
    D,
    E,
    FakeTransport,
    G,
    provider,
    signed_webhook,
)

FRESH = datetime(2026, 1, 1, tzinfo=UTC)


def _check(
    *,
    sha: str = G,
    name: str = "unit-validation",
    app_id: int = 15368,
    status: str = "completed",
    conclusion: str | None = "success",
    run_id: int = 1,
    external_id: str | None = None,
) -> JsonObject:
    value: JsonObject = {
        "id": run_id,
        "name": name,
        "head_sha": sha,
        "status": status,
        "conclusion": conclusion,
        "app": {"id": app_id},
        "started_at": "2026-08-29T11:59:00Z",
    }
    if external_id is not None:
        value["external_id"] = external_id
    return value


def test_snapshot_and_alias_observations_cover_successful_read_paths() -> None:
    fake = FakeTransport()
    main = provider(fake)
    snapshot = main.observe_snapshot(7)
    assert snapshot.group is None
    body, headers = signed_webhook(delivery="snapshot-group")
    grouped = main.observe_snapshot(
        7,
        group_sha=G,
        group_webhook_body=body,
        group_webhook_headers=headers,
    )
    assert grouped.group is not None
    assert grouped.group.pull_request_numbers == (7,)
    assert main.observe_ref().ref == "refs/heads/main"
    assert main.observe_main().commit == A
    assert main.observe_admission_check.__func__ is main.observe_pr_head_admission_check.__func__
    assert main.observe_release_authorization.__func__ is main.parse_release_authorization.__func__


def test_check_runs_accept_queued_pending_and_timestamp_fallbacks() -> None:
    fake = FakeTransport()
    queued = _check(name="queued", status="queued", conclusion=None, run_id=1)
    queued.pop("started_at")
    queued["updated_at"] = "2026-08-29T11:58:00Z"
    pending = _check(name="pending", status="in_progress", conclusion=None, run_id=2)
    completed = _check(name="completed", run_id=3, external_id="nonce-3")
    fake.runs = [queued, pending, completed]
    checks = provider(fake).observe_check_runs(G)
    assert [(item.context, item.conclusion, item.nonce) for item in checks] == [
        ("queued", "pending", "1"),
        ("pending", "pending", "2"),
        ("completed", "success", "nonce-3"),
    ]


@pytest.mark.parametrize(
    "mutation",
    [
        {"check_total_count": 2},
        {"check_pages": [[], [_check(name="second", run_id=2)]], "check_total_count": 2},
        {"runs": [_check(run_id=0)]},
        {"runs": [_check(status="unknown")]},
        {"runs": [_check(sha=A)]},
    ],
)
def test_check_run_pagination_and_shape_failures(mutation: dict[str, object]) -> None:
    fake = FakeTransport()
    if "check_total_count" in mutation:
        fake.check_pages = [[_check()]]
        fake.check_total_count = cast(int, mutation["check_total_count"])
    elif "check_pages" in mutation:
        fake.check_pages = cast(list[list[JsonObject]], mutation["check_pages"])
        fake.check_total_count = cast(int, mutation["check_total_count"])
    else:
        fake.runs = cast(list[JsonObject], mutation["runs"])
    with pytest.raises(ProtectedMainProviderError):
        provider(fake).observe_check_runs(G)


def test_merge_group_checks_success_and_explicit_contexts() -> None:
    fake = FakeTransport()
    fake.runs = [
        _check(),
        _check(
            name="avo-main-release", app_id=9001, status="in_progress", conclusion=None, run_id=2
        ),
    ]
    checks = provider(fake).observe_merge_group_checks(
        G,
        operation_id="sha256:" + "2" * 64,
        package_digest="sha256:" + "3" * 64,
        composition_digest="sha256:" + "4" * 64,
        config_digest="sha256:" + "5" * 64,
        freshness_cutoff=FRESH,
        allowlisted_contexts=("unit-validation",),
    )
    assert checks.allowlisted_contexts == ["unit-validation"]
    assert checks.checks[0].context == "unit-validation"
    with pytest.raises(ProtectedMainProviderError):
        provider(fake).observe_merge_group_checks(
            G,
            operation_id="bad",
            package_digest="sha256:" + "3" * 64,
            composition_digest="sha256:" + "4" * 64,
            config_digest="sha256:" + "5" * 64,
            freshness_cutoff=datetime(2026, 1, 1),
        )


def test_admission_and_hold_check_success_paths() -> None:
    fake = FakeTransport()
    fake.runs = [_check(sha=D, name="avo-main-release", app_id=9001, external_id="admission-nonce")]
    main = provider(fake)
    admission_check = main.observe_admission_check(D, freshness_cutoff=FRESH)
    fake.runs = [
        _check(
            sha=G,
            name="avo-main-release",
            app_id=9001,
            status="in_progress",
            conclusion=None,
            run_id=2,
            external_id="hold-nonce",
        )
    ]
    hold_check = main.observe_group_hold_check(G, freshness_cutoff=FRESH)
    assert admission_check.run_id == "1"
    assert hold_check.nonce == "hold-nonce"
    with pytest.raises(ProtectedMainProviderError):
        main.observe_pr_head_admission_check(D, freshness_cutoff=datetime(2026, 1, 1))
    with pytest.raises(ProtectedMainProviderError):
        main.observe_group_hold_check(G, freshness_cutoff=datetime(2026, 1, 1))


def test_all_contract_parser_aliases_accept_and_identity_checks_reject() -> None:
    from tests.unit.test_protected_main_coverage import (
        _admission_payload,
        _authorization,
        _hold_payload,
        _payload,
        _transition,
    )

    main = provider(FakeTransport())
    admission = _admission_payload()
    hold = _hold_payload()
    authorization = _payload(_authorization())
    transition = _payload(_transition(_authorization()))
    receipt = _payload(
        MainProviderReceipt.model_construct(
            repository_digest=main.repository_digest,
            target_ref="refs/heads/main",
            operation_id="sha256:" + "2" * 64,
            release_authorization_digest="sha256:" + "3" * 64,
            provider_identity="github-protected-main",
            provider_api_version="2022-11-28",
            outcome="observed",
            result_commit=G,
            result_tree=E,
            result_parents=[A],
            response_digest="sha256:" + "4" * 64,
            observed_at=datetime(2026, 8, 29, 12, tzinfo=UTC),
        )
    )
    assert main.observe_admission(admission).pull_request_number == 7
    assert main.observe_hold(hold).group_sha == G
    assert main.observe_release_transition(transition).outcome == "transitioned"
    # The fixture is constructed for attester checks, so repair its content
    # address before exercising the strict parser.
    authorization["authorization_digest"] = canonical_digest(
        {key: value for key, value in authorization.items() if key != "authorization_digest"}
    )
    parsed_authorization = main.observe_release_authorization(authorization)
    assert parsed_authorization.used is False
    assert main.observe_provider_receipt(receipt).target_ref == "refs/heads/main"
    for method, payload, field in [
        (main.parse_admission, admission, "validation_app_id"),
        (main.parse_hold, hold, "release_issuer_app_id"),
        (main.parse_release_authorization, authorization, "used"),
        (main.parse_release_transition, transition, "outcome"),
        (main.parse_provider_receipt, receipt, "repository_digest"),
    ]:
        altered = dict(payload)
        altered[field] = (
            9002 if field.endswith("app_id") else (True if field == "used" else "wrong")
        )
        with pytest.raises(ProtectedMainProviderError):
            method(altered)


def _valid_admission(main: Any, pr: Any, queue: Any) -> MainQueueAdmissionObservation:
    provider_value = main
    return MainQueueAdmissionObservation.model_construct(
        repository_digest=provider_value.repository_digest,
        target_ref="refs/heads/main",
        operation_id=queue.operation_id,
        preparation_authorization_digest="sha256:" + "6" * 64,
        package_digest="sha256:" + "7" * 64,
        composition_digest="sha256:" + "8" * 64,
        pull_request_number=pr.number,
        pull_request_url=pr.url,
        base_commit=pr.base_commit,
        base_tree=pr.base_tree,
        head_commit=pr.head_commit,
        head_tree=pr.head_tree,
        admission_sha=pr.head_commit,
        admission_run_id="admission-run",
        admission_nonce="admission-nonce",
        queue_generation_digest=queue.queue_generation_digest,
        protection_manifest_digest=queue.protection_manifest_digest,
        issuer_identity=provider_value.release_issuer_identity,
        release_issuer_app_id=provider_value.release_issuer_app_id,
        issuer_isolation_digest=provider_value.issuer_isolation_digest,
        validation_app_id=15368,
        check_context="avo-main-release",
        check_state="completed",
        check_conclusion="success",
        release_transition=False,
        one_use=True,
        observed_at=datetime.now(UTC),
    )


def test_attester_admission_success_and_preparation_binding() -> None:
    fake = FakeTransport()
    fake.runs = [_check(sha=D, name="avo-main-release", app_id=9001, external_id="admission-nonce")]
    main = provider(fake)
    pr = main.observe_pull_request(7)
    queue = main.observe_queue()
    admission = _valid_admission(main, pr, queue)
    check = MainCheckObservation.model_construct(
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
    assert (
        attester.attest_admission(
            admission,
            pr,
            queue,
            admission_check=check,
            preparation_authorization_digest=admission.preparation_authorization_digest,
            freshness_cutoff=FRESH,
        )
        is admission
    )
    with pytest.raises(ProtectedMainProviderError):
        attester.attest_admission(
            admission,
            pr,
            queue,
            admission_check=check,
            preparation_authorization_digest="sha256:" + "9" * 64,
            freshness_cutoff=FRESH,
        )


def test_attester_merge_group_checks_and_release_rejects_drift() -> None:
    from tests.unit.test_protected_main_coverage import _authorization, _transition

    fake = FakeTransport()
    fake.runs = [
        _check(),
        _check(
            name="avo-main-release", app_id=9001, status="in_progress", conclusion=None, run_id=2
        ),
    ]
    main = provider(fake)
    body, headers = signed_webhook(delivery="attester-group")
    queue = main.observe_queue()
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
    assert MainGraduationAttester(main).attest_merge_group_checks(checks, group) is checks
    altered = checks.model_copy(update={"target_ref": "refs/heads/other"})
    with pytest.raises(ProtectedMainProviderError):
        MainGraduationAttester(main).attest_merge_group_checks(altered, group)
    auth = _authorization()
    transition = _transition(auth)
    # The release path is intentionally exercised through the valid receipt;
    # the fixture's identity and SHA drift are rejected by the attester.
    fake.runs = [
        _check(
            name="avo-main-release",
            app_id=9001,
            status="completed",
            conclusion="success",
            run_id=12,
            external_id="hold-nonce",
        )
    ]
    assert (
        MainGraduationAttester(main).attest_release(auth, _hold_payload_model(auth), transition)
        is transition
    )


def _hold_payload_model(auth: Any) -> MainReleaseHoldObservation:
    from tests.unit.test_protected_main_coverage import _hold_payload

    value = MainReleaseHoldObservation.model_validate(_hold_payload())
    return value.model_copy(
        update={
            "repository_digest": auth.repository_digest,
            "operation_id": auth.operation_id,
            "group_sha": auth.group_sha,
            "hold_run_id": auth.hold_run_id,
            "hold_nonce": auth.hold_nonce,
        }
    )
