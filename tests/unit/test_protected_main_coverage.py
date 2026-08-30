"""Additional branch coverage for the protected-main observation boundary.

These tests intentionally exercise failure edges that are easy to miss in the
provider's fail-closed parsers.  The adversarial fixture is reused, while this
file remains independent of its implementation details beyond the documented
transport seam.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import cast

import pytest
from pydantic import BaseModel

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
    ProtectedMainRejected,
)
from avo_correlate.contracts.main_graduation import (
    MainCheckObservation,
    MainMergeGroupChecks,
    MainMergeGroupWebhookReceipt,
    MainReleaseAuthorization,
    MainReleaseHoldObservation,
    MainReleaseTransitionReceipt,
)
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.test_protected_main_adversarial import (
    ISOLATION,
    A,
    C,
    D,
    E,
    FakeTransport,
    G,
    check,
    provider,
    signed_webhook,
)


def _payload(model: BaseModel) -> JsonObject:
    return cast(JsonObject, model.model_dump(mode="json"))


def _admission_payload() -> JsonObject:
    from avo_correlate.contracts.main_graduation import MainQueueAdmissionObservation

    return _payload(
        MainQueueAdmissionObservation.model_construct(
            repository_digest=github_repository_digest("avo", "repo"),
            target_ref="refs/heads/main",
            operation_id="sha256:" + "2" * 64,
            preparation_authorization_digest="sha256:" + "3" * 64,
            package_digest="sha256:" + "4" * 64,
            composition_digest="sha256:" + "5" * 64,
            pull_request_number=7,
            pull_request_url="https://github.com/avo/repo/pull/7",
            base_commit=A,
            base_tree=C,
            head_commit=D,
            head_tree=E,
            admission_sha=D,
            admission_run_id="admission-run",
            admission_nonce="admission-nonce",
            queue_generation_digest="sha256:" + "6" * 64,
            protection_manifest_digest="sha256:" + "7" * 64,
            issuer_identity="isolated-release",
            release_issuer_app_id=9001,
            issuer_isolation_digest=ISOLATION,
            validation_app_id=15368,
            check_context="avo-main-release",
            check_state="completed",
            check_conclusion="success",
            release_transition=False,
            one_use=True,
            observed_at=datetime(2026, 8, 29, 12, tzinfo=UTC),
        )
    )


def _hold_payload() -> JsonObject:
    from avo_correlate.contracts.main_graduation import MainQueueAdmissionObservation

    admission = MainQueueAdmissionObservation.model_validate(_admission_payload())
    receipt = MainMergeGroupWebhookReceipt.model_construct(
        repository_digest=admission.repository_digest,
        target_ref="refs/heads/main",
        operation_id=admission.operation_id,
        group_sha=G,
        group_tree=E,
        group_parents=[A, D],
        pull_request_number=7,
        queue_generation_digest=admission.queue_generation_digest,
        delivery_id="delivery-hold",
        body_digest="sha256:" + "8" * 64,
        observed_at=datetime(2026, 8, 29, 12, tzinfo=UTC),
        receipt_digest="sha256:" + "9" * 64,
    )
    receipt = receipt.model_copy(
        update={
            "receipt_digest": canonical_digest(
                receipt.model_dump(exclude={"receipt_digest"}, mode="json")
            )
        }
    )
    checks = MainMergeGroupChecks.model_construct(
        repository_digest=admission.repository_digest,
        target_ref="refs/heads/main",
        operation_id=admission.operation_id,
        package_digest=admission.package_digest,
        composition_digest=admission.composition_digest,
        group_sha=G,
        checks=[
            MainCheckObservation.model_construct(
                name="unit-validation", context="unit-validation", app_id=15368,
                sha=G, status="completed", conclusion="success", run_id="1",
                nonce="1", observed_at=datetime(2026, 8, 29, 12, tzinfo=UTC)
            )
        ],
        allowlisted_contexts=["unit-validation"],
        config_digest="sha256:" + "a" * 64,
        validation_app_id=15368,
        freshness_cutoff=datetime(2026, 1, 1, tzinfo=UTC),
        observed_at=datetime(2026, 8, 29, 12, tzinfo=UTC),
    )
    return _payload(
        MainReleaseHoldObservation.model_construct(
            repository_digest=admission.repository_digest,
            target_ref="refs/heads/main",
            operation_id=admission.operation_id,
            preparation_authorization_digest=admission.preparation_authorization_digest,
            admission_observation_digest="sha256:" + "b" * 64,
            package_digest=admission.package_digest,
            composition_digest=admission.composition_digest,
            pull_request_number=7,
            group_sha=G,
            group_tree=E,
            group_parents=[A, D],
            expected_group_parents=[A, D],
            group_topology_digest="sha256:" + "c" * 64,
            base_commit=A,
            base_tree=C,
            composition_tree=E,
            queue_generation_digest=admission.queue_generation_digest,
            queue_members=[7],
            max_entries_per_group=1,
            hold_run_id="hold-run",
            hold_nonce="hold-nonce",
            issuer_identity="isolated-release",
            release_issuer_app_id=9001,
            issuer_isolation_digest=ISOLATION,
            check_context="avo-main-release",
            check_state="in_progress",
            check_conclusion="pending",
            validation_app_id=15368,
            other_required_checks=checks,
            merge_group_receipt=receipt,
            protection_manifest_digest="sha256:" + "d" * 64,
            attestation_manifest_digest="sha256:" + "e" * 64,
            observed_at=datetime(2026, 8, 29, 12, tzinfo=UTC),
        )
    )


def _authorization() -> MainReleaseAuthorization:
    return MainReleaseAuthorization.model_construct(
        repository_digest=github_repository_digest("avo", "repo"),
        target_ref="refs/heads/main",
        operation_id="sha256:" + "2" * 64,
        preparation_authorization_digest="sha256:" + "3" * 64,
        admission_observation_digest="sha256:" + "4" * 64,
        hold_observation_digest="sha256:" + "5" * 64,
        package_digest="sha256:" + "6" * 64,
        composition_digest="sha256:" + "7" * 64,
        group_sha=G,
        hold_run_id="12",
        hold_nonce="hold-nonce",
        queue_generation_digest="sha256:" + "8" * 64,
        lease_identity="lease",
        lease_digest="sha256:" + "9" * 64,
        policy_epoch="sha256:" + "a" * 64,
        release_issuer_identity="isolated-release",
        release_issuer_app_id=9001,
        issuer_isolation_digest=ISOLATION,
        authorization_digest="sha256:" + "b" * 64,
        one_use=True,
        used=False,
        deploy_performed=False,
        expires_at=datetime(2026, 8, 30, tzinfo=UTC),
        authorized_at=datetime(2026, 8, 29, tzinfo=UTC),
    )


def _transition(
    auth: MainReleaseAuthorization, *, outcome: str = "transitioned"
) -> MainReleaseTransitionReceipt:
    return MainReleaseTransitionReceipt.model_construct(
        repository_digest=auth.repository_digest,
        target_ref="refs/heads/main",
        operation_id=auth.operation_id,
        release_authorization_digest=canonical_digest(auth),
        group_sha=G,
        hold_run_id="12",
        hold_nonce="hold-nonce",
        issuer_identity="isolated-release",
        release_issuer_app_id=9001,
        validation_app_id=15368,
        issuer_isolation_digest=ISOLATION,
        outcome=outcome,
        transition_count=1,
        response_digest="sha256:" + "c" * 64,
        observed_at=datetime(2026, 8, 29, 12, tzinfo=UTC),
        deploy_performed=False,
    )


@pytest.mark.parametrize(
    ("method", "value"),
    [("parse_admission", "issuer_identity"), ("parse_hold", "issuer_identity")],
)
def test_contract_parsers_accept_valid_shape_and_reject_controller_drift(
    method: str, value: str
) -> None:
    main = provider(FakeTransport())
    payload = _admission_payload() if method == "parse_admission" else _hold_payload()
    assert getattr(main, method)(payload)
    payload[value] = "untrusted"
    with pytest.raises(ProtectedMainProviderError):
        getattr(main, method)(payload)


def test_contract_parsers_cover_malformed_payloads_and_release_outcomes() -> None:
    main = provider(FakeTransport())
    for method, payload in [
        (main.parse_admission, {"repository_digest": "bad"}),
        (main.parse_hold, {"repository_digest": "bad"}),
        (main.parse_release_authorization, {"repository_digest": "bad"}),
        (main.parse_provider_receipt, {"repository_digest": "bad"}),
    ]:
        with pytest.raises(ProtectedMainProviderError):
            method(cast(JsonObject, payload))
    transition = _payload(_transition(_authorization()))
    assert main.parse_release_transition(transition).outcome == "transitioned"
    transition["outcome"] = "not-a-real-outcome"
    with pytest.raises(ProtectedMainProviderError):
        main.parse_release_transition(transition)


def test_release_attestation_accepts_transition_and_rejects_drift() -> None:
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
    transition = _transition(auth)
    # The authorization digest is deliberately calculated exactly as the
    # attester does; model_construct keeps this fixture focused on the stage.
    assert MainGraduationAttester(main).attest_release(auth, hold, transition) is transition
    for mutation in ("issuer_identity", "group_sha", "outcome"):
        bad = _transition(auth).model_copy(
            update={mutation: "bad" if mutation != "outcome" else "reconciliation_required"}
        )
        with pytest.raises(ProtectedMainProviderError):
            MainGraduationAttester(main).attest_release(auth, hold, bad)


@pytest.mark.parametrize("status", [400, 500, 302])
def test_rest_and_graphql_statuses_fail_closed(status: int) -> None:
    fake = FakeTransport()

    def transport(
        method: str,
        url: str,
        body: JsonBody | None,
        headers: Mapping[str, str],
    ) -> tuple[int, JsonValue]:
        if url.endswith("/graphql"):
            return status, {"data": {}}
        return status, {"full_name": "avo/repo"}

    main = provider(cast(JsonTransport, transport))
    with pytest.raises((ProtectedMainRejected, ProtectedMainProviderError)):
        main.observe_repository()
    with pytest.raises((ProtectedMainRejected, ProtectedMainProviderError)):
        main.observe_queue()
    assert fake is not None


def test_transport_exceptions_and_malformed_repository_reads_are_wrapped() -> None:
    def broken(
        _method: str,
        _url: str,
        _body: JsonBody | None,
        _headers: Mapping[str, str],
    ) -> tuple[int, JsonValue]:
        raise OSError("network down")

    with pytest.raises(ProtectedMainProviderError, match="transport failure"):
        provider(cast(JsonTransport, broken)).observe_repository()
    fake = FakeTransport()
    fake.pr["base"] = None
    with pytest.raises(ProtectedMainProviderError):
        provider(fake).observe_pull_request(7)


@pytest.mark.parametrize("body", [b"{", b"\xff", b"null", b"{\"action\":true}"])
def test_webhook_body_parse_edges_fail_closed(body: bytes) -> None:
    main = provider(FakeTransport())
    signature = "sha256=" + hmac.new(b"webhook-secret", body, hashlib.sha256).hexdigest()
    headers = {
        "X-GitHub-Event": "merge_group",
        "X-GitHub-Delivery": "body-edge-" + str(len(body)),
        "X-Hub-Signature-256": signature,
    }
    with pytest.raises(ProtectedMainProviderError):
        main.observe_merge_group(G, webhook_body=body, webhook_headers=headers)


@pytest.mark.parametrize(
    "mutation",
    [
        {"action": "completed"},
        {"repository": {"full_name": "other/repo"}},
        {
            "merge_group": {
                "head_sha": G,
                "head_ref": "refs/heads/main",
                "base_sha": A,
                "base_ref": "main",
            }
        },
        {
            "merge_group": {
                "head_sha": G,
                "head_ref": "refs/heads/gh-readonly-queue/main/7",
                "base_sha": D,
                "base_ref": "main",
            }
        },
    ],
)
def test_webhook_semantic_and_ref_binding_failures(mutation: JsonObject) -> None:
    fake = FakeTransport()
    main = provider(fake)
    queue = main.observe_queue()
    body, headers = signed_webhook(delivery="semantic-" + str(len(fake.calls)))
    decoded = cast(JsonObject, json.loads(body))
    for key, value in mutation.items():
        if key == "merge_group":
            cast(JsonObject, decoded["merge_group"]).update(cast(JsonObject, value))
        else:
            decoded[key] = value
    body = json.dumps(decoded, separators=(",", ":")).encode()
    headers["X-Hub-Signature-256"] = "sha256=" + hmac.new(
        b"webhook-secret", body, hashlib.sha256
    ).hexdigest()
    with pytest.raises(ProtectedMainProviderError):
        main.observe_merge_group(
            G,
            webhook_body=body,
            webhook_headers=headers,
            queue=queue,
            pull_request_number=7,
        )


def test_webhook_missing_secret_and_header_shape_are_rejected() -> None:
    fake = FakeTransport()
    main = ProtectedMainProvider(
        "avo", "repo", github_repository_digest("avo", "repo"),
        release_issuer_identity="isolated-release", release_issuer_app_id=9001,
        issuer_isolation_digest=ISOLATION, trusted_check_contexts=("unit-validation",),
        token="token", transport=fake,
    )
    body, headers = signed_webhook(delivery="missing-secret")
    with pytest.raises(ProtectedMainProviderError):
        main.observe_merge_group(G, webhook_body=body, webhook_headers=headers)
    main = provider(fake)
    body, headers = signed_webhook(delivery="bad-header")
    headers["X-GitHub-Delivery"] = ""
    with pytest.raises(ProtectedMainProviderError):
        main.observe_merge_group(G, webhook_body=body, webhook_headers=headers)


@pytest.mark.parametrize("field", ["status", "conclusion", "name", "id", "app"])
def test_check_run_malformed_fields_fail_closed(field: str) -> None:
    fake = FakeTransport()
    run = check()
    run[field] = None
    fake.runs = [run]
    with pytest.raises(ProtectedMainProviderError):
        provider(fake).observe_check_runs(G)


def test_ruleset_resolution_edge_failures_are_not_accepted() -> None:
    mutations: list[tuple[str, JsonValue]] = [
        ("ruleset_source_type", "Team"),
        ("ruleset_id", 99),
        ("ruleset_source", "other/repo"),
    ]
    for key, value in mutations:
        fake = FakeTransport()
        fake.effective_rules[0][key] = value
        with pytest.raises(ProtectedMainProviderError):
            provider(fake).observe_protection()
    fake = FakeTransport()
    fake.ruleset["bypass_actors"] = "missing-list"
    with pytest.raises(ProtectedMainProviderError):
        provider(fake).observe_protection()


def test_protection_rejects_malformed_effective_rule_and_org_resolution() -> None:
    fake = FakeTransport()
    fake.effective_rules[0]["parameters"] = None
    with pytest.raises(ProtectedMainProviderError):
        provider(fake).observe_protection()
    fake = FakeTransport()
    fake.effective_rules[0]["ruleset_source_type"] = "Organization"
    fake.effective_rules[0]["ruleset_source"] = "avo"
    with pytest.raises(ProtectedMainProviderError):
        provider(fake).observe_protection()
