from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
    MainGraduationJournalError,
    MainGraduationRecordConflictError,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.main_graduation import (
    MainCheckObservation,
    MainCompositionArtifact,
    MainDeltaManifest,
    MainGraduationAttempt,
    MainGraduationEligibilityRecord,
    MainGraduationIntent,
    MainGraduationPlan,
    MainInverseDeltaArtifact,
    MainMergeGroupChecks,
    MainPreparationAuthorization,
    MainProtectionManifest,
    MainProviderReceipt,
    MainQueueAdmissionObservation,
    MainQueueObservation,
    MainReconciliation,
    MainReleaseAuthorization,
    MainReleaseIssuerBinding,
    MainReleaseTransitionReceipt,
    MainSourcePackageBinding,
)
from avo_correlate.domain.canonical import canonical_digest

DIGEST = "sha256:" + "1" * 64
BASE = "a" * 40
HEAD = "b" * 40
TREE = "c" * 40


def test_main_binding_rejects_wrong_target_and_deploy() -> None:
    with pytest.raises(ValidationError):
        MainQueueAdmissionObservation(
            operation_id=DIGEST,
            repository_digest=DIGEST,
            target_ref="refs/heads/integration",
            preparation_authorization_digest=DIGEST,
            package_digest=DIGEST,
            composition_digest=DIGEST,
            pull_request_number=1,
            pull_request_url="https://example.test/p/1",
            base_commit=BASE,
            base_tree=TREE,
            head_commit=HEAD,
            head_tree=TREE,
            admission_sha=HEAD,
            admission_run_id="run",
            admission_nonce="nonce",
            queue_generation_digest=DIGEST,
            protection_manifest_digest=DIGEST,
            issuer_identity="isolated-release",
            release_issuer_app_id=9001,
            issuer_isolation_digest=DIGEST,
            observed_at=datetime.now(UTC),
        )


def test_eligibility_sequence_is_gap_free() -> None:
    with pytest.raises(ValidationError):
        MainGraduationEligibilityRecord(
            operation_id=DIGEST,
            repository_digest=DIGEST,
            scheduler_sequence=3,
            previous_scheduler_sequence=1,
            submission_digest=DIGEST,
            classification="eligible",
            ordinary=True,
            nonempty=True,
        )


def test_source_package_uses_a_distinct_upstream_operation() -> None:
    artifact = ArtifactRef(
        digest=DIGEST,
        size_bytes=1,
        media_type="application/vnd.avo.integration-campaign+json",
        role="integration-campaign-package",
        created_at=datetime.now(UTC),
    )
    values = {
        "operation_id": DIGEST,
        "source_operation_id": "sha256:" + "2" * 64,
        "repository_digest": DIGEST,
        "package_digest": DIGEST,
        "package_artifact": artifact,
        "child_artifacts": [artifact.model_copy(update={"role": "source-child"})],
        "source_result_commit": HEAD,
        "source_result_tree": TREE,
        "source_result_parent": BASE,
        "source_issuer": "source-controller",
    }
    assert MainSourcePackageBinding(**values).source_operation_id != DIGEST
    with pytest.raises(ValidationError, match="must differ"):
        MainSourcePackageBinding(**{**values, "source_operation_id": DIGEST})


def test_queue_topology_digest_is_canonical_and_binds_two_parent_form() -> None:
    topology = {
        "expected_group_parents": [BASE, HEAD],
        "merge_method": "squash",
        "provider_identity": "provider",
        "provider_api_version": "v1",
        "queue_manifest_digest": DIGEST,
    }
    values = {
        "operation_id": DIGEST,
        "repository_digest": DIGEST,
        "queue_generation_digest": DIGEST,
        "queue_manifest_digest": DIGEST,
        "expected_base_commit": BASE,
        "expected_base_tree": TREE,
        "protection_manifest_digest": DIGEST,
        "protection_epoch": DIGEST,
        "provider_identity": "provider",
        "provider_api_version": "v1",
        "expected_group_parents": [BASE, HEAD],
        "group_topology_digest": canonical_digest(topology),
        "merge_method": "squash",
        "isolated_release_issuer": "release",
        "release_issuer_app_id": 9001,
        "issuer_isolation_digest": DIGEST,
        "observed_at": datetime.now(UTC),
    }
    assert MainQueueObservation(**values).expected_group_parents == [BASE, HEAD]
    with pytest.raises(ValidationError, match="topology digest"):
        MainQueueObservation(**{**values, "group_topology_digest": DIGEST})


def test_inverse_delta_digest_is_canonical() -> None:
    values = {
        "operation_id": DIGEST,
        "repository_digest": DIGEST,
        "completion_package_digest": "sha256:" + "2" * 64,
        "current_main_commit": HEAD,
        "current_main_tree": TREE,
        "inverse_changed_paths": ["src/feature.py"],
        "inverse_tree": BASE,
        "policy_epoch": DIGEST,
    }
    probe = MainInverseDeltaArtifact.model_construct(**values, inverse_delta_digest=DIGEST)
    artifact = MainInverseDeltaArtifact(
        **values,
        inverse_delta_digest=canonical_digest(
            probe.model_dump(exclude={"inverse_delta_digest"}, mode="json")
        ),
    )
    assert artifact.inverse_delta_digest != DIGEST


@pytest.mark.parametrize(
    "field, value",
    [
        ("package_digest", "sha256:" + "2" * 64),
        ("base_tree", BASE),
        ("candidate_commit", BASE),
        ("lease_identity", "other-lease"),
        ("policy_epoch", "sha256:" + "2" * 64),
    ],
)
def test_preparation_chain_rejects_each_shared_binding_edge(
    tmp_path: Path, field: str, value: str
) -> None:
    source = MainSourcePackageBinding.model_construct(package_digest=DIGEST)
    composition = MainCompositionArtifact.model_construct(
        composition_digest=DIGEST,
        base_commit=BASE,
        base_tree=TREE,
        candidate_commit=HEAD,
        candidate_tree=TREE,
    )
    plan = MainGraduationPlan.model_construct(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        target_ref="refs/heads/main",
        package=source,
        composition=composition,
        policy_epoch=DIGEST,
    )
    intent = MainGraduationIntent.model_construct(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        target_ref="refs/heads/main",
        plan_digest=canonical_digest(plan),
        package_digest=DIGEST,
        composition_digest=DIGEST,
        base_commit=BASE,
        base_tree=TREE,
        candidate_commit=HEAD,
        candidate_tree=TREE,
        lease_identity="lease",
        lease_digest=DIGEST,
        policy_epoch=DIGEST,
    )
    preparation = MainPreparationAuthorization.model_construct(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        target_ref="refs/heads/main",
        plan_digest=canonical_digest(plan),
        intent_digest=canonical_digest(intent),
        package_digest=DIGEST,
        composition_digest=DIGEST,
        base_commit=BASE,
        base_tree=TREE,
        candidate_commit=HEAD,
        candidate_tree=TREE,
        lease_identity="lease",
        lease_digest=DIGEST,
        policy_epoch=DIGEST,
    ).model_copy(update={field: value})
    journal = MainGraduationJournal(tmp_path)
    original_read = journal._read  # pyright: ignore[reportPrivateUsage]

    def read(kind: str, _operation_id: str):
        if kind == "plan":
            return plan, None
        if kind == "intent":
            return intent, None
        return original_read(kind, _operation_id)

    journal._read = read  # type: ignore[method-assign]
    with pytest.raises(MainGraduationJournalError, match="preparation plan/intent"):
        journal._require_preparation_chain(preparation)  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    "field, value",
    [("repository_digest", "sha256:" + "2" * 64), ("issuer_identity", "attacker")],
)
def test_transition_rejects_attacker_repository_or_issuer(
    tmp_path: Path, field: str, value: str
) -> None:
    now = datetime.now(UTC)
    authorization = MainReleaseAuthorization.model_construct(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        target_ref="refs/heads/main",
        group_sha=HEAD,
        hold_run_id="run",
        hold_nonce="nonce",
        release_issuer_identity="release",
        release_issuer_app_id=9001,
        issuer_isolation_digest=DIGEST,
        authorized_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    receipt = MainReleaseTransitionReceipt.model_construct(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        target_ref="refs/heads/main",
        release_authorization_digest=canonical_digest(authorization),
        group_sha=HEAD,
        hold_run_id="run",
        hold_nonce="nonce",
        issuer_identity="release",
        release_issuer_app_id=9001,
        issuer_isolation_digest=DIGEST,
        observed_at=now,
    ).model_copy(update={field: value})
    journal = MainGraduationJournal(tmp_path)
    journal._read = lambda _kind, _operation: (authorization, None)  # type: ignore[method-assign]
    with pytest.raises(MainGraduationJournalError, match="does not bind"):
        journal._require_release_authorization(receipt)  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize("offset, accepted", [(-1, False), (0, True), (300, True), (301, False)])
def test_transition_requires_inclusive_authorization_time_window(
    tmp_path: Path, offset: int, accepted: bool
) -> None:
    issued = datetime.now(UTC)
    authorization = MainReleaseAuthorization.model_construct(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        target_ref="refs/heads/main",
        group_sha=HEAD,
        hold_run_id="run",
        hold_nonce="nonce",
        release_issuer_identity="release",
        release_issuer_app_id=9001,
        issuer_isolation_digest=DIGEST,
        authorized_at=issued,
        expires_at=issued + timedelta(seconds=300),
    )
    receipt = MainReleaseTransitionReceipt.model_construct(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        target_ref="refs/heads/main",
        release_authorization_digest=canonical_digest(authorization),
        group_sha=HEAD,
        hold_run_id="run",
        hold_nonce="nonce",
        issuer_identity="release",
        release_issuer_app_id=9001,
        issuer_isolation_digest=DIGEST,
        observed_at=issued + timedelta(seconds=offset),
    )
    journal = MainGraduationJournal(tmp_path)
    journal._read = lambda _kind, _operation: (authorization, None)  # type: ignore[method-assign]
    if accepted:
        journal._require_release_authorization(receipt)  # pyright: ignore[reportPrivateUsage]
    else:
        with pytest.raises(MainGraduationJournalError, match="validity window"):
            journal._require_release_authorization(receipt)  # pyright: ignore[reportPrivateUsage]


def test_provider_receipt_rejects_provider_identity_substitution(tmp_path: Path) -> None:
    authorization = MainReleaseAuthorization.model_construct(
        operation_id=DIGEST, repository_digest=DIGEST, target_ref="refs/heads/main"
    )
    queue = MainQueueObservation.model_construct(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        target_ref="refs/heads/main",
        provider_identity="provider",
        provider_api_version="v1",
    )
    protection = MainProtectionManifest.model_construct(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        target_ref="refs/heads/main",
        provider_identity="provider",
        provider_api_version="v1",
    )
    plan = MainGraduationPlan.model_construct(
        operation_id=DIGEST,
        composition=MainCompositionArtifact.model_construct(candidate_tree=TREE, base_commit=BASE),
    )
    receipt = MainProviderReceipt.model_construct(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        target_ref="refs/heads/main",
        release_authorization_digest=canonical_digest(authorization),
        provider_identity="attacker",
        provider_api_version="v1",
        outcome="observed",
        result_tree=TREE,
        result_parents=[BASE],
        observed_at=datetime.now(UTC) + timedelta(seconds=1),
    )
    journal = MainGraduationJournal(tmp_path)
    transition = MainReleaseTransitionReceipt.model_construct(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        target_ref="refs/heads/main",
        release_authorization_digest=canonical_digest(authorization),
        observed_at=datetime.now(UTC),
    )
    records = {
        "release-authorization": authorization,
        "release-transition": transition,
        "queue": queue,
        "protection": protection,
        "plan": plan,
    }
    journal._read = lambda kind, _operation: (records[kind], None)  # type: ignore[method-assign]
    journal._require_release_authorization = lambda _transition: None  # type: ignore[method-assign]
    with pytest.raises(MainGraduationJournalError, match="provider receipt authorization"):
        journal._require_provider_receipt(receipt)  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize("source_record", [None, "different", "same"])
def test_plan_requires_durable_strict_source_package(
    tmp_path: Path, source_record: str | None
) -> None:
    journal = MainGraduationJournal(tmp_path)
    raw = b"{}"
    reference = journal._store.put_bytes(  # pyright: ignore[reportPrivateUsage]
        raw,
        media_type="application/vnd.avo.integration-campaign+json",
        role="integration-campaign-package",
        max_bytes=1024,
    )
    package = MainSourcePackageBinding.model_construct(
        operation_id=DIGEST,
        source_operation_id="sha256:" + "2" * 64,
        package_artifact=reference,
        package_digest=reference.digest,
        child_artifacts=[],
    )
    plan = MainGraduationPlan.model_construct(operation_id=DIGEST, package=package)
    if source_record is None:
        journal._read = lambda _kind, _operation: None  # type: ignore[method-assign]
        expected = "durable source-package"
    elif source_record == "different":
        other = package.model_copy(update={"source_operation_id": "sha256:" + "3" * 64})
        journal._read = lambda _kind, _operation: (other, None)  # type: ignore[method-assign]
        expected = "differs from durable"
    else:
        journal._read = lambda _kind, _operation: (package, None)  # type: ignore[method-assign]
        expected = "source package or child"
    with pytest.raises(MainGraduationJournalError, match=expected):
        journal._verify_plan_evidence(plan)  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize("outcome", ["ambiguous", "rejected"])
def test_provider_recovery_receipts_do_not_claim_success_and_remain_verifiable(
    tmp_path: Path, outcome: str
) -> None:
    authorization = MainReleaseAuthorization.model_construct(
        operation_id=DIGEST, repository_digest=DIGEST, target_ref="refs/heads/main"
    )
    queue = MainQueueObservation.model_construct(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        target_ref="refs/heads/main",
        provider_identity="provider",
        provider_api_version="v1",
    )
    protection = MainProtectionManifest.model_construct(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        target_ref="refs/heads/main",
        provider_identity="provider",
        provider_api_version="v1",
    )
    plan = MainGraduationPlan.model_construct(
        operation_id=DIGEST,
        composition=MainCompositionArtifact.model_construct(candidate_tree=TREE, base_commit=BASE),
    )
    receipt = MainProviderReceipt.model_construct(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        target_ref="refs/heads/main",
        release_authorization_digest=canonical_digest(authorization),
        provider_identity="provider",
        provider_api_version="v1",
        outcome=outcome,
        result_commit=None,
        result_tree=None,
        result_parents=[],
        observed_at=datetime.now(UTC) + timedelta(seconds=1),
    )
    journal = MainGraduationJournal(tmp_path)
    transition = MainReleaseTransitionReceipt.model_construct(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        target_ref="refs/heads/main",
        release_authorization_digest=canonical_digest(authorization),
        observed_at=datetime.now(UTC),
    )
    records = {
        "release-authorization": authorization,
        "release-transition": transition,
        "queue": queue,
        "protection": protection,
        "plan": plan,
    }
    journal._read = lambda kind, _operation: (records[kind], None)  # type: ignore[method-assign]
    journal._require_release_authorization = lambda _transition: None  # type: ignore[method-assign]
    journal._require_provider_receipt(receipt)  # pyright: ignore[reportPrivateUsage]


def test_provider_receipt_without_durable_transition_is_rejected(tmp_path: Path) -> None:
    authorization = MainReleaseAuthorization.model_construct(
        operation_id=DIGEST, repository_digest=DIGEST, target_ref="refs/heads/main"
    )
    receipt = MainProviderReceipt.model_construct(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        target_ref="refs/heads/main",
        release_authorization_digest=canonical_digest(authorization),
    )
    journal = MainGraduationJournal(tmp_path)
    journal._read = lambda kind, _operation: (
        (authorization, None) if kind == "release-authorization" else None
    )  # type: ignore[method-assign]
    with pytest.raises(MainGraduationJournalError, match="durable release transition"):
        journal._require_provider_receipt(receipt)  # pyright: ignore[reportPrivateUsage]


def test_reconciliation_rejects_wrong_composition_tree_or_repository(tmp_path: Path) -> None:
    now = datetime.now(UTC)
    authorization = MainReleaseAuthorization.model_construct(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        target_ref="refs/heads/main",
        group_sha=HEAD,
        hold_run_id="run",
        hold_nonce="nonce",
        release_issuer_identity="release",
        release_issuer_app_id=9001,
        issuer_isolation_digest=DIGEST,
        authorized_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    transition = MainReleaseTransitionReceipt.model_construct(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        target_ref="refs/heads/main",
        release_authorization_digest=canonical_digest(authorization),
        group_sha=HEAD,
        hold_run_id="run",
        hold_nonce="nonce",
        issuer_identity="release",
        release_issuer_app_id=9001,
        issuer_isolation_digest=DIGEST,
        observed_at=now,
    )
    queue = MainQueueObservation.model_construct(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        target_ref="refs/heads/main",
        queue_generation_digest=DIGEST,
        provider_identity="provider",
        provider_api_version="v1",
    )
    protection = MainProtectionManifest.model_construct(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        target_ref="refs/heads/main",
        provider_identity="provider",
        provider_api_version="v1",
    )
    plan = MainGraduationPlan.model_construct(
        operation_id=DIGEST,
        composition=MainCompositionArtifact.model_construct(candidate_tree=TREE, base_commit=BASE),
    )
    provider = MainProviderReceipt.model_construct(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        target_ref="refs/heads/main",
        release_authorization_digest=canonical_digest(authorization),
        provider_identity="provider",
        provider_api_version="v1",
        outcome="observed",
        result_commit=HEAD,
        result_tree=TREE,
        result_parents=[BASE],
        observed_at=now + timedelta(seconds=1),
    )
    reconciliation = MainReconciliation.model_construct(
        operation_id=DIGEST,
        repository_digest="sha256:" + "2" * 64,
        target_ref="refs/heads/main",
        state="completed",
        transition_receipt_digest=canonical_digest(transition),
        queue_generation_digest=DIGEST,
        main_commit=HEAD,
        main_tree=BASE,
        main_parents=[BASE],
        expected_tree=TREE,
        expected_base_commit=BASE,
    )
    journal = MainGraduationJournal(tmp_path)
    records = {
        "release-authorization": authorization,
        "release-transition": transition,
        "provider-receipt": provider,
        "queue": queue,
        "protection": protection,
        "plan": plan,
    }
    journal._read = lambda kind, _operation: (records[kind], None)  # type: ignore[method-assign]
    with pytest.raises(MainGraduationJournalError, match="reconciliation prior-stage"):
        journal._require_reconciliation(reconciliation)  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize("ordinary, nonempty", [(False, True), (True, False), (False, False)])
def test_eligibility_exclusion_allows_each_nonordinary_or_empty_axis(
    ordinary: bool, nonempty: bool
) -> None:
    record = MainGraduationEligibilityRecord(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        scheduler_sequence=1,
        submission_digest=DIGEST,
        classification="excluded",
        exclusion_reason="not eligible for main graduation",
        exclusion_evidence_digest=DIGEST,
        ordinary=ordinary,
        nonempty=nonempty,
    )
    assert record.classification == "excluded"


def test_release_authorization_digest_is_canonical() -> None:
    now = datetime.now(UTC)
    values = {
        "operation_id": DIGEST,
        "repository_digest": DIGEST,
        "preparation_authorization_digest": DIGEST,
        "admission_observation_digest": DIGEST,
        "hold_observation_digest": DIGEST,
        "package_digest": DIGEST,
        "composition_digest": DIGEST,
        "group_sha": HEAD,
        "hold_run_id": "hold-run",
        "hold_nonce": "hold-nonce",
        "queue_generation_digest": DIGEST,
        "lease_identity": "lease",
        "lease_digest": DIGEST,
        "policy_epoch": DIGEST,
        "release_issuer_identity": "isolated-release",
        "release_issuer_app_id": 9001,
        "issuer_isolation_digest": DIGEST,
        "one_use": True,
        "used": False,
        "deploy_performed": False,
        "expires_at": now + timedelta(minutes=5),
        "authorized_at": now,
    }
    probe = MainReleaseAuthorization.model_construct(
        **values,
        authorization_digest=DIGEST,
    )
    auth = MainReleaseAuthorization(
        **values,
        authorization_digest=canonical_digest(
            probe.model_dump(exclude={"authorization_digest"}, mode="json")
        ),
    )
    with pytest.raises(ValidationError):
        MainReleaseAuthorization.model_validate(
            {**auth.model_dump(mode="json"), "authorization_digest": DIGEST}
        )


def test_journal_create_once_and_canonical_read(tmp_path: Path) -> None:
    eligibility = MainGraduationEligibilityRecord(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        scheduler_sequence=1,
        submission_digest=DIGEST,
        classification="eligible",
        ordinary=True,
        nonempty=True,
    )
    attempt = MainGraduationAttempt(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        scheduler_sequence=1,
        eligibility_record_digest=canonical_digest(eligibility),
    )
    journal = MainGraduationJournal(tmp_path)
    journal.record_eligibility(eligibility)
    first = journal.record_attempt(attempt)
    second = journal.record_attempt(attempt)
    assert first.digest == second.digest
    assert journal.read_attempt(DIGEST)[0] == attempt  # type: ignore[index]

    journal.delete_artifact(first.digest)
    with pytest.raises(MainGraduationJournalError):
        journal.read_attempt(DIGEST)


def test_journal_rejects_attempt_without_canonical_durable_eligibility(tmp_path: Path) -> None:
    attempt = MainGraduationAttempt(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        scheduler_sequence=1,
        eligibility_record_digest=DIGEST,
    )
    with pytest.raises(MainGraduationJournalError, match="durable eligibility"):
        MainGraduationJournal(tmp_path).record_attempt(attempt)


def test_global_admission_run_nonce_replay_uses_original_reference(tmp_path: Path) -> None:
    journal = MainGraduationJournal(tmp_path)
    first_ref = journal._store.put_bytes(  # pyright: ignore[reportPrivateUsage]
        b"admission", media_type="application/json", role="test", max_bytes=1024
    )
    replay_ref = first_ref.model_copy(update={"created_at": datetime.now(UTC) + timedelta(days=1)})
    admission = MainQueueAdmissionObservation.model_construct(
        operation_id=DIGEST, admission_run_id="run", admission_nonce="nonce"
    )
    assert journal._index_run_nonce("admission", admission, first_ref) is None  # pyright: ignore[reportPrivateUsage]
    assert journal._index_run_nonce("admission", admission, replay_ref) == first_ref  # pyright: ignore[reportPrivateUsage]
    conflicting = admission.model_copy(update={"operation_id": "sha256:" + "2" * 64})
    with pytest.raises(MainGraduationRecordConflictError):
        journal._index_run_nonce("admission", conflicting, replay_ref)  # pyright: ignore[reportPrivateUsage]


def test_delta_uses_strict_policy_path_and_ordinary_risk() -> None:
    values = {
        "operation_id": DIGEST,
        "repository_digest": DIGEST,
        "package_digest": DIGEST,
        "source_result_commit": BASE,
        "source_result_tree": TREE,
        "source_result_parent": HEAD,
        "path_manifest_digest": DIGEST,
        "delta_digest": DIGEST,
        "ordinary_risk_digest": DIGEST,
    }
    for path in (
        "src\\feature.py",
        "src/../feature.py",
        "src/avo_correlate/contracts/promotion_policy.py",
    ):
        with pytest.raises(ValidationError):
            MainDeltaManifest(**values, changed_paths=[path])


def test_journal_blocks_later_open_eligible_sequence(tmp_path: Path) -> None:
    journal = MainGraduationJournal(tmp_path)
    first = MainGraduationEligibilityRecord(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        scheduler_sequence=1,
        submission_digest=DIGEST,
        classification="eligible",
        ordinary=True,
        nonempty=True,
    )
    journal.record_eligibility(first)
    second = first.model_copy(
        update={
            "operation_id": "sha256:" + "2" * 64,
            "submission_digest": "sha256:" + "2" * 64,
            "scheduler_sequence": 2,
            "previous_scheduler_sequence": 1,
        }
    )
    with pytest.raises(MainGraduationJournalError):
        journal.record_eligibility(second)


def test_journal_rejects_traversal_kind_and_duplicate_sequence(tmp_path: Path) -> None:
    journal = MainGraduationJournal(tmp_path)
    with pytest.raises(ValueError):
        journal.read("../plan", DIGEST)
    first = MainGraduationEligibilityRecord(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        scheduler_sequence=1,
        submission_digest=DIGEST,
        classification="eligible",
        ordinary=True,
        nonempty=True,
    )
    journal.record_eligibility(first)
    duplicate = first.model_copy(
        update={
            "operation_id": "sha256:" + "2" * 64,
            "submission_digest": "sha256:" + "2" * 64,
        }
    )
    with pytest.raises(MainGraduationJournalError):
        journal.record_eligibility(duplicate)


def test_issuer_type_and_group_check_semantics_are_structural() -> None:
    with pytest.raises(ValidationError):
        MainReleaseIssuerBinding(issuer_id="release", app_id=15368, isolation_digest=DIGEST)
    now = datetime.now(UTC)
    check = MainCheckObservation(
        name="validation",
        context="validate",
        app_id=15368,
        sha=HEAD,
        status="completed",
        conclusion="success",
        run_id="run",
        nonce="nonce",
        observed_at=now,
    )
    group = MainMergeGroupChecks(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        package_digest=DIGEST,
        composition_digest=DIGEST,
        group_sha=HEAD,
        checks=[check],
        allowlisted_contexts=["validate"],
        config_digest=DIGEST,
        freshness_cutoff=now - timedelta(minutes=1),
        observed_at=now,
    )
    assert group.checks[0].app_id == 15368
    with pytest.raises(ValidationError):
        MainProviderReceipt(
            operation_id=DIGEST,
            repository_digest=DIGEST,
            release_authorization_digest=DIGEST,
            provider_identity="provider",
            provider_api_version="v1",
            outcome="observed",
            result_commit=HEAD,
            result_tree=TREE,
            result_parents=[],
            response_digest=DIGEST,
            observed_at=now,
        )
