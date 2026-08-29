from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
    MainGraduationJournalError,
)
from avo_correlate.contracts.main_graduation import (
    MainCheckObservation,
    MainDeltaManifest,
    MainGraduationAttempt,
    MainGraduationEligibilityRecord,
    MainMergeGroupChecks,
    MainProviderReceipt,
    MainQueueAdmissionObservation,
    MainReleaseAuthorization,
    MainReleaseIssuerBinding,
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
    attempt = MainGraduationAttempt(
        operation_id=DIGEST,
        repository_digest=DIGEST,
        scheduler_sequence=1,
        eligibility_record_digest=DIGEST,
    )
    journal = MainGraduationJournal(tmp_path)
    first = journal.record_attempt(attempt)
    second = journal.record_attempt(attempt)
    assert first.digest == second.digest
    assert journal.read_attempt(DIGEST)[0] == attempt  # type: ignore[index]

    journal.delete_artifact(first.digest)
    with pytest.raises(MainGraduationJournalError):
        journal.read_attempt(DIGEST)


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
