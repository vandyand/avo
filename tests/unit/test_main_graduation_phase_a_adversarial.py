"""Adversarial tests for the Phase-A protected-main journal boundary.

These tests intentionally exercise the journal's content-addressed indexes and
restart behavior.  They do not grant any provider or merge capability to the
test process.  The small phase-chain bypass is only a fixture seam: the
records still pass their own Pydantic validators and the tests focus on the
CAS/index invariants.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

import avo_correlate.adapters.artifacts.main_graduation_journal as journal_module
from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
    MainGraduationJournalError,
    MainGraduationRecordConflictError,
)
from avo_correlate.contracts import (
    MainClaimedReleaseTransitionReceipt,
    MainExternalIdentity,
    MainLeaseEvidenceReadRequest,
    MainLeaseEvidenceRecord,
    MainMergeGroupWebhookReceipt,
    MainMutationFenceResolution,
    MainMutationIntent,
    MainMutationReceipt,
    MainMutationStage,
    MainQueueAdmissionObservation,
    MainUnresolvedMutationFence,
    StrictModel,
    main_stage_identity_digest,
    main_target_scope_digest,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest
from tests.unit.phase_a_test_support import TEST_PHASE_A_AUTHORITY

R = "sha256:" + "1" * 64
OP = "sha256:" + "2" * 64
OP2 = "sha256:" + "3" * 64
D = "sha256:" + "4" * 64
D2 = "sha256:" + "5" * 64
D3 = "sha256:" + "6" * 64
BASE = "a" * 40
HEAD = "b" * 40
NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _journal(root: Path) -> MainGraduationJournal:
    return MainGraduationJournal(root, phase_a_authority_verifier=TEST_PHASE_A_AUTHORITY)


def _with_digest(model: type[StrictModel], field: str, **values: Any) -> StrictModel:
    probe = model.model_construct(**values, **{field: D})  # pyright: ignore[reportArgumentType]
    return model.model_validate(
        {**values, field: canonical_digest(probe.model_dump(exclude={field}, mode="json"))}
    )


def _external(
    operation_id: str = OP,
    key: str = "refs/heads/avo/candidate/op",
    stage: MainMutationStage = "candidate_publication",
) -> MainExternalIdentity:
    identity = main_stage_identity_digest(
        operation_id,
        stage,
        key,
        queue_generation_digest=(
            None if stage in {"candidate_publication", "pull_request_open"} else D2
        ),
        repository_digest=R,
        target_ref="refs/heads/main",
    )
    return MainExternalIdentity(
        repository_digest=R,
        operation_id=operation_id,
        stage=stage,
        external_key=key,
        queue_generation_digest=(
            None if stage in {"candidate_publication", "pull_request_open"} else D2
        ),
        identity_digest=identity,
    )


def _intent(
    operation_id: str = OP,
    key: str = "refs/heads/avo/candidate/op",
    stage: MainMutationStage = "candidate_publication",
) -> MainMutationIntent:
    return cast(
        MainMutationIntent,
        _with_digest(
            MainMutationIntent,
            "intent_digest",
            repository_digest=R,
            target_ref="refs/heads/main",
            operation_id=operation_id,
            stage=stage,
            lease_identity="avo-controller",
            lease_digest=D2,
            lease_epoch_digest=D2,
            policy_epoch_digest=D2,
            controller_config_digest=D2,
            preparation_authorization_digest=D2,
            external_identity=_external(operation_id, key, stage),
            request_digest=D3,
            recorded_at=NOW,
        ),
    )


def _receipt(intent: MainMutationIntent, response_digest: str = D3) -> MainMutationReceipt:
    return cast(
        MainMutationReceipt,
        _with_digest(
            MainMutationReceipt,
            "receipt_digest",
            repository_digest=R,
            target_ref="refs/heads/main",
            operation_id=intent.operation_id,
            stage=intent.stage,
            intent_digest=intent.intent_digest,
            parent_intent_digest=intent.parent_intent_digest,
            lease_identity=intent.lease_identity,
            lease_digest=intent.lease_digest,
            lease_epoch_digest=intent.lease_epoch_digest,
            policy_epoch_digest=intent.policy_epoch_digest,
            controller_config_digest=intent.controller_config_digest,
            preparation_authorization_digest=intent.preparation_authorization_digest,
            external_identity=intent.external_identity,
            outcome="ambiguous",
            dispatch_started=True,
            response_digest=response_digest,
            observed_at=NOW,
        ),
    )


def _rejected_receipt(intent: MainMutationIntent) -> MainMutationReceipt:
    return cast(
        MainMutationReceipt,
        _with_digest(
            MainMutationReceipt,
            "receipt_digest",
            repository_digest=R,
            target_ref="refs/heads/main",
            operation_id=intent.operation_id,
            stage=intent.stage,
            intent_digest=intent.intent_digest,
            parent_intent_digest=intent.parent_intent_digest,
            lease_identity=intent.lease_identity,
            lease_digest=intent.lease_digest,
            lease_epoch_digest=intent.lease_epoch_digest,
            policy_epoch_digest=intent.policy_epoch_digest,
            controller_config_digest=intent.controller_config_digest,
            preparation_authorization_digest=intent.preparation_authorization_digest,
            external_identity=intent.external_identity,
            outcome="rejected",
            dispatch_started=False,
            response_digest=D3,
            observed_at=NOW,
        ),
    )


def _fence(receipt: MainMutationReceipt, operation_id: str = OP) -> MainUnresolvedMutationFence:
    return cast(
        MainUnresolvedMutationFence,
        _with_digest(
            MainUnresolvedMutationFence,
            "fence_digest",
            repository_digest=R,
            target_ref="refs/heads/main",
            operation_id=operation_id,
            stage="candidate_publication",
            intent_digest=receipt.intent_digest,
            source_receipt_digest=receipt.receipt_digest,
            external_identity_digest=receipt.external_identity.identity_digest,
            lease_identity="avo-controller",
            lease_digest=D2,
            target_scope_digest=main_target_scope_digest(R, "refs/heads/main"),
            opened_at=NOW,
        ),
    )


def _resolution(
    fence: MainUnresolvedMutationFence, outcome: str = "observed"
) -> MainMutationFenceResolution:
    return cast(
        MainMutationFenceResolution,
        _with_digest(
            MainMutationFenceResolution,
            "resolution_digest",
            repository_digest=R,
            target_ref="refs/heads/main",
            fence_digest=fence.fence_digest,
            operation_id=fence.operation_id,
            intent_digest=fence.intent_digest,
            external_identity_digest=fence.external_identity_digest,
            lease_identity=fence.lease_identity,
            lease_digest=fence.lease_digest,
            target_scope_digest=fence.target_scope_digest,
            resolved_receipt_digest=fence.source_receipt_digest,
            authoritative_observation_digest=D3,
            provider_identity="trusted-observer",
            provider_api_version="v1",
            outcome=outcome,
            resolved_at=NOW + timedelta(minutes=1),
        ),
    )


def _transition(
    claim_digest: str, response_digest: str = D3
) -> MainClaimedReleaseTransitionReceipt:
    return cast(
        MainClaimedReleaseTransitionReceipt,
        _with_digest(
            MainClaimedReleaseTransitionReceipt,
            "receipt_digest",
            repository_digest=R,
            target_ref="refs/heads/main",
            operation_id=OP,
            release_authorization_digest=D2,
            claim_digest=claim_digest,
            group_sha=HEAD,
            hold_run_id="hold-run",
            hold_nonce="hold-nonce",
            issuer_identity="isolated-release",
            release_issuer_app_id=9002,
            issuer_isolation_digest=D2,
            outcome="transitioned",
            response_digest=response_digest,
            observed_at=NOW,
            mutation_receipt_digest=D3,
        ),
    )


def _lease_record(
    operation_id: str = OP, *, expires_at: datetime = NOW + timedelta(hours=1)
) -> MainLeaseEvidenceRecord:
    values: dict[str, Any] = {
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "operation_id": operation_id,
        "owner": "avo-controller",
        "policy_epoch": D2,
        "lease_epoch_digest": D2,
        "acquired_at": NOW,
        "expires_at": expires_at,
    }
    construct = cast(Any, MainLeaseEvidenceRecord.model_construct)
    probe = construct(**values, lease_digest=D, evidence_digest=D)
    values["lease_digest"] = canonical_digest(
        probe.model_dump(exclude={"lease_digest", "evidence_digest"}, mode="json")
    )
    probe = construct(**values, evidence_digest=D)
    values["evidence_digest"] = canonical_digest(
        probe.model_dump(exclude={"evidence_digest"}, mode="json")
    )
    return MainLeaseEvidenceRecord.model_validate(values)


def _disable_phase_prerequisites(journal: MainGraduationJournal) -> None:
    # The production chain is covered elsewhere; these tests target Phase-A
    # CAS behavior and keep their fixtures independent of the coordinator.
    journal._validate_phase_chain = lambda _kind, _record: None  # type: ignore[method-assign]


def test_intent_operation_stage_and_external_object_identities_are_create_once(
    tmp_path: Path,
) -> None:
    journal = _journal(tmp_path)
    _disable_phase_prerequisites(journal)
    first = _intent()
    journal.record_mutation_intent(first)

    with pytest.raises(MainGraduationRecordConflictError):
        journal.record_mutation_intent(_intent(key="refs/heads/avo/candidate/other"))

    other_operation = _intent(OP2)
    with pytest.raises(MainGraduationRecordConflictError):
        journal.record_mutation_intent(other_operation)


def test_receipt_resolution_and_transition_identities_are_one_use(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    _disable_phase_prerequisites(journal)
    intent = _intent()
    journal.record_mutation_intent(intent)
    receipt = _receipt(intent)
    journal.record_mutation_receipt(receipt)
    with pytest.raises(MainGraduationRecordConflictError):
        journal.record_mutation_receipt(_receipt(intent, D2))

    fence = _fence(receipt)
    journal.record_unresolved_mutation_fence(fence)
    first_resolution = _resolution(fence)
    journal._close_target_fence_if_resolved = lambda _resolution: None  # type: ignore[method-assign]
    journal.record_mutation_fence_resolution(first_resolution)
    with pytest.raises(MainGraduationRecordConflictError):
        journal.record_mutation_fence_resolution(_resolution(fence, "not_applied"))

    claim = D2
    transition = _transition(claim)
    journal.record_claimed_release_transition(transition)
    with pytest.raises(MainGraduationRecordConflictError):
        journal.record_claimed_release_transition(_transition(claim, D2))


def test_target_fence_has_one_active_winner_under_concurrency(tmp_path: Path) -> None:
    seed = _journal(tmp_path)
    _disable_phase_prerequisites(seed)
    intent = _intent()
    seed.record_mutation_intent(intent)
    receipt = _receipt(intent)
    seed.record_mutation_receipt(receipt)
    fence_a = _fence(receipt)
    fence_b = _fence(receipt).model_copy(update={"opened_at": NOW + timedelta(seconds=1)})
    # Recompute the content address after changing the fixture payload.
    fence_b = fence_b.model_copy(
        update={
            "fence_digest": canonical_digest(
                fence_b.model_dump(exclude={"fence_digest"}, mode="json")
            )
        }
    )

    def attempt(fence: MainUnresolvedMutationFence) -> str:
        journal = _journal(tmp_path)
        _disable_phase_prerequisites(journal)
        try:
            journal.record_unresolved_mutation_fence(fence)
            return "won"
        except (MainGraduationRecordConflictError, MainGraduationJournalError):
            return "lost"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, (fence_a, fence_b)))
    assert outcomes.count("won") == 1
    assert outcomes.count("lost") == 1


def test_closed_fence_replay_does_not_reopen_the_target_fence(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    _disable_phase_prerequisites(journal)
    intent = _intent()
    journal.record_mutation_intent(intent)
    receipt = _receipt(intent)
    journal.record_mutation_receipt(receipt)
    fence = _fence(receipt)
    journal.record_unresolved_mutation_fence(fence)
    journal.record_mutation_fence_resolution(_resolution(fence))

    active = journal._target_fence_path(fence)  # pyright: ignore[reportPrivateUsage]
    assert not active.exists()
    with pytest.raises(MainGraduationRecordConflictError):
        journal.record_unresolved_mutation_fence(fence)
    assert not active.exists()


def test_phase_a_restart_repairs_local_pointer_but_requires_global_indexes(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    _disable_phase_prerequisites(journal)
    intent = _intent()
    reference = journal.record_mutation_intent(intent)
    local = journal._phase_local_path("mutation-intent", intent.intent_digest)  # pyright: ignore[reportPrivateUsage]
    local.unlink()

    restarted = _journal(tmp_path)
    _disable_phase_prerequisites(restarted)
    assert restarted.record_mutation_intent(intent).digest == reference.digest
    assert restarted.read_mutation_intent(intent.intent_digest) is not None

    stage_index = restarted._stage_identity_path(  # pyright: ignore[reportPrivateUsage]
        intent.external_identity.identity_digest
    )
    stage_index.unlink()
    with pytest.raises(MainGraduationJournalError):
        restarted.read_mutation_intent(intent.intent_digest)


def test_tampered_global_envelope_and_missing_cas_artifact_fail_closed(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    _disable_phase_prerequisites(journal)
    intent = _intent()
    reference = journal.record_mutation_intent(intent)
    stage_index = journal._stage_identity_path(  # pyright: ignore[reportPrivateUsage]
        intent.external_identity.identity_digest
    )
    payload = json.loads(stage_index.read_text(encoding="utf-8"))
    payload["operation_id"] = OP2
    stage_index.write_bytes(canonical_bytes(payload))
    with pytest.raises(MainGraduationRecordConflictError):
        journal.read_mutation_intent(intent.intent_digest)

    # Restore the index and remove its content-addressed artifact.  Reads must
    # reject the dangling CAS reference instead of trusting the local pointer.
    stage_index.write_bytes(
        canonical_bytes(
            {
                "key": intent.external_identity.identity_digest,
                "operation_id": OP,
                "reference": reference,
            }
        )
    )
    assert journal.delete_artifact(reference.digest)
    with pytest.raises(MainGraduationJournalError):
        journal.read_mutation_intent(intent.intent_digest)


def test_lease_expiry_and_exact_release_are_fail_closed(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    record = _lease_record()
    journal.record_lease_evidence_record(record)
    with pytest.raises(MainGraduationJournalError, match="expired"):
        journal.assert_lease_evidence(
            MainLeaseEvidenceReadRequest(
                repository_digest=R,
                target_ref="refs/heads/main",
                operation_id=OP,
                lease_digest=record.lease_digest,
                requested_at=record.expires_at,
            )
        )
    with pytest.raises(MainGraduationRecordConflictError):
        journal.release_target_lease(R, "refs/heads/main", OP2, record.lease_digest)
    assert journal.release_target_lease(R, "refs/heads/main", OP, record.lease_digest)
    assert not journal.release_target_lease(R, "refs/heads/main", OP, record.lease_digest)


def test_run_nonce_and_webhook_global_indexes_repair_missing_local_pointers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A crash after global CAS but before the local pointer is recoverable."""
    journal = _journal(tmp_path)
    admission = MainQueueAdmissionObservation.model_validate(
        {
            "repository_digest": R,
            "operation_id": OP,
            "preparation_authorization_digest": D2,
            "package_digest": D2,
            "composition_digest": D2,
            "pull_request_number": 7,
            "pull_request_url": "https://github.com/vandyand/avo/pull/7",
            "base_commit": BASE,
            "base_tree": "c" * 40,
            "head_commit": HEAD,
            "head_tree": "d" * 40,
            "admission_sha": HEAD,
            "admission_run_id": "admission-run",
            "admission_nonce": "admission-nonce",
            "queue_generation_digest": D2,
            "protection_manifest_digest": D2,
            "issuer_identity": "isolated-admission",
            "release_issuer_app_id": 9002,
            "issuer_isolation_digest": D2,
            "observed_at": NOW,
        }
    )
    admission_ref = journal._store.put_bytes(  # pyright: ignore[reportPrivateUsage]
        canonical_bytes(admission),
        media_type="application/vnd.avo.main-graduation-queue-admission+json",
        role="main-graduation-queue-admission",
        max_bytes=32 * 1024 * 1024,
    )
    def missing(_kind: str, _key: str) -> None:
        return None

    monkeypatch.setattr(journal, "_read", missing)
    assert journal._index_run_nonce(  # pyright: ignore[reportPrivateUsage]
        "admission", admission, admission_ref
    ) is None
    assert journal._index_run_nonce(  # pyright: ignore[reportPrivateUsage]
        "admission", admission, admission_ref
    ) == admission_ref

    webhook_values: dict[str, Any] = {
        "repository_digest": R,
        "target_ref": "refs/heads/main",
        "operation_id": OP,
        "group_sha": HEAD,
        "group_tree": "c" * 40,
        "group_parents": [BASE],
        "pull_request_number": 7,
        "queue_generation_digest": D2,
        "delivery_id": "delivery-global-first",
        "body_digest": D3,
        "observed_at": NOW,
    }
    webhook_probe = MainMergeGroupWebhookReceipt.model_construct(
        **webhook_values,
        receipt_digest=D,
    )
    webhook_values["receipt_digest"] = canonical_digest(
        webhook_probe.model_dump(exclude={"receipt_digest"}, mode="json")
    )
    webhook = MainMergeGroupWebhookReceipt.model_validate(webhook_values)
    webhook_ref = journal._store.put_bytes(  # pyright: ignore[reportPrivateUsage]
        canonical_bytes(webhook),
        media_type="application/vnd.avo.main-graduation-merge-group-webhook-receipt+json",
        role="main-graduation-merge-group-webhook-receipt",
        max_bytes=32 * 1024 * 1024,
    )
    assert journal._index_webhook_delivery(  # pyright: ignore[reportPrivateUsage]
        webhook, webhook_ref
    ) is None
    assert journal._index_webhook_delivery(  # pyright: ignore[reportPrivateUsage]
        webhook, webhook_ref
    ) == webhook_ref


def test_resolution_outcome_rules_do_not_treat_not_applied_as_observed() -> None:
    intent = _intent()
    receipt = _receipt(intent)
    fence = _fence(receipt)
    resolution = _resolution(fence, "not_applied")
    assert resolution.outcome == "not_applied"
    # A not-applied resolution is a terminal observation, not permission to
    # continue a parent chain; the journal's parent-resolution validator must
    # reject it when a subsequent intent attempts to rely on it.
    successor = cast(
        MainMutationIntent,
        _with_digest(
            MainMutationIntent,
            "intent_digest",
            repository_digest=R,
            target_ref="refs/heads/main",
            operation_id=OP,
            stage="pull_request_open",
            parent_stage="candidate_publication",
            parent_intent_digest=intent.intent_digest,
            parent_resolution_digest=resolution.resolution_digest,
            lease_identity="avo-controller",
            lease_digest=D2,
            lease_epoch_digest=D2,
            policy_epoch_digest=D2,
            controller_config_digest=D2,
            preparation_authorization_digest=D2,
            external_identity=_external(OP, "refs/heads/avo/candidate/pr", "pull_request_open"),
            request_digest=D3,
            recorded_at=NOW + timedelta(minutes=2),
        ),
    )
    journal = _journal(Path("."))
    # The record is not needed for this contract-level check; the validator
    # must never interpret a terminal not-applied result as authorization.
    journal._read = lambda kind, key: (  # type: ignore[method-assign]
        (resolution, cast(Any, None)) if kind == "mutation-fence-resolution" else None
    )
    with pytest.raises(MainGraduationJournalError, match="differs"):
        journal._verify_phase_parent_resolution(successor)  # pyright: ignore[reportPrivateUsage]


def test_rejected_dispatch_never_qualifies_for_an_unresolved_fence(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    _disable_phase_prerequisites(journal)
    intent = _intent()
    journal.record_mutation_intent(intent)
    rejected = _rejected_receipt(intent)
    journal.record_mutation_receipt(rejected)
    fence = _fence(rejected)
    with pytest.raises(MainGraduationJournalError, match="ambiguous"):
        MainGraduationJournal._validate_phase_chain(  # pyright: ignore[reportPrivateUsage]
            journal, "unresolved-mutation-fence", fence
        )


def test_intent_has_a_target_fence_before_any_provider_dispatch(tmp_path: Path) -> None:
    """Regression guard for the crash window between dispatch and receipt.

    A durable intent is the first fact that a provider mutation may occur.  It
    must reserve the target-scoped unresolved slot before a provider can be
    called; otherwise a crash after dispatch but before a receipt allows a
    second attempt to race the unknown external state.
    """
    journal = _journal(tmp_path)
    _disable_phase_prerequisites(journal)
    intent = _intent()
    journal.record_mutation_intent(intent)
    with pytest.raises(MainGraduationJournalError, match="unresolved"):
        journal.assert_no_unresolved_mutation_fence(R, "refs/heads/main")


def test_phase_a_lease_rejects_missing_authority_verifier(tmp_path: Path) -> None:
    with pytest.raises(MainGraduationJournalError, match="authority verifier"):
        MainGraduationJournal(tmp_path).record_lease_evidence_record(_lease_record())


def test_phase_a_resolution_rejects_missing_authority_verifier(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    _disable_phase_prerequisites(journal)
    intent = _intent()
    journal.record_mutation_intent(intent)
    receipt = _receipt(intent)
    journal.record_mutation_receipt(receipt)
    fence = _fence(receipt)
    journal.record_unresolved_mutation_fence(fence)
    journal._phase_a_authority_verifier = None  # type: ignore[reportPrivateUsage]
    with pytest.raises(MainGraduationJournalError, match="authority verifier"):
        journal.record_mutation_fence_resolution(_resolution(fence))


def test_terminal_intent_replay_cannot_reopen_reservation(tmp_path: Path) -> None:
    journal = _journal(tmp_path)
    _disable_phase_prerequisites(journal)
    intent = _intent()
    journal.record_mutation_intent(intent)
    terminal = _rejected_receipt(intent)
    journal.record_mutation_receipt(terminal)
    active = journal._target_fence_path(intent)  # pyright: ignore[reportPrivateUsage]
    assert not active.exists()

    restarted = _journal(tmp_path)
    _disable_phase_prerequisites(restarted)
    with pytest.raises(MainGraduationRecordConflictError, match="dispatch is prohibited"):
        restarted.record_mutation_intent(intent)
    assert not active.exists()


def test_generic_windows_reservation_race_reuses_exact_winner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A destination race must not discard an exact reservation winner."""
    journal = _journal(tmp_path)
    _disable_phase_prerequisites(journal)
    intent = _intent()
    active = journal._target_fence_path(intent)  # pyright: ignore[reportPrivateUsage]
    original_replace = journal_module.os.replace

    def race(source: object, destination: object) -> None:
        if Path(destination) == active and not active.exists():
            original_replace(source, destination)
            # Windows may report a directory replacement race as a generic
            # OSError even though the competing reservation is now present.
            raise OSError("destination appeared during reservation publish")
        original_replace(source, destination)

    monkeypatch.setattr(journal_module.os, "replace", race)
    journal.record_mutation_intent(intent)

    assert active.is_dir()
    assert journal._target_reservation_record_path(active).is_file()  # type: ignore[reportPrivateUsage]
    assert not list(active.parent.glob(".tmp-*"))
