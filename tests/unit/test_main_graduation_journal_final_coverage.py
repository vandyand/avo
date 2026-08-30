"""High-yield fail-closed coverage for the durable main-graduation journal.

The production journal deliberately has many small rejection branches.  These
tests keep the existing end-to-end fixtures but exercise the recovery and
tamper paths directly, so that a future refactor cannot silently turn a
missing prior record into an authorization.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
    MainGraduationJournalError,
    MainGraduationRecordConflictError,
    _check_digest,
    _strict_pairs,
)
from avo_correlate.contracts.base import ArtifactRef, StrictModel
from avo_correlate.contracts.main_graduation import (
    EligibilityLedgerStarted,
    MainGraduationAttempt,
    MainGraduationEligibilityRecord,
    MainInverseDeltaArtifact,
    MainRollbackAuthorization,
    MainRollbackIntent,
)
from avo_correlate.contracts.main_graduation_phase_a import (
    MainUnresolvedMutationFence,
    main_target_scope_digest,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest
from tests.unit.test_main_graduation_journal_coverage import (
    BASE,
    D2,
    HEAD,
    NOW,
    TREE,
    D,
    R,
    completion,
    ref,
)

# These tests intentionally exercise private durable seams.
# pyright: reportPrivateUsage=false, reportArgumentType=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false


def _chain(journal: MainGraduationJournal) -> tuple[Any, dict[str, Any]]:
    """Return a completion fixture and a map suitable for stage validators."""
    package = completion()
    prep = package.preparation_authorization
    admission = package.admission_observation
    hold = package.hold_observation
    authorization = package.release_authorization
    transition = package.transition_receipt
    object.__setattr__(package.intent, "candidate_ref", package.composition.candidate_ref)
    object.__setattr__(prep, "intent_digest", canonical_digest(package.intent))
    object.__setattr__(admission, "preparation_authorization_digest", canonical_digest(prep))
    object.__setattr__(hold, "preparation_authorization_digest", canonical_digest(prep))
    object.__setattr__(hold, "admission_observation_digest", canonical_digest(admission))
    object.__setattr__(
        hold, "attestation_manifest_digest", canonical_digest(package.attestation_manifest)
    )
    object.__setattr__(authorization, "admission_observation_digest", canonical_digest(admission))
    object.__setattr__(authorization, "preparation_authorization_digest", canonical_digest(prep))
    object.__setattr__(authorization, "hold_observation_digest", canonical_digest(hold))
    object.__setattr__(transition, "release_authorization_digest", canonical_digest(authorization))
    object.__setattr__(
        package.provider_receipt, "release_authorization_digest", canonical_digest(authorization)
    )
    object.__setattr__(
        package.reconciliation, "transition_receipt_digest", canonical_digest(transition)
    )
    records = {
        "plan": package.plan,
        "intent": package.intent,
        "preparation-authorization": prep,
        "queue-admission": admission,
        "release-hold": hold,
        "queue": package.queue_observation,
        "protection": package.protection_manifest,
        "attestations": package.attestation_manifest,
        "merge-group-checks": package.merge_group_checks,
        "release-authorization": authorization,
        "release-transition": transition,
        "provider-receipt": package.provider_receipt,
        "reconciliation": package.reconciliation,
        "merge-group-webhook-receipt": hold.merge_group_receipt,
    }
    return package, records


def test_constructor_and_key_guards_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="max_record_bytes"):
        MainGraduationJournal(tmp_path / "zero", max_record_bytes=0)
    with pytest.raises(ValueError, match="composition authority"):
        MainGraduationJournal(tmp_path / "partial", composition_root=tmp_path)
    for value in ("", "sha256:short", "sha1:" + "a" * 64, "x" * 71):
        with pytest.raises(ValueError, match="SHA-256"):
            _check_digest(value)
    with pytest.raises(ValueError, match="duplicate"):
        _strict_pairs([("a", 1), ("a", 2)])
    journal = MainGraduationJournal(tmp_path / "journal")
    with pytest.raises(ValueError, match="unknown"):
        journal.read("unknown", D)
    with pytest.raises(ValueError, match="SHA-256"):
        journal.read("plan", "bad")
    with pytest.raises(ValueError, match="unknown"):
        journal.record("unknown", EligibilityLedgerStarted.model_construct())


def test_all_public_record_and_read_wrappers_delegate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keep the thin API surface covered when new journal stages are added."""
    journal = MainGraduationJournal(tmp_path)
    recorded: list[str] = []
    read_kinds: list[str] = []

    def record(kind: str, _value: object) -> Any:
        recorded.append(kind)
        return ref()

    def read(kind: str, _key: str) -> tuple[Any, Any] | None:
        read_kinds.append(kind)
        return None

    monkeypatch.setattr(journal, "_record", record)
    monkeypatch.setattr(journal, "_read", read)
    value = object()
    record_methods = (
        ("record_ledger_started", "ledger-started"),
        ("record_plan", "plan"),
        ("record_release_issuer_binding", "release-issuer-binding"),
        ("record_source_package", "source-package"),
        ("record_delta", "delta"),
        ("record_composition", "composition"),
        ("record_queue_observation", "queue"),
        ("record_protection_manifest", "protection"),
        ("record_attestation_manifest", "attestations"),
        ("record_merge_group_checks", "merge-group-checks"),
        ("record_intent", "intent"),
        ("record_preparation_authorization", "preparation-authorization"),
        ("record_queue_admission", "queue-admission"),
        ("record_release_hold", "release-hold"),
        ("record_merge_group_webhook_receipt", "merge-group-webhook-receipt"),
        ("record_release_authorization", "release-authorization"),
        ("record_release_transition", "release-transition"),
        ("record_provider_receipt", "provider-receipt"),
        ("record_reconciliation", "reconciliation"),
        ("record_rollback_authorization", "rollback-authorization"),
        ("record_inverse_delta", "inverse-delta"),
        ("record_rollback_intent", "rollback-intent"),
        ("record_attempt", "attempt"),
        ("record_eligibility", "eligibility"),
        ("record_completion", "completion"),
    )
    for name, _kind in record_methods:
        getattr(journal, name)(value)
    assert recorded == [kind for _name, kind in record_methods]
    journal.record("plan", value)
    assert recorded[-1] == "plan"
    read_methods = (
        "read_ledger_started",
        "read_plan",
        "read_release_issuer_binding",
        "read_source_package",
        "read_delta",
        "read_composition",
        "read_composition_proof",
        "read_queue_observation",
        "read_protection_manifest",
        "read_attestation_manifest",
        "read_merge_group_checks",
        "read_intent",
        "read_preparation_authorization",
        "read_queue_admission",
        "read_merge_group_webhook_receipt",
        "read_release_hold",
        "read_release_authorization",
        "read_release_transition",
        "read_provider_receipt",
        "read_reconciliation",
        "read_rollback_authorization",
        "read_inverse_delta",
        "read_rollback_intent",
        "read_attempt",
        "read_eligibility",
        "read_completion",
    )
    for name in read_methods:
        assert getattr(journal, name)(D) is None
    assert journal.read("plan", D) is None
    assert journal.read_package(D) is None
    assert journal.record_package(value).digest == D
    assert len(read_kinds) == len(read_methods) + 2


def test_read_and_index_recovery_reject_malformed_or_tampered_state(tmp_path: Path) -> None:
    journal = MainGraduationJournal(tmp_path)
    started = EligibilityLedgerStarted(
        activation_digest=D,
        repository_digest=R,
        controller_config_digest=D2,
        scheduler_sequence_watermark=0,
        streak=0,
    )
    stored = journal.record_ledger_started(started)
    index = tmp_path / "main-graduation-index" / "ledger-started" / f"{D[7:]}.json"
    index.write_text("{}", encoding="utf-8")
    with pytest.raises(MainGraduationJournalError, match="malformed"):
        journal.read_ledger_started(D)
    index.write_bytes(canonical_bytes(stored))
    # The reference is valid JSON but points at a different role than the index.
    index.write_text(
        json.dumps(
            stored.model_copy(update={"role": "wrong"}).model_dump(mode="json"),
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    with pytest.raises(MainGraduationJournalError, match="malformed"):
        journal.read_ledger_started(D)


def test_all_stage_dispatches_reject_missing_durable_priors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = MainGraduationJournal(tmp_path)
    package, _ = _chain(journal)
    stages: list[tuple[Callable[..., object], object]] = [
        (journal._require_preparation_chain, package.preparation_authorization),
        (journal._require_queue_admission, package.admission_observation),
        (journal._require_admission, package.hold_observation),
        (journal._require_hold, package.release_authorization),
        (journal._require_release_authorization, package.transition_receipt),
        (journal._require_provider_receipt, package.provider_receipt),
        (journal._require_reconciliation, package.reconciliation),
    ]
    monkeypatch.setattr(journal, "_read", lambda _kind, _key: None)
    for validator, value in stages:
        with pytest.raises(MainGraduationJournalError):
            validator(value)


def test_stage_binding_and_chronology_errors_are_recoverable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = MainGraduationJournal(tmp_path)
    package, records = _chain(journal)

    def read(kind: str, _key: str) -> tuple[Any, Any] | None:
        value = records.get(kind)
        return None if value is None else (value, ref())

    monkeypatch.setattr(journal, "_read", read)
    mutations: list[tuple[Callable[[], object], str]] = [
        (
            lambda: journal._require_preparation_chain(
                package.preparation_authorization.model_copy(update={"lease_digest": D2})
            ),
            "binding",
        ),
        (
            lambda: journal._require_preparation_chain(
                package.preparation_authorization.model_copy(
                    update={"authorized_at": NOW - timedelta(days=1)}
                )
            ),
            "predates",
        ),
        (
            lambda: journal._require_preparation_chain(
                package.preparation_authorization.model_copy(update={"candidate_tree": BASE})
            ),
            "binding",
        ),
        (
            lambda: journal._require_queue_admission(
                package.admission_observation.model_copy(
                    update={"observed_at": NOW - timedelta(days=1)}
                )
            ),
            "predates",
        ),
        (
            lambda: journal._require_queue_admission(
                package.admission_observation.model_copy(update={"head_tree": BASE})
            ),
            "binding",
        ),
        (
            lambda: journal._require_queue_admission(
                package.admission_observation.model_copy(update={"check_context": "wrong"})
            ),
            "issuer",
        ),
        (
            lambda: journal._require_admission(
                package.hold_observation.model_copy(update={"group_sha": HEAD})
            ),
            "PR-head",
        ),
        (
            lambda: journal._require_admission(
                package.hold_observation.model_copy(update={"observed_at": NOW - timedelta(days=1)})
            ),
            "chronology",
        ),
        (
            lambda: journal._require_admission(
                package.hold_observation.model_copy(update={"queue_generation_digest": D2})
            ),
            "generation",
        ),
        (
            lambda: journal._require_hold(
                package.release_authorization.model_copy(update={"hold_nonce": "wrong"})
            ),
            "pending hold",
        ),
        (
            lambda: journal._require_hold(
                package.release_authorization.model_copy(
                    update={"authorized_at": NOW - timedelta(days=1)}
                )
            ),
            "predates",
        ),
        (
            lambda: journal._require_release_authorization(
                package.transition_receipt.model_copy(
                    update={"observed_at": NOW + timedelta(hours=1)}
                )
            ),
            "validity",
        ),
        (
            lambda: journal._require_provider_receipt(
                package.provider_receipt.model_copy(update={"observed_at": NOW - timedelta(days=1)})
            ),
            "predates",
        ),
        (
            lambda: journal._require_provider_receipt(
                package.provider_receipt.model_copy(update={"provider_identity": "wrong"})
            ),
            "binding",
        ),
        (
            lambda: journal._require_reconciliation(
                package.reconciliation.model_copy(update={"queue_generation_digest": D2})
            ),
            "binding",
        ),
        (
            lambda: journal._require_reconciliation(
                package.reconciliation.model_copy(update={"main_tree": BASE})
            ),
            "composition",
        ),
    ]
    for invoke, message in mutations:
        with pytest.raises(MainGraduationJournalError, match=message):
            invoke()


def test_issuer_lease_and_webhook_recovery_edges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = MainGraduationJournal(tmp_path)
    package, _ = _chain(journal)
    with pytest.raises(MainGraduationJournalError, match="controller-pinned"):
        journal._require_controller_issuer_binding(package.release_issuer_binding)
    bad_intent = package.intent.model_copy(update={"lease_identity": "other"})
    with pytest.raises(MainGraduationJournalError, match="lease evidence binding"):
        journal._verify_intent_lease(bad_intent)
    receipt = package.hold_observation.merge_group_receipt
    with pytest.raises(MainGraduationJournalError, match="not durably indexed"):
        journal._verify_webhook_delivery(receipt)
    monkeypatch.setattr(journal, "_read", lambda _kind, _key: None)
    with pytest.raises(MainGraduationJournalError, match="durable"):
        journal._require_merge_group_receipt(package.hold_observation)


def test_run_nonce_and_delivery_conflicts_are_detected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = MainGraduationJournal(tmp_path)
    record = package = completion().admission_observation
    reference = ref()
    monkeypatch.setattr(journal, "_read", lambda _kind, _key: (record, reference))
    journal._index_run_nonce("admission", record, reference)
    path = journal._run_nonce_path("admission", record.admission_run_id, record.admission_nonce)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["operation_id"] = D2
    path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
    with pytest.raises(MainGraduationRecordConflictError, match="already bound"):
        journal._index_run_nonce("admission", record, reference)
    with pytest.raises(MainGraduationJournalError, match="malformed"):
        journal._index_run_nonce("hold", record, reference)
    assert package.operation_id == D


def test_global_run_nonce_and_webhook_indexes_recover_orphaned_local_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A committed global claim must be able to rebuild its local pointer."""

    journal = MainGraduationJournal(tmp_path)
    package = completion()
    admission = package.admission_observation
    admission_bytes = canonical_bytes(admission)
    admission_ref = journal._store.put_bytes(  # pyright: ignore[reportPrivateUsage]
        admission_bytes,
        media_type="application/vnd.avo.main-graduation-queue-admission+json",
        role="main-graduation-queue-admission",
        max_bytes=journal._max,  # pyright: ignore[reportPrivateUsage]
    )
    monkeypatch.setattr(journal, "_read", lambda _kind, _key: None)
    journal._index_run_nonce("admission", admission, admission_ref)  # pyright: ignore[reportPrivateUsage]
    assert journal._index_run_nonce(  # pyright: ignore[reportPrivateUsage]
        "admission", admission, admission_ref
    ) == admission_ref

    webhook = package.hold_observation.merge_group_receipt
    webhook_ref = journal._store.put_bytes(  # pyright: ignore[reportPrivateUsage]
        canonical_bytes(webhook),
        media_type="application/vnd.avo.main-graduation-merge-group-webhook-receipt+json",
        role="main-graduation-merge-group-webhook-receipt",
        max_bytes=journal._max,  # pyright: ignore[reportPrivateUsage]
    )
    journal._index_webhook_delivery(webhook, webhook_ref)  # pyright: ignore[reportPrivateUsage]
    assert journal._index_webhook_delivery(  # pyright: ignore[reportPrivateUsage]
        webhook, webhook_ref
    ) == webhook_ref


class _IdentityFixture(StrictModel):
    operation_id: str
    payload: str


def test_phase_identity_indexes_are_create_once_and_conflict_closed(tmp_path: Path) -> None:
    journal = MainGraduationJournal(tmp_path)
    first = _IdentityFixture(operation_id=D, payload="one")
    first_ref = journal._store.put_bytes(  # pyright: ignore[reportPrivateUsage]
        canonical_bytes(first),
        media_type="application/vnd.avo.main-graduation-mutation-receipt+json",
        role="main-graduation-mutation-receipt",
        max_bytes=journal._max,  # pyright: ignore[reportPrivateUsage]
    )
    journal._cas_phase_identity(  # pyright: ignore[reportPrivateUsage]
        "mutation-receipt", D, first, first_ref
    )
    journal._cas_phase_identity(  # pyright: ignore[reportPrivateUsage]
        "mutation-receipt", D, first, first_ref
    )
    second = _IdentityFixture(operation_id=D, payload="two")
    second_ref = journal._store.put_bytes(  # pyright: ignore[reportPrivateUsage]
        canonical_bytes(second),
        media_type="application/vnd.avo.main-graduation-mutation-receipt+json",
        role="main-graduation-mutation-receipt",
        max_bytes=journal._max,  # pyright: ignore[reportPrivateUsage]
    )
    with pytest.raises(MainGraduationRecordConflictError):
        journal._cas_phase_identity(  # pyright: ignore[reportPrivateUsage]
            "mutation-receipt", D, second, second_ref
        )


def test_target_fence_open_claim_is_atomic_under_competing_writers(tmp_path: Path) -> None:
    def make_fence(digest_seed: str) -> MainUnresolvedMutationFence:
        values = {
            "repository_digest": R,
            "target_ref": "refs/heads/main",
            "operation_id": D,
            "stage": "candidate_publication",
            "intent_digest": D,
            "source_receipt_digest": D,
            "external_identity_digest": D,
            "lease_identity": "avo-controller",
            "lease_digest": D,
            "target_scope_digest": main_target_scope_digest(R, "refs/heads/main"),
                "opened_at": NOW + timedelta(seconds=0 if digest_seed == D else 1),
        }
        probe = MainUnresolvedMutationFence.model_construct(**values, fence_digest=digest_seed)
        values["fence_digest"] = canonical_digest(
            probe.model_dump(exclude={"fence_digest"}, mode="json")
        )
        return MainUnresolvedMutationFence.model_validate(values)

    # Repeat the race against fresh scopes.  Before target-fence publication
    # became atomic, the loser could read the winner's mkdir-created but still
    # empty record.json and fail with a malformed-index error.
    for iteration in range(20):
        journal = MainGraduationJournal(tmp_path / str(iteration))
        fences = [make_fence(D), make_fence(D2)]
        references = [
            journal._store.put_bytes(  # pyright: ignore[reportPrivateUsage]
                canonical_bytes(fence),
                media_type="application/vnd.avo.main-graduation-unresolved-mutation-fence+json",
                role="main-graduation-unresolved-mutation-fence",
                max_bytes=journal._max,  # pyright: ignore[reportPrivateUsage]
            )
            for fence in fences
        ]

        def claim(
            index: int,
            *,
            target_journal: MainGraduationJournal = journal,
            target_fences: list[MainUnresolvedMutationFence] = fences,
            target_references: list[ArtifactRef] = references,
        ) -> str:
            try:
                target_journal._cas_target_fence(  # pyright: ignore[reportPrivateUsage]
                    target_fences[index], target_references[index]
                )
            except MainGraduationRecordConflictError:
                return "conflict"
            return "claimed"

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(claim, range(2)))
        assert sorted(outcomes) == ["claimed", "conflict"]


def test_eligibility_sequence_and_attempt_recovery_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = MainGraduationJournal(tmp_path)
    excluded = MainGraduationEligibilityRecord(
        operation_id=D,
        repository_digest=R,
        scheduler_sequence=1,
        submission_digest=D,
        classification="excluded",
        exclusion_reason="not ordinary",
        exclusion_evidence_digest=D,
        ordinary=False,
        nonempty=True,
    )
    journal.record_eligibility(excluded)
    with pytest.raises(MainGraduationRecordConflictError, match="occupied"):
        journal._check_eligibility_predecessor(excluded.model_copy(update={"operation_id": D2}))
    missing = excluded.model_copy(
        update={"operation_id": D2, "scheduler_sequence": 3, "previous_scheduler_sequence": 2}
    )
    with pytest.raises(MainGraduationJournalError, match="predecessor"):
        journal._check_eligibility_predecessor(missing)
    watermark = excluded.model_copy(
        update={
            "operation_id": D2,
            "scheduler_sequence": 3,
            "previous_scheduler_sequence": None,
            "scheduler_watermark": 1,
        }
    )
    with pytest.raises(MainGraduationJournalError, match="adjacent"):
        journal._check_eligibility_predecessor(watermark)
    first = MainGraduationEligibilityRecord.model_copy(
        excluded, update={"operation_id": D2, "scheduler_sequence": 2}
    )
    open_prior = excluded.model_copy(
        update={"classification": "eligible", "ordinary": True, "nonempty": True}
    )
    monkeypatch.setattr(journal, "read_eligibility_sequence", lambda _sequence: (D, ref()))
    monkeypatch.setattr(journal, "read_eligibility", lambda _operation: (open_prior, ref()))
    with pytest.raises(MainGraduationJournalError, match="open eligible"):
        journal._check_eligibility_predecessor(
            first.model_copy(update={"previous_scheduler_sequence": 1})
        )
    attempt = MainGraduationAttempt.model_construct(
        operation_id=D2, scheduler_sequence=1, eligibility_record_digest=D
    )
    with pytest.raises(MainGraduationJournalError, match="eligibility"):
        journal._require_attempt_eligibility(attempt)
    monkeypatch.setattr(journal, "_read", lambda _kind, _key: (excluded, ref()))
    with pytest.raises(MainGraduationJournalError, match="eligibility"):
        journal._require_attempt_eligibility(attempt)


def test_rollback_intent_and_authorization_recovery_edges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = MainGraduationJournal(tmp_path)
    package = completion()
    inverse = MainInverseDeltaArtifact.model_construct(
        operation_id=D,
        repository_digest=R,
        target_ref="refs/heads/main",
        completion_package_digest=D,
        current_main_commit=HEAD,
        current_main_tree=TREE,
        inverse_tree=BASE,
        inverse_delta_digest=D2,
        inverse_delta_artifact_digest=D,
        policy_epoch=D,
    )
    intent = MainRollbackIntent.model_construct(
        operation_id=D,
        repository_digest=R,
        target_ref="refs/heads/main",
        completion_package_digest=D,
        inverse_delta_digest=D2,
        inverse_delta_artifact_digest=D,
        base_commit=HEAD,
        base_tree=TREE,
        current_main_commit=HEAD,
        current_main_tree=TREE,
        candidate_commit=HEAD,
        candidate_tree=TREE,
        inverse_tree=BASE,
        lease_identity="lease",
        lease_digest=D,
        policy_epoch=D,
        intent_digest=D,
        recorded_at=NOW,
    )
    authorization = MainRollbackAuthorization.model_construct(
        operation_id=D,
        repository_digest=R,
        target_ref="refs/heads/main",
        completion_package_digest=D,
        current_main_commit=HEAD,
        current_main_tree=TREE,
        inverse_delta_digest=D2,
        inverse_delta_artifact_digest=D,
        inverse_tree=BASE,
        lease_identity="lease",
        lease_digest=D,
        policy_epoch=D,
        authorization_digest=D,
        authorized_at=NOW,
    )
    records = {"inverse-delta": inverse, "completion": package, "rollback-intent": intent}
    monkeypatch.setattr(
        journal, "_read", lambda kind, _key: (records[kind], ref()) if kind in records else None
    )
    with pytest.raises(MainGraduationJournalError, match="inverse delta binding"):
        journal._require_inverse_delta(intent)
    monkeypatch.setattr(journal, "_require_inverse_delta", lambda _intent: None)
    with pytest.raises(MainGraduationJournalError, match="rollback intent binding"):
        journal._require_rollback_intent(authorization.model_copy(update={"inverse_tree": TREE}))
    monkeypatch.setattr(journal, "_read", lambda _kind, _key: None)
    with pytest.raises(MainGraduationJournalError, match="durable intent"):
        journal._require_rollback_intent(authorization)
