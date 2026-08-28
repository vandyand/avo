from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier, Event, Lock

import pytest
from test_synthetic_validation_contracts import request

from avo_correlate.adapters.artifacts.synthetic_validation_journal import (
    SyntheticValidationJournal,
)
from avo_correlate.application.synthetic_validation_service import (
    SyntheticValidationCleanupRefusedError,
    SyntheticValidationService,
)
from avo_correlate.contracts.synthetic_validation import (
    SyntheticValidationCompletionProof,
    SyntheticValidationPlan,
)


class _CompletionProofVerifier:
    """Small durable-proof stand-in for service-level cleanup tests."""

    def verify(
        self,
        plan: SyntheticValidationPlan,
        proof: SyntheticValidationCompletionProof,
    ) -> None:
        del plan
        if proof.completion_digest != "sha256:" + "b" * 64:
            raise ValueError("completion artifact is not durable test evidence")


class Provider:
    def __init__(
        self,
        ref: str | None = None,
        *,
        create_error: bool = False,
        delete_error: bool = False,
        publish_before_error: bool = True,
    ):
        self.ref = ref
        self.create_error = create_error
        self.delete_error = delete_error
        self.publish_before_error = publish_before_error
        self.create_calls = 0
        self.delete_calls = 0

    def read_validation_ref(self, repository_digest: str, ref: str) -> object | None:
        del repository_digest, ref
        return None if self.ref is None else {"commit": self.ref, "tree": "6" * 40}

    def create_validation_ref(self, repository_digest: str, ref: str, commit: str) -> object:
        del repository_digest, ref
        self.create_calls += 1
        if not self.create_error or self.publish_before_error:
            self.ref = commit
        if self.create_error:
            raise RuntimeError("lost acknowledgment")
        return None

    def delete_validation_ref(self, repository_digest: str, ref: str) -> object:
        del repository_digest, ref
        self.delete_calls += 1
        if not self.delete_error:
            self.ref = None
        if self.delete_error:
            raise RuntimeError("lost acknowledgment")
        return None


def service(tmp_path: Path, provider: Provider) -> SyntheticValidationService:
    return SyntheticValidationService(
        provider,
        SyntheticValidationJournal(tmp_path),
        completion_proof_verifier=_CompletionProofVerifier(),
    )


def proof(plan: SyntheticValidationPlan) -> SyntheticValidationCompletionProof:
    return SyntheticValidationCompletionProof(
        operation_id=plan.operation_id,
        plan_digest=plan.plan_digest,
        completion_digest="sha256:" + "b" * 64,
    )


def test_create_success_and_duplicate_replay_do_not_mutate(tmp_path: Path) -> None:
    provider = Provider()
    controller = service(tmp_path, provider)
    result = controller.trigger(request())
    assert result.outcome == "created" and provider.create_calls == 1
    again = controller.trigger(request())
    assert again == result and provider.create_calls == 1


def test_lost_ack_exact_ref_reconciles_and_absent_is_terminal(tmp_path: Path) -> None:
    provider = Provider(create_error=True)
    result = service(tmp_path, provider).trigger(request())
    assert result.outcome == "reconciled"
    provider = Provider(create_error=True, publish_before_error=False)
    result = service(tmp_path / "absent", provider).trigger(request())
    assert result.outcome == "reconciliation_required"
    assert provider.create_calls == 1


def test_preseeded_exact_ref_is_quarantined_without_authorization(tmp_path: Path) -> None:
    provider = Provider(ref="5" * 40)
    result = service(tmp_path, provider).trigger(request())
    assert result.outcome == "quarantined"
    assert result.observed_commit == "5" * 40
    assert provider.create_calls == 0


def test_authorized_ambiguous_create_recovers_read_only(tmp_path: Path) -> None:
    provider = Provider(create_error=True, publish_before_error=False)
    controller = service(tmp_path, provider)
    first = controller.trigger(request())
    second = controller.trigger(request())
    assert first.outcome == "reconciliation_required"
    assert second.outcome == "reconciliation_required"
    assert provider.create_calls == 1


class _ConcurrentProvider(Provider):
    def __init__(self) -> None:
        super().__init__()
        self._lock = Lock()
        self._initial_reads = Barrier(2)
        self._create_done = Event()
        self._read_calls = 0

    def read_validation_ref(self, repository_digest: str, ref: str) -> object | None:
        with self._lock:
            self._read_calls += 1
            read_number = self._read_calls
        if read_number <= 2:
            self._initial_reads.wait(timeout=5)
        else:
            self._create_done.wait(timeout=5)
        return super().read_validation_ref(repository_digest, ref)

    def create_validation_ref(self, repository_digest: str, ref: str, commit: str) -> object:
        result = super().create_validation_ref(repository_digest, ref, commit)
        self._create_done.set()
        return result


def test_concurrent_triggers_have_one_create_authorization_owner(tmp_path: Path) -> None:
    provider = _ConcurrentProvider()
    plan = service(tmp_path, provider).prepare(request())
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(service(tmp_path, provider).trigger, plan),
            pool.submit(service(tmp_path, provider).trigger, plan),
        ]
        results = [future.result() for future in futures]
    assert provider.create_calls == 1
    assert {result.outcome for result in results} <= {
        "created",
        "reconciled",
        "reconciliation_required",
    }


def test_ambiguous_absence_eventually_reconciles_without_recreate(tmp_path: Path) -> None:
    provider = Provider(create_error=True, publish_before_error=False)
    controller = service(tmp_path, provider)
    first = controller.trigger(request())
    assert first.outcome == "reconciliation_required" and provider.create_calls == 1
    provider.ref = "5" * 40
    second = controller.trigger(request())
    assert second.outcome == "reconciled" and provider.create_calls == 1


def test_commit_only_provider_observation_is_reconciliation_error(tmp_path: Path) -> None:
    class CommitOnly(Provider):
        def read_validation_ref(self, repository_digest: str, ref: str) -> object | None:
            del repository_digest, ref
            return "5" * 40

    result = service(tmp_path, CommitOnly()).trigger(request())
    assert result.outcome == "reconciliation_required"


def test_wrong_sha_and_cleanup_proof(tmp_path: Path) -> None:
    provider = Provider(ref="9" * 40)
    controller = service(tmp_path, provider)
    result = controller.trigger(request())
    assert result.outcome == "invalid" and provider.create_calls == 0
    plan = controller.prepare(request())
    try:
        controller.cleanup(
            plan,
            SyntheticValidationCompletionProof(
                operation_id=plan.operation_id,
                plan_digest="sha256:" + "c" * 64,
                completion_digest="sha256:" + "b" * 64,
            ),
        )
    except SyntheticValidationCleanupRefusedError:
        pass
    else:
        raise AssertionError("cleanup without exact plan proof must be refused")


def test_cleanup_rejects_wrong_operation_before_provider_read_or_delete(tmp_path: Path) -> None:
    provider = Provider()
    controller = service(tmp_path, provider)
    controller.trigger(request())
    plan = controller.prepare(request())
    wrong_operation = SyntheticValidationCompletionProof(
        operation_id="sha256:" + "d" * 64,
        plan_digest=plan.plan_digest,
        completion_digest="sha256:" + "b" * 64,
    )
    with pytest.raises(SyntheticValidationCleanupRefusedError):
        controller.cleanup(plan, wrong_operation)
    assert provider.delete_calls == 0


def test_cleanup_success_and_ambiguous_delete_recovery(tmp_path: Path) -> None:
    provider = Provider()
    controller = service(tmp_path, provider)
    controller.trigger(request())
    plan = controller.prepare(request())
    cleaned = controller.cleanup(plan, proof(plan))
    assert cleaned.outcome == "cleaned" and provider.delete_calls == 1
    provider = Provider()
    controller = service(tmp_path / "ambiguous", provider)
    controller.trigger(request())
    plan = controller.prepare(request())
    provider.delete_error = True
    result = controller.cleanup(plan, proof(plan))
    assert result.outcome == "reconciliation_required"


def test_cleanup_rejects_forged_completion_digest_before_read_or_delete(
    tmp_path: Path,
) -> None:
    provider = Provider()
    controller = service(tmp_path, provider)
    controller.trigger(request())
    plan = controller.prepare(request())
    forged = SyntheticValidationCompletionProof(
        operation_id=plan.operation_id,
        plan_digest=plan.plan_digest,
        completion_digest="sha256:" + "c" * 64,
    )
    with pytest.raises(SyntheticValidationCleanupRefusedError):
        controller.cleanup(plan, forged)
    assert provider.delete_calls == 0
