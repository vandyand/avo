"""Focused recovery/error-path coverage for the validation service.

These cases deliberately keep the provider fake small and assert the mutation
boundary: an uncertain observation must never turn into a second create.
"""

from pathlib import Path

import pytest
from test_synthetic_validation_contracts import request

from avo_correlate.adapters.artifacts.synthetic_validation_journal import (
    SyntheticValidationJournal,
)
from avo_correlate.application.synthetic_validation_service import (
    SyntheticValidationCleanupRefusedError,
    SyntheticValidationConflictError,
    SyntheticValidationService,
)
from avo_correlate.contracts.synthetic_validation import (
    SyntheticValidationCompletionProof,
    SyntheticValidationCreateAuthorization,
    SyntheticValidationPlan,
)


class Provider:
    def __init__(self) -> None:
        self.ref: str | None = None
        self.create_calls = 0
        self.delete_calls = 0

    def read_validation_ref(self, repository_digest: str, ref: str) -> object | None:
        del repository_digest, ref
        if self.ref is None:
            return None
        return {"commit": self.ref, "tree": "6" * 40}

    def create_validation_ref(self, repository_digest: str, ref: str, commit: str) -> object:
        del repository_digest, ref
        self.create_calls += 1
        self.ref = commit
        return None

    def delete_validation_ref(self, repository_digest: str, ref: str) -> object:
        del repository_digest, ref
        self.delete_calls += 1
        self.ref = None
        return None


class ProofVerifier:
    def verify(
        self, plan: SyntheticValidationPlan, proof: SyntheticValidationCompletionProof
    ) -> None:
        del plan
        if proof.completion_digest != "sha256:" + "b" * 64:
            raise ValueError("completion evidence is not trusted")


def make_service(tmp_path: Path, provider: Provider) -> SyntheticValidationService:
    return SyntheticValidationService(
        provider,
        SyntheticValidationJournal(tmp_path),
        completion_proof_verifier=ProofVerifier(),
    )


def make_proof(plan: SyntheticValidationPlan) -> SyntheticValidationCompletionProof:
    return SyntheticValidationCompletionProof(
        operation_id=plan.operation_id,
        plan_digest=plan.plan_digest,
        completion_digest="sha256:" + "b" * 64,
    )


def test_trigger_plan_records_unrecorded_plan_and_rejects_replay_mix(tmp_path: Path) -> None:
    provider = Provider()
    first = make_service(tmp_path, provider)
    plan = first.prepare(request())

    # A caller may supply a prepared plan to a fresh process.  The service
    # records it before reading the remote ref, and then fences a forged replay.
    fresh = make_service(tmp_path / "fresh", provider)
    result = fresh.trigger(plan)
    assert result.outcome == "created"
    forged = plan.model_copy(update={"expected_tree": "7" * 40})
    with pytest.raises(SyntheticValidationConflictError, match="conflicting replay"):
        fresh.trigger(forged)
    assert provider.create_calls == 1


def test_provider_read_error_is_uncertain_without_create(tmp_path: Path) -> None:
    class ReadFailure(Provider):
        def read_validation_ref(self, repository_digest: str, ref: str) -> object | None:
            del repository_digest, ref
            raise OSError("provider unavailable")

    provider = ReadFailure()
    result = make_service(tmp_path, provider).trigger(request())
    assert result.outcome == "reconciliation_required"
    assert result.error == "ref read requires reconciliation"
    assert provider.create_calls == 0


def test_malformed_provider_observation_is_uncertain_without_create(tmp_path: Path) -> None:
    class Malformed(Provider):
        def read_validation_ref(self, repository_digest: str, ref: str) -> object | None:
            del repository_digest, ref
            return {"commit": "5" * 40}

    provider = Malformed()
    result = make_service(tmp_path, provider).trigger(request())
    assert result.outcome == "reconciliation_required"
    assert provider.create_calls == 0


def test_create_success_with_wrong_tree_is_quarantined(tmp_path: Path) -> None:
    class WrongAfterCreate(Provider):
        def __init__(self) -> None:
            super().__init__()
            self.read_calls = 0

        def read_validation_ref(self, repository_digest: str, ref: str) -> object | None:
            self.read_calls += 1
            if self.read_calls == 1:
                return None
            del repository_digest, ref
            return {"commit": "5" * 40, "tree": "7" * 40}

    provider = WrongAfterCreate()
    result = make_service(tmp_path, provider).trigger(request())
    assert result.outcome == "invalid"
    assert result.error == "create returned success but ref has a wrong SHA; quarantined"
    assert provider.create_calls == 1


def test_lost_create_claim_reconciles_without_remote_create(tmp_path: Path) -> None:
    class LostClaimJournal(SyntheticValidationJournal):
        def __init__(self, root: Path, provider: Provider) -> None:
            super().__init__(root)
            self.provider = provider

        def claim_create_authorization(
            self, authorization: SyntheticValidationCreateAuthorization
        ) -> bool:
            # Another process won the claim and published before this caller
            # could observe it.  The loser must perform only the read below.
            expected = authorization.expected_commit
            self.provider.ref = expected
            return False

    provider = Provider()
    service = SyntheticValidationService(
        provider,
        LostClaimJournal(tmp_path, provider),
        completion_proof_verifier=ProofVerifier(),
    )
    result = service.trigger(request())
    assert result.outcome == "reconciled"
    assert provider.create_calls == 0


def test_cleanup_absence_is_idempotent_without_delete(tmp_path: Path) -> None:
    provider = Provider()
    service = make_service(tmp_path, provider)
    service.trigger(request())
    plan = service.prepare(request())
    provider.ref = None
    result = service.cleanup(plan, make_proof(plan))
    assert result.outcome == "cleaned"
    assert provider.delete_calls == 0
    assert service.cleanup(plan, make_proof(plan)) == result


def test_cleanup_success_that_leaves_ref_requires_reconciliation(tmp_path: Path) -> None:
    class StickyDelete(Provider):
        def delete_validation_ref(self, repository_digest: str, ref: str) -> object:
            del repository_digest, ref
            self.delete_calls += 1
            return None

    provider = StickyDelete()
    service = make_service(tmp_path, provider)
    service.trigger(request())
    plan = service.prepare(request())
    result = service.cleanup(plan, make_proof(plan))
    assert result.outcome == "reconciliation_required"
    assert result.error == "delete succeeded but ref remains"
    assert provider.delete_calls == 1


def test_cleanup_requires_configured_completion_verifier(tmp_path: Path) -> None:
    provider = Provider()
    service = SyntheticValidationService(provider, SyntheticValidationJournal(tmp_path))
    service.trigger(request())
    plan = service.prepare(request())
    with pytest.raises(SyntheticValidationCleanupRefusedError, match="verification"):
        service.cleanup(plan, make_proof(plan))
    assert provider.delete_calls == 0
