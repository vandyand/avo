"""AVO-004.6 case 7: failed soak followed by protected rollback.

This module is intentionally a small adapter around the existing promotion
boundary.  It does not know how a hosted provider updates refs and exposes no
ref-update operation of its own.  Rollback is submitted through the same
``IntegrationPromotionService`` PR/squash operation used for an ordinary
candidate, with the failed integration head as its protected base and the
authorized restore tree as its candidate.
"""

from __future__ import annotations

from collections.abc import Callable, Collection
from dataclasses import dataclass
from typing import Any, Literal, Protocol, cast

from avo_correlate.adapters.artifacts.drill_journal import IntegrationDrillJournal
from avo_correlate.application.integration_promotion_service import IntegrationPromotionService
from avo_correlate.contracts.base import ArtifactRef, Sha256Digest
from avo_correlate.contracts.integration_drill import (
    IntegrationDrillCaseResult,
    IntegrationDrillRollbackAuthorization,
    IntegrationDrillRollbackIntent,
    IntegrationDrillRollbackReceipt,
    IntegrationDrillSoakObservation,
    IntegrationRollbackRequest,
)
from avo_correlate.contracts.integration_promotion import (
    CandidatePublicationBinding,
    IntegrationPromotionIntent,
    IntegrationPromotionReceipt,
    IntegrationPromotionReport,
)
from avo_correlate.contracts.promotion_bundle import PromotionBundle
from avo_correlate.domain.canonical import canonical_digest

TARGET_REF = "refs/heads/integration"
CASE_ID = 7


class IntegrationRollbackDrillError(RuntimeError):
    """A rollback drill input or observed topology is unsafe."""


class IntegrationSoakPort(Protocol):
    def observe(self, request: IntegrationRollbackRequest) -> IntegrationDrillSoakObservation: ...


class PromotionReceiptReader(Protocol):
    def read_receipt(
        self, operation_id: str
    ) -> tuple[IntegrationPromotionReceipt, ArtifactRef] | None: ...

    def read_intent(
        self, operation_id: str
    ) -> tuple[IntegrationPromotionIntent, ArtifactRef] | None: ...


class RollbackRepositoryVerifier(Protocol):
    """Trusted repository-side verification of every rollback Git identity."""

    def verify(self, request: IntegrationRollbackRequest) -> None: ...


class DeterministicFailedIntegrationSoak:
    """Repeatable case-7 soak: the exact synthetic result always fails."""

    def observe(self, request: IntegrationRollbackRequest) -> IntegrationDrillSoakObservation:
        values: dict[str, Any] = {
            "schema_version": 1,
            "operation_id": request.operation_id,
            "repository_digest": request.repository_digest,
            "target_ref": request.target_ref,
            "main_before_commit": request.main_before_commit,
            "main_after_commit": request.main_before_commit,
            "deploy_performed": False,
            "target_head_commit": request.failed_integration_head_commit,
            "target_head_tree": request.failed_integration_head_tree,
            "target_parents": [],
            "outcome": "failed",
            "error": "deterministic integration soak failure",
            "evidence_artifacts": [],
        }
        values["observation_id"] = canonical_digest(values)
        return IntegrationDrillSoakObservation.model_validate(values)


@dataclass(frozen=True, slots=True)
class IntegrationRollbackDrillExecution:
    request: IntegrationRollbackRequest
    soak: IntegrationDrillSoakObservation
    authorization: IntegrationDrillRollbackAuthorization
    intent: IntegrationDrillRollbackIntent
    receipt: IntegrationDrillRollbackReceipt
    case: IntegrationDrillCaseResult
    report: IntegrationPromotionReport
    evidence_artifacts: tuple[ArtifactRef, ...]
    replayed: bool = False


class IntegrationDrillRollbackService:
    """Journal soak evidence and execute one separately authorized rollback.

    ``promotion`` must be the normal PR-native promotion service.  The service
    only calls its ``promote`` method and therefore cannot force-update a ref.
    ``promotion_journal`` is required so a successful report can be tied to the
    exact provider receipt rather than inferred from a boolean result.
    """

    def __init__(
        self,
        journal: IntegrationDrillJournal,
        promotion: IntegrationPromotionService,
        promotion_journal: PromotionReceiptReader,
        *,
        main_head_reader: Callable[[], str],
        repository_verifier: RollbackRepositoryVerifier,
        trusted_rollback_issuers: Collection[str],
        soak: IntegrationSoakPort | None = None,
        attester_identity: str = "avo-004.6-case-7-attester-v1",
    ) -> None:
        if not attester_identity.strip():
            raise ValueError("attester_identity must be non-empty")
        issuers = frozenset(value.strip() for value in trusted_rollback_issuers if value.strip())
        if not issuers:
            raise ValueError("trusted_rollback_issuers must be non-empty")
        self._journal = journal
        self._promotion = promotion
        self._promotion_journal = promotion_journal
        self._main_head_reader = main_head_reader
        self._repository_verifier = repository_verifier
        self._trusted_rollback_issuers = issuers
        self._soak = soak or DeterministicFailedIntegrationSoak()
        self._attester_identity = attester_identity

    def run(
        self,
        request: IntegrationRollbackRequest,
        *,
        authorization: IntegrationDrillRollbackAuthorization,
        bundle: PromotionBundle,
        publication: CandidatePublicationBinding,
        bundle_digest: Sha256Digest,
        intent_factory: Callable[[Any], IntegrationPromotionIntent],
    ) -> IntegrationRollbackDrillExecution:
        """Run or replay case 7; every mutation is delegated to promotion."""
        self._validate_request(request)
        self._repository_verifier.verify(request)
        self._assert_main(request.main_before_commit)
        self._validate_authorization(request, authorization)
        self._validate_publication(request, publication, bundle)
        existing = self._journal.read_case_result(request.operation_id, CASE_ID)
        if existing is not None:
            return self._replay(request, existing[0], authorization)

        soak = self._journal.read_soak_observation(request.operation_id)
        if soak is None:
            soak = self._soak.observe(request)
            self._validate_soak(request, soak)
            soak_ref = self._journal.record_soak_observation(soak)
        else:
            soak, soak_ref = soak
            self._validate_soak(request, soak)

        auth_ref = self._journal.record_rollback_authorization(authorization)
        intent = self._make_intent(request, authorization, self._attester_identity)
        intent_ref = self._journal.record_rollback_intent(intent)

        # IntegrationPromotionService performs its own lease, durable intent,
        # mutation authorization, protected PR merge, and one reconciliation.
        report = self._promotion.promote(
            bundle,
            publication=publication,
            bundle_digest=bundle_digest,
            operation_id=request.promotion_operation_id,
            intent_factory=intent_factory,
        )
        if report.operation_id != request.promotion_operation_id:
            raise IntegrationRollbackDrillError("promotion report operation identity differs")
        main_after = self._assert_main(request.main_before_commit)
        if main_after != request.main_before_commit:
            raise IntegrationRollbackDrillError("rollback changed main")
        promotion_receipt = self._promotion_journal.read_receipt(request.promotion_operation_id)
        promotion_intent = self._promotion_journal.read_intent(request.promotion_operation_id)
        if report.outcome in {"applied", "already_applied"}:
            self._validate_promotion_intent(request, publication, promotion_intent)
        receipt = self._make_receipt(
            request,
            authorization,
            intent,
            self._attester_identity,
            report,
            promotion_receipt,
        )
        receipt_ref: ArtifactRef | None = None
        if receipt.outcome != "reconciliation_required":
            receipt_ref = self._journal.record_rollback_receipt(receipt)

        if receipt.outcome in ("applied", "already_applied", "reconciliation_required"):
            outcome: Literal[
                "applied", "already_applied", "rejected", "reconciliation_required"
            ] = receipt.outcome
        else:
            outcome = "rejected"
        error = receipt.error
        evidence_artifacts = [soak_ref, auth_ref, intent_ref]
        if receipt_ref is not None:
            evidence_artifacts.append(receipt_ref)
        case = IntegrationDrillCaseResult(
            case_id=CASE_ID,
            operation_id=request.operation_id,
            repository_digest=request.repository_digest,
            target_ref=request.target_ref,
            main_before_commit=request.main_before_commit,
            main_after_commit=main_after,
            target_head_commit=receipt.target_head_commit,
            target_head_tree=receipt.target_head_tree,
            target_parents=receipt.target_parents,
            outcome=outcome,
            attester_identity=self._attester_identity,
            evidence_artifacts=evidence_artifacts,
            soak_observation=soak.observation_id,
            rollback_intent=intent.intent_digest,
            rollback_receipt=receipt.receipt_digest,
            error=error,
        )
        if receipt_ref is not None:
            self._journal.record_case_result(case)
        return IntegrationRollbackDrillExecution(
            request, soak, authorization, intent, receipt, case, report,
            tuple(evidence_artifacts),
        )

    def verify_replay(
        self,
        request: IntegrationRollbackRequest,
        authorization: IntegrationDrillRollbackAuthorization,
    ) -> None:
        """Run the trusted, read-only fences required before replaying case 7."""
        self._validate_request(request)
        self._repository_verifier.verify(request)
        self._assert_main(request.main_before_commit)
        self._validate_authorization(request, authorization)

    def _replay(
        self,
        request: IntegrationRollbackRequest,
        case: IntegrationDrillCaseResult,
        supplied_authorization: IntegrationDrillRollbackAuthorization,
    ) -> IntegrationRollbackDrillExecution:
        if case.case_id != CASE_ID or case.operation_id != request.operation_id:
            raise IntegrationRollbackDrillError("case-7 replay identity mismatch")
        if (
            case.main_before_commit != request.main_before_commit
            or case.main_after_commit != request.main_before_commit
        ):
            raise IntegrationRollbackDrillError("replayed case does not prove main unchanged")
        soak_loaded = self._journal.read_soak_observation(request.operation_id)
        auth_loaded = self._journal.read_rollback_authorization(request.operation_id)
        intent_loaded = self._journal.read_rollback_intent(request.operation_id)
        receipt_loaded = self._journal.read_rollback_receipt(request.operation_id)
        if None in (soak_loaded, auth_loaded, intent_loaded, receipt_loaded):
            raise IntegrationRollbackDrillError("case-7 evidence is incomplete")
        soak, soak_ref = cast(tuple[IntegrationDrillSoakObservation, ArtifactRef], soak_loaded)
        authorization, _auth_ref = cast(
            tuple[IntegrationDrillRollbackAuthorization, ArtifactRef], auth_loaded
        )
        intent, _intent_ref = cast(
            tuple[IntegrationDrillRollbackIntent, ArtifactRef], intent_loaded
        )
        receipt, receipt_ref = cast(
            tuple[IntegrationDrillRollbackReceipt, ArtifactRef], receipt_loaded
        )
        self._validate_request(request)
        self._validate_authorization(request, supplied_authorization)
        if supplied_authorization != authorization:
            raise IntegrationRollbackDrillError("replay authorization differs")
        self._validate_authorization(request, authorization)
        self._validate_soak(request, soak)
        if (
            case.rollback_receipt != receipt.receipt_digest
            or case.rollback_intent != intent.intent_digest
        ):
            raise IntegrationRollbackDrillError("case-7 replay references differ")
        if (
            intent.operation_id != request.operation_id
            or receipt.operation_id != request.operation_id
            or intent.promotion_operation_id != request.promotion_operation_id
            or receipt.promotion_operation_id != request.promotion_operation_id
            or intent.authorization_id != authorization.authorization_id
            or receipt.intent_digest != intent.intent_digest
            or intent.repository_digest != request.repository_digest
            or receipt.repository_digest != request.repository_digest
            or intent.target_ref != request.target_ref
            or receipt.target_ref != request.target_ref
            or intent.main_before_commit != request.main_before_commit
            or receipt.main_before_commit != request.main_before_commit
            or intent.main_after_commit != request.main_before_commit
            or receipt.main_after_commit != request.main_before_commit
            or intent.failed_integration_head_commit
            != request.failed_integration_head_commit
            or receipt.failed_integration_head_commit
            != request.failed_integration_head_commit
            or intent.failed_integration_head_tree != request.failed_integration_head_tree
            or receipt.failed_integration_head_tree != request.failed_integration_head_tree
            or intent.restore_to_commit != request.restore_to_commit
            or receipt.restore_to_commit != request.restore_to_commit
            or intent.restore_to_tree != request.restore_to_tree
            or receipt.restore_to_tree != request.restore_to_tree
            or intent.rollback_candidate_commit != request.rollback_candidate_commit
            or receipt.rollback_candidate_commit != request.rollback_candidate_commit
            or intent.rollback_candidate_parent_commit
            != request.rollback_candidate_parent_commit
            or receipt.rollback_candidate_parent_commit
            != request.rollback_candidate_parent_commit
        ):
            raise IntegrationRollbackDrillError(
                "case-7 replay topology or promotion binding differs"
            )
        if (
            intent.attester_identity != self._attester_identity
            or receipt.attester_identity != self._attester_identity
            or case.attester_identity != self._attester_identity
        ):
            raise IntegrationRollbackDrillError("case-7 attester identity differs")
        return IntegrationRollbackDrillExecution(
            request, soak, authorization, intent, receipt, case,
            IntegrationPromotionReport(
                operation_id=request.promotion_operation_id, outcome="already_applied",
                checks=["case_7_replay"], errors=[]
            ),
            (soak_ref, _auth_ref, _intent_ref, receipt_ref), True,
        )

    @staticmethod
    def _validate_request(request: IntegrationRollbackRequest) -> None:
        if request.target_ref != TARGET_REF:
            raise IntegrationRollbackDrillError("rollback target must be protected integration")
        for value in (
            request.main_before_commit,
            request.failed_integration_head_commit,
            request.failed_integration_head_tree,
            request.restore_to_commit,
            request.restore_to_tree,
            request.rollback_candidate_commit,
            request.rollback_candidate_parent_commit,
        ):
            if not _is_git(value):
                raise IntegrationRollbackDrillError(
                    "rollback request contains malformed Git object"
                )
        if request.rollback_candidate_parent_commit != request.failed_integration_head_commit:
            raise IntegrationRollbackDrillError(
                "rollback candidate is not parented by failed integration head"
            )
        if request.rollback_candidate_commit in {
            request.failed_integration_head_commit,
            request.restore_to_commit,
        }:
            raise IntegrationRollbackDrillError(
                "rollback candidate must be a new commit distinct from restore anchor"
            )

    def _assert_main(self, expected: str) -> str:
        actual = self._main_head_reader()
        if actual != expected or not _is_git(actual):
            raise IntegrationRollbackDrillError("main head is stale or malformed")
        return actual

    def _validate_authorization(
        self,
        request: IntegrationRollbackRequest,
        authorization: IntegrationDrillRollbackAuthorization,
    ) -> None:
        if (
            authorization.operation_id != request.operation_id
            or authorization.repository_digest != request.repository_digest
            or authorization.target_ref != request.target_ref
            or authorization.main_before_commit != request.main_before_commit
            or authorization.main_after_commit != request.main_before_commit
            or authorization.target_head_commit != request.failed_integration_head_commit
            or authorization.target_head_tree != request.failed_integration_head_tree
            or authorization.failed_integration_head_commit
            != request.failed_integration_head_commit
            or authorization.failed_integration_head_tree != request.failed_integration_head_tree
            or authorization.restore_to_commit != request.restore_to_commit
            or authorization.restore_to_tree != request.restore_to_tree
            or authorization.rollback_candidate_commit
            != request.rollback_candidate_commit
            or authorization.rollback_candidate_parent_commit
            != request.rollback_candidate_parent_commit
            or not authorization.authorized
            or authorization.issuer not in self._trusted_rollback_issuers
        ):
            raise IntegrationRollbackDrillError("rollback authorization is stale or mismatched")
        if authorization.authorization_id != rollback_authorization_digest(authorization):
            raise IntegrationRollbackDrillError("rollback authorization digest mismatch")

    @staticmethod
    def _validate_soak(
        request: IntegrationRollbackRequest, soak: IntegrationDrillSoakObservation
    ) -> None:
        if (
            soak.operation_id != request.operation_id
            or soak.repository_digest != request.repository_digest
            or soak.target_ref != request.target_ref
            or soak.main_before_commit != request.main_before_commit
            or soak.main_after_commit != request.main_before_commit
            or soak.target_head_commit != request.failed_integration_head_commit
            or soak.target_head_tree != request.failed_integration_head_tree
            or soak.target_parents
            or soak.outcome != "failed"
        ):
            raise IntegrationRollbackDrillError(
                "integration soak is not the exact deterministic failure"
            )

    @staticmethod
    def _validate_publication(
        request: IntegrationRollbackRequest,
        publication: CandidatePublicationBinding,
        bundle: PromotionBundle,
    ) -> None:
        if (
            publication.repository_digest != request.repository_digest
            or publication.base_commit != request.failed_integration_head_commit
            or publication.base_tree != request.failed_integration_head_tree
            or publication.candidate_commit != request.rollback_candidate_commit
            or publication.candidate_tree != request.restore_to_tree
            or not publication.verified
            or bundle.snapshot.repository_digest != request.repository_digest
            or bundle.snapshot.target_ref != request.target_ref
            or bundle.snapshot.commit != request.failed_integration_head_commit
            or bundle.snapshot.tree != request.failed_integration_head_tree
        ):
            raise IntegrationRollbackDrillError("rollback publication or bundle topology is stale")

    @staticmethod
    def _validate_promotion_intent(
        request: IntegrationRollbackRequest,
        publication: CandidatePublicationBinding,
        loaded: tuple[IntegrationPromotionIntent, ArtifactRef] | None,
    ) -> None:
        if loaded is None:
            raise IntegrationRollbackDrillError(
                "successful rollback has no durable promotion intent"
            )
        intent = loaded[0]
        expected = {
            "operation_id": request.promotion_operation_id,
            "repository_digest": request.repository_digest,
            "target_ref": request.target_ref,
            "candidate_ref": publication.candidate_ref,
            "base_commit": request.failed_integration_head_commit,
            "base_tree": request.failed_integration_head_tree,
            "candidate_commit": request.rollback_candidate_commit,
            "candidate_tree": request.restore_to_tree,
            "candidate_head_ref": publication.candidate_ref,
            "candidate_head_commit": request.rollback_candidate_commit,
            "candidate_head_tree": request.restore_to_tree,
            "target_base_ref": request.target_ref,
            "target_base_commit": request.failed_integration_head_commit,
            "target_base_tree": request.failed_integration_head_tree,
        }
        actual = intent.model_dump(mode="python")
        if any(actual[name] != value for name, value in expected.items()):
            raise IntegrationRollbackDrillError("durable promotion intent is not rollback-bound")

    @staticmethod
    def _make_intent(
        request: IntegrationRollbackRequest,
        authorization: IntegrationDrillRollbackAuthorization,
        attester_identity: str,
    ) -> IntegrationDrillRollbackIntent:
        values: dict[str, Any] = {
            "schema_version": 1,
            "operation_id": request.operation_id,
            "promotion_operation_id": request.promotion_operation_id,
            "repository_digest": request.repository_digest,
            "target_ref": request.target_ref,
            "main_before_commit": request.main_before_commit,
            "main_after_commit": request.main_before_commit,
            "deploy_performed": False,
            "target_head_commit": request.failed_integration_head_commit,
            "target_head_tree": request.failed_integration_head_tree,
            "target_parents": [],
            "authorization_id": authorization.authorization_id,
            "attester_identity": attester_identity,
            "authorized": True,
            "reason": authorization.reason,
            "failed_integration_head_commit": request.failed_integration_head_commit,
            "failed_integration_head_tree": request.failed_integration_head_tree,
            "restore_to_commit": request.restore_to_commit,
            "restore_to_tree": request.restore_to_tree,
            "rollback_candidate_commit": request.rollback_candidate_commit,
            "rollback_candidate_parent_commit": request.rollback_candidate_parent_commit,
        }
        values["intent_digest"] = canonical_digest(values)
        return IntegrationDrillRollbackIntent.model_validate(values)

    @staticmethod
    def _make_receipt(
        request: IntegrationRollbackRequest,
        authorization: IntegrationDrillRollbackAuthorization,
        intent: IntegrationDrillRollbackIntent,
        attester_identity: str,
        report: IntegrationPromotionReport,
        loaded: tuple[IntegrationPromotionReceipt, ArtifactRef] | None,
    ) -> IntegrationDrillRollbackReceipt:
        promotion_receipt = loaded[0] if loaded is not None else None
        successful = report.outcome in {"applied", "already_applied"}
        if successful and (
            promotion_receipt is None
            or promotion_receipt.outcome not in {"applied", "already_applied"}
            or promotion_receipt.expected_target_ref != request.target_ref
            or promotion_receipt.expected_base_commit != request.failed_integration_head_commit
            or promotion_receipt.expected_candidate_commit
            != request.rollback_candidate_commit
            or promotion_receipt.expected_candidate_tree != request.restore_to_tree
            or promotion_receipt.applied_result_tree != request.restore_to_tree
            or promotion_receipt.applied_result_parent_commit
            != request.failed_integration_head_commit
            or promotion_receipt.applied_result_commit is None
        ):
            outcome = "reconciliation_required"
            error = "successful promotion report lacks exact rollback receipt"
        elif successful:
            outcome = "already_applied" if report.outcome == "already_applied" else "applied"
            error = None
        elif report.outcome == "reconciliation_required":
            outcome = "reconciliation_required"
            error = "; ".join(report.errors) or "rollback promotion requires reconciliation"
        else:
            outcome = "stale_target" if report.outcome == "stale_base" else "rejected"
            error = "; ".join(report.errors) or f"rollback promotion outcome: {report.outcome}"

        result_commit = (
            promotion_receipt.applied_result_commit
            if outcome in {"applied", "already_applied"} and promotion_receipt is not None
            else None
        )
        result_tree = (
            promotion_receipt.applied_result_tree
            if outcome in {"applied", "already_applied"} and promotion_receipt is not None
            else None
        )
        values: dict[str, Any] = {
            "schema_version": 1,
            "operation_id": request.operation_id,
            "promotion_operation_id": request.promotion_operation_id,
            "repository_digest": request.repository_digest,
            "target_ref": request.target_ref,
            "main_before_commit": request.main_before_commit,
            "main_after_commit": request.main_before_commit,
            "deploy_performed": False,
            "target_head_commit": result_commit or request.failed_integration_head_commit,
            "target_head_tree": result_tree or request.failed_integration_head_tree,
            "target_parents": [request.failed_integration_head_commit] if result_commit else [],
            "intent_digest": intent.intent_digest,
            "receipt_digest": "sha256:" + "0" * 64,
            "outcome": outcome,
            "attester_identity": attester_identity,
            "failed_integration_head_commit": request.failed_integration_head_commit,
            "failed_integration_head_tree": request.failed_integration_head_tree,
            "restore_to_commit": request.restore_to_commit,
            "restore_to_tree": request.restore_to_tree,
            "rollback_candidate_commit": request.rollback_candidate_commit,
            "rollback_candidate_parent_commit": request.rollback_candidate_parent_commit,
            "result_commit": result_commit,
            "result_tree": result_tree,
            "error": error,
        }
        values["receipt_digest"] = canonical_digest(
            {key: value for key, value in values.items() if key != "receipt_digest"}
        )
        return IntegrationDrillRollbackReceipt.model_validate(values)


def _is_git(value: str) -> bool:
    return len(value) in {40, 64} and all(char in "0123456789abcdef" for char in value)


def rollback_authorization_digest(
    authorization: IntegrationDrillRollbackAuthorization,
) -> Sha256Digest:
    """Return the canonical identity of an authorization payload."""
    return canonical_digest(
        authorization.model_dump(
            exclude={"authorization_id"}, exclude_none=True, mode="json"
        )
    )


# Short aliases make the case available to callers that use the roadmap term.
IntegrationSoakRollbackService = IntegrationDrillRollbackService

__all__ = [
    "CASE_ID",
    "TARGET_REF",
    "DeterministicFailedIntegrationSoak",
    "IntegrationDrillRollbackService",
    "IntegrationRollbackDrillError",
    "IntegrationRollbackDrillExecution",
    "IntegrationRollbackRequest",
    "IntegrationSoakRollbackService",
    "rollback_authorization_digest",
]
