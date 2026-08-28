"""Fail-closed orchestration for PR-native integration promotion."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime
from typing import Literal, Protocol

from avo_correlate.application.promotion_service import (
    PromotionController,
    TrustedPromotionRepository,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_promotion import (
    CandidatePublicationBinding,
    IntegrationMergeResult,
    IntegrationPromotionIntent,
    IntegrationPromotionPreconditionError,
    IntegrationPromotionReceipt,
    IntegrationPromotionReport,
    IntegrationProviderObservation,
    IntegrationProviderReconciliation,
    PromotionLeaseEvidence,
    PromotionMutationAuthorization,
)
from avo_correlate.contracts.promotion_bundle import PromotionBundle
from avo_correlate.domain.canonical import canonical_digest


class PromotionLease(Protocol):
    identity: str
    digest: str


class HostedIntegrationProvider(Protocol):
    def observe(self, intent: IntegrationPromotionIntent) -> IntegrationProviderObservation: ...
    def merge(
        self,
        intent: IntegrationPromotionIntent,
        *,
        lease_guard: Callable[[], None],
        mutation_authorize: Callable[[], None],
    ) -> IntegrationMergeResult: ...
    def reconcile(
        self, intent: IntegrationPromotionIntent
    ) -> IntegrationProviderReconciliation: ...


class PublicationVerifier(Protocol):
    """Trusted verifier for controller-owned candidate publication evidence."""

    def __call__(self, binding: CandidatePublicationBinding, bundle: PromotionBundle) -> bool: ...


class IntegrationPromotionJournal(Protocol):
    def read_intent(
        self, operation_id: str
    ) -> tuple[IntegrationPromotionIntent, ArtifactRef] | None: ...
    def read_receipt(
        self, operation_id: str
    ) -> tuple[IntegrationPromotionReceipt, ArtifactRef] | None: ...
    def read_lease_evidence(
        self, operation_id: str
    ) -> tuple[PromotionLeaseEvidence, ArtifactRef] | None: ...
    def read_mutation_authorization(
        self, operation_id: str
    ) -> tuple[PromotionMutationAuthorization, ArtifactRef] | None: ...
    def acquire_lease(
        self, repository_digest: str, target_ref: str, operation_id: str, *, lease_seconds: int
    ) -> PromotionLease: ...
    def assert_current(self, lease: PromotionLease) -> None: ...
    def release_lease(self, lease: PromotionLease) -> None: ...
    def release_matching_lease(
        self, repository_digest: str, target_ref: str, operation_id: str, identity: str, digest: str
    ) -> bool: ...
    def record_intent(self, intent: IntegrationPromotionIntent) -> ArtifactRef: ...
    def record_receipt(self, receipt: IntegrationPromotionReceipt) -> ArtifactRef: ...
    def record_mutation_authorization(
        self, authorization: PromotionMutationAuthorization
    ) -> ArtifactRef: ...


class IntegrationPromotionService:
    def __init__(
        self,
        controller: PromotionController,
        integration_repository: TrustedPromotionRepository,
        provider: HostedIntegrationProvider,
        journal: IntegrationPromotionJournal,
        publication_verifier: PublicationVerifier,
        *,
        lease_seconds: int = 300,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        self._controller, self._repository, self._provider, self._journal = (
            controller,
            integration_repository,
            provider,
            journal,
        )
        self._lease_seconds = lease_seconds
        self._publication_verifier = publication_verifier
        self._clock = clock or (lambda: datetime.now(UTC))

    def promote(
        self,
        bundle: PromotionBundle,
        *,
        publication: CandidatePublicationBinding,
        bundle_digest: str,
        operation_id: str,
        intent_factory: Callable[[PromotionLease], IntegrationPromotionIntent],
        lease_seconds: int | None = None,
    ) -> IntegrationPromotionReport:
        effective_lease_seconds = self._lease_seconds if lease_seconds is None else lease_seconds
        if effective_lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        checks: list[str] = []
        lease: PromotionLease | None = None
        mutation_may_have_occurred = False
        safe_release = False
        try:
            self._assert_publication_binding(publication, bundle)
            if not self._publication_verifier(publication, bundle):
                raise ValueError("candidate publication verifier rejected evidence")
            checks.append("publication_verified")
            existing = self._journal.read_receipt(operation_id)
            if existing is not None:
                receipt, ref = existing
                if receipt.bundle_digest != bundle_digest or receipt.operation_id != operation_id:
                    return self._report(
                        operation_id,
                        "invalid",
                        ["receipt_existing"],
                        ["receipt binding mismatch"],
                        None,
                    )
                durable_receipt_intent = self._journal.read_intent(operation_id)
                if durable_receipt_intent is None:
                    return self._report(
                        operation_id,
                        "reconciliation_required",
                        ["receipt_existing", "missing_intent"],
                        ["durable receipt has no matching durable intent"],
                        None,
                    )
                recovery_intent = durable_receipt_intent[0]
                self._assert_durable_lease_evidence(recovery_intent)
                self._assert_intent_binding_without_lease(
                    recovery_intent, bundle, bundle_digest, operation_id
                )
                self._assert_publication_intent_binding(publication, recovery_intent)
                self._assert_receipt_binding(receipt, recovery_intent)
                self._journal.release_matching_lease(
                    recovery_intent.repository_digest,
                    recovery_intent.target_ref,
                    recovery_intent.operation_id,
                    recovery_intent.controller_lease_identity,
                    recovery_intent.controller_lease_digest,
                )
                return self._report(
                    operation_id, receipt.outcome, ["receipt_existing"], [], receipt, ref
                )
            durable = self._journal.read_intent(operation_id)
            if durable is not None:
                intent = durable[0]
                self._assert_durable_lease_evidence(intent)
                self._assert_intent_binding_without_lease(
                    intent, bundle, bundle_digest, operation_id
                )
                self._assert_publication_intent_binding(publication, intent)
                authorization = self._journal.read_mutation_authorization(operation_id)
                if authorization is None:
                    return self._report(
                        operation_id,
                        "invalid",
                        ["intent_existing", "mutation_authorization_missing"],
                        ["durable intent has no mutation authorization marker"],
                        None,
                    )
                self._assert_mutation_authorization(intent, authorization[0])
                reconciliation = self._provider.reconcile(intent)
                checks.extend(("intent_existing", "reconciled_once"))
                self._assert_reconciliation_binding(intent, reconciliation)
                outcome = self._classify_reconciliation(reconciliation, intent)
                if outcome != "already_applied":
                    return self._report(
                        operation_id,
                        "reconciliation_required",
                        checks,
                        ["existing intent requires reconciliation"],
                        None,
                    )
                merge = IntegrationMergeResult(
                    outcome="ambiguous",
                    response_digest=canonical_digest(reconciliation),
                    error="reconciled existing intent",
                )
                receipt = self._receipt(intent, merge, reconciliation, outcome)
                ref = self._journal.record_receipt(receipt)
                self._journal.release_matching_lease(
                    intent.repository_digest,
                    intent.target_ref,
                    intent.operation_id,
                    intent.controller_lease_identity,
                    intent.controller_lease_digest,
                )
                safe_release = True
                return self._report(operation_id, outcome, checks, [], receipt, ref)

            lease = self._journal.acquire_lease(
                bundle.snapshot.repository_digest,
                bundle.snapshot.target_ref,
                operation_id,
                lease_seconds=effective_lease_seconds,
            )
            self._journal.assert_current(lease)
            self._assert_lease_evidence(operation_id, lease)
            intent = intent_factory(lease)
            self._assert_intent_binding(intent, bundle, bundle_digest, operation_id, lease)
            self._assert_publication_intent_binding(publication, intent)
            replay = self._controller.replay(
                bundle, bundle_digest=bundle_digest, repository=self._repository
            )
            checks.extend(replay.checks)
            if replay.outcome != "would_apply":
                safe_release = True
                return self._report(
                    operation_id,
                    "invalid" if replay.outcome == "invalid_bundle" else replay.outcome,
                    checks,
                    replay.errors,
                    None,
                )
            self._journal.assert_current(lease)
            self._assert_observation(intent, self._provider.observe(intent))
            checks.append("provider_precondition")
            self._journal.assert_current(lease)
            self._journal.record_intent(intent)
            checks.append("intent_durable")
            mutation_may_have_occurred = True
            self._journal.assert_current(lease)
            try:
                assert lease is not None
                merge = self._provider.merge(
                    intent,
                    lease_guard=lambda: self._journal.assert_current(lease),
                    mutation_authorize=lambda: self._authorize_mutation(intent, lease),
                )
            except IntegrationPromotionPreconditionError as exc:
                # The provider proved that its final preconditions failed before
                # any mutating request.  This is not transport ambiguity: do not
                # reconcile or claim success.  Persist an invalid terminal receipt
                # so a restart cannot reconcile this durable intent into success.
                safe_release = True
                receipt = self._precondition_receipt(intent, str(exc))
                ref = self._journal.record_receipt(receipt)
                return self._report(
                    operation_id,
                    "invalid",
                    [*checks, "merge_precondition_failed"],
                    [str(exc)],
                    receipt,
                    ref,
                )
            except (ValueError, RuntimeError, OSError) as exc:
                merge = IntegrationMergeResult(
                    outcome="ambiguous",
                    response_digest=canonical_digest({"error": str(exc)}),
                    error=str(exc),
                )
            checks.append("merge_submitted")
            reconciliation = self._provider.reconcile(intent)
            checks.append("reconciled_once")
            self._assert_reconciliation_binding(intent, reconciliation)
            outcome = self._classify(merge, reconciliation, intent)
            receipt = self._receipt(intent, merge, reconciliation, outcome)
            self._journal.assert_current(lease)
            ref = self._journal.record_receipt(receipt)
            safe_release = outcome != "reconciliation_required"
            return self._report(
                operation_id,
                outcome,
                checks,
                [receipt.error] if receipt.error else [],
                receipt,
                ref,
            )
        except (ValueError, RuntimeError, OSError) as exc:
            return self._report(
                operation_id,
                "reconciliation_required" if mutation_may_have_occurred else "invalid",
                checks or ["boundary"],
                [str(exc)],
                None,
            )
        finally:
            if lease is not None and (safe_release or not mutation_may_have_occurred):
                with suppress(ValueError, RuntimeError, OSError):
                    self._journal.release_lease(lease)

    def _assert_lease_evidence(self, operation_id: str, lease: PromotionLease) -> None:
        loaded = self._journal.read_lease_evidence(operation_id)
        if loaded is None:
            raise ValueError("promotion lease evidence is missing")
        evidence, _reference = loaded
        if (
            evidence.operation_id != operation_id
            or evidence.identity != lease.identity
            or evidence.digest != lease.digest
        ):
            raise ValueError("promotion lease evidence does not bind to acquired lease")

    def _assert_durable_lease_evidence(
        self, intent: IntegrationPromotionIntent
    ) -> None:
        loaded = self._journal.read_lease_evidence(intent.operation_id)
        if loaded is None:
            raise ValueError("promotion lease evidence is missing for durable intent")
        evidence, _reference = loaded
        if (
            evidence.operation_id != intent.operation_id
            or evidence.repository_digest != intent.repository_digest
            or evidence.target_ref != intent.target_ref
            or evidence.identity != intent.controller_lease_identity
            or evidence.digest != intent.controller_lease_digest
        ):
            raise ValueError("durable intent lease binding differs from lease evidence")

    @staticmethod
    def _assert_mutation_authorization(
        intent: IntegrationPromotionIntent, authorization: PromotionMutationAuthorization
    ) -> None:
        if (
            authorization.operation_id != intent.operation_id
            or authorization.intent_digest != canonical_digest(intent)
            or authorization.lease_identity != intent.controller_lease_identity
            or authorization.lease_digest != intent.controller_lease_digest
        ):
            raise ValueError("mutation authorization does not bind to durable intent")

    def _authorize_mutation(
        self, intent: IntegrationPromotionIntent, lease: PromotionLease
    ) -> None:
        self._journal.record_mutation_authorization(
            PromotionMutationAuthorization(
                operation_id=intent.operation_id,
                intent_digest=canonical_digest(intent),
                lease_identity=lease.identity,
                lease_digest=lease.digest,
                authorized_at=self._clock(),
            )
        )

    @staticmethod
    def _assert_intent_binding(
        intent: IntegrationPromotionIntent,
        bundle: PromotionBundle,
        bundle_digest: str,
        operation_id: str,
        lease: PromotionLease,
    ) -> None:
        IntegrationPromotionService._assert_intent_binding_without_lease(
            intent, bundle, bundle_digest, operation_id
        )
        if (
            intent.controller_lease_identity != lease.identity
            or intent.controller_lease_digest != lease.digest
        ):
            raise ValueError("intent lease binding differs from acquired lease")

    @staticmethod
    def _assert_intent_binding_without_lease(
        intent: IntegrationPromotionIntent,
        bundle: PromotionBundle,
        bundle_digest: str,
        operation_id: str,
    ) -> None:
        if (
            intent.operation_id != operation_id
            or intent.repository_digest != bundle.snapshot.repository_digest
            or intent.target_ref != bundle.snapshot.target_ref
        ):
            raise ValueError("intent identity does not match operation or lease scope")
        if (
            intent.bundle_digest != bundle_digest
            or intent.candidate_digest != bundle.request.candidate_digest
        ):
            raise ValueError("intent and bundle differ")
        if (
            intent.base_commit != bundle.snapshot.commit
            or intent.base_tree != bundle.snapshot.tree
            or intent.protection_evidence_digest != bundle.snapshot.protection_evidence_digest
            or intent.controller_config_digest != bundle.controller_config_digest
            or intent.evidence_manifest_digest != bundle.provenance.evidence_manifest_digest
            or intent.publication_evidence_digest != bundle.provenance.source_provenance_digest
        ):
            raise ValueError("intent binding differs from bundle snapshot or evidence")

    @staticmethod
    def _assert_publication_binding(
        publication: CandidatePublicationBinding, bundle: PromotionBundle
    ) -> None:
        if (
            publication.repository_digest != bundle.snapshot.repository_digest
            or publication.base_commit != bundle.snapshot.commit
            or publication.base_tree != bundle.snapshot.tree
            or publication.candidate_digest != bundle.request.candidate_digest
            or publication.publication_evidence_digest != bundle.provenance.source_provenance_digest
            or (
                bundle.rollback_authorization is None
                and publication.controller_publisher_identity
                != bundle.controller_config.controller_identity
            )
            or publication.publication_evidence_digest not in bundle.evidence_digests
        ):
            raise ValueError("candidate publication does not match bundle provenance")

    @staticmethod
    def _assert_publication_intent_binding(
        publication: CandidatePublicationBinding, intent: IntegrationPromotionIntent
    ) -> None:
        if (
            publication.repository_digest != intent.repository_digest
            or publication.base_commit != intent.base_commit
            or publication.base_tree != intent.base_tree
            or publication.candidate_digest != intent.candidate_digest
            or publication.candidate_ref != intent.candidate_ref
            or publication.candidate_commit != intent.candidate_commit
            or publication.candidate_tree != intent.candidate_tree
            or publication.publication_evidence_digest != intent.publication_evidence_digest
        ):
            raise ValueError("candidate publication does not match intent")

    @staticmethod
    def _assert_receipt_binding(
        receipt: IntegrationPromotionReceipt, intent: IntegrationPromotionIntent
    ) -> None:
        if receipt.intent_digest != canonical_digest(intent):
            raise ValueError("receipt intent digest does not match durable intent")
        expected = {
            "operation_id": intent.operation_id,
            "bundle_digest": intent.bundle_digest,
            "expected_target_ref": intent.target_ref,
            "expected_candidate_commit": intent.candidate_commit,
            "expected_candidate_tree": intent.candidate_tree,
            "expected_base_commit": intent.base_commit,
            "expected_main_commit": intent.expected_main_commit,
            "expected_protection_evidence_digest": intent.protection_evidence_digest,
            "expected_provider_identity": intent.provider_identity,
            "expected_provider_api_version": intent.provider_api_version,
            "observed_target_ref": intent.target_ref,
            "observed_base_commit": intent.base_commit,
            "observed_protection_evidence_digest": intent.protection_evidence_digest,
            "observed_provider_identity": intent.provider_identity,
            "observed_provider_api_version": intent.provider_api_version,
        }
        actual = receipt.model_dump(mode="python")
        if any(actual[key] != value for key, value in expected.items()):
            raise ValueError("receipt binding differs from durable intent")
        if receipt.outcome in {"applied", "already_applied"} and (
            receipt.observed_head_tree != intent.candidate_tree
        ):
            raise ValueError("receipt candidate tree differs from durable intent")

    @staticmethod
    def _assert_observation(
        intent: IntegrationPromotionIntent, observation: IntegrationProviderObservation
    ) -> None:
        expected = {
            "repository_digest": intent.repository_digest,
            "pull_request_number": intent.pull_request_number,
            "pull_request_url": intent.pull_request_url,
            "candidate_repository_digest": intent.repository_digest,
            "target_repository_digest": intent.repository_digest,
            "base_ref": intent.target_ref,
            "base_commit": intent.base_commit,
            "base_tree": intent.base_tree,
            "head_ref": intent.candidate_ref,
            "head_commit": intent.candidate_commit,
            "candidate_tree": intent.candidate_tree,
            "synthetic_merge_commit": intent.synthetic_merge_commit,
            "synthetic_merge_tree": intent.synthetic_merge_tree,
            "protection_evidence_digest": intent.protection_evidence_digest,
            "check_evidence_manifest_digest": intent.check_evidence_manifest_digest,
            "provider_identity": intent.provider_identity,
            "provider_api_version": intent.provider_api_version,
            "open_state": "open",
            "draft": False,
        }
        actual = observation.model_dump(mode="python")
        for name, value in expected.items():
            if actual[name] != value:
                raise ValueError(f"provider binding mismatch: {name}")

    @staticmethod
    def _assert_reconciliation_binding(
        intent: IntegrationPromotionIntent, reconciliation: IntegrationProviderReconciliation
    ) -> None:
        expected = {
            "repository_digest": intent.repository_digest,
            "pull_request_number": intent.pull_request_number,
            "pull_request_url": intent.pull_request_url,
            "provider_identity": intent.provider_identity,
            "provider_api_version": intent.provider_api_version,
            "target_ref": intent.target_ref,
            "protection_evidence_digest": intent.protection_evidence_digest,
        }
        actual = reconciliation.model_dump(mode="python")
        for name, value in expected.items():
            if actual[name] != value:
                raise ValueError(f"reconciliation binding mismatch: {name}")

    @classmethod
    def _classify(
        cls,
        merge: IntegrationMergeResult,
        reconciliation: IntegrationProviderReconciliation,
        intent: IntegrationPromotionIntent,
    ) -> Literal[
        "applied",
        "already_applied",
        "stale_base",
        "not_applicable",
        "reconciliation_required",
    ]:
        exact = (
            reconciliation.merged
            and reconciliation.merge_commit == reconciliation.target_head_commit
            and reconciliation.target_head_tree == intent.candidate_tree
            and reconciliation.target_first_parent == intent.base_commit
            and reconciliation.target_parents == [intent.base_commit]
        )
        if (
            exact
            and merge.outcome == "applied"
            and merge.result_commit == reconciliation.merge_commit
            and merge.result_tree == reconciliation.target_head_tree
            and merge.first_parent_commit == reconciliation.target_first_parent
        ):
            return "applied"
        if exact and merge.outcome == "ambiguous":
            return "already_applied"
        if not reconciliation.merged and merge.outcome == "rejected":
            return (
                "stale_base"
                if reconciliation.target_head_commit != intent.base_commit
                else "not_applicable"
            )
        return "reconciliation_required"

    @classmethod
    def _classify_reconciliation(
        cls, reconciliation: IntegrationProviderReconciliation, intent: IntegrationPromotionIntent
    ) -> Literal["already_applied", "reconciliation_required"]:
        return (
            "already_applied"
            if reconciliation.merged
            and reconciliation.merge_commit == reconciliation.target_head_commit
            and reconciliation.target_head_tree == intent.candidate_tree
            and reconciliation.target_first_parent == intent.base_commit
            and reconciliation.target_parents == [intent.base_commit]
            else "reconciliation_required"
        )

    @staticmethod
    def _receipt(
        intent: IntegrationPromotionIntent,
        merge: IntegrationMergeResult,
        reconciliation: IntegrationProviderReconciliation,
        outcome: Literal[
            "intent_recorded",
            "applied",
            "already_applied",
            "stale_base",
            "not_applicable",
            "invalid",
            "reconciliation_required",
        ],
    ) -> IntegrationPromotionReceipt:
        applied = outcome in {"applied", "already_applied"}
        return IntegrationPromotionReceipt(
            operation_id=intent.operation_id,
            intent_digest=canonical_digest(intent),
            bundle_digest=intent.bundle_digest,
            expected_target_ref=intent.target_ref,
            expected_candidate_commit=intent.candidate_commit,
            expected_candidate_tree=intent.candidate_tree,
            expected_base_commit=intent.base_commit,
            expected_main_commit=intent.expected_main_commit,
            expected_protection_evidence_digest=intent.protection_evidence_digest,
            main_protection_evidence_digest=merge.main_protection_evidence_digest,
            expected_provider_identity=intent.provider_identity,
            expected_provider_api_version=intent.provider_api_version,
            merge_method="squash",
            applied_result_commit=reconciliation.merge_commit if applied else None,
            applied_result_tree=reconciliation.target_head_tree if applied else None,
            applied_result_parent_commit=reconciliation.target_first_parent if applied else None,
            outcome=outcome,
            observed_target_ref=reconciliation.target_ref,
            observed_base_commit=intent.base_commit,
            observed_head_commit=reconciliation.target_head_commit if applied else None,
            observed_head_tree=reconciliation.target_head_tree if applied else None,
            observed_protection_evidence_digest=reconciliation.protection_evidence_digest,
            observed_provider_identity=reconciliation.provider_identity,
            observed_provider_api_version=reconciliation.provider_api_version,
            observation_digest=canonical_digest(reconciliation),
            error=None if applied else (merge.error or "promotion did not reconcile"),
        )

    @staticmethod
    def _precondition_receipt(
        intent: IntegrationPromotionIntent, error: str
    ) -> IntegrationPromotionReceipt:
        """Build a durable non-success receipt without a provider reconciliation.

        A final precondition failure occurs before the provider mutation boundary,
        so there is deliberately no observed head or merge result.  Persisting
        this terminal invalid state prevents recovery from re-running
        reconciliation and manufacturing a later success for the same intent.
        """
        return IntegrationPromotionReceipt(
            operation_id=intent.operation_id,
            intent_digest=canonical_digest(intent),
            bundle_digest=intent.bundle_digest,
            expected_target_ref=intent.target_ref,
            expected_candidate_commit=intent.candidate_commit,
            expected_candidate_tree=intent.candidate_tree,
            expected_base_commit=intent.base_commit,
            expected_main_commit=intent.expected_main_commit,
            expected_protection_evidence_digest=intent.protection_evidence_digest,
            expected_provider_identity=intent.provider_identity,
            expected_provider_api_version=intent.provider_api_version,
            merge_method="squash",
            outcome="invalid",
            observed_target_ref=intent.target_ref,
            observed_base_commit=intent.base_commit,
            observed_protection_evidence_digest=intent.protection_evidence_digest,
            observed_provider_identity=intent.provider_identity,
            observed_provider_api_version=intent.provider_api_version,
            observation_digest=canonical_digest(
                {
                    "kind": "integration-promotion-precondition-failure",
                    "operation_id": intent.operation_id,
                    "error": error,
                }
            ),
            error=error,
        )

    @staticmethod
    def _report(
        operation_id: str,
        outcome: Literal[
            "ready",
            "intent_recorded",
            "applied",
            "already_applied",
            "stale_base",
            "not_applicable",
            "invalid",
            "reconciliation_required",
        ],
        checks: list[str],
        errors: list[str],
        receipt: IntegrationPromotionReceipt | None,
        ref: ArtifactRef | None = None,
    ) -> IntegrationPromotionReport:
        return IntegrationPromotionReport(
            operation_id=operation_id,
            outcome=outcome,
            intent_digest=receipt.intent_digest if receipt else None,
            receipt_digest=ref.digest if ref else canonical_digest(receipt) if receipt else None,
            checks=checks or ["boundary"],
            errors=errors,
        )


__all__ = [
    "HostedIntegrationProvider",
    "IntegrationPromotionJournal",
    "IntegrationPromotionService",
    "PromotionLease",
    "PublicationVerifier",
]
