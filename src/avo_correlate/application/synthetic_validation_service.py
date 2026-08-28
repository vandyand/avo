"""Recovery-safe orchestration of an exact-SHA synthetic validation ref."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Literal, Protocol, TypedDict, Unpack, cast

from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.synthetic_validation import (
    SyntheticValidationAttempt,
    SyntheticValidationCompletionProof,
    SyntheticValidationCreateAuthorization,
    SyntheticValidationObservation,
    SyntheticValidationOutcome,
    SyntheticValidationPlan,
    SyntheticValidationRequest,
    synthetic_validation_operation_id,
    validation_ref_for,
)


class SyntheticValidationProvider(Protocol):
    """Minimal provider port; create is the only remote trigger."""

    def read_validation_ref(self, repository_digest: str, ref: str) -> object | None: ...

    def create_validation_ref(self, repository_digest: str, ref: str, commit: str) -> object: ...

    def delete_validation_ref(self, repository_digest: str, ref: str) -> object: ...


class SyntheticValidationJournal(Protocol):
    """Durable records required by the validation state machine."""

    def read_plan(
        self, operation_id: str
    ) -> SyntheticValidationPlan | tuple[SyntheticValidationPlan, ArtifactRef] | None: ...

    def record_plan(self, plan: SyntheticValidationPlan) -> ArtifactRef: ...

    def read_outcome(
        self, operation_id: str
    ) -> SyntheticValidationOutcome | tuple[SyntheticValidationOutcome, ArtifactRef] | None: ...

    def record_outcome(self, outcome: SyntheticValidationOutcome) -> ArtifactRef: ...

    def read_attempt(
        self, operation_id: str
    ) -> SyntheticValidationAttempt | tuple[SyntheticValidationAttempt, ArtifactRef] | None: ...

    def record_attempt(self, attempt: SyntheticValidationAttempt) -> ArtifactRef: ...

    def read_create_authorization(
        self, operation_id: str
    ) -> (
        SyntheticValidationCreateAuthorization
        | tuple[SyntheticValidationCreateAuthorization, ArtifactRef]
        | None
    ): ...

    def claim_create_authorization(
        self, authorization: SyntheticValidationCreateAuthorization
    ) -> bool: ...

    def read_cleanup(
        self, operation_id: str
    ) -> SyntheticValidationOutcome | tuple[SyntheticValidationOutcome, ArtifactRef] | None: ...

    def record_cleanup(self, outcome: SyntheticValidationOutcome) -> ArtifactRef: ...


class SyntheticValidationCompletionProofVerifier(Protocol):
    """Verify caller completion proof against durable campaign evidence."""

    def verify(
        self, plan: SyntheticValidationPlan, proof: SyntheticValidationCompletionProof
    ) -> None: ...


class TriggerOptions(TypedDict, total=False):
    target_repository_digest: str | None
    target_ref: str | None
    target_identity: str | None
    trusted_check_contexts: Sequence[str]
    provider_identity: str
    provider_api_version: str


OutcomeKind = Literal[
    "created",
    "already_present",
    "reconciled",
    "reconciliation_required",
    "invalid",
    "quarantined",
    "cleaned",
]


class SyntheticValidationService:
    """Prepare, trigger, reconcile, and safely clean one validation ref."""

    def __init__(
        self,
        provider: SyntheticValidationProvider,
        journal: SyntheticValidationJournal,
        *,
        completion_proof_verifier: SyntheticValidationCompletionProofVerifier | None = None,
    ) -> None:
        self._provider = provider
        self._journal = journal
        self._completion_proof_verifier = completion_proof_verifier

    def prepare(
        self,
        request_or_observation: SyntheticValidationRequest | SyntheticValidationObservation,
        *,
        target_repository_digest: str | None = None,
        target_ref: str | None = None,
        target_identity: str | None = None,
        trusted_check_contexts: Sequence[str] = (),
        provider_identity: str = "synthetic-validation-provider",
        provider_api_version: str = "1",
    ) -> SyntheticValidationPlan:
        """Create and durably record a plan, without changing the provider."""
        request = _request(
            request_or_observation,
            target_repository_digest=target_repository_digest,
            target_ref=target_ref,
            target_identity=target_identity,
            trusted_check_contexts=trusted_check_contexts,
            provider_identity=provider_identity,
            provider_api_version=provider_api_version,
        )
        operation_id = synthetic_validation_operation_id(request)
        existing = _unwrap(self._journal.read_plan(operation_id))
        if existing is not None:
            if existing != SyntheticValidationPlan(
                operation_id=operation_id,
                request=request,
                validation_ref=validation_ref_for(operation_id),
                expected_commit=request.observation.synthetic_commit,
                expected_tree=request.observation.synthetic_tree,
            ):
                raise SyntheticValidationConflictError("conflicting replay for operation")
            return existing
        plan = SyntheticValidationPlan(
            operation_id=operation_id,
            request=request,
            validation_ref=validation_ref_for(operation_id),
            expected_commit=request.observation.synthetic_commit,
            expected_tree=request.observation.synthetic_tree,
        )
        self._journal.record_plan(plan)
        return plan

    def trigger(
        self,
        request_or_plan: SyntheticValidationRequest
        | SyntheticValidationObservation
        | SyntheticValidationPlan,
        **kwargs: Unpack[TriggerOptions],
    ) -> SyntheticValidationOutcome:
        """Trigger once and reconcile both successful and ambiguous responses."""
        if isinstance(request_or_plan, SyntheticValidationPlan):
            plan = _unwrap(self._journal.read_plan(request_or_plan.operation_id))
            if plan is None:
                self._journal.record_plan(request_or_plan)
                plan = request_or_plan
            elif plan != request_or_plan:
                raise SyntheticValidationConflictError("conflicting replay for operation")
        else:
            plan = self.prepare(request_or_plan, **kwargs)
        durable = _unwrap(self._journal.read_outcome(plan.operation_id))
        if durable is not None:
            _check_outcome_binding(durable, plan)
            return durable

        prior_attempt = self._journal.read_attempt(plan.operation_id)
        prior_attempt = _unwrap(prior_attempt)
        if prior_attempt is not None and (
            prior_attempt.plan_digest != plan.plan_digest
            or prior_attempt.validation_ref != plan.validation_ref
            or prior_attempt.expected_commit != plan.expected_commit
            or prior_attempt.expected_tree != plan.expected_tree
        ):
            raise SyntheticValidationConflictError("durable attempt is not bound to the plan")
        authorization = _unwrap(self._journal.read_create_authorization(plan.operation_id))
        if authorization is not None:
            _check_authorization_binding(authorization, plan)
        state = self._read(plan)
        if state[0] == "error":
            return self._uncertain(plan, "read_error")
        if state[0] == "exact":
            if authorization is None:
                return self._save(
                    _outcome(
                        plan,
                        "quarantined",
                        observed_commit=state[1],
                        observed_tree=state[2],
                        error="existing validation ref was pre-seeded without authorization",
                    )
                )
            return self._save(
                _outcome(
                    plan,
                    "reconciled" if prior_attempt is not None else "already_present",
                    observed_commit=state[1],
                    observed_tree=state[2],
                )
            )
        if state[0] == "wrong":
            return self._save(
                _outcome(
                    plan,
                    "invalid",
                    observed_commit=state[1],
                    observed_tree=state[2],
                    error="existing validation ref points to a wrong SHA; quarantined",
                )
            )

        # An earlier ambiguous create is a durable no-replay fence.  Continue
        # with a read-only reconciliation, but never issue create twice.
        if prior_attempt is not None:
            return self._uncertain(plan, "create_ambiguous")

        # A durable authorization is an immutable pre-create fence. If it
        # exists, this operation has crossed (or may have crossed) the
        # mutation boundary; recovery must remain read-only.
        if authorization is not None:
            return self._uncertain(plan, "create_ambiguous")

        authorization = SyntheticValidationCreateAuthorization(
            operation_id=plan.operation_id,
            plan_digest=plan.plan_digest,
            validation_ref=plan.validation_ref,
            expected_commit=plan.expected_commit,
            expected_tree=plan.expected_tree,
        )
        if not self._journal.claim_create_authorization(authorization):
            after_claim = self._read(plan)
            if after_claim[0] == "exact":
                return self._save(
                    _outcome(
                        plan,
                        "reconciled",
                        observed_commit=after_claim[1],
                        observed_tree=after_claim[2],
                    )
                )
            if after_claim[0] == "wrong":
                return self._save(
                    _outcome(
                        plan,
                        "invalid",
                        observed_commit=after_claim[1],
                        observed_tree=after_claim[2],
                        error="concurrent create left a wrong SHA; quarantined",
                    )
                )
            return self._uncertain(plan, "create_ambiguous")

        try:
            self._provider.create_validation_ref(
                plan.request.target_repository_digest, plan.validation_ref, plan.expected_commit
            )
        except Exception:  # provider transport outcome is intentionally ambiguous
            after = self._read(plan)
            if after[0] == "exact":
                return self._save(
                    _outcome(
                        plan,
                        "reconciled",
                        observed_commit=after[1],
                        observed_tree=after[2],
                    )
                )
            if after[0] == "wrong":
                return self._save(
                    _outcome(
                        plan,
                        "invalid",
                        observed_commit=after[1],
                        observed_tree=after[2],
                        error="ambiguous create left a wrong SHA; quarantined",
                    )
                )
            return self._uncertain(plan, "create_ambiguous")

        after = self._read(plan)
        if after[0] == "exact":
            return self._save(
                _outcome(plan, "created", observed_commit=after[1], observed_tree=after[2])
            )
        if after[0] == "wrong":
            return self._save(
                _outcome(
                    plan,
                    "invalid",
                    observed_commit=after[1],
                    observed_tree=after[2],
                    error="create returned success but ref has a wrong SHA; quarantined",
                )
            )
        return self._uncertain(plan, "create_ambiguous")

    run = trigger
    ensure = trigger

    def cleanup(
        self,
        plan_or_operation: SyntheticValidationPlan | str,
        proof: SyntheticValidationCompletionProof,
    ) -> SyntheticValidationOutcome:
        """Delete only with durable, operation- and plan-bound completion proof."""
        if isinstance(plan_or_operation, str):
            loaded: SyntheticValidationPlan | None = _unwrap(
                self._journal.read_plan(plan_or_operation)
            )
            if loaded is None:
                raise SyntheticValidationConflictError("cannot clean up an unknown operation")
            plan = loaded
        else:
            plan = plan_or_operation
            loaded = _unwrap(self._journal.read_plan(plan.operation_id))
            if loaded is None:
                raise SyntheticValidationCleanupRefusedError(
                    "cleanup requires a durably recorded plan"
                )
            if loaded != plan:
                raise SyntheticValidationConflictError("cleanup plan differs from durable plan")
            plan = loaded
        if (
            proof.operation_id != plan.operation_id
            or proof.plan_digest != plan.plan_digest
            or proof.completed is not True
        ):
            raise SyntheticValidationCleanupRefusedError(
                "cleanup requires completion proof bound to the exact plan"
            )
        verifier = self._completion_proof_verifier
        if verifier is None:
            raise SyntheticValidationCleanupRefusedError(
                "cleanup requires durable completion proof verification"
            )
        try:
            verifier.verify(plan, proof)
        except Exception as exc:
            raise SyntheticValidationCleanupRefusedError(
                "completion proof is not bound to durable campaign evidence"
            ) from exc
        durable = _unwrap(self._journal.read_cleanup(plan.operation_id))
        if durable is not None and durable.outcome != "reconciliation_required":
            _check_outcome_binding(durable, plan)
            return durable
        state = self._read(plan)
        if state[0] == "none":
            result = _outcome(plan, "cleaned", error=None)
            return self._save_cleanup(result)
        if state[0] == "error":
            return self._save_cleanup(
                _outcome(plan, "reconciliation_required", error="ref read failed")
            )
        if state[0] == "wrong":
            return self._save_cleanup(
                _outcome(
                    plan,
                    "invalid",
                    observed_commit=state[1],
                    observed_tree=state[2],
                    error="ref does not contain the planned SHA; refusing delete",
                )
            )
        try:
            self._provider.delete_validation_ref(
                plan.request.target_repository_digest, plan.validation_ref
            )
        except Exception:
            after = self._read(plan)
            if after[0] == "none":
                return self._save_cleanup(_outcome(plan, "cleaned"))
            if after[0] == "exact":
                return self._save_cleanup(
                    _outcome(plan, "reconciliation_required", error="delete response ambiguous")
                )
            return self._save_cleanup(
                _outcome(plan, "reconciliation_required", error="delete response ambiguous")
            )
        after = self._read(plan)
        if after[0] == "none":
            return self._save_cleanup(_outcome(plan, "cleaned"))
        if after[0] == "exact":
            return self._save_cleanup(
                _outcome(plan, "reconciliation_required", error="delete succeeded but ref remains")
            )
        if after[0] == "wrong":
            return self._save_cleanup(
                _outcome(plan, "invalid", error="delete changed ref to a wrong SHA")
            )
        return self._save_cleanup(
            _outcome(plan, "reconciliation_required", error="deleted ref could not be reconciled")
        )

    def _read(self, plan: SyntheticValidationPlan) -> tuple[str, str | None, str | None]:
        try:
            raw = self._provider.read_validation_ref(
                plan.request.target_repository_digest, plan.validation_ref
            )
        except Exception as exc:
            return "error", f"ref reconciliation failed: {exc}", None
        if raw is None:
            return "none", None, None
        try:
            commit, tree = _ref_values(raw)
        except (TypeError, ValueError) as exc:
            return "error", f"provider returned malformed ref: {exc}", None
        if commit == plan.expected_commit:
            if tree is not None and tree != plan.expected_tree:
                return "wrong", commit, tree
            return "exact", commit, tree
        return "wrong", commit, tree

    def _save(self, outcome: SyntheticValidationOutcome) -> SyntheticValidationOutcome:
        try:
            self._journal.record_outcome(outcome)
        except Exception as exc:
            # Concurrent callers may derive different successful labels
            # (created/reconciled) for the same exact ref.  The immutable
            # outcome index chooses one; return that winner instead of
            # turning a harmless loser race into a failed trigger.
            durable = _unwrap(self._journal.read_outcome(outcome.operation_id))
            if durable is None:
                raise
            if (
                durable.operation_id != outcome.operation_id
                or durable.plan_digest != outcome.plan_digest
                or durable.validation_ref != outcome.validation_ref
                or durable.expected_commit != outcome.expected_commit
                or durable.expected_tree != outcome.expected_tree
            ):
                raise SyntheticValidationConflictError(
                    "concurrent durable outcome is not bound to the operation"
                ) from exc
            return durable
        return outcome

    def _uncertain(
        self, plan: SyntheticValidationPlan, kind: Literal["create_ambiguous", "read_error"]
    ) -> SyntheticValidationOutcome:
        self._journal.record_attempt(
            SyntheticValidationAttempt(
                operation_id=plan.operation_id,
                plan_digest=plan.plan_digest,
                validation_ref=plan.validation_ref,
                expected_commit=plan.expected_commit,
                expected_tree=plan.expected_tree,
                kind=kind,
            )
        )
        message = (
            "create response requires reconciliation"
            if kind == "create_ambiguous"
            else "ref read requires reconciliation"
        )
        return _outcome(plan, "reconciliation_required", error=message)

    def _save_cleanup(self, outcome: SyntheticValidationOutcome) -> SyntheticValidationOutcome:
        # An uncertain delete is deliberately not finalized in the create-once
        # cleanup index: a later caller must be able to reconcile again and
        # durably record ``cleaned`` once absence is proven.
        if outcome.outcome == "reconciliation_required":
            return outcome
        self._journal.record_cleanup(outcome)
        return outcome


class SyntheticValidationConflictError(ValueError):
    """A replay attempts to use a different immutable operation plan."""


class SyntheticValidationCleanupRefusedError(ValueError):
    """Cleanup was requested without exact durable campaign completion proof."""


def _request(
    value: object,
    *,
    target_repository_digest: str | None,
    target_ref: str | None,
    target_identity: str | None,
    trusted_check_contexts: Sequence[str],
    provider_identity: str,
    provider_api_version: str,
) -> SyntheticValidationRequest:
    if isinstance(value, SyntheticValidationRequest):
        return value
    if not isinstance(value, SyntheticValidationObservation):
        raise TypeError("expected synthetic validation request or observation")
    observation = value
    return SyntheticValidationRequest(
        observation=observation,
        target_repository_digest=target_repository_digest or observation.repository_digest,
        target_ref=target_ref or observation.base_ref,
        target_identity=target_identity or "integration-campaign",
        trusted_check_contexts=list(trusted_check_contexts),
        provider_identity=provider_identity,
        provider_api_version=provider_api_version,
    )


def _unwrap[T](value: T | tuple[T, ArtifactRef] | None) -> T | None:
    if value is None:
        return None
    if isinstance(value, tuple):
        return cast(T, value[0])
    return cast(T, value)


def _ref_values(value: object) -> tuple[str, str | None]:
    if isinstance(value, str):
        raise ValueError("provider ref observation must include commit and tree")
    if not isinstance(value, Mapping):
        raise ValueError("provider ref observation must be a mapping")
    mapped = cast(Mapping[str, object], value)
    commit = mapped.get("commit", mapped.get("sha", mapped.get("oid")))
    tree = mapped.get("tree")
    if not isinstance(commit, str) or not isinstance(tree, str):
        raise ValueError("provider ref observation must include commit and tree")
    return commit, tree


def _outcome(
    plan: SyntheticValidationPlan,
    outcome: OutcomeKind,
    *,
    observed_commit: str | None = None,
    observed_tree: str | None = None,
    error: str | None = None,
) -> SyntheticValidationOutcome:
    return SyntheticValidationOutcome(
        operation_id=plan.operation_id,
        plan_digest=plan.plan_digest,
        validation_ref=plan.validation_ref,
        expected_commit=plan.expected_commit,
        expected_tree=plan.expected_tree,
        outcome=outcome,  # type: ignore[arg-type]
        observed_commit=observed_commit,
        observed_tree=observed_tree,
        error=error,
    )


def _check_outcome_binding(
    outcome: SyntheticValidationOutcome, plan: SyntheticValidationPlan
) -> None:
    if (
        outcome.plan_digest != plan.plan_digest
        or outcome.validation_ref != plan.validation_ref
        or outcome.expected_commit != plan.expected_commit
        or outcome.expected_tree != plan.expected_tree
    ):
        raise SyntheticValidationConflictError("durable outcome is not bound to the plan")


def _check_authorization_binding(
    authorization: SyntheticValidationCreateAuthorization,
    plan: SyntheticValidationPlan,
) -> None:
    if (
        authorization.plan_digest != plan.plan_digest
        or authorization.validation_ref != plan.validation_ref
        or authorization.expected_commit != plan.expected_commit
        or authorization.expected_tree != plan.expected_tree
    ):
        raise SyntheticValidationConflictError(
            "durable create authorization is not bound to the plan"
        )


__all__ = [
    "SyntheticValidationCleanupRefusedError",
    "SyntheticValidationCompletionProofVerifier",
    "SyntheticValidationConflictError",
    "SyntheticValidationProvider",
    "SyntheticValidationService",
]
