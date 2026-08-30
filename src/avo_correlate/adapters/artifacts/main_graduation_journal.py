"""Create-once content-addressed journal for protected-main graduation."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import tempfile
from contextlib import suppress
from pathlib import Path
from typing import Any, Literal, Protocol, cast

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.contracts.base import ArtifactRef, StrictModel
from avo_correlate.contracts.integration_campaign import (
    IntegrationCampaignEvidencePackage,
    verify_campaign_package_artifact,
)
from avo_correlate.contracts.main_graduation import (
    EligibilityLedgerStarted,
    MainAttestationManifest,
    MainBound,
    MainCompletionPackage,
    MainCompositionArtifact,
    MainCompositionProof,
    MainDeltaManifest,
    MainGraduationAttempt,
    MainGraduationEligibilityRecord,
    MainGraduationIntent,
    MainGraduationPlan,
    MainInverseDeltaArtifact,
    MainLeaseEvidence,
    MainMergeGroupChecks,
    MainMergeGroupWebhookReceipt,
    MainPreparationAuthorization,
    MainProtectionManifest,
    MainProviderReceipt,
    MainQueueAdmissionObservation,
    MainQueueObservation,
    MainReconciliation,
    MainRef,
    MainReleaseAuthorization,
    MainReleaseHoldObservation,
    MainReleaseIssuerBinding,
    MainReleaseTransitionReceipt,
    MainRollbackAuthorization,
    MainRollbackIntent,
    MainSourcePackageBinding,
)
from avo_correlate.contracts.main_graduation_phase_a import (
    MainClaimedReleaseTransitionReceipt,
    MainLeaseEvidenceReadRequest,
    MainLeaseEvidenceRecord,
    MainMutationFenceResolution,
    MainMutationIntent,
    MainMutationReceipt,
    MainReleaseClaim,
    MainUnresolvedMutationFence,
    main_target_scope_digest,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest


class MainGraduationJournalError(RuntimeError):
    """An indexed record is missing, malformed, tampered, or conflicting."""


class MainGraduationRecordConflictError(MainGraduationJournalError):
    """A create-once key was already bound to different canonical bytes."""


class _MainBaseReader(Protocol):
    """Trusted controller capability used by the concrete composition authority."""

    def fresh_main_base(self) -> object: ...


class _ReferenceEnvelope(Protocol):
    reference: ArtifactRef


_COMPOSITION_VERIFIER_ID = "avo_correlate.adapters.git.main_composition.MainCompositionAdapter"
_COMPOSITION_VERIFIER_VERSION = "1"
_BASE_OBSERVER_ID = "avo_correlate.adapters.git.main_composition.MainBaseReader"


class _RunNonceEnvelope(StrictModel):
    """Canonical global one-use identity bound to the original local record ref."""

    schema_version: Literal[1] = 1
    stage: Literal["admission", "hold"]
    operation_id: str
    run_id: str
    nonce: str
    reference: ArtifactRef


class _WebhookDeliveryEnvelope(StrictModel):
    """Durable create-once binding for one native webhook delivery ID."""

    schema_version: Literal[1] = 1
    operation_id: str
    delivery_id: str
    reference: ArtifactRef


class _PhaseReferenceEnvelope(StrictModel):
    """Canonical local/global CAS binding for a Phase-A artifact."""

    schema_version: Literal[1] = 1
    key: str
    operation_id: str
    reference: ArtifactRef


class _TargetLeaseEnvelope(StrictModel):
    schema_version: Literal[1] = 1
    target_scope_digest: str
    operation_id: str
    lease_digest: str
    reference: ArtifactRef


class _TargetFenceEnvelope(StrictModel):
    schema_version: Literal[1] = 1
    target_scope_digest: str
    operation_id: str
    fence_digest: str
    reference: ArtifactRef


_MODELS: dict[str, type[StrictModel]] = {
    "ledger-started": EligibilityLedgerStarted,
    "plan": MainGraduationPlan,
    "source-package": MainSourcePackageBinding,
    "delta": MainDeltaManifest,
    "composition": MainCompositionArtifact,
    "composition-proof": MainCompositionProof,
    "queue": MainQueueObservation,
    "protection": MainProtectionManifest,
    "attestations": MainAttestationManifest,
    "merge-group-checks": MainMergeGroupChecks,
    "merge-group-webhook-receipt": MainMergeGroupWebhookReceipt,
    "release-issuer-binding": MainReleaseIssuerBinding,
    "intent": MainGraduationIntent,
    "preparation-authorization": MainPreparationAuthorization,
    "queue-admission": MainQueueAdmissionObservation,
    "release-hold": MainReleaseHoldObservation,
    "release-authorization": MainReleaseAuthorization,
    "release-transition": MainReleaseTransitionReceipt,
    "provider-receipt": MainProviderReceipt,
    "reconciliation": MainReconciliation,
    "inverse-delta": MainInverseDeltaArtifact,
    "rollback-authorization": MainRollbackAuthorization,
    "rollback-intent": MainRollbackIntent,
    "attempt": MainGraduationAttempt,
    "eligibility": MainGraduationEligibilityRecord,
    "completion": MainCompletionPackage,
    "lease-evidence-record": MainLeaseEvidenceRecord,
    "mutation-intent": MainMutationIntent,
    "mutation-receipt": MainMutationReceipt,
    "release-claim": MainReleaseClaim,
    "unresolved-mutation-fence": MainUnresolvedMutationFence,
    "mutation-fence-resolution": MainMutationFenceResolution,
    "claimed-release-transition": MainClaimedReleaseTransitionReceipt,
}

_PHASE_A_KINDS = frozenset(
    {
        "lease-evidence-record",
        "mutation-intent",
        "mutation-receipt",
        "release-claim",
        "unresolved-mutation-fence",
        "mutation-fence-resolution",
        "claimed-release-transition",
    }
)


def _digest_bytes(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _operation_id(record: Any) -> str:
    value = getattr(record, "operation_id", None)
    if value is None:
        value = getattr(record, "activation_digest", None)
    if value is None:
        value = getattr(record, "submission_digest", None)
    if value is None:
        raise ValueError("main graduation record lacks a SHA-256 operation identity")
    if len(value) != 71 or not _is_digest(value):
        raise ValueError("main graduation record lacks a SHA-256 operation identity")
    return value


def _is_digest(value: str) -> bool:
    return value.startswith("sha256:") and all(char in "0123456789abcdef" for char in value[7:])


def _check_digest(value: str) -> None:
    if len(value) != 71 or not _is_digest(value):
        raise ValueError("journal key must be a SHA-256 digest")


def _same_artifact_ref(left: ArtifactRef, right: ArtifactRef) -> bool:
    """Compare immutable content identity; creation time is observational metadata."""
    return (
        left.digest,
        left.size_bytes,
        left.media_type,
        left.role,
    ) == (
        right.digest,
        right.size_bytes,
        right.media_type,
        right.role,
    )


class MainGraduationJournal:
    """Persist one canonical record per operation/ledger key using ``xb`` indexes."""

    def __init__(
        self,
        root: Path,
        *,
        artifact_store: FilesystemArtifactStore | None = None,
        release_issuer_binding: MainReleaseIssuerBinding | None = None,
        policy_epoch: str | None = None,
        composition_root: Path | None = None,
        repository_digest: str | None = None,
        base_reader: _MainBaseReader | None = None,
        max_record_bytes: int = 32 * 1024 * 1024,
    ) -> None:
        if max_record_bytes <= 0:
            raise ValueError("max_record_bytes must be positive")
        self._root = root.resolve()
        self._indexes = self._root / "main-graduation-index"
        self._store = artifact_store or FilesystemArtifactStore(self._root / "artifacts")
        self._release_issuer_binding = release_issuer_binding
        self._policy_epoch = policy_epoch or (
            canonical_digest(
                {
                    "controller_config_digest": release_issuer_binding.controller_config_digest,
                    "main_policy": "ordinary",
                }
            )
            if release_issuer_binding is not None
            else None
        )
        self._max = max_record_bytes
        capabilities = (composition_root, repository_digest, base_reader)
        if any(value is not None for value in capabilities) and not all(
            value is not None for value in capabilities
        ):
            raise ValueError(
                "composition authority requires Git root, repository digest, and base reader"
            )
        self._composition_root = (
            composition_root.resolve() if composition_root is not None else None
        )
        self._composition_repository_digest = repository_digest
        self._composition_base_reader = base_reader
        if self._policy_epoch is not None:
            _check_digest(self._policy_epoch)

    @property
    def root(self) -> Path:
        return self._root

    def delete_artifact(self, digest: str) -> bool:
        """Recovery/test seam; indexed reads still fail closed after deletion."""
        return self._store.delete(digest)

    def _record(self, kind: str, record: StrictModel) -> ArtifactRef:
        model = _MODELS.get(kind)
        if model is None:
            raise ValueError(f"unknown main graduation record kind: {kind}")
        if kind in _PHASE_A_KINDS:
            return self._record_phase_a(kind, record)
        try:
            data = canonical_bytes(record)
            # Reparse to ensure nested model_construct() values cannot bypass
            # semantic validators at the journal boundary.
            checked = model.model_validate_json(data)
            data = canonical_bytes(checked)
            operation_id = _operation_id(checked)
            if kind == "release-issuer-binding":
                self._require_controller_issuer_binding(cast(MainReleaseIssuerBinding, checked))
            if kind == "eligibility":
                self._check_eligibility_predecessor(cast(MainGraduationEligibilityRecord, checked))
            if kind == "attempt":
                self._require_attempt_eligibility(cast(MainGraduationAttempt, checked))
            if kind == "source-package":
                self._verify_source_package(cast(MainSourcePackageBinding, checked))
            elif kind == "composition-proof":
                self._verify_composition_proof(cast(MainCompositionProof, checked))
            elif kind == "plan":
                index = self._indexes / kind / f"{operation_id.removeprefix('sha256:')}.json"
                self._verify_plan_evidence(cast(MainGraduationPlan, checked))
                if not index.is_file():
                    self._verify_plan_composition(cast(MainGraduationPlan, checked))
            elif kind == "intent":
                self._verify_intent_lease(cast(MainGraduationIntent, checked))
            elif kind == "preparation-authorization":
                self._require_preparation_chain(cast(MainPreparationAuthorization, checked))
            elif kind == "queue-admission":
                self._require_queue_admission(cast(MainQueueAdmissionObservation, checked))
            elif kind == "release-hold":
                self._require_merge_group_receipt(cast(MainReleaseHoldObservation, checked))
                self._require_admission(cast(MainReleaseHoldObservation, checked))
            elif kind == "release-authorization":
                self._require_hold(cast(MainReleaseAuthorization, checked))
            elif kind == "release-transition":
                self._require_release_authorization(cast(MainReleaseTransitionReceipt, checked))
            elif kind == "provider-receipt":
                self._require_provider_receipt(cast(MainProviderReceipt, checked))
            elif kind == "reconciliation":
                self._require_reconciliation(cast(MainReconciliation, checked))
            elif kind == "rollback-authorization":
                self._require_rollback_intent(cast(MainRollbackAuthorization, checked))
            elif kind == "rollback-intent":
                self._require_inverse_delta(cast(MainRollbackIntent, checked))
            if kind == "completion":
                self._materialize_children(cast(MainCompletionPackage, checked))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise MainGraduationJournalError(f"invalid main graduation {kind}") from exc
        reference = self._store.put_bytes(
            data,
            media_type=f"application/vnd.avo.main-graduation-{kind}+json",
            role=f"main-graduation-{kind}",
            max_bytes=self._max,
        )
        _sync_directory(self._store.path_for_digest(reference.digest).parent)
        # Claim the global one-use identity before the operation-local index.
        # Otherwise a rejected cross-operation reuse would leave an apparently
        # valid local admission/hold record behind.
        if kind == "queue-admission":
            prior_global = self._index_run_nonce(
                "admission", cast(MainQueueAdmissionObservation, checked), reference
            )
            if prior_global is not None:
                reference = prior_global
        elif kind == "release-hold":
            prior_global = self._index_run_nonce(
                "hold", cast(MainReleaseHoldObservation, checked), reference
            )
            if prior_global is not None:
                reference = prior_global
        elif kind == "merge-group-webhook-receipt":
            prior_delivery = self._index_webhook_delivery(
                cast(MainMergeGroupWebhookReceipt, checked), reference
            )
            if prior_delivery is not None:
                reference = prior_delivery
        index = self._indexes / kind / f"{operation_id.removeprefix('sha256:')}.json"
        index.parent.mkdir(parents=True, exist_ok=True)
        payload = canonical_bytes(reference)
        try:
            _write_exclusive_durable(index, payload)
        except FileExistsError:
            try:
                old = self._read_reference(index)
                old_data = self._store.read_bytes(old)
            except (OSError, ValueError, RuntimeError, TypeError, json.JSONDecodeError) as exc:
                raise MainGraduationJournalError("main graduation index is malformed") from exc
            if old.digest != reference.digest or old_data != data:
                raise MainGraduationRecordConflictError(
                    f"conflicting main graduation {kind} for {operation_id}"
                ) from None
            return old
        except OSError as exc:
            raise MainGraduationJournalError("main graduation record was not indexed") from exc
        if kind == "eligibility":
            self._index_eligibility_sequence(
                cast(MainGraduationEligibilityRecord, checked), reference
            )
        return reference

    def _read_reference(self, index: Path) -> ArtifactRef:
        try:
            if index.stat().st_size > self._max:
                raise ValueError("main graduation index is too large")
            data = index.read_text(encoding="utf-8").encode("utf-8")
            parsed = json.loads(data, object_pairs_hook=_strict_pairs)
            if canonical_bytes(parsed) != data:
                raise ValueError("main graduation index is not canonical JSON")
            return ArtifactRef.model_validate(parsed)
        except (
            OSError,
            ValueError,
            TypeError,
            AttributeError,
            UnicodeError,
            json.JSONDecodeError,
        ) as exc:
            raise MainGraduationJournalError("main graduation index is malformed") from exc

    def _read(self, kind: str, key: str) -> tuple[StrictModel, ArtifactRef] | None:
        if kind not in _MODELS:
            raise ValueError("unknown main graduation record kind")
        _check_digest(key)
        if kind in _PHASE_A_KINDS:
            return self._read_phase_a(kind, key)
        index = self._indexes / kind / f"{key.removeprefix('sha256:')}.json"
        if not index.is_file():
            return None
        try:
            reference = self._read_reference(index)
            if (
                reference.role != f"main-graduation-{kind}"
                or reference.media_type != f"application/vnd.avo.main-graduation-{kind}+json"
                or reference.size_bytes > self._max
            ):
                raise ValueError("main graduation artifact metadata mismatch")
            data = self._store.read_bytes(reference)
            parsed = json.loads(data.decode("utf-8"), object_pairs_hook=_strict_pairs)
            if canonical_bytes(parsed) != data:
                raise ValueError("main graduation record is not canonical JSON")
            record = _MODELS[kind].model_validate(parsed)
            if kind == "source-package":
                self._verify_source_package(cast(MainSourcePackageBinding, record))
            elif kind == "plan":
                self._verify_plan_evidence(cast(MainGraduationPlan, record))
            elif kind == "composition-proof":
                self._verify_composition_proof(cast(MainCompositionProof, record))
            elif kind == "intent":
                self._verify_intent_lease(cast(MainGraduationIntent, record))
            elif kind == "preparation-authorization":
                self._require_preparation_chain(cast(MainPreparationAuthorization, record))
            elif kind == "queue-admission":
                self._require_queue_admission(cast(MainQueueAdmissionObservation, record))
            elif kind == "release-hold":
                self._require_merge_group_receipt(cast(MainReleaseHoldObservation, record))
                self._require_admission(cast(MainReleaseHoldObservation, record))
            elif kind == "merge-group-webhook-receipt":
                self._verify_webhook_delivery(cast(MainMergeGroupWebhookReceipt, record), reference)
            elif kind == "release-authorization":
                self._require_hold(cast(MainReleaseAuthorization, record))
            elif kind == "release-transition":
                self._require_release_authorization(cast(MainReleaseTransitionReceipt, record))
            elif kind == "provider-receipt":
                self._require_provider_receipt(cast(MainProviderReceipt, record))
            elif kind == "reconciliation":
                self._require_reconciliation(cast(MainReconciliation, record))
            elif kind == "rollback-authorization":
                self._require_rollback_intent(cast(MainRollbackAuthorization, record))
            elif kind == "rollback-intent":
                self._require_inverse_delta(cast(MainRollbackIntent, record))
            if kind == "completion":
                self._verify_children(cast(MainCompletionPackage, record))
            if _operation_id(record) != key:
                raise MainGraduationRecordConflictError(
                    "main graduation identity does not match index"
                )
            return record, reference
        except MainGraduationRecordConflictError:
            raise
        except (
            OSError,
            RuntimeError,
            ValueError,
            TypeError,
            UnicodeError,
            json.JSONDecodeError,
        ) as exc:
            raise MainGraduationJournalError(
                f"malformed or unverifiable main graduation {kind}"
            ) from exc

    @staticmethod
    def _child_values(package: MainCompletionPackage) -> dict[str, StrictModel]:
        values: dict[str, StrictModel] = {
            "main-graduation-source-package": package.source_package,
            "main-graduation-delta": package.delta,
            "main-graduation-composition": package.composition,
            "main-graduation-queue-observation": package.queue_observation,
            "main-graduation-protection-manifest": package.protection_manifest,
            "main-graduation-attestation-manifest": package.attestation_manifest,
            "main-graduation-merge-group-checks": package.merge_group_checks,
            "main-graduation-merge-group-webhook-receipt": (
                package.hold_observation.merge_group_receipt
            ),
            "main-graduation-release-issuer-binding": package.release_issuer_binding,
            "main-graduation-plan": package.plan,
            "main-graduation-intent": package.intent,
            "main-graduation-preparation-authorization": package.preparation_authorization,
            "main-graduation-queue-admission": package.admission_observation,
            "main-graduation-release-hold": package.hold_observation,
            "main-graduation-release-authorization": package.release_authorization,
            "main-graduation-release-transition": package.transition_receipt,
            "main-graduation-provider-receipt": package.provider_receipt,
            "main-graduation-reconciliation": package.reconciliation,
        }
        # ``model_construct`` is used by a few C1-C3 coverage probes.  Keep
        # those probes able to exercise the historical child closure, while a
        # normally validated C4 package always has the complete authority
        # fields and takes this strict branch.
        if not hasattr(package, "lease_evidence_record"):
            return values
        values.update(
            {
                "main-graduation-lease-evidence-record": package.lease_evidence_record,
                "main-graduation-release-claim": package.release_claim,
                "main-graduation-claimed-release-transition": package.claimed_transition_receipt,
                "main-graduation-mutation-intent": package.release_transition_intent,
                "main-graduation-mutation-receipt": package.release_transition_mutation_receipt,
            }
        )
        if package.release_transition_fence_resolution is not None:
            values[
                "main-graduation-mutation-fence-resolution"
            ] = package.release_transition_fence_resolution
        return values

    def _materialize_children(self, package: MainCompletionPackage) -> None:
        self._verify_completion_prerequisites(package)
        references = {item.role: item for item in package.artifacts}
        values = self._child_values(package)
        if set(references) != set(values):
            raise MainGraduationJournalError("completion child artifacts are incomplete")
        for role, value in values.items():
            expected = references[role]
            payload = canonical_bytes(value)
            if (
                expected.role != role
                or expected.media_type != f"application/vnd.avo.{role}+json"
                or expected.digest != _digest_bytes(payload)
                or expected.size_bytes != len(payload)
            ):
                raise MainGraduationJournalError(
                    f"completion child artifact is not content-bound: {role}"
                )
            stored = self._store.put_bytes(
                payload,
                media_type=expected.media_type,
                role=expected.role,
                max_bytes=self._max,
            )
            try:
                read_back = self._store.read_bytes(expected)
            except (OSError, RuntimeError, ValueError) as exc:
                raise MainGraduationJournalError(
                    f"completion child artifact is unreadable: {role}"
                ) from exc
            if (
                stored.digest != expected.digest
                or stored.role != role
                or stored.media_type != expected.media_type
                or read_back != payload
            ):
                raise MainGraduationJournalError(
                    f"completion child artifact metadata mismatch: {role}"
                )

    def _verify_children(self, package: MainCompletionPackage) -> None:
        self._verify_completion_prerequisites(package)
        references = {item.role: item for item in package.artifacts}
        values = self._child_values(package)
        if set(references) != set(values):
            raise MainGraduationJournalError("completion child artifacts are incomplete")
        for role, value in values.items():
            expected = references[role]
            if expected.role != role or expected.media_type != f"application/vnd.avo.{role}+json":
                raise MainGraduationJournalError(
                    f"completion child artifact metadata mismatch: {role}"
                )
            try:
                data = self._store.read_bytes(expected)
            except (OSError, RuntimeError, ValueError) as exc:
                raise MainGraduationJournalError(
                    f"completion child artifact is unreadable: {role}"
                ) from exc
            if data != canonical_bytes(value) or expected.digest != _digest_bytes(data):
                raise MainGraduationJournalError(
                    f"completion child artifact contents mismatch: {role}"
                )

    # ------------------------------------------------------------------
    # Phase-A journal records
    # ------------------------------------------------------------------

    @staticmethod
    def _phase_key(kind: str, record: StrictModel) -> str:
        if kind == "lease-evidence-record":
            return _operation_id(record)
        field = {
            "mutation-intent": "intent_digest",
            "mutation-receipt": "receipt_digest",
            "release-claim": "claim_digest",
            "unresolved-mutation-fence": "fence_digest",
            "mutation-fence-resolution": "resolution_digest",
            "claimed-release-transition": "receipt_digest",
        }[kind]
        value = getattr(record, field)
        _check_digest(value)
        return value

    @staticmethod
    def _phase_role(kind: str) -> str:
        return f"main-graduation-{kind}"

    def _phase_local_path(self, kind: str, key: str) -> Path:
        _check_digest(key)
        return self._indexes / kind / f"{key.removeprefix('sha256:')}.json"

    def _phase_reference_envelope(
        self, kind: str, key: str, record: StrictModel, reference: ArtifactRef
    ) -> _PhaseReferenceEnvelope:
        return _PhaseReferenceEnvelope(
            key=key, operation_id=_operation_id(record), reference=reference
        )

    def _record_phase_a(self, kind: str, record: StrictModel) -> ArtifactRef:
        model = _MODELS[kind]
        try:
            data = canonical_bytes(record)
            checked = model.model_validate_json(data)
            data = canonical_bytes(checked)
            key = self._phase_key(kind, checked)
            self._validate_phase_chain(kind, checked)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise MainGraduationJournalError(f"invalid main graduation {kind}") from exc
        reference = self._store.put_bytes(
            data,
            media_type=f"application/vnd.avo.{self._phase_role(kind)}+json",
            role=self._phase_role(kind),
            max_bytes=self._max,
        )
        _sync_directory(self._store.path_for_digest(reference.digest).parent)
        if kind == "lease-evidence-record":
            prior = self._cas_target_lease(cast(MainLeaseEvidenceRecord, checked), reference)
            if prior is not None:
                reference = prior
        elif kind == "mutation-intent":
            intent = cast(MainMutationIntent, checked)
            self._cas_stage_identity(intent.external_identity.identity_digest, intent, reference)
            self._cas_operation_stage_identity(intent, reference)
            self._cas_external_object_identity(intent, reference)
        elif kind == "mutation-receipt":
            receipt = cast(MainMutationReceipt, checked)
            self._cas_phase_identity("mutation-receipt", receipt.intent_digest, receipt, reference)
        elif kind == "unresolved-mutation-fence":
            self._cas_target_fence(cast(MainUnresolvedMutationFence, checked), reference)
        elif kind == "release-claim":
            self._cas_release_claim(cast(MainReleaseClaim, checked), reference)
        elif kind == "mutation-fence-resolution":
            resolution = cast(MainMutationFenceResolution, checked)
            self._cas_phase_identity(
                "mutation-fence-resolution", resolution.fence_digest, resolution, reference
            )
        elif kind == "claimed-release-transition":
            transition = cast(MainClaimedReleaseTransitionReceipt, checked)
            self._cas_phase_identity(
                "claimed-release-transition", transition.claim_digest, transition, reference
            )
        result = self._cas_phase_local(kind, key, checked, reference, data)
        if kind == "mutation-fence-resolution":
            self._close_target_fence_if_resolved(cast(MainMutationFenceResolution, checked))
        return result

    def _cas_phase_local(
        self, kind: str, key: str, record: StrictModel, reference: ArtifactRef, data: bytes
    ) -> ArtifactRef:
        path = self._phase_local_path(kind, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = canonical_bytes(self._phase_reference_envelope(kind, key, record, reference))
        try:
            _write_exclusive_durable(path, payload)
            return reference
        except FileExistsError:
            current = self._read_phase_envelope(path, kind, key)
            if current.operation_id == _operation_id(record):
                old_data = self._store.read_bytes(current.reference)
                if old_data == data and _same_artifact_ref(current.reference, reference):
                    return current.reference
            try:
                old_data = self._store.read_bytes(current.reference)
            except (OSError, RuntimeError, ValueError) as exc:
                raise MainGraduationJournalError(f"{kind} canonical artifact is missing") from exc
            if old_data != data:
                raise MainGraduationRecordConflictError(f"conflicting {kind} for {key}") from None
            raise MainGraduationRecordConflictError(
                f"{kind} index points at a different canonical reference"
            ) from None
        except OSError as exc:
            raise MainGraduationJournalError(f"{kind} was not durably indexed") from exc

    def _read_phase_envelope(self, path: Path, kind: str, key: str) -> _PhaseReferenceEnvelope:
        try:
            raw = path.read_bytes()
            if len(raw) > self._max:
                raise ValueError("phase-A index is too large")
            envelope = _PhaseReferenceEnvelope.model_validate(
                json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_pairs)
            )
            if canonical_bytes(envelope) != raw or envelope.key != key:
                raise ValueError("phase-A index is noncanonical")
            expected_role = self._phase_role(kind)
            if (
                envelope.reference.role != expected_role
                or envelope.reference.media_type != f"application/vnd.avo.{expected_role}+json"
                or envelope.reference.size_bytes > self._max
            ):
                raise ValueError("phase-A index metadata mismatch")
            return envelope
        except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
            raise MainGraduationJournalError(f"{kind} index is malformed") from exc

    def _read_phase_a(self, kind: str, key: str) -> tuple[StrictModel, ArtifactRef] | None:
        path = self._phase_local_path(kind, key)
        if not path.is_file():
            return None
        envelope = self._read_phase_envelope(path, kind, key)
        try:
            data = self._store.read_bytes(envelope.reference)
            if (
                len(data) != envelope.reference.size_bytes
                or _digest_bytes(data) != envelope.reference.digest
            ):
                raise ValueError("phase-A artifact hash mismatch")
            record: StrictModel = _MODELS[kind].model_validate_json(data)
            if _operation_id(record) != envelope.operation_id:
                raise MainGraduationRecordConflictError("phase-A operation identity differs")
            if self._phase_key(kind, record) != key:
                raise MainGraduationRecordConflictError("phase-A key differs from record")
            self._validate_phase_chain(kind, record)
            if kind == "unresolved-mutation-fence":
                self._assert_target_fence(cast(MainUnresolvedMutationFence, record))
            elif kind == "release-claim":
                self._assert_release_claim(cast(MainReleaseClaim, record))
            if kind == "mutation-receipt":
                receipt = cast(MainMutationReceipt, record)
                self._assert_phase_identity(kind, receipt.intent_digest, receipt)
            elif kind == "mutation-fence-resolution":
                resolution = cast(MainMutationFenceResolution, record)
                self._assert_phase_identity(kind, resolution.fence_digest, resolution)
            elif kind == "claimed-release-transition":
                transition = cast(MainClaimedReleaseTransitionReceipt, record)
                self._assert_phase_identity(kind, transition.claim_digest, transition)
            return record, envelope.reference
        except MainGraduationRecordConflictError:
            raise
        except (
            OSError,
            RuntimeError,
            ValueError,
            TypeError,
            UnicodeError,
            json.JSONDecodeError,
        ) as exc:
            raise MainGraduationJournalError(
                f"malformed or unverifiable main graduation {kind}"
            ) from exc

    def _target_lease_path(self, record: MainBound) -> Path:
        key = main_target_scope_digest(record.repository_digest, record.target_ref)
        return self._indexes / "target-lease" / f"{key.removeprefix('sha256:')}.json"

    def _target_fence_path(self, record: MainBound) -> Path:
        key = main_target_scope_digest(record.repository_digest, record.target_ref)
        return self._indexes / "target-unresolved-fence-active" / key.removeprefix("sha256:")

    @staticmethod
    def _target_fence_record_path(active: Path) -> Path:
        return active / "record.json"

    def _target_fence_closed_path(self, record: MainUnresolvedMutationFence) -> Path:
        scope = main_target_scope_digest(record.repository_digest, record.target_ref)
        return (
            self._indexes
            / "target-unresolved-fence-closed"
            / (f"{scope.removeprefix('sha256:')}-{record.fence_digest.removeprefix('sha256:')}")
        )

    def _cas_target_lease(
        self, record: MainLeaseEvidenceRecord, reference: ArtifactRef
    ) -> ArtifactRef | None:
        envelope = _TargetLeaseEnvelope(
            target_scope_digest=main_target_scope_digest(
                record.repository_digest, record.target_ref
            ),
            operation_id=record.operation_id,
            lease_digest=record.lease_digest,
            reference=reference,
        )
        return self._cas_global_envelope(
            self._target_lease_path(record), envelope, record, "target lease"
        )

    def _cas_target_fence(
        self, record: MainUnresolvedMutationFence, reference: ArtifactRef
    ) -> None:
        path = self._target_fence_path(record)
        if path.exists():
            current = self._read_target_fence_envelope(path, record)
            if current.fence_digest == record.fence_digest:
                return
            if self._read("mutation-fence-resolution", current.fence_digest) is None:
                raise MainGraduationRecordConflictError("target has an unresolved mutation fence")
            old = MainUnresolvedMutationFence.model_validate_json(
                self._store.read_bytes(current.reference)
            )
            closed = self._target_fence_closed_path(old)
            closed.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.replace(path, closed)
                _sync_directory(closed.parent)
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise MainGraduationJournalError(
                    "resolved target fence could not be closed"
                ) from exc
        envelope = _TargetFenceEnvelope(
            target_scope_digest=main_target_scope_digest(
                record.repository_digest, record.target_ref
            ),
            operation_id=record.operation_id,
            fence_digest=record.fence_digest,
            reference=reference,
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            path.mkdir()
        except FileExistsError:
            raise MainGraduationRecordConflictError("target mutation fence claim raced") from None
        try:
            record_path = self._target_fence_record_path(path)
            with record_path.open("x", encoding="utf-8", newline="") as handle:
                handle.write(canonical_bytes(envelope).decode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
            _sync_directory(path)
            _sync_directory(path.parent)
        except OSError as exc:
            raise MainGraduationJournalError(
                "target mutation fence was not durably indexed"
            ) from exc

    def _cas_release_claim(self, record: MainReleaseClaim, reference: ArtifactRef) -> None:
        path = (
            self._indexes / "release-claim-key" / f"{record.claim_key.removeprefix('sha256:')}.json"
        )
        envelope = self._phase_reference_envelope(
            "release-claim", record.claim_key, record, reference
        )
        self._cas_global_envelope(path, envelope, record, "release claim")

    def _cas_global_envelope(
        self, path: Path, envelope: StrictModel, record: StrictModel, description: str
    ) -> ArtifactRef | None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = canonical_bytes(envelope)
        try:
            _write_exclusive_durable(path, payload)
            return None
        except FileExistsError:
            try:
                raw = path.read_bytes()
                current = type(envelope).model_validate(
                    json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_pairs)
                )
                if canonical_bytes(current) != raw:
                    raise ValueError("global index is noncanonical")
                if current.model_dump(exclude={"reference"}, mode="json") != envelope.model_dump(
                    exclude={"reference"}, mode="json"
                ):
                    raise MainGraduationRecordConflictError(f"conflicting {description}") from None
                current_reference = cast(_ReferenceEnvelope, current).reference
                expected_reference = cast(_ReferenceEnvelope, envelope).reference
                old_data = self._store.read_bytes(current_reference)
                if old_data != canonical_bytes(record) or not _same_artifact_ref(
                    current_reference,
                    expected_reference,
                ):
                    raise MainGraduationRecordConflictError(f"conflicting {description}") from None
                return current_reference
            except MainGraduationRecordConflictError:
                raise
            except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
                raise MainGraduationJournalError(f"{description} index is malformed") from exc
        except OSError as exc:
            raise MainGraduationJournalError(f"{description} was not durably indexed") from exc

    def _replace_global_envelope(
        self, path: Path, envelope: StrictModel, record: StrictModel, description: str
    ) -> None:
        """Replace a resolved target pointer atomically, never exposing a gap."""
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        payload = canonical_bytes(envelope)
        try:
            with temporary.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            _sync_directory(path.parent)
        except FileExistsError:
            raise MainGraduationRecordConflictError(f"{description} replacement raced") from None
        except OSError as exc:
            with suppress(OSError):
                temporary.unlink(missing_ok=True)
            raise MainGraduationJournalError(f"{description} was not atomically replaced") from exc

    def _stage_identity_path(self, identity_digest: str) -> Path:
        _check_digest(identity_digest)
        return self._indexes / "stage-identity" / f"{identity_digest.removeprefix('sha256:')}.json"

    def _operation_stage_identity_path(self, intent: MainMutationIntent) -> Path:
        key = canonical_digest({"operation_id": intent.operation_id, "stage": intent.stage})
        return self._indexes / "operation-stage-identity" / f"{key.removeprefix('sha256:')}.json"

    def _external_object_identity_path(self, intent: MainMutationIntent) -> Path:
        key = canonical_digest(
            {
                "repository_digest": intent.repository_digest,
                "target_ref": intent.target_ref,
                "stage": intent.stage,
                "external_key": intent.external_identity.external_key,
                "queue_generation_digest": intent.external_identity.queue_generation_digest,
            }
        )
        return self._indexes / "external-object-identity" / f"{key.removeprefix('sha256:')}.json"

    def _cas_stage_identity(
        self, identity_digest: str, intent: MainMutationIntent, reference: ArtifactRef
    ) -> None:
        envelope = self._phase_reference_envelope(
            "mutation-intent", identity_digest, intent, reference
        )
        self._cas_global_envelope(
            self._stage_identity_path(identity_digest), envelope, intent, "stage identity"
        )

    def _phase_identity_path(self, kind: str, key: str) -> Path:
        _check_digest(key)
        return self._indexes / f"{kind}-identity" / f"{key.removeprefix('sha256:')}.json"

    def _cas_phase_identity(
        self, kind: str, key: str, record: StrictModel, reference: ArtifactRef
    ) -> None:
        envelope = self._phase_reference_envelope(kind, key, record, reference)
        self._cas_global_envelope(
            self._phase_identity_path(kind, key), envelope, record, f"{kind} identity"
        )

    def _assert_phase_identity(self, kind: str, key: str, record: StrictModel) -> None:
        path = self._phase_identity_path(kind, key)
        if not path.is_file():
            raise MainGraduationJournalError(f"{kind} identity is not indexed")
        current = self._read_phase_envelope(path, kind, key)
        if self._store.read_bytes(current.reference) != canonical_bytes(record):
            raise MainGraduationRecordConflictError(f"{kind} identity differs")

    def _assert_stage_identity(self, intent: MainMutationIntent) -> None:
        path = self._stage_identity_path(intent.external_identity.identity_digest)
        if not path.is_file():
            raise MainGraduationJournalError("mutation stage identity is not indexed")
        current = self._read_phase_envelope(
            path, "mutation-intent", intent.external_identity.identity_digest
        )
        data = self._store.read_bytes(current.reference)
        if data != canonical_bytes(intent):
            raise MainGraduationRecordConflictError("mutation stage identity differs")
        for path, key, description in (
            (
                self._operation_stage_identity_path(intent),
                canonical_digest({"operation_id": intent.operation_id, "stage": intent.stage}),
                "operation stage identity",
            ),
            (
                self._external_object_identity_path(intent),
                canonical_digest(
                    {
                        "repository_digest": intent.repository_digest,
                        "target_ref": intent.target_ref,
                        "stage": intent.stage,
                        "external_key": intent.external_identity.external_key,
                        "queue_generation_digest": intent.external_identity.queue_generation_digest,
                    }
                ),
                "external object identity",
            ),
        ):
            if not path.is_file():
                raise MainGraduationJournalError(f"{description} is not indexed")
            current = self._read_phase_envelope(path, "mutation-intent", key)
            if self._store.read_bytes(current.reference) != canonical_bytes(intent):
                raise MainGraduationRecordConflictError(f"{description} differs")

    def _cas_operation_stage_identity(
        self, intent: MainMutationIntent, reference: ArtifactRef
    ) -> None:
        envelope = self._phase_reference_envelope(
            "mutation-intent",
            canonical_digest({"operation_id": intent.operation_id, "stage": intent.stage}),
            intent,
            reference,
        )
        self._cas_global_envelope(
            self._operation_stage_identity_path(intent),
            envelope,
            intent,
            "operation stage identity",
        )

    def _cas_external_object_identity(
        self, intent: MainMutationIntent, reference: ArtifactRef
    ) -> None:
        key = canonical_digest(
            {
                "repository_digest": intent.repository_digest,
                "target_ref": intent.target_ref,
                "stage": intent.stage,
                "external_key": intent.external_identity.external_key,
                "queue_generation_digest": intent.external_identity.queue_generation_digest,
            }
        )
        envelope = self._phase_reference_envelope("mutation-intent", key, intent, reference)
        self._cas_global_envelope(
            self._external_object_identity_path(intent),
            envelope,
            intent,
            "external object identity",
        )

    def _read_target_fence_envelope(
        self, path: Path, expected: MainUnresolvedMutationFence
    ) -> _TargetFenceEnvelope:
        try:
            raw = self._target_fence_record_path(path).read_bytes()
            envelope = _TargetFenceEnvelope.model_validate(
                json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_pairs)
            )
            if (
                canonical_bytes(envelope) != raw
                or envelope.target_scope_digest != expected.target_scope_digest
            ):
                raise ValueError("target fence index is noncanonical")
            current = MainUnresolvedMutationFence.model_validate_json(
                self._store.read_bytes(envelope.reference)
            )
            if current.fence_digest != envelope.fence_digest:
                raise MainGraduationRecordConflictError("target fence reference differs")
            return envelope
        except MainGraduationRecordConflictError:
            raise
        except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
            raise MainGraduationJournalError("target mutation fence index is malformed") from exc

    def _assert_target_lease(self, record: MainLeaseEvidenceRecord) -> None:
        path = self._target_lease_path(record)
        if not path.is_file():
            raise MainGraduationJournalError("target lease is not globally indexed")
        try:
            raw = path.read_bytes()
            envelope = _TargetLeaseEnvelope.model_validate(
                json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_pairs)
            )
            if (
                canonical_bytes(envelope) != raw
                or envelope.target_scope_digest
                != main_target_scope_digest(record.repository_digest, record.target_ref)
                or envelope.operation_id != record.operation_id
            ):
                raise MainGraduationRecordConflictError("target lease binding differs")
            if envelope.lease_digest != record.lease_digest:
                raise MainGraduationRecordConflictError("target lease digest differs")
            if self._store.read_bytes(envelope.reference) != canonical_bytes(record):
                raise MainGraduationRecordConflictError("target lease artifact differs")
        except MainGraduationRecordConflictError:
            raise
        except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
            raise MainGraduationJournalError("target lease index is malformed") from exc

    def _assert_target_fence(self, record: MainUnresolvedMutationFence) -> None:
        path = self._target_fence_path(record)
        if path.is_dir():
            envelope = self._read_target_fence_envelope(path, record)
            if envelope.fence_digest != record.fence_digest:
                raise MainGraduationRecordConflictError("target mutation fence digest differs")
            return
        closed = self._target_fence_closed_path(record) / "record.json"
        if not closed.is_file():
            raise MainGraduationJournalError("target mutation fence is not globally indexed")
        envelope = self._read_target_fence_envelope(closed.parent, record)
        if envelope.fence_digest != record.fence_digest:
            raise MainGraduationRecordConflictError("target mutation fence digest differs")

    def _assert_release_claim(self, record: MainReleaseClaim) -> None:
        path = (
            self._indexes
            / "release-claim-key"
            / (f"{record.claim_key.removeprefix('sha256:')}.json")
        )
        if not path.is_file():
            raise MainGraduationJournalError("release claim is not globally indexed")
        current = self._read_phase_envelope(path, "release-claim", record.claim_key)
        if self._store.read_bytes(current.reference) != canonical_bytes(record):
            raise MainGraduationRecordConflictError("release claim identity differs")

    def _close_target_fence_if_resolved(self, resolution: MainMutationFenceResolution) -> None:
        fence_prior = self._read("unresolved-mutation-fence", resolution.fence_digest)
        if fence_prior is None:
            raise MainGraduationJournalError("resolution fence is missing")
        fence = cast(MainUnresolvedMutationFence, fence_prior[0])
        active = self._target_fence_path(fence)
        if not active.exists():
            return
        current = self._read_target_fence_envelope(active, fence)
        if current.fence_digest != fence.fence_digest:
            raise MainGraduationRecordConflictError("target fence closure differs")
        closed = self._target_fence_closed_path(fence)
        closed.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.replace(active, closed)
            _sync_directory(closed.parent)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise MainGraduationJournalError("resolved target fence could not be closed") from exc

    def _verify_phase_parent_resolution(self, intent: MainMutationIntent) -> None:
        if intent.parent_resolution_digest is None:
            return
        resolved = self._read("mutation-fence-resolution", intent.parent_resolution_digest)
        if resolved is None:
            raise MainGraduationJournalError("mutation intent resolution predecessor is missing")
        resolution = cast(MainMutationFenceResolution, resolved[0])
        if resolution.operation_id != intent.operation_id or resolution.outcome != "observed":
            raise MainGraduationJournalError("mutation intent resolution predecessor differs")
        fence_prior = self._read("unresolved-mutation-fence", resolution.fence_digest)
        if fence_prior is None:
            raise MainGraduationJournalError("mutation resolution fence is missing")
        fence = cast(MainUnresolvedMutationFence, fence_prior[0])
        if fence.intent_digest != intent.parent_intent_digest or fence.stage != intent.parent_stage:
            raise MainGraduationJournalError("mutation resolution does not close exact predecessor")
        receipt_prior = self._read("mutation-receipt", resolution.resolved_receipt_digest)
        if receipt_prior is None or cast(MainMutationReceipt, receipt_prior[0]).outcome not in {
            "ambiguous",
            "reconciliation_required",
        }:
            raise MainGraduationJournalError("mutation resolution receipt is not ambiguous")

    def _validate_phase_chain(self, kind: str, record: StrictModel) -> None:
        if kind == "lease-evidence-record":
            return
        if kind == "mutation-intent":
            intent = cast(MainMutationIntent, record)
            prep_prior = self._read("preparation-authorization", intent.operation_id)
            if prep_prior is None:
                raise MainGraduationJournalError(
                    "mutation intent requires preparation authorization"
                )
            prep = cast(MainPreparationAuthorization, prep_prior[0])
            lease_prior = self._read("lease-evidence-record", intent.operation_id)
            if lease_prior is None:
                raise MainGraduationJournalError("mutation intent requires durable lease evidence")
            lease = cast(MainLeaseEvidenceRecord, lease_prior[0])
            if (
                intent.preparation_authorization_digest != prep.authorization_digest
                or intent.repository_digest != prep.repository_digest
                or intent.target_ref != prep.target_ref
                or intent.lease_identity != prep.lease_identity
                or intent.lease_digest != prep.lease_digest
                or intent.policy_epoch_digest != prep.policy_epoch
                or intent.controller_config_digest
                != self._controller_config_digest(intent.operation_id)
                or lease.owner != intent.lease_identity
                or lease.lease_digest != intent.lease_digest
                or lease.policy_epoch != intent.policy_epoch_digest
                or lease.lease_epoch_digest != intent.lease_epoch_digest
                or lease.repository_digest != intent.repository_digest
                or lease.target_ref != intent.target_ref
                or intent.recorded_at >= lease.expires_at
            ):
                raise MainGraduationJournalError("mutation intent preparation binding differs")
            if intent.parent_receipt is not None:
                prior = self._read("mutation-receipt", intent.parent_receipt.receipt_digest)
                if prior is None or cast(MainMutationReceipt, prior[0]) != intent.parent_receipt:
                    raise MainGraduationJournalError(
                        "mutation intent parent receipt is not durable"
                    )
            self._verify_phase_parent_resolution(intent)
            if intent.stage == "release_transition":
                auth_prior = self._read("release-authorization", intent.operation_id)
                claim = self._read("release-claim", intent.release_claim_digest or "")
                if auth_prior is None or claim is None:
                    raise MainGraduationJournalError(
                        "release intent requires durable authorization and claim"
                    )
                if intent.release_authorization_digest != canonical_digest(auth_prior[0]):
                    raise MainGraduationJournalError("release intent authorization differs")
                if intent.release_claim_digest != canonical_digest(claim[0]):
                    raise MainGraduationJournalError("release intent claim differs")
            return
        if kind == "mutation-receipt":
            receipt = cast(MainMutationReceipt, record)
            prior = self._read("mutation-intent", receipt.intent_digest)
            if (
                prior is None
                or cast(MainMutationIntent, prior[0]).operation_id != receipt.operation_id
            ):
                raise MainGraduationJournalError("mutation receipt intent is not durable")
            intent = cast(MainMutationIntent, prior[0])
            self._assert_stage_identity(intent)
            if (
                intent.stage != receipt.stage
                or intent.external_identity != receipt.external_identity
                or intent.parent_intent_digest != receipt.parent_intent_digest
                or intent.lease_identity != receipt.lease_identity
                or intent.lease_digest != receipt.lease_digest
                or intent.lease_epoch_digest != receipt.lease_epoch_digest
                or intent.policy_epoch_digest != receipt.policy_epoch_digest
                or intent.controller_config_digest != receipt.controller_config_digest
                or intent.preparation_authorization_digest
                != receipt.preparation_authorization_digest
                or intent.release_authorization_digest != receipt.release_authorization_digest
                or intent.release_claim_digest != receipt.release_claim_digest
            ):
                raise MainGraduationJournalError("mutation receipt intent binding differs")
            return
        if kind == "release-claim":
            claim = cast(MainReleaseClaim, record)
            auth_prior = self._read("release-authorization", claim.operation_id)
            hold_prior = self._read("release-hold", claim.operation_id)
            if auth_prior is None or hold_prior is None:
                raise MainGraduationJournalError(
                    "release claim requires durable hold and authorization"
                )
            auth = cast(MainReleaseAuthorization, auth_prior[0])
            hold = cast(MainReleaseHoldObservation, hold_prior[0])
            lease_prior = self._read("lease-evidence-record", claim.operation_id)
            if lease_prior is None:
                raise MainGraduationJournalError("release claim requires durable lease evidence")
            lease = cast(MainLeaseEvidenceRecord, lease_prior[0])
            if any(
                (
                    claim.authorization_digest != auth.authorization_digest,
                    claim.hold_observation_digest != canonical_digest(hold),
                    claim.group_sha != auth.group_sha,
                    claim.group_sha != hold.group_sha,
                    claim.hold_run_id != auth.hold_run_id,
                    claim.hold_run_id != hold.hold_run_id,
                    claim.hold_nonce != auth.hold_nonce,
                    claim.hold_nonce != hold.hold_nonce,
                    claim.queue_generation_digest != auth.queue_generation_digest,
                    claim.queue_generation_digest != hold.queue_generation_digest,
                    claim.lease_identity != auth.lease_identity,
                    claim.lease_digest != auth.lease_digest,
                    claim.lease_digest != lease.lease_digest,
                    claim.lease_epoch_digest != lease.lease_epoch_digest,
                    claim.lease_expires_at != lease.expires_at,
                    claim.authorization_expires_at != auth.expires_at,
                    claim.claimed_at >= claim.authorization_expires_at,
                    claim.claimed_at >= claim.lease_expires_at,
                    claim.release_issuer_identity != auth.release_issuer_identity,
                    claim.issuer_isolation_digest != auth.issuer_isolation_digest,
                    claim.target_scope_digest
                    != main_target_scope_digest(claim.repository_digest, claim.target_ref),
                    claim.release_issuer_app_id != auth.release_issuer_app_id,
                )
            ):
                raise MainGraduationJournalError("release claim binding differs")
            return
        if kind == "unresolved-mutation-fence":
            fence = cast(MainUnresolvedMutationFence, record)
            receipt_prior = self._read("mutation-receipt", fence.source_receipt_digest)
            if receipt_prior is None:
                raise MainGraduationJournalError("mutation fence requires durable receipt")
            receipt = cast(MainMutationReceipt, receipt_prior[0])
            if (
                receipt.outcome not in {"ambiguous", "reconciliation_required"}
                or not receipt.dispatch_started
            ):
                raise MainGraduationJournalError("mutation fence requires an ambiguous receipt")
            if (
                receipt.intent_digest != fence.intent_digest
                or receipt.operation_id != fence.operation_id
                or receipt.repository_digest != fence.repository_digest
                or receipt.target_ref != fence.target_ref
                or receipt.external_identity.identity_digest != fence.external_identity_digest
                or receipt.lease_identity != fence.lease_identity
                or receipt.lease_digest != fence.lease_digest
            ):
                raise MainGraduationJournalError("mutation fence external identity differs")
            return
        if kind == "mutation-fence-resolution":
            resolution = cast(MainMutationFenceResolution, record)
            fence_prior = self._read("unresolved-mutation-fence", resolution.fence_digest)
            if fence_prior is None:
                raise MainGraduationJournalError("mutation resolution requires durable fence")
            fence = cast(MainUnresolvedMutationFence, fence_prior[0])
            if (
                resolution.operation_id != fence.operation_id
                or resolution.intent_digest != fence.intent_digest
            ):
                raise MainGraduationJournalError("mutation resolution binding differs")
            if any(
                (
                    resolution.external_identity_digest != fence.external_identity_digest,
                    resolution.lease_identity != fence.lease_identity,
                    resolution.lease_digest != fence.lease_digest,
                    resolution.target_scope_digest != fence.target_scope_digest,
                    not resolution.authoritative_observation_digest.startswith("sha256:"),
                    not resolution.provider_identity,
                    not resolution.provider_api_version,
                )
            ):
                raise MainGraduationJournalError("mutation resolution fence binding differs")
            receipt_prior = self._read("mutation-receipt", resolution.resolved_receipt_digest)
            if receipt_prior is None:
                raise MainGraduationJournalError("mutation resolution receipt is missing")
            source_receipt = cast(MainMutationReceipt, receipt_prior[0])
            if (
                source_receipt.intent_digest != resolution.intent_digest
                or source_receipt.outcome not in {"ambiguous", "reconciliation_required"}
            ):
                raise MainGraduationJournalError("mutation resolution receipt is not ambiguous")
            if resolution.outcome == "observed":
                # Only an observed provider result can authorize a subsequent
                # mutation intent.  ``not_applied`` closes the fence safely,
                # but it is not proof that the requested mutation occurred.
                return
            if resolution.outcome == "not_applied":
                return
        if kind == "claimed-release-transition":
            receipt = cast(MainClaimedReleaseTransitionReceipt, record)
            claim_prior = self._read("release-claim", receipt.claim_digest)
            auth_prior = self._read("release-authorization", receipt.operation_id)
            if claim_prior is None or auth_prior is None:
                raise MainGraduationJournalError(
                    "claimed transition requires durable claim and authorization"
                )
            claim = cast(MainReleaseClaim, claim_prior[0])
            auth = cast(MainReleaseAuthorization, auth_prior[0])
            if (
                receipt.release_authorization_digest != auth.authorization_digest
                or receipt.claim_digest != claim.claim_digest
                or receipt.group_sha != claim.group_sha
                or receipt.hold_run_id != claim.hold_run_id
                or receipt.hold_nonce != claim.hold_nonce
                or receipt.issuer_identity != claim.release_issuer_identity
                or receipt.issuer_isolation_digest != claim.issuer_isolation_digest
            ):
                raise MainGraduationJournalError("claimed transition binding differs")

    def _controller_config_digest(self, operation_id: str) -> str:
        prior = self._read("plan", operation_id)
        if prior is None:
            raise MainGraduationJournalError("mutation intent plan is missing")
        return cast(MainGraduationPlan, prior[0]).controller_config_digest

    def _verify_completion_prerequisites(self, package: MainCompletionPackage) -> None:
        """Completion is only a closure over already verified durable stages."""
        stages: tuple[tuple[str, StrictModel], ...] = (
            ("source-package", package.source_package),
            ("delta", package.delta),
            ("composition", package.composition),
            ("queue", package.queue_observation),
            ("protection", package.protection_manifest),
            ("attestations", package.attestation_manifest),
            ("merge-group-checks", package.merge_group_checks),
            ("merge-group-webhook-receipt", package.hold_observation.merge_group_receipt),
            ("release-issuer-binding", package.release_issuer_binding),
            ("plan", package.plan),
            ("intent", package.intent),
            ("preparation-authorization", package.preparation_authorization),
            ("queue-admission", package.admission_observation),
            ("release-hold", package.hold_observation),
            ("release-authorization", package.release_authorization),
            ("release-transition", package.transition_receipt),
            ("provider-receipt", package.provider_receipt),
            ("reconciliation", package.reconciliation),
        )
        for kind, record in stages:
            self._require_exact(kind, record)
        if hasattr(package, "lease_evidence_record"):
            phase_records: tuple[tuple[str, StrictModel], ...] = (
                ("lease-evidence-record", package.lease_evidence_record),
                ("release-claim", package.release_claim),
                ("claimed-release-transition", package.claimed_transition_receipt),
                ("mutation-intent", package.release_transition_intent),
                ("mutation-receipt", package.release_transition_mutation_receipt),
            )
            if package.release_transition_fence_resolution is not None:
                phase_records += (
                    (
                        "mutation-fence-resolution",
                        package.release_transition_fence_resolution,
                    ),
                )
            for kind, record in phase_records:
                self._require_phase_exact(kind, record)
        # Re-run the standalone loaders after exact matching.  This makes a
        # model_construct completion incapable of bypassing nested checks.
        self._verify_source_package(package.source_package)
        self._verify_plan_evidence(package.plan)
        self._require_preparation_chain(package.preparation_authorization)
        self._require_admission(package.hold_observation)
        self._require_hold(package.release_authorization)
        self._require_release_authorization(package.transition_receipt)
        self._require_provider_receipt(package.provider_receipt)
        self._require_reconciliation(package.reconciliation)

    def _verify_source_package(self, package: MainSourcePackageBinding) -> None:
        """Verify the raw package and every immutable child before indexing."""
        try:
            raw = self._store.read_bytes(package.package_artifact)
            parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_pairs)
            if canonical_bytes(parsed) != raw:
                raise ValueError("source package is not canonical JSON")
            source = IntegrationCampaignEvidencePackage.model_validate(parsed)
            verify_campaign_package_artifact(source, package.package_artifact, raw)
            if source.receipt.outcome not in {"applied", "already_applied"}:
                raise ValueError("source campaign package is not terminally applied")
            if (
                source.deploy_performed
                or source.reconciliation.target_head_commit != package.source_result_commit
            ):
                raise ValueError("source package result differs from binding")
            self._require_integration_target(source)
            if (
                source.reconciliation.target_head_tree != package.source_result_tree
                or source.reconciliation.target_first_parent != package.source_result_parent
                or source.reconciliation.target_parents != [package.source_result_parent]
                or source.receipt.applied_result_commit not in {None, package.source_result_commit}
                or source.receipt.applied_result_tree not in {None, package.source_result_tree}
                or source.receipt.applied_result_parent_commit
                not in {None, package.source_result_parent}
            ):
                raise ValueError("source package topology differs from binding")
            if source.intent.repository_digest != package.repository_digest:
                raise ValueError("source package repository differs from binding")
            if (
                source.intent.operation_id != package.source_operation_id
                or package.source_operation_id == package.operation_id
                or source.bundle.controller_config.controller_identity != package.source_issuer
            ):
                raise ValueError("source package operation or issuer differs from binding")
            required = {
                reference.digest
                for reference in (*source.evidence_artifacts, source.lease_evidence_artifact)
            }
            actual = {reference.digest for reference in package.child_artifacts}
            if actual != required:
                raise ValueError("source package child closure differs from canonical package")
            expected_refs = {
                reference.digest: reference
                for reference in (*source.evidence_artifacts, source.lease_evidence_artifact)
            }
            for reference in package.child_artifacts:
                expected = expected_refs[reference.digest]
                if (
                    reference.role != expected.role
                    or reference.media_type != expected.media_type
                    or reference.size_bytes != expected.size_bytes
                ):
                    raise ValueError("source package child metadata differs from canonical package")
                if not reference.media_type.startswith("application/vnd.avo."):
                    raise ValueError("source package child media type is not allowlisted")
                child = self._store.read_bytes(reference)
                if len(child) != reference.size_bytes or _digest_bytes(child) != reference.digest:
                    raise ValueError("source package child is missing or tampered")
                child_json = json.loads(child.decode("utf-8"), object_pairs_hook=_strict_pairs)
                if canonical_bytes(child_json) != child:
                    raise ValueError("source package child is not canonical JSON")
        except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
            raise MainGraduationJournalError("source package or child is unverifiable") from exc

    @staticmethod
    def _require_integration_target(package: IntegrationCampaignEvidencePackage) -> None:
        """Require one exact protected integration target across every closure edge."""

        integration_ref = "refs/heads/integration"
        if any(
            target_ref != integration_ref
            for target_ref in (
                package.intent.target_ref,
                package.bundle.snapshot.target_ref,
                package.bundle.comparison.target_ref,
                package.observation.base_ref,
                package.reconciliation.target_ref,
            )
        ):
            raise ValueError("source package integration target closure differs")

    def _verify_plan_composition(self, plan: MainGraduationPlan) -> None:
        """Recompute C2 with the internally rooted concrete authority.

        This is called only before claiming a new plan index.  Reads of an
        existing plan use :meth:`_verify_plan_composition_durable` and never
        consult live Git state.
        """
        if (
            self._composition_root is None
            or self._composition_repository_digest is None
            or self._composition_base_reader is None
        ):
            raise MainGraduationJournalError(
                "plan requires a controller-rooted composition authority"
            )
        proof = getattr(plan, "composition_proof", None)
        reference = getattr(plan, "composition_proof_artifact", None)
        if proof is None or reference is None:
            raise MainGraduationJournalError("plan requires an exact durable composition proof")
        try:
            from avo_correlate.adapters.git.main_composition import MainCompositionAdapter

            authority = MainCompositionAdapter(
                self._composition_root,
                self,
                repository_digest=self._composition_repository_digest,
                base_reader=self._composition_base_reader,
                controller_config_digest=plan.controller_config_digest,
                policy_epoch=plan.policy_epoch,
            )
            expected = authority.verify(plan.package, plan.delta, plan.composition)
        except Exception as exc:
            if isinstance(exc, MainGraduationJournalError):
                raise
            raise MainGraduationJournalError(
                "controller-rooted composition authority rejected plan"
            ) from exc
        if canonical_bytes(expected) != canonical_bytes(proof):
            raise MainGraduationJournalError(
                "plan composition proof differs from rooted recomputation"
            )
        self._verify_composition_proof(expected, plan=plan)
        durable = self._record("composition-proof", expected)
        if durable != reference:
            raise MainGraduationJournalError("plan composition proof reference differs")

    def _authorize_composition(
        self,
        source: MainSourcePackageBinding,
        delta: MainDeltaManifest,
        composition: MainCompositionArtifact,
        *,
        controller_config_digest: str,
        policy_epoch: str,
    ) -> tuple[MainCompositionProof, ArtifactRef]:
        """Private adapter path: recompute, then create the durable proof."""

        if (
            self._composition_root is None
            or self._composition_repository_digest is None
            or self._composition_base_reader is None
        ):
            raise MainGraduationJournalError(
                "composition authority lacks trusted Git/base capabilities"
            )
        try:
            from avo_correlate.adapters.git.main_composition import MainCompositionAdapter

            authority = MainCompositionAdapter(
                self._composition_root,
                self,
                repository_digest=self._composition_repository_digest,
                base_reader=self._composition_base_reader,
                controller_config_digest=controller_config_digest,
                policy_epoch=policy_epoch,
            )
            proof = authority.verify(source, delta, composition)
            self._verify_composition_proof(proof)
            reference = self._record("composition-proof", proof)
            return proof, reference
        except MainGraduationJournalError:
            raise
        except Exception as exc:
            raise MainGraduationJournalError(
                "controller-rooted composition authority rejected composition"
            ) from exc

    def _verify_plan_composition_durable(self, plan: MainGraduationPlan) -> None:
        """Validate an indexed proof using immutable records only."""

        proof = getattr(plan, "composition_proof", None)
        reference = getattr(plan, "composition_proof_artifact", None)
        if proof is None or reference is None:
            raise MainGraduationJournalError("plan requires an exact durable composition proof")
        durable = self._read("composition-proof", plan.operation_id)
        if durable is None:
            raise MainGraduationJournalError("plan requires a durable composition proof record")
        if canonical_bytes(durable[0]) != canonical_bytes(proof):
            raise MainGraduationJournalError("plan composition proof differs from durable record")
        if durable[1] != reference:
            raise MainGraduationJournalError("plan composition proof reference differs")
        self._verify_composition_proof(proof, plan=plan)

    def _verify_composition_proof(
        self, proof: MainCompositionProof, *, plan: MainGraduationPlan | None = None
    ) -> None:
        """Validate proof content and controller-rooted implementation identity."""

        try:
            payload = canonical_bytes(proof)
            checked = MainCompositionProof.model_validate_json(payload)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise MainGraduationJournalError("composition proof is invalid") from exc
        if canonical_bytes(checked) != payload:
            raise MainGraduationJournalError("composition proof is not canonical")
        if (
            checked.verifier_identity != _COMPOSITION_VERIFIER_ID
            or checked.verifier_version != _COMPOSITION_VERIFIER_VERSION
            or checked.base_observer_identity != _BASE_OBSERVER_ID
            or checked.git_root_digest != checked.repository_digest
        ):
            raise MainGraduationJournalError("composition proof implementation root differs")
        root = self._release_issuer_binding
        if root is None:
            raise MainGraduationJournalError("composition proof lacks controller root")
        if (
            checked.operation_id != root.operation_id
            or checked.repository_digest != root.repository_digest
            or checked.target_ref != root.target_ref
            or checked.controller_config_digest != root.controller_config_digest
            or checked.source_issuer != root.trusted_source_issuer
            or checked.source_domain != root.trusted_source_domain
        ):
            raise MainGraduationJournalError("composition proof differs from controller root")
        if self._policy_epoch is not None and checked.policy_epoch != self._policy_epoch:
            raise MainGraduationJournalError(
                "composition proof policy epoch differs from controller root"
            )
        if plan is not None and (
            checked.operation_id != plan.operation_id
            or checked.repository_digest != plan.repository_digest
            or checked.target_ref != plan.target_ref
            or checked.controller_config_digest != plan.controller_config_digest
            or checked.policy_epoch != plan.policy_epoch
            or checked.package_digest != plan.package.package_digest
            or checked.source_operation_id != plan.package.source_operation_id
            or checked.source_result_commit != plan.package.source_result_commit
            or checked.source_result_parent != plan.package.source_result_parent
            or checked.source_result_tree != plan.package.source_result_tree
            or checked.delta_digest != plan.delta.delta_digest
            or checked.path_manifest_digest != plan.delta.path_manifest_digest
            or checked.ordinary_risk_digest != plan.delta.ordinary_risk_digest
            or checked.composition_digest != plan.composition.composition_digest
            or checked.base_commit != plan.composition.base_commit
            or checked.base_tree != plan.composition.base_tree
            or checked.candidate_commit != plan.composition.candidate_commit
            or checked.candidate_tree != plan.composition.candidate_tree
            or checked.candidate_parent_commit != plan.composition.candidate_parent_commit
            or checked.candidate_ref != plan.composition.candidate_ref
            or checked.retention_ref != plan.composition.retention_ref
        ):
            raise MainGraduationJournalError("composition proof does not bind exact plan")

    def _verify_plan_evidence(self, plan: MainGraduationPlan) -> None:
        """Plans may only cite the raw package and its typed immutable children."""
        durable_source = self._read("source-package", plan.operation_id)
        if durable_source is None:
            raise MainGraduationJournalError("plan requires durable source-package record")
        if canonical_bytes(durable_source[0]) != canonical_bytes(plan.package):
            raise MainGraduationJournalError("plan source-package differs from durable record")
        # Do not rely on the durable-record lookup alone: this repeats the
        # raw upstream package and child semantic closure at the plan boundary.
        self._verify_source_package(plan.package)
        issuer_prior = self._read("release-issuer-binding", plan.operation_id)
        if issuer_prior is None:
            raise MainGraduationJournalError("plan requires durable release-issuer-binding")
        issuer_binding = cast(MainReleaseIssuerBinding, issuer_prior[0])
        self._require_controller_issuer_binding(issuer_binding)
        if canonical_bytes(issuer_binding) != canonical_bytes(plan.release_issuer_binding):
            raise MainGraduationJournalError(
                "plan release issuer binding differs from durable record"
            )
        if (
            issuer_binding.repository_digest != plan.repository_digest
            or issuer_binding.target_ref != plan.target_ref
            or issuer_binding.controller_config_digest != plan.controller_config_digest
            or issuer_binding.trusted_source_issuer != plan.package.source_issuer
            or issuer_binding.trusted_source_domain != plan.package.source_domain
        ):
            raise MainGraduationJournalError(
                "plan source authority differs from controller binding"
            )
        expected = {plan.package.package_artifact.digest: plan.package.package_artifact}
        expected.update({item.digest: item for item in plan.package.child_artifacts})
        actual = {item.digest: item for item in plan.evidence_artifacts}
        if set(actual) != set(expected):
            raise MainGraduationJournalError("plan evidence closure is incomplete or opaque")
        for digest, reference in actual.items():
            authoritative = expected[digest]
            if reference != authoritative:
                raise MainGraduationJournalError(
                    "plan evidence metadata differs from typed reference"
                )
            try:
                raw = self._store.read_bytes(reference)
            except (OSError, RuntimeError, ValueError) as exc:
                raise MainGraduationJournalError("plan evidence artifact is unavailable") from exc
            if len(raw) != reference.size_bytes or _digest_bytes(raw) != reference.digest:
                raise MainGraduationJournalError("plan evidence artifact is tampered")
        durable_delta = self._read("delta", plan.operation_id)
        durable_composition = self._read("composition", plan.operation_id)
        if durable_delta is None or durable_composition is None:
            raise MainGraduationJournalError(
                "plan requires durable exact delta and composition records"
            )
        if canonical_bytes(durable_delta[0]) != canonical_bytes(plan.delta) or canonical_bytes(
            durable_composition[0]
        ) != canonical_bytes(plan.composition):
            raise MainGraduationJournalError("plan delta/composition differs from durable records")
        self._verify_plan_composition_durable(plan)

    def _require_controller_issuer_binding(self, binding: MainReleaseIssuerBinding) -> None:
        """Accept authority only when it matches the journal's controller-owned root."""
        configured = self._release_issuer_binding
        if configured is None:
            raise MainGraduationJournalError(
                "journal lacks controller-pinned release issuer binding"
            )
        try:
            configured_data = canonical_bytes(configured)
            checked = MainReleaseIssuerBinding.model_validate_json(configured_data)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise MainGraduationJournalError(
                "controller release issuer binding is invalid"
            ) from exc
        if canonical_bytes(checked) != canonical_bytes(binding):
            raise MainGraduationJournalError("release issuer binding differs from controller root")

    def _verify_intent_lease(self, intent: MainGraduationIntent) -> None:
        """Reparse durable lease evidence before it can authorize preparation."""
        evidence = intent.lease_evidence
        reference = intent.lease_evidence_artifact
        if (
            evidence.operation_id != intent.operation_id
            or evidence.repository_digest != intent.repository_digest
            or evidence.target_ref != intent.target_ref
            or evidence.identity != intent.lease_identity
            or evidence.lease_digest != intent.lease_digest
            or reference.role != "main-graduation-lease-evidence"
            or reference.media_type != "application/vnd.avo.main-graduation-lease-evidence+json"
        ):
            raise MainGraduationJournalError("intent lease evidence binding differs")
        try:
            raw = self._store.read_bytes(reference)
            parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_pairs)
            if canonical_bytes(parsed) != raw:
                raise ValueError("lease evidence is not canonical JSON")
            durable = MainLeaseEvidence.model_validate(parsed)
        except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
            raise MainGraduationJournalError("intent lease evidence is unverifiable") from exc
        if (
            canonical_bytes(durable) != canonical_bytes(evidence)
            or reference.digest != _digest_bytes(raw)
            or reference.size_bytes != len(raw)
        ):
            raise MainGraduationJournalError("intent lease evidence contents differ")

    def _require_exact(self, kind: str, record: StrictModel) -> None:
        durable = self._read(kind, _operation_id(record))
        if durable is None or canonical_bytes(durable[0]) != canonical_bytes(record):
            raise MainGraduationJournalError(f"{kind} is not the durable canonical prior stage")

    def _require_phase_exact(self, kind: str, record: StrictModel) -> None:
        """Require an exact durable phase-A artifact by its content key."""

        key = self._phase_key(kind, record)
        durable = self._read(kind, key)
        if durable is None or canonical_bytes(durable[0]) != canonical_bytes(record):
            raise MainGraduationJournalError(f"{kind} is not the durable canonical prior stage")

    def _require_preparation_chain(self, preparation: MainPreparationAuthorization) -> None:
        """Close the plan → intent → preparation authority chain once, everywhere."""
        plan_prior = self._read("plan", preparation.operation_id)
        intent_prior = self._read("intent", preparation.operation_id)
        if plan_prior is None or intent_prior is None:
            raise MainGraduationJournalError("preparation requires durable plan and intent")
        plan = cast(MainGraduationPlan, plan_prior[0])
        intent = cast(MainGraduationIntent, intent_prior[0])
        composition = plan.composition
        if (
            preparation.plan_digest != canonical_digest(plan)
            or preparation.intent_digest != canonical_digest(intent)
            or intent.plan_digest != canonical_digest(plan)
            or preparation.operation_id != plan.operation_id
            or preparation.operation_id != intent.operation_id
            or preparation.repository_digest != plan.repository_digest
            or preparation.repository_digest != intent.repository_digest
            or preparation.target_ref != plan.target_ref
            or preparation.target_ref != intent.target_ref
            or preparation.package_digest != plan.package.package_digest
            or preparation.package_digest != intent.package_digest
            or preparation.composition_digest != composition.composition_digest
            or preparation.composition_digest != intent.composition_digest
            or preparation.base_commit != composition.base_commit
            or preparation.base_commit != intent.base_commit
            or preparation.base_tree != composition.base_tree
            or preparation.base_tree != intent.base_tree
            or preparation.candidate_commit != composition.candidate_commit
            or preparation.candidate_commit != intent.candidate_commit
            or preparation.candidate_tree != composition.candidate_tree
            or preparation.candidate_tree != intent.candidate_tree
            or intent.candidate_ref != composition.candidate_ref
            or preparation.lease_identity != intent.lease_identity
            or preparation.lease_digest != intent.lease_digest
            or preparation.policy_epoch != intent.policy_epoch
            or preparation.policy_epoch != plan.policy_epoch
        ):
            raise MainGraduationJournalError("preparation plan/intent binding differs")
        if re.fullmatch(r"refs/heads/avo/candidate/[0-9a-f]{64}", intent.candidate_ref) is None:
            raise MainGraduationJournalError("intent candidate ref is outside controller namespace")
        if intent.recorded_at > preparation.authorized_at:
            raise MainGraduationJournalError("preparation predates intent")

    def _require_queue_admission(self, admission: MainQueueAdmissionObservation) -> None:
        """Admission independently closes the queue/base/protection snapshot."""
        plan = self._read("plan", admission.operation_id)
        queue = self._read("queue", admission.operation_id)
        protection = self._read("protection", admission.operation_id)
        preparation = self._read("preparation-authorization", admission.operation_id)
        if plan is None or queue is None or protection is None or preparation is None:
            raise MainGraduationJournalError("admission requires durable queue preparation chain")
        p = cast(MainGraduationPlan, plan[0])
        q = cast(MainQueueObservation, queue[0])
        protection_manifest = cast(MainProtectionManifest, protection[0])
        prep = cast(MainPreparationAuthorization, preparation[0])
        self._require_preparation_chain(prep)
        if prep.authorized_at > admission.observed_at:
            raise MainGraduationJournalError("admission predates preparation authorization")
        composition = p.composition
        if (
            admission.preparation_authorization_digest != canonical_digest(prep)
            or admission.package_digest != p.package.package_digest
            or admission.composition_digest != composition.composition_digest
            or admission.repository_digest != p.repository_digest
            or admission.target_ref != p.target_ref
            or admission.base_commit != composition.base_commit
            or admission.base_tree != composition.base_tree
            or admission.head_commit != composition.candidate_commit
            or admission.head_tree != composition.candidate_tree
            or admission.queue_generation_digest != q.queue_generation_digest
            or admission.protection_manifest_digest != protection_manifest.manifest_digest
        ):
            raise MainGraduationJournalError("admission plan/queue binding differs")
        if (
            q.repository_digest != p.repository_digest
            or q.target_ref != p.target_ref
            or q.expected_base_commit != composition.base_commit
            or q.expected_base_tree != composition.base_tree
            or q.merge_method != "squash"
            or q.protection_manifest_digest != protection_manifest.manifest_digest
            or q.protection_epoch != protection_manifest.protection_epoch
            or q.release_issuer_app_id != protection_manifest.release_issuer_app_id
            or q.issuer_isolation_digest != protection_manifest.issuer_isolation_digest
            or q.isolated_release_issuer != protection_manifest.isolated_release_issuer
            or q.provider_identity != protection_manifest.provider_identity
            or q.provider_api_version != protection_manifest.provider_api_version
        ):
            raise MainGraduationJournalError("queue/protection/base closure differs")
        if not (
            admission.issuer_identity == q.isolated_release_issuer
            and admission.release_issuer_app_id == q.release_issuer_app_id
            and admission.issuer_isolation_digest == q.issuer_isolation_digest
            and admission.check_context == protection_manifest.release_context
        ):
            raise MainGraduationJournalError("admission queue issuer differs")

    def _require_admission(self, hold: MainReleaseHoldObservation) -> None:
        prior = self._read("queue-admission", hold.operation_id)
        if prior is None:
            raise MainGraduationJournalError("release hold requires durable queue admission")
        admission = cast(MainQueueAdmissionObservation, prior[0])
        self._require_queue_admission(admission)
        if hold.admission_observation_digest != canonical_digest(admission):
            raise MainGraduationJournalError("hold admission digest differs")
        preparation = self._read("preparation-authorization", hold.operation_id)
        intent = self._read("intent", hold.operation_id)
        plan = self._read("plan", hold.operation_id)
        if preparation is None or intent is None or plan is None:
            raise MainGraduationJournalError("hold requires durable preparation chain")
        prep = cast(MainPreparationAuthorization, preparation[0])
        durable_intent = cast(MainGraduationIntent, intent[0])
        durable_plan = cast(MainGraduationPlan, plan[0])
        if (
            admission.preparation_authorization_digest != canonical_digest(prep)
            or hold.preparation_authorization_digest != canonical_digest(prep)
            or prep.intent_digest != canonical_digest(durable_intent)
            or prep.plan_digest != canonical_digest(durable_plan)
        ):
            raise MainGraduationJournalError("admission/hold preparation binding differs")
        if not (prep.authorized_at <= admission.observed_at <= hold.observed_at):
            raise MainGraduationJournalError("admission/hold preparation chronology differs")
        if any(
            value != expected
            for value, expected in (
                (admission.package_digest, durable_plan.package.package_digest),
                (admission.composition_digest, durable_plan.composition.composition_digest),
                (hold.package_digest, durable_plan.package.package_digest),
                (hold.composition_digest, durable_plan.composition.composition_digest),
                (admission.repository_digest, durable_plan.repository_digest),
                (hold.repository_digest, durable_plan.repository_digest),
                (admission.target_ref, durable_plan.target_ref),
                (hold.target_ref, durable_plan.target_ref),
            )
        ):
            raise MainGraduationJournalError("admission/hold plan binding differs")
        if admission.operation_id != hold.operation_id:
            raise MainGraduationJournalError("admission operation differs from hold")
        if admission.pull_request_number != hold.pull_request_number:
            raise MainGraduationJournalError("admission PR differs from hold")
        if admission.base_commit != hold.base_commit or admission.base_tree != hold.base_tree:
            raise MainGraduationJournalError("admission base differs from hold")
        if (
            admission.head_commit != durable_plan.composition.candidate_commit
            or admission.head_tree != durable_plan.composition.candidate_tree
            or admission.base_commit != durable_plan.composition.base_commit
            or admission.base_tree != durable_plan.composition.base_tree
            or hold.group_tree != durable_plan.composition.candidate_tree
            or hold.composition_tree != durable_plan.composition.candidate_tree
        ):
            raise MainGraduationJournalError("admission/hold composition binding differs")
        if admission.queue_generation_digest != hold.queue_generation_digest:
            raise MainGraduationJournalError("queue generation differs from admission")
        if admission.head_commit == hold.group_sha:
            raise MainGraduationJournalError("PR-head SHA cannot be reused as group SHA")
        queue = self._read("queue", hold.operation_id)
        protection = self._read("protection", hold.operation_id)
        attestations = self._read("attestations", hold.operation_id)
        checks = self._read("merge-group-checks", hold.operation_id)
        if queue is None or protection is None or attestations is None or checks is None:
            raise MainGraduationJournalError("hold requires durable queue evidence")
        q = cast(MainQueueObservation, queue[0])
        p = cast(MainProtectionManifest, protection[0])
        a = cast(MainAttestationManifest, attestations[0])
        c = cast(MainMergeGroupChecks, checks[0])
        if (
            admission.queue_generation_digest != q.queue_generation_digest
            or admission.protection_manifest_digest != p.manifest_digest
            or hold.protection_manifest_digest != p.manifest_digest
            or hold.attestation_manifest_digest != canonical_digest(a)
            or hold.other_required_checks != c
            or hold.group_topology_digest != q.group_topology_digest
            or hold.expected_group_parents != q.expected_group_parents
            or a.operation_id != durable_plan.operation_id
            or a.repository_digest != durable_plan.repository_digest
            or a.target_ref != durable_plan.target_ref
            or a.package_digest != durable_plan.package.package_digest
            or a.composition_digest != durable_plan.composition.composition_digest
            or a.policy_epoch != durable_plan.policy_epoch
        ):
            raise MainGraduationJournalError("hold durable evidence binding differs")
        if not (
            admission.issuer_identity
            == hold.issuer_identity
            == q.isolated_release_issuer
            == p.isolated_release_issuer
            and admission.release_issuer_app_id
            == hold.release_issuer_app_id
            == q.release_issuer_app_id
            == p.release_issuer_app_id
            and admission.issuer_isolation_digest
            == hold.issuer_isolation_digest
            == q.issuer_isolation_digest
            == p.issuer_isolation_digest
            and admission.check_context == hold.check_context == p.release_context
        ):
            raise MainGraduationJournalError("admission/hold issuer isolation differs")

    def _require_hold(self, authorization: MainReleaseAuthorization) -> None:
        prior = self._read("release-hold", authorization.operation_id)
        if prior is None:
            raise MainGraduationJournalError("release authorization requires durable pending hold")
        hold = cast(MainReleaseHoldObservation, prior[0])
        self._require_admission(hold)
        if authorization.hold_observation_digest != canonical_digest(hold):
            raise MainGraduationJournalError("release authorization hold digest differs")
        if (
            authorization.group_sha != hold.group_sha
            or authorization.hold_run_id != hold.hold_run_id
            or authorization.hold_nonce != hold.hold_nonce
            or authorization.queue_generation_digest != hold.queue_generation_digest
        ):
            raise MainGraduationJournalError("release authorization does not bind pending hold")
        if authorization.release_issuer_app_id != hold.release_issuer_app_id:
            raise MainGraduationJournalError("release issuer differs from hold")
        if authorization.release_issuer_identity != hold.issuer_identity:
            raise MainGraduationJournalError("release issuer identity differs from hold")
        if authorization.issuer_isolation_digest != hold.issuer_isolation_digest:
            raise MainGraduationJournalError("issuer isolation differs from hold")
        if hold.observed_at > authorization.authorized_at:
            raise MainGraduationJournalError("release authorization predates hold observation")
        admission = self._read("queue-admission", authorization.operation_id)
        preparation = self._read("preparation-authorization", authorization.operation_id)
        intent = self._read("intent", authorization.operation_id)
        plan = self._read("plan", authorization.operation_id)
        if admission is None or preparation is None or intent is None or plan is None:
            raise MainGraduationJournalError("release authorization requires durable prior stages")
        a = cast(MainQueueAdmissionObservation, admission[0])
        prep = cast(MainPreparationAuthorization, preparation[0])
        durable_intent = cast(MainGraduationIntent, intent[0])
        durable_plan = cast(MainGraduationPlan, plan[0])
        if (
            authorization.admission_observation_digest != canonical_digest(a)
            or authorization.preparation_authorization_digest != canonical_digest(prep)
            or prep.intent_digest != canonical_digest(durable_intent)
            or prep.plan_digest != canonical_digest(durable_plan)
            or authorization.package_digest != durable_plan.package.package_digest
            or authorization.composition_digest != durable_plan.composition.composition_digest
            or authorization.lease_identity != prep.lease_identity
            or authorization.lease_digest != prep.lease_digest
            or authorization.policy_epoch != prep.policy_epoch
            or authorization.repository_digest != durable_plan.repository_digest
            or authorization.target_ref != durable_plan.target_ref
        ):
            raise MainGraduationJournalError("release authorization prior-stage binding differs")

    def _require_release_authorization(self, receipt: MainReleaseTransitionReceipt) -> None:
        prior = self._read("release-authorization", receipt.operation_id)
        if prior is None:
            raise MainGraduationJournalError("transition requires durable release authorization")
        authorization = cast(MainReleaseAuthorization, prior[0])
        if receipt.release_authorization_digest != canonical_digest(authorization):
            raise MainGraduationJournalError("transition authorization digest differs")
        if not (authorization.authorized_at <= receipt.observed_at <= authorization.expires_at):
            raise MainGraduationJournalError("transition is outside authorization validity window")
        if (
            receipt.operation_id != authorization.operation_id
            or receipt.repository_digest != authorization.repository_digest
            or receipt.target_ref != authorization.target_ref
            or receipt.group_sha != authorization.group_sha
            or receipt.hold_run_id != authorization.hold_run_id
            or receipt.hold_nonce != authorization.hold_nonce
            or receipt.issuer_identity != authorization.release_issuer_identity
            or receipt.release_issuer_app_id != authorization.release_issuer_app_id
            or receipt.issuer_isolation_digest != authorization.issuer_isolation_digest
        ):
            raise MainGraduationJournalError("transition receipt does not bind authorization")

    def _require_provider_receipt(self, receipt: MainProviderReceipt) -> None:
        prior = self._read("release-authorization", receipt.operation_id)
        transition_prior = self._read("release-transition", receipt.operation_id)
        if prior is None:
            raise MainGraduationJournalError(
                "provider receipt requires durable release authorization"
            )
        authorization = cast(MainReleaseAuthorization, prior[0])
        if transition_prior is None:
            raise MainGraduationJournalError("provider receipt requires durable release transition")
        transition = cast(MainReleaseTransitionReceipt, transition_prior[0])
        self._require_release_authorization(transition)
        if receipt.observed_at < transition.observed_at:
            raise MainGraduationJournalError("provider receipt predates release transition")
        queue_prior = self._read("queue", receipt.operation_id)
        protection_prior = self._read("protection", receipt.operation_id)
        plan_prior = self._read("plan", receipt.operation_id)
        if queue_prior is None or protection_prior is None or plan_prior is None:
            raise MainGraduationJournalError("provider receipt requires durable queue evidence")
        queue = cast(MainQueueObservation, queue_prior[0])
        protection = cast(MainProtectionManifest, protection_prior[0])
        plan = cast(MainGraduationPlan, plan_prior[0])
        if (
            receipt.release_authorization_digest != canonical_digest(authorization)
            or transition.release_authorization_digest != canonical_digest(authorization)
            or receipt.operation_id != transition.operation_id
            or receipt.repository_digest != authorization.repository_digest
            or receipt.target_ref != authorization.target_ref
            or receipt.repository_digest != transition.repository_digest
            or receipt.target_ref != transition.target_ref
            or receipt.repository_digest != queue.repository_digest
            or receipt.target_ref != queue.target_ref
            or receipt.provider_identity != queue.provider_identity
            or receipt.provider_identity != protection.provider_identity
            or receipt.provider_api_version != queue.provider_api_version
            or receipt.provider_api_version != protection.provider_api_version
        ):
            raise MainGraduationJournalError("provider receipt authorization binding differs")
        if receipt.outcome == "observed" and (
            receipt.result_tree != plan.composition.candidate_tree
            or receipt.result_parents != [plan.composition.base_commit]
        ):
            raise MainGraduationJournalError("provider receipt result differs from composition")

    def _require_reconciliation(self, reconciliation: MainReconciliation) -> None:
        transition = self._read("release-transition", reconciliation.operation_id)
        receipt = self._read("provider-receipt", reconciliation.operation_id)
        queue = self._read("queue", reconciliation.operation_id)
        protection = self._read("protection", reconciliation.operation_id)
        plan = self._read("plan", reconciliation.operation_id)
        if (
            transition is None
            or receipt is None
            or queue is None
            or protection is None
            or plan is None
        ):
            raise MainGraduationJournalError(
                "reconciliation requires durable transition and provider result"
            )
        transition_record = cast(MainReleaseTransitionReceipt, transition[0])
        provider = cast(MainProviderReceipt, receipt[0])
        q = cast(MainQueueObservation, queue[0])
        p = cast(MainProtectionManifest, protection[0])
        graduation_plan = cast(MainGraduationPlan, plan[0])
        self._require_release_authorization(transition_record)
        self._require_provider_receipt(provider)
        if reconciliation.state == "completed" and transition_record.outcome not in {
            "transitioned",
            "already_transitioned",
        }:
            raise MainGraduationJournalError(
                "completed reconciliation requires terminal transition"
            )
        if (
            reconciliation.operation_id != transition_record.operation_id
            or reconciliation.repository_digest != q.repository_digest
            or reconciliation.repository_digest != p.repository_digest
            or reconciliation.target_ref != q.target_ref
            or reconciliation.target_ref != p.target_ref
            or reconciliation.transition_receipt_digest != canonical_digest(transition_record)
            or reconciliation.queue_generation_digest != q.queue_generation_digest
        ):
            raise MainGraduationJournalError("reconciliation prior-stage binding differs")
        if reconciliation.state == "completed" and (
            provider.outcome != "observed"
            or reconciliation.main_commit != provider.result_commit
            or reconciliation.main_tree != provider.result_tree
            or reconciliation.main_parents != provider.result_parents
            or reconciliation.expected_tree != graduation_plan.composition.candidate_tree
            or reconciliation.main_tree != graduation_plan.composition.candidate_tree
            or reconciliation.expected_base_commit != graduation_plan.composition.base_commit
            or reconciliation.main_parents != [graduation_plan.composition.base_commit]
        ):
            raise MainGraduationJournalError("completed reconciliation differs from composition")

    def _require_rollback_intent(self, authorization: MainRollbackAuthorization) -> None:
        prior = self._read("rollback-intent", authorization.operation_id)
        if prior is None:
            raise MainGraduationJournalError("rollback authorization requires durable intent")
        intent = cast(MainRollbackIntent, prior[0])
        self._require_inverse_delta(intent)
        if intent.completion_package_digest != authorization.completion_package_digest:
            raise MainGraduationJournalError("rollback package differs from intent")
        if (
            intent.current_main_commit != authorization.current_main_commit
            or intent.current_main_tree != authorization.current_main_tree
            or intent.base_commit != authorization.current_main_commit
            or intent.inverse_delta_digest != authorization.inverse_delta_digest
            or intent.inverse_delta_artifact_digest != authorization.inverse_delta_artifact_digest
            or intent.inverse_tree != authorization.inverse_tree
            or intent.policy_epoch != authorization.policy_epoch
            or intent.repository_digest != authorization.repository_digest
            or intent.target_ref != authorization.target_ref
        ):
            raise MainGraduationJournalError("rollback intent binding differs from authorization")
        if intent.base_commit != authorization.current_main_commit:
            raise MainGraduationJournalError("rollback intent is not current-tip bound")
        if (
            intent.lease_identity != authorization.lease_identity
            or intent.lease_digest != authorization.lease_digest
        ):
            raise MainGraduationJournalError("rollback lease differs from authorization")

    def _require_inverse_delta(self, intent: MainRollbackIntent) -> None:
        prior = self._read("inverse-delta", intent.operation_id)
        if prior is None:
            raise MainGraduationJournalError("rollback intent requires durable inverse delta")
        inverse = cast(MainInverseDeltaArtifact, prior[0])
        completion_prior = self._read("completion", intent.operation_id)
        if completion_prior is None:
            raise MainGraduationJournalError("rollback inverse requires durable completion")
        completion = cast(MainCompletionPackage, completion_prior[0])
        if (
            intent.inverse_delta_artifact_digest != canonical_digest(inverse)
            or intent.inverse_delta_digest != inverse.inverse_delta_digest
            or intent.completion_package_digest != inverse.completion_package_digest
            or inverse.completion_package_digest != canonical_digest(completion)
            or intent.current_main_commit != inverse.current_main_commit
            or intent.current_main_tree != inverse.current_main_tree
            or inverse.current_main_commit != completion.reconciliation.main_commit
            or inverse.current_main_tree != completion.reconciliation.main_tree
            or intent.inverse_tree != inverse.inverse_tree
            or intent.policy_epoch != inverse.policy_epoch
            or intent.repository_digest != inverse.repository_digest
            or intent.target_ref != inverse.target_ref
            or inverse.repository_digest != completion.repository_digest
            or inverse.target_ref != completion.target_ref
        ):
            raise MainGraduationJournalError("rollback inverse delta binding differs")

    def _require_attempt_eligibility(self, attempt: MainGraduationAttempt) -> None:
        prior = self._read("eligibility", attempt.operation_id)
        if prior is None:
            raise MainGraduationJournalError("attempt requires durable eligibility record")
        eligibility = cast(MainGraduationEligibilityRecord, prior[0])
        if (
            eligibility.classification != "eligible"
            or not eligibility.ordinary
            or not eligibility.nonempty
            or attempt.eligibility_record_digest != canonical_digest(eligibility)
            or attempt.scheduler_sequence != eligibility.scheduler_sequence
            or attempt.repository_digest != eligibility.repository_digest
            or attempt.target_ref != eligibility.target_ref
        ):
            raise MainGraduationJournalError("attempt eligibility binding differs")

    def _run_nonce_path(self, stage: str, run_id: str, nonce: str) -> Path:
        # Store an opaque content-addressed key: attacker input cannot escape
        # the index and the original values remain in the canonical record.
        key = canonical_digest({"stage": stage, "run_id": run_id, "nonce": nonce})
        return self._indexes / f"{stage}-run-nonce" / f"{key.removeprefix('sha256:')}.json"

    def _webhook_delivery_path(self, delivery_id: str) -> Path:
        key = canonical_digest({"stage": "merge-group-webhook", "delivery_id": delivery_id})
        return (
            self._indexes / "merge-group-webhook-delivery" / f"{key.removeprefix('sha256:')}.json"
        )

    def _index_webhook_delivery(
        self, record: MainMergeGroupWebhookReceipt, reference: ArtifactRef
    ) -> ArtifactRef | None:
        path = self._webhook_delivery_path(record.delivery_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = canonical_bytes(
            _WebhookDeliveryEnvelope(
                operation_id=record.operation_id,
                delivery_id=record.delivery_id,
                reference=reference,
            )
        )
        try:
            _write_exclusive_durable(path, payload)
            return None
        except FileExistsError:
            try:
                raw = path.read_text(encoding="utf-8").encode("utf-8")
                parsed = json.loads(raw, object_pairs_hook=_strict_pairs)
                current = _WebhookDeliveryEnvelope.model_validate(parsed)
                if canonical_bytes(current) != raw:
                    raise ValueError("webhook delivery index is noncanonical")
                if (
                    current.reference.role != "main-graduation-merge-group-webhook-receipt"
                    or current.reference.media_type
                    != "application/vnd.avo.main-graduation-merge-group-webhook-receipt+json"
                    or current.reference.size_bytes > self._max
                ):
                    raise ValueError("webhook delivery reference metadata mismatch")
                old_data = self._store.read_bytes(current.reference)
                old_parsed = json.loads(old_data.decode("utf-8"), object_pairs_hook=_strict_pairs)
                if canonical_bytes(old_parsed) != old_data:
                    raise ValueError("webhook delivery receipt is noncanonical")
                old = MainMergeGroupWebhookReceipt.model_validate(old_parsed)
            except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
                raise MainGraduationJournalError("webhook delivery index is malformed") from exc
            if (
                current.delivery_id != record.delivery_id
                or current.operation_id != record.operation_id
                or old != record
            ):
                raise MainGraduationRecordConflictError(
                    f"merge-group webhook delivery is already bound: {record.delivery_id}"
                ) from None
            return current.reference
        except OSError as exc:
            raise MainGraduationJournalError("webhook delivery was not durably indexed") from exc

    def _verify_webhook_delivery(
        self, record: MainMergeGroupWebhookReceipt, reference: ArtifactRef | None = None
    ) -> None:
        path = self._webhook_delivery_path(record.delivery_id)
        if not path.is_file():
            raise MainGraduationJournalError("merge-group webhook delivery is not durably indexed")
        try:
            raw = path.read_text(encoding="utf-8").encode("utf-8")
            envelope = _WebhookDeliveryEnvelope.model_validate(
                json.loads(raw, object_pairs_hook=_strict_pairs)
            )
            if canonical_bytes(envelope) != raw:
                raise ValueError("webhook delivery index is noncanonical")
            if envelope.operation_id != record.operation_id:
                raise MainGraduationRecordConflictError("webhook delivery operation differs")
            if (
                envelope.delivery_id != record.delivery_id
                or envelope.reference.role != "main-graduation-merge-group-webhook-receipt"
                or envelope.reference.media_type
                != "application/vnd.avo.main-graduation-merge-group-webhook-receipt+json"
                or envelope.reference.size_bytes > self._max
                or (reference is not None and envelope.reference != reference)
            ):
                raise MainGraduationRecordConflictError("webhook delivery reference differs")
            if self._store.read_bytes(envelope.reference) != canonical_bytes(record):
                raise MainGraduationRecordConflictError("webhook delivery receipt differs")
        except MainGraduationRecordConflictError:
            raise
        except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
            raise MainGraduationJournalError("webhook delivery index is malformed") from exc

    def _require_merge_group_receipt(self, hold: MainReleaseHoldObservation) -> None:
        durable = self._read("merge-group-webhook-receipt", hold.operation_id)
        if durable is None:
            raise MainGraduationJournalError(
                "release hold requires durable merge-group webhook receipt"
            )
        receipt = cast(MainMergeGroupWebhookReceipt, durable[0])
        if receipt != hold.merge_group_receipt:
            raise MainGraduationRecordConflictError(
                "release hold receipt differs from durable receipt"
            )

    def _index_run_nonce(
        self,
        stage: Literal["admission", "hold"],
        record: MainQueueAdmissionObservation | MainReleaseHoldObservation,
        reference: ArtifactRef,
    ) -> ArtifactRef | None:
        if stage == "admission":
            if not isinstance(record, MainQueueAdmissionObservation):
                raise MainGraduationJournalError("admission run/nonce record is malformed")
            run_id, nonce = record.admission_run_id, record.admission_nonce
        else:
            if not isinstance(record, MainReleaseHoldObservation):
                raise MainGraduationJournalError("hold run/nonce record is malformed")
            run_id, nonce = record.hold_run_id, record.hold_nonce
        path = self._run_nonce_path(stage, run_id, nonce)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = canonical_bytes(
            _RunNonceEnvelope(
                stage=stage,
                operation_id=record.operation_id,
                run_id=run_id,
                nonce=nonce,
                reference=reference,
            )
        )
        try:
            _write_exclusive_durable(path, payload)
            return None
        except FileExistsError:
            try:
                raw = path.read_text(encoding="utf-8").encode("utf-8")
                parsed = json.loads(raw, object_pairs_hook=_strict_pairs)
                current = _RunNonceEnvelope.model_validate(parsed)
                if canonical_bytes(current) != raw:
                    raise ValueError("run/nonce index is noncanonical")
            except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
                raise MainGraduationJournalError("run/nonce index is malformed") from exc
            kind = "queue-admission" if stage == "admission" else "release-hold"
            local = self._read(kind, record.operation_id)
            if local is None:
                # The global CAS may have committed immediately before a
                # process crash while the operation-local pointer was still
                # absent.  Recover from the canonical artifact named by the
                # global envelope; never infer from caller data alone.
                try:
                    global_data = self._store.read_bytes(current.reference)
                    parsed_record = (
                        MainQueueAdmissionObservation.model_validate_json(global_data)
                        if stage == "admission"
                        else MainReleaseHoldObservation.model_validate_json(global_data)
                    )
                except FileNotFoundError:
                    raise MainGraduationRecordConflictError(
                        f"{stage} run/nonce is not bound to a local record"
                    ) from None
                except (
                    OSError,
                    RuntimeError,
                    ValueError,
                    TypeError,
                    UnicodeError,
                    json.JSONDecodeError,
                ) as exc:
                    raise MainGraduationJournalError(
                        f"{stage} global run/nonce artifact is malformed"
                    ) from exc
                if (
                    current.stage != stage
                    or current.operation_id != parsed_record.operation_id
                    or current.run_id != run_id
                    or current.nonce != nonce
                    or parsed_record != record
                ):
                    raise MainGraduationRecordConflictError(
                        f"{stage} run/nonce is already bound"
                    ) from None
                return current.reference
            local_record, local_reference = local
            if (
                current.stage != stage
                or current.operation_id != record.operation_id
                or current.run_id != run_id
                or current.nonce != nonce
                or canonical_bytes(local_record) != canonical_bytes(record)
                or current.reference != local_reference
            ):
                raise MainGraduationRecordConflictError(
                    f"{stage} run/nonce is already bound"
                ) from None
            return local_reference
        except OSError as exc:
            raise MainGraduationJournalError("run/nonce was not durably indexed") from exc

    # Public Phase-A surface.  The explicit names keep callers from relying on
    # the internal kind strings and make the read-only boundary auditable.
    def record_lease_evidence_record(self, record: MainLeaseEvidenceRecord) -> ArtifactRef:
        return self._record("lease-evidence-record", record)

    def read_lease_evidence_record(
        self, operation_id: str
    ) -> tuple[MainLeaseEvidenceRecord, ArtifactRef] | None:
        result = self._read("lease-evidence-record", operation_id)
        return cast(tuple[MainLeaseEvidenceRecord, ArtifactRef] | None, result)

    record_main_lease_evidence = record_lease_evidence_record
    read_main_lease_evidence = read_lease_evidence_record

    def assert_lease_evidence(
        self, request: MainLeaseEvidenceReadRequest
    ) -> MainLeaseEvidenceRecord:
        result = self.read_lease_evidence_record(request.operation_id)
        if result is None:
            raise MainGraduationJournalError("main lease evidence is missing")
        record = result[0]
        if record.lease_digest != request.lease_digest or (
            record.repository_digest != request.repository_digest
            or record.target_ref != request.target_ref
        ):
            raise MainGraduationRecordConflictError("main lease evidence binding differs")
        if request.requested_at >= record.expires_at:
            raise MainGraduationJournalError("main lease evidence has expired")
        return record

    def release_target_lease(
        self, repository_digest: str, target_ref: str, operation_id: str, lease_digest: str
    ) -> bool:
        """Release only an exactly matching transient target lease pointer."""
        _check_digest(repository_digest)
        _check_digest(operation_id)
        _check_digest(lease_digest)
        scope = MainBound(repository_digest=repository_digest, target_ref=cast(MainRef, target_ref))
        path = self._target_lease_path(scope)
        if not path.is_file():
            return False
        try:
            raw = path.read_bytes()
            envelope = _TargetLeaseEnvelope.model_validate(
                json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_pairs)
            )
            if canonical_bytes(envelope) != raw:
                raise ValueError("target lease index is noncanonical")
            if envelope.target_scope_digest != main_target_scope_digest(
                repository_digest, target_ref
            ) or (envelope.operation_id, envelope.lease_digest) != (operation_id, lease_digest):
                raise MainGraduationRecordConflictError("target lease release binding differs")
            durable = self.read_lease_evidence_record(operation_id)
            if durable is None or durable[0].lease_digest != lease_digest:
                raise MainGraduationRecordConflictError("target lease release artifact differs")
            if self._store.read_bytes(envelope.reference) != canonical_bytes(durable[0]):
                raise MainGraduationRecordConflictError("target lease release artifact differs")
            path.unlink()
            _sync_directory(path.parent)
            return True
        except MainGraduationRecordConflictError:
            raise
        except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
            raise MainGraduationJournalError("target lease release is unverifiable") from exc

    def record_mutation_intent(self, record: MainMutationIntent) -> ArtifactRef:
        return self._record("mutation-intent", record)

    def read_mutation_intent(
        self, intent_digest: str
    ) -> tuple[MainMutationIntent, ArtifactRef] | None:
        return cast(
            tuple[MainMutationIntent, ArtifactRef] | None,
            self._read("mutation-intent", intent_digest),
        )

    def record_mutation_receipt(self, record: MainMutationReceipt) -> ArtifactRef:
        return self._record("mutation-receipt", record)

    def read_mutation_receipt(
        self, receipt_digest: str
    ) -> tuple[MainMutationReceipt, ArtifactRef] | None:
        return cast(
            tuple[MainMutationReceipt, ArtifactRef] | None,
            self._read("mutation-receipt", receipt_digest),
        )

    def record_release_claim(self, record: MainReleaseClaim) -> ArtifactRef:
        return self._record("release-claim", record)

    def claim_release(self, record: MainReleaseClaim) -> ArtifactRef:
        """Persist the one-use claim with a global create-once CAS."""
        return self.record_release_claim(record)

    def read_release_claim(self, claim_digest: str) -> tuple[MainReleaseClaim, ArtifactRef] | None:
        return cast(
            tuple[MainReleaseClaim, ArtifactRef] | None, self._read("release-claim", claim_digest)
        )

    def record_unresolved_mutation_fence(self, record: MainUnresolvedMutationFence) -> ArtifactRef:
        return self._record("unresolved-mutation-fence", record)

    def read_unresolved_mutation_fence(
        self, fence_digest: str
    ) -> tuple[MainUnresolvedMutationFence, ArtifactRef] | None:
        return cast(
            tuple[MainUnresolvedMutationFence, ArtifactRef] | None,
            self._read("unresolved-mutation-fence", fence_digest),
        )

    def record_mutation_fence_resolution(self, record: MainMutationFenceResolution) -> ArtifactRef:
        return self._record("mutation-fence-resolution", record)

    def read_mutation_fence_resolution(
        self, resolution_digest: str
    ) -> tuple[MainMutationFenceResolution, ArtifactRef] | None:
        return cast(
            tuple[MainMutationFenceResolution, ArtifactRef] | None,
            self._read("mutation-fence-resolution", resolution_digest),
        )

    def assert_no_unresolved_mutation_fence(self, repository_digest: str, target_ref: str) -> None:
        _check_digest(repository_digest)
        scope = MainBound(repository_digest=repository_digest, target_ref=cast(MainRef, target_ref))
        path = self._target_fence_path(scope)
        if not path.exists():
            return
        if not path.is_dir():
            raise MainGraduationJournalError("target mutation fence index is malformed")
        try:
            raw = self._target_fence_record_path(path).read_bytes()
            envelope = _TargetFenceEnvelope.model_validate(
                json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_pairs)
            )
            if canonical_bytes(envelope) != raw:
                raise ValueError("target fence index is noncanonical")
            if self._read("mutation-fence-resolution", envelope.fence_digest) is not None:
                return
        except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
            raise MainGraduationJournalError("target mutation fence is unverifiable") from exc
        raise MainGraduationJournalError("target has an unresolved mutation fence")

    def record_claimed_release_transition(
        self, record: MainClaimedReleaseTransitionReceipt
    ) -> ArtifactRef:
        return self._record("claimed-release-transition", record)

    def read_claimed_release_transition(
        self, receipt_digest: str
    ) -> tuple[MainClaimedReleaseTransitionReceipt, ArtifactRef] | None:
        return cast(
            tuple[MainClaimedReleaseTransitionReceipt, ArtifactRef] | None,
            self._read("claimed-release-transition", receipt_digest),
        )

    def record(self, kind: str, record: StrictModel) -> ArtifactRef:
        return self._record(kind, record)

    def read(self, kind: str, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read(kind, operation_id)

    def _sequence_path(self, sequence: int) -> Path:
        if sequence <= 0:
            raise ValueError("scheduler sequence must be positive")
        return self._indexes / "ledger-sequence" / f"{sequence:020d}.json"

    def _check_eligibility_predecessor(self, record: MainGraduationEligibilityRecord) -> None:
        path = self._sequence_path(record.scheduler_sequence)
        if path.is_file():
            existing = self.read_eligibility_sequence(record.scheduler_sequence)
            if existing is None or existing[0] != record.operation_id:
                raise MainGraduationRecordConflictError(
                    "scheduler sequence is already occupied"
                ) from None
            durable = self._read("eligibility", existing[0])
            if durable is None or canonical_bytes(durable[0]) != canonical_bytes(record):
                raise MainGraduationRecordConflictError(
                    "scheduler sequence differs from canonical eligibility record"
                ) from None
            return
        if record.previous_scheduler_sequence is not None:
            previous = self.read_eligibility_sequence(record.previous_scheduler_sequence)
            if previous is None:
                raise MainGraduationJournalError("scheduler sequence predecessor is missing")
            prior = self.read_eligibility(previous[0])
            if prior is None:
                raise MainGraduationJournalError("scheduler predecessor record is missing")
            prior_record = cast(MainGraduationEligibilityRecord, prior[0])
            if (
                prior_record.classification == "eligible"
                and prior_record.terminal_disposition is None
            ):
                raise MainGraduationJournalError(
                    "later sequence is blocked by open eligible attempt"
                )
        elif record.scheduler_watermark is not None:
            if record.scheduler_sequence != record.scheduler_watermark + 1:
                raise MainGraduationJournalError("scheduler sequence is not adjacent to watermark")
            return
        elif record.scheduler_sequence != 1:
            raise MainGraduationJournalError("scheduler sequence predecessor is required")

    def _index_eligibility_sequence(
        self, record: MainGraduationEligibilityRecord, reference: ArtifactRef
    ) -> None:
        path = self._sequence_path(record.scheduler_sequence)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = canonical_bytes({"operation_id": record.operation_id, "reference": reference})
        try:
            _write_exclusive_durable(path, payload)
        except FileExistsError:
            existing = self.read_eligibility_sequence(record.scheduler_sequence)
            if existing is None or existing[0] != record.operation_id:
                raise MainGraduationRecordConflictError(
                    "scheduler sequence is already occupied"
                ) from None
            durable = self._read("eligibility", existing[0])
            immutable_existing = (
                existing[1].digest,
                existing[1].role,
                existing[1].media_type,
                existing[1].size_bytes,
            )
            immutable_reference = (
                reference.digest,
                reference.role,
                reference.media_type,
                reference.size_bytes,
            )
            if (
                durable is None
                or canonical_bytes(durable[0]) != canonical_bytes(record)
                or immutable_existing != immutable_reference
            ):
                raise MainGraduationRecordConflictError(
                    "scheduler sequence differs from canonical eligibility record"
                ) from None
        except OSError as exc:
            raise MainGraduationJournalError("scheduler sequence was not durably indexed") from exc

    def read_eligibility_sequence(self, sequence: int) -> tuple[str, ArtifactRef] | None:
        path = self._sequence_path(sequence)
        if not path.is_file():
            return None
        try:
            raw = path.read_text(encoding="utf-8").encode("utf-8")
            payload = json.loads(raw, object_pairs_hook=_strict_pairs)
            if set(payload) != {"operation_id", "reference"} or canonical_bytes(payload) != raw:
                raise ValueError("scheduler index is not canonical JSON")
            operation_id = payload["operation_id"]
            reference = ArtifactRef.model_validate(payload["reference"])
            _check_digest(operation_id)
            if (
                reference.role != "main-graduation-eligibility"
                or reference.media_type != "application/vnd.avo.main-graduation-eligibility+json"
            ):
                raise ValueError("scheduler index metadata mismatch")
            data = self._store.read_bytes(reference)
            if len(data) != reference.size_bytes or _digest_bytes(data) != reference.digest:
                raise ValueError("scheduler index artifact hash mismatch")
            durable = self._read("eligibility", operation_id)
            if durable is None:
                raise ValueError("scheduler index eligibility record is missing")
            record, durable_reference = durable
            immutable_sequence_ref = (
                reference.digest,
                reference.role,
                reference.media_type,
                reference.size_bytes,
            )
            immutable_durable_ref = (
                durable_reference.digest,
                durable_reference.role,
                durable_reference.media_type,
                durable_reference.size_bytes,
            )
            if (
                immutable_sequence_ref != immutable_durable_ref
                or cast(MainGraduationEligibilityRecord, record).scheduler_sequence != sequence
            ):
                raise ValueError("scheduler index does not match eligibility record")
            return operation_id, reference
        except (
            OSError,
            ValueError,
            TypeError,
            UnicodeError,
            KeyError,
            json.JSONDecodeError,
        ) as exc:
            raise MainGraduationJournalError("scheduler sequence index is malformed") from exc

    def record_ledger_started(self, record: EligibilityLedgerStarted) -> ArtifactRef:
        return self._record("ledger-started", record)

    def read_ledger_started(self, activation_digest: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("ledger-started", activation_digest)

    def record_plan(self, record: MainGraduationPlan) -> ArtifactRef:
        return self._record("plan", record)

    def read_plan(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("plan", operation_id)

    def record_release_issuer_binding(self, record: MainReleaseIssuerBinding) -> ArtifactRef:
        return self._record("release-issuer-binding", record)

    def read_release_issuer_binding(
        self, operation_id: str
    ) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("release-issuer-binding", operation_id)

    def record_source_package(self, record: MainSourcePackageBinding) -> ArtifactRef:
        return self._record("source-package", record)

    def read_source_package(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("source-package", operation_id)

    def record_delta(self, record: MainDeltaManifest) -> ArtifactRef:
        return self._record("delta", record)

    def read_delta(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("delta", operation_id)

    def record_composition(self, record: MainCompositionArtifact) -> ArtifactRef:
        return self._record("composition", record)

    def read_composition(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("composition", operation_id)

    def read_composition_proof(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("composition-proof", operation_id)

    def record_queue_observation(self, record: MainQueueObservation) -> ArtifactRef:
        return self._record("queue", record)

    def read_queue_observation(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("queue", operation_id)

    def record_protection_manifest(self, record: MainProtectionManifest) -> ArtifactRef:
        return self._record("protection", record)

    def read_protection_manifest(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("protection", operation_id)

    def record_attestation_manifest(self, record: MainAttestationManifest) -> ArtifactRef:
        return self._record("attestations", record)

    def read_attestation_manifest(
        self, operation_id: str
    ) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("attestations", operation_id)

    def record_merge_group_checks(self, record: MainMergeGroupChecks) -> ArtifactRef:
        return self._record("merge-group-checks", record)

    def read_merge_group_checks(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("merge-group-checks", operation_id)

    def record_intent(self, record: MainGraduationIntent) -> ArtifactRef:
        return self._record("intent", record)

    def read_intent(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("intent", operation_id)

    def record_preparation_authorization(self, record: MainPreparationAuthorization) -> ArtifactRef:
        return self._record("preparation-authorization", record)

    def read_preparation_authorization(
        self, operation_id: str
    ) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("preparation-authorization", operation_id)

    def record_queue_admission(self, record: MainQueueAdmissionObservation) -> ArtifactRef:
        return self._record("queue-admission", record)

    def read_queue_admission(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("queue-admission", operation_id)

    def record_release_hold(self, record: MainReleaseHoldObservation) -> ArtifactRef:
        return self._record("release-hold", record)

    def record_merge_group_webhook_receipt(
        self, record: MainMergeGroupWebhookReceipt
    ) -> ArtifactRef:
        return self._record("merge-group-webhook-receipt", record)

    def read_merge_group_webhook_receipt(
        self, operation_id: str
    ) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("merge-group-webhook-receipt", operation_id)

    def read_release_hold(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("release-hold", operation_id)

    def record_release_authorization(self, record: MainReleaseAuthorization) -> ArtifactRef:
        return self._record("release-authorization", record)

    def read_release_authorization(
        self, operation_id: str
    ) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("release-authorization", operation_id)

    def record_release_transition(self, record: MainReleaseTransitionReceipt) -> ArtifactRef:
        return self._record("release-transition", record)

    def read_release_transition(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("release-transition", operation_id)

    def record_provider_receipt(self, record: MainProviderReceipt) -> ArtifactRef:
        return self._record("provider-receipt", record)

    def read_provider_receipt(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("provider-receipt", operation_id)

    def record_reconciliation(self, record: MainReconciliation) -> ArtifactRef:
        return self._record("reconciliation", record)

    def read_reconciliation(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("reconciliation", operation_id)

    def record_rollback_authorization(self, record: MainRollbackAuthorization) -> ArtifactRef:
        return self._record("rollback-authorization", record)

    def read_rollback_authorization(
        self, operation_id: str
    ) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("rollback-authorization", operation_id)

    def record_inverse_delta(self, record: MainInverseDeltaArtifact) -> ArtifactRef:
        return self._record("inverse-delta", record)

    def read_inverse_delta(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("inverse-delta", operation_id)

    def record_rollback_intent(self, record: MainRollbackIntent) -> ArtifactRef:
        return self._record("rollback-intent", record)

    def read_rollback_intent(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("rollback-intent", operation_id)

    def record_attempt(self, record: MainGraduationAttempt) -> ArtifactRef:
        return self._record("attempt", record)

    def read_attempt(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("attempt", operation_id)

    def record_eligibility(self, record: MainGraduationEligibilityRecord) -> ArtifactRef:
        return self._record("eligibility", record)

    def read_eligibility(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("eligibility", operation_id)

    def record_completion(self, record: MainCompletionPackage) -> ArtifactRef:
        return self._record("completion", record)

    def read_completion(self, operation_id: str) -> tuple[StrictModel, ArtifactRef] | None:
        return self._read("completion", operation_id)

    record_package = record_completion
    read_package = read_completion


def _strict_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _sync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    except OSError as exc:
        if os.name == "nt" and exc.errno in {
            errno.EINVAL,
            errno.EACCES,
            errno.ENOTSUP,
            errno.EOPNOTSUPP,
        }:
            return
        raise
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_exclusive_durable(path: Path, payload: bytes) -> None:
    """Publish a complete file without exposing an empty create-once path."""

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        # Hard-link publication is create-once: readers see either no file or
        # the complete payload, never the zero-length temporary destination.
        os.link(temporary, path)
        _sync_directory(path.parent)
    finally:
        with suppress(OSError):
            temporary.unlink()


__all__ = [
    "MainGraduationJournal",
    "MainGraduationJournalError",
    "MainGraduationRecordConflictError",
]
