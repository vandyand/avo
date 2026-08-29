"""Create-once content-addressed journal for protected-main graduation."""

from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Literal, cast

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.contracts.base import ArtifactRef, StrictModel
from avo_correlate.contracts.integration_campaign import (
    IntegrationCampaignEvidencePackage,
    verify_campaign_package_artifact,
)
from avo_correlate.contracts.main_graduation import (
    EligibilityLedgerStarted,
    MainAttestationManifest,
    MainCompletionPackage,
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
    MainReleaseHoldObservation,
    MainReleaseTransitionReceipt,
    MainRollbackAuthorization,
    MainRollbackIntent,
    MainSourcePackageBinding,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest


class MainGraduationJournalError(RuntimeError):
    """An indexed record is missing, malformed, tampered, or conflicting."""


class MainGraduationRecordConflictError(MainGraduationJournalError):
    """A create-once key was already bound to different canonical bytes."""


_MODELS: dict[str, type[StrictModel]] = {
    "ledger-started": EligibilityLedgerStarted,
    "plan": MainGraduationPlan,
    "source-package": MainSourcePackageBinding,
    "delta": MainDeltaManifest,
    "composition": MainCompositionArtifact,
    "queue": MainQueueObservation,
    "protection": MainProtectionManifest,
    "attestations": MainAttestationManifest,
    "merge-group-checks": MainMergeGroupChecks,
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
}


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


class MainGraduationJournal:
    """Persist one canonical record per operation/ledger key using ``xb`` indexes."""

    def __init__(
        self,
        root: Path,
        *,
        artifact_store: FilesystemArtifactStore | None = None,
        max_record_bytes: int = 32 * 1024 * 1024,
    ) -> None:
        if max_record_bytes <= 0:
            raise ValueError("max_record_bytes must be positive")
        self._root = root.resolve()
        self._indexes = self._root / "main-graduation-index"
        self._store = artifact_store or FilesystemArtifactStore(self._root / "artifacts")
        self._max = max_record_bytes

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
        try:
            data = canonical_bytes(record)
            # Reparse to ensure nested model_construct() values cannot bypass
            # semantic validators at the journal boundary.
            checked = model.model_validate_json(data)
            data = canonical_bytes(checked)
            operation_id = _operation_id(checked)
            if kind == "eligibility":
                self._check_eligibility_predecessor(cast(MainGraduationEligibilityRecord, checked))
            if kind == "attempt":
                self._require_attempt_eligibility(cast(MainGraduationAttempt, checked))
            if kind == "source-package":
                self._verify_source_package(cast(MainSourcePackageBinding, checked))
            elif kind == "plan":
                self._verify_plan_evidence(cast(MainGraduationPlan, checked))
            elif kind == "queue-admission":
                self._require_queue_admission(cast(MainQueueAdmissionObservation, checked))
            elif kind == "release-hold":
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
        index = self._indexes / kind / f"{operation_id.removeprefix('sha256:')}.json"
        index.parent.mkdir(parents=True, exist_ok=True)
        payload = canonical_bytes(reference)
        try:
            with index.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            _sync_directory(index.parent)
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
        except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
            raise MainGraduationJournalError("main graduation index is malformed") from exc

    def _read(self, kind: str, key: str) -> tuple[StrictModel, ArtifactRef] | None:
        if kind not in _MODELS:
            raise ValueError("unknown main graduation record kind")
        _check_digest(key)
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
            elif kind == "queue-admission":
                self._require_queue_admission(cast(MainQueueAdmissionObservation, record))
            elif kind == "release-hold":
                self._require_admission(cast(MainReleaseHoldObservation, record))
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
        return {
            "main-graduation-source-package": package.source_package,
            "main-graduation-delta": package.delta,
            "main-graduation-composition": package.composition,
            "main-graduation-queue-observation": package.queue_observation,
            "main-graduation-protection-manifest": package.protection_manifest,
            "main-graduation-attestation-manifest": package.attestation_manifest,
            "main-graduation-merge-group-checks": package.merge_group_checks,
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
        # Re-run the standalone loaders after exact matching.  This makes a
        # model_construct completion incapable of bypassing nested checks.
        self._verify_source_package(package.source_package)
        self._verify_plan_evidence(package.plan)
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

    def _verify_plan_evidence(self, plan: MainGraduationPlan) -> None:
        """Plans may only cite the raw package and its typed immutable children."""
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

    def _require_exact(self, kind: str, record: StrictModel) -> None:
        durable = self._read(kind, _operation_id(record))
        if durable is None or canonical_bytes(durable[0]) != canonical_bytes(record):
            raise MainGraduationJournalError(f"{kind} is not the durable canonical prior stage")

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
        if (
            receipt.group_sha != authorization.group_sha
            or receipt.hold_run_id != authorization.hold_run_id
            or receipt.hold_nonce != authorization.hold_nonce
            or receipt.release_issuer_app_id != authorization.release_issuer_app_id
            or receipt.issuer_isolation_digest != authorization.issuer_isolation_digest
        ):
            raise MainGraduationJournalError("transition receipt does not bind authorization")

    def _require_provider_receipt(self, receipt: MainProviderReceipt) -> None:
        prior = self._read("release-authorization", receipt.operation_id)
        if prior is None:
            raise MainGraduationJournalError(
                "provider receipt requires durable release authorization"
            )
        authorization = cast(MainReleaseAuthorization, prior[0])
        if (
            receipt.release_authorization_digest != canonical_digest(authorization)
            or receipt.repository_digest != authorization.repository_digest
            or receipt.target_ref != authorization.target_ref
        ):
            raise MainGraduationJournalError("provider receipt authorization binding differs")

    def _require_reconciliation(self, reconciliation: MainReconciliation) -> None:
        transition = self._read("release-transition", reconciliation.operation_id)
        receipt = self._read("provider-receipt", reconciliation.operation_id)
        queue = self._read("queue", reconciliation.operation_id)
        if transition is None or receipt is None or queue is None:
            raise MainGraduationJournalError(
                "reconciliation requires durable transition and provider result"
            )
        transition_record = cast(MainReleaseTransitionReceipt, transition[0])
        provider = cast(MainProviderReceipt, receipt[0])
        q = cast(MainQueueObservation, queue[0])
        if (
            reconciliation.transition_receipt_digest != canonical_digest(transition_record)
            or reconciliation.queue_generation_digest != q.queue_generation_digest
            or reconciliation.main_commit != provider.result_commit
            or reconciliation.main_tree != provider.result_tree
            or reconciliation.main_parents != provider.result_parents
            or reconciliation.expected_base_commit != q.expected_base_commit
        ):
            raise MainGraduationJournalError("reconciliation prior-stage binding differs")

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
        payload = canonical_bytes({"operation_id": record.operation_id, "reference": reference})
        try:
            with path.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            _sync_directory(path.parent)
            return None
        except FileExistsError:
            try:
                current = json.loads(
                    path.read_text(encoding="utf-8"), object_pairs_hook=_strict_pairs
                )
                if canonical_bytes(current) != path.read_text(encoding="utf-8").encode("utf-8"):
                    raise ValueError("run/nonce index is noncanonical")
            except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
                raise MainGraduationJournalError("run/nonce index is malformed") from exc
            original = ArtifactRef.model_validate(current.get("reference"))
            immutable_original = (
                original.digest,
                original.role,
                original.media_type,
                original.size_bytes,
            )
            immutable_replay = (
                reference.digest,
                reference.role,
                reference.media_type,
                reference.size_bytes,
            )
            original_bytes = self._store.read_bytes(original)
            replay_bytes = self._store.read_bytes(reference)
            if (
                current.get("operation_id") != record.operation_id
                or immutable_original != immutable_replay
                or original_bytes != replay_bytes
            ):
                raise MainGraduationRecordConflictError(
                    f"{stage} run/nonce is already bound"
                ) from None
            return original
        except OSError as exc:
            raise MainGraduationJournalError("run/nonce was not durably indexed") from exc

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
            try:
                old_data = path.read_text(encoding="utf-8").encode("utf-8")
                old = json.loads(old_data, object_pairs_hook=_strict_pairs)
                if canonical_bytes(old) != old_data:
                    raise ValueError("scheduler sequence index is not canonical JSON")
            except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
                raise MainGraduationJournalError("scheduler sequence index is malformed") from exc
            if old.get("operation_id") != record.operation_id:
                raise MainGraduationRecordConflictError(
                    "scheduler sequence is already occupied"
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
        elif (
            record.scheduler_watermark is not None
            and record.scheduler_sequence != record.scheduler_watermark + 1
        ):
            raise MainGraduationJournalError("scheduler sequence is not adjacent to watermark")
        elif record.scheduler_sequence != 1:
            raise MainGraduationJournalError("scheduler sequence predecessor is required")

    def _index_eligibility_sequence(
        self, record: MainGraduationEligibilityRecord, reference: ArtifactRef
    ) -> None:
        path = self._sequence_path(record.scheduler_sequence)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = canonical_bytes({"operation_id": record.operation_id, "reference": reference})
        try:
            with path.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            _sync_directory(path.parent)
        except FileExistsError:
            try:
                existing_data = path.read_text(encoding="utf-8").encode("utf-8")
                existing = json.loads(existing_data, object_pairs_hook=_strict_pairs)
                if canonical_bytes(existing) != existing_data:
                    raise ValueError("scheduler sequence index is not canonical JSON")
            except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
                raise MainGraduationJournalError("scheduler sequence index is malformed") from exc
            if existing.get("operation_id") != record.operation_id:
                raise MainGraduationRecordConflictError(
                    "scheduler sequence is already occupied"
                ) from None
        except OSError as exc:
            raise MainGraduationJournalError("scheduler sequence was not durably indexed") from exc

    def read_eligibility_sequence(self, sequence: int) -> tuple[str, ArtifactRef] | None:
        path = self._sequence_path(sequence)
        if not path.is_file():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_strict_pairs)
            if canonical_bytes(payload) != path.read_text(encoding="utf-8").encode("utf-8"):
                raise ValueError("scheduler index is not canonical JSON")
            operation_id = payload["operation_id"]
            reference = ArtifactRef.model_validate(payload["reference"])
            _check_digest(operation_id)
            if reference.role != "main-graduation-eligibility":
                raise ValueError("scheduler index role mismatch")
            self._store.read_bytes(reference)
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


__all__ = [
    "MainGraduationJournal",
    "MainGraduationJournalError",
    "MainGraduationRecordConflictError",
]
