"""Controller-owned, non-mutating promotion bundle generation and replay."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_promotion import CandidatePublicationBinding
from avo_correlate.contracts.promotion_bundle import (
    GitRefSnapshot,
    PromotionBundle,
    PromotionControllerConfig,
    PromotionDryRunInput,
    PromotionDryRunResult,
    PromotionProvenanceBinding,
    PromotionReplayReport,
    RollbackPromotionBundleAuthorization,
    WorkspaceComparison,
    promotion_bundle_bytes,
    promotion_bundle_digest,
    promotion_bundle_payload,
    promotion_policy_payload,
)
from avo_correlate.contracts.promotion_policy import (
    GateAttestation,
    PathManifestAttestation,
    PromotionDecision,
    PromotionOutcome,
    PromotionPolicy,
    PromotionRequest,
    path_manifest_digest,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest


class TrustedPromotionRepository(Protocol):
    def snapshot(self) -> GitRefSnapshot:
        """Return the currently trusted target-ref snapshot."""
        ...

    def compare_candidate(self, root: Path, snapshot: GitRefSnapshot) -> WorkspaceComparison:
        """Compare a candidate tree to the supplied trusted base snapshot."""
        ...


class PromotionStaleBaseError(RuntimeError):
    """The repository changed during bundle construction."""


class PromotionProvenanceError(ValueError):
    """The supplied provenance could not be independently verified."""


class PromotionEvidenceError(ValueError):
    """Controller-owned attestation evidence could not be independently verified."""


class RollbackPromotionAuthorizationJournal:
    """Create-once durable storage for controller rollback authority.

    The content-addressed object store is sufficient for bytes, but it does not
    prevent two different authorizations from being used for one operation.  A
    tiny operation index supplies that missing invariant.
    """

    def __init__(self, artifact_store: FilesystemArtifactStore) -> None:
        self._store = artifact_store
        self._root = artifact_store.root / "rollback-promotion-authorizations"

    def record(
        self,
        authorization: RollbackPromotionBundleAuthorization,
        *,
        canary_package_artifact: ArtifactRef | None = None,
        publication: CandidatePublicationBinding | None = None,
    ) -> ArtifactRef:
        payload = canonical_bytes(authorization)
        reference = self._store.put_bytes(
            payload,
            media_type="application/vnd.avo.rollback-promotion-authorization+json",
            role="rollback-promotion-authorization",
            max_bytes=1024 * 1024,
        )
        index = self._root / authorization.operation_id.removeprefix("sha256:")
        self._root.mkdir(parents=True, exist_ok=True)
        index_payload: dict[str, object] = {
            "authorization": authorization.model_dump(mode="json"),
            "artifact": reference.model_dump(mode="json"),
        }
        if canary_package_artifact is not None:
            index_payload["canary_package_artifact"] = canary_package_artifact.model_dump(
                mode="json"
            )
        if publication is not None:
            index_payload["publication"] = publication.model_dump(mode="json")
        value = canonical_bytes(index_payload)
        try:
            with index.open("xb") as handle:
                handle.write(value)
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError:
            try:
                existing = json.loads(index.read_bytes())
                existing_auth = RollbackPromotionBundleAuthorization.model_validate(
                    existing["authorization"]
                )
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                raise ValueError("rollback authorization index is malformed") from exc
            if existing_auth != authorization:
                raise ValueError("conflicting rollback authorization for operation") from None
            existing_reference = ArtifactRef.model_validate(existing["artifact"])
            if (
                existing_reference.role != "rollback-promotion-authorization"
                or existing_reference.media_type
                != "application/vnd.avo.rollback-promotion-authorization+json"
            ):
                raise ValueError("rollback authorization artifact metadata is malformed") from None
            if self._store.read_bytes(existing_reference) != payload:
                raise ValueError("rollback authorization artifact is missing or corrupt") from None
            if canary_package_artifact is not None:
                existing_canary = ArtifactRef.model_validate(
                    existing.get("canary_package_artifact")
                )
                if existing_canary != canary_package_artifact:
                    raise ValueError("conflicting durable canary package binding") from None
            if publication is not None:
                existing_publication = CandidatePublicationBinding.model_validate(
                    existing.get("publication")
                )
                if existing_publication != publication:
                    raise ValueError("conflicting durable publication binding") from None
            return existing_reference
        return reference

    def require(
        self,
        authorization: RollbackPromotionBundleAuthorization,
        *,
        require_children: bool = False,
    ) -> None:
        index = self._root / authorization.operation_id.removeprefix("sha256:")
        try:
            raw = index.read_bytes()
            if canonical_bytes(json.loads(raw)) != raw:
                raise ValueError("rollback authorization index is not canonical JSON")
            value = json.loads(raw)
            existing = RollbackPromotionBundleAuthorization.model_validate(value["authorization"])
            if existing != authorization:
                raise ValueError("rollback authorization differs from durable authority")
            artifact = value["artifact"]
            reference = ArtifactRef.model_validate(artifact)
            if (
                reference.role != "rollback-promotion-authorization"
                or reference.media_type
                != "application/vnd.avo.rollback-promotion-authorization+json"
            ):
                raise ValueError("rollback authorization artifact metadata is malformed")
            data = self._store.read_bytes(reference)
            if data != canonical_bytes(authorization):
                raise ValueError("rollback authorization artifact differs from durable authority")
            if require_children:
                canary_reference = ArtifactRef.model_validate(value["canary_package_artifact"])
                if (
                    canary_reference.digest != authorization.canary_package_digest
                    or canary_reference.role != "integration-campaign-package"
                    or canary_reference.media_type
                    != "application/vnd.avo.integration-campaign+json"
                ):
                    raise ValueError("durable canary package binding is malformed")
                canary_data = self._store.read_bytes(canary_reference)
                canary_raw = json.loads(
                    canary_data,
                    object_pairs_hook=_strict_object_pairs,
                )
                if canonical_bytes(canary_raw) != canary_data:
                    raise ValueError("durable canary package is not canonical JSON")
                from avo_correlate.contracts.integration_campaign import (
                    IntegrationCampaignEvidencePackage,
                )

                canary = IntegrationCampaignEvidencePackage.model_validate(
                    canary_raw
                )
                if canonical_digest(canary) != authorization.canary_package_digest:
                    raise ValueError("durable canary package differs from authorization")
                publication = CandidatePublicationBinding.model_validate(value["publication"])
                if (
                    publication.repository_digest != authorization.repository_digest
                    or publication.base_commit != authorization.failed_integration_head_commit
                    or publication.base_tree != authorization.failed_integration_head_tree
                    or publication.candidate_commit != authorization.rollback_candidate_commit
                    or publication.candidate_tree != authorization.rollback_candidate_tree
                    or publication.candidate_digest != authorization.candidate_digest
                    or publication.publication_evidence_digest
                    != authorization.publication_evidence_digest
                ):
                    raise ValueError("durable publication differs from authorization")
                if not self._store.exists(authorization.publication_evidence_digest):
                    raise ValueError("publication evidence is missing from durable store")
                publication_data = self._store.path_for_digest(
                    authorization.publication_evidence_digest
                ).read_bytes()
                if (
                    f"sha256:{hashlib.sha256(publication_data).hexdigest()}"
                    != authorization.publication_evidence_digest
                ):
                    raise ValueError("publication evidence digest is corrupt")
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("rollback authorization is not durably recorded") from exc


ProvenanceVerifier = Callable[[str, str, str], object]
EvidenceVerifier = Callable[[str, str, str, str], object]


def _strict_object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


_policy_payload = promotion_policy_payload
_sorted_bundle_payload = promotion_bundle_payload
bundle_bytes = promotion_bundle_bytes


def _provenance_verified(
    verifier: ProvenanceVerifier, digest: str, candidate_digest: str, base_digest: str
) -> bool:
    result = verifier(digest, candidate_digest, base_digest)
    if isinstance(result, bool):
        return result
    return bool(getattr(result, "verified", False))


def _evidence_verified(
    verifier: EvidenceVerifier,
    digest: str,
    issuer_id: str,
    candidate_digest: str,
    base_digest: str,
) -> bool:
    result = verifier(digest, issuer_id, candidate_digest, base_digest)
    if isinstance(result, bool):
        return result
    return bool(getattr(result, "verified", False))


def _path_evidence_digest(candidate_digest: str, base_digest: str, paths: list[str]) -> str:
    manifest_digest = path_manifest_digest(paths)
    return canonical_digest(
        {
            "candidate_digest": candidate_digest,
            "base_digest": base_digest,
            "path_manifest_digest": manifest_digest,
        }
    )


def _base_evidence_digest(snapshot: GitRefSnapshot, candidate_digest: str) -> str:
    return canonical_digest(
        {
            "candidate_digest": candidate_digest,
            "snapshot": snapshot.model_dump(mode="json"),
        }
    )


def _validate_gate_scope(request: PromotionRequest, config: PromotionControllerConfig) -> None:
    risk = PromotionPolicy.derive_risk(request.changed_paths)
    required = config.policy.low_gates if risk.value == "low" else config.policy.ordinary_gates
    unexpected = sorted({item.gate_name for item in request.gate_attestations}.difference(required))
    if unexpected:
        raise ValueError(f"unexpected gate evidence: {','.join(unexpected)}")


class PromotionController:
    def __init__(
        self,
        repository: TrustedPromotionRepository,
        provenance_verifier: ProvenanceVerifier,
        evidence_verifier: EvidenceVerifier,
        artifact_store: FilesystemArtifactStore,
        *,
        trusted_config: PromotionControllerConfig,
        trusted_repository_root: Path,
        trusted_artifact_root: Path,
        max_bundle_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        repository_root = trusted_repository_root.resolve()
        artifact_root = trusted_artifact_root.resolve()
        if artifact_store.root != artifact_root:
            raise ValueError("artifact store root does not match trusted artifact root")
        if _roots_overlap(repository_root, artifact_root):
            raise ValueError("artifact store must not overlap the trusted repository")
        self._repository = repository
        self._provenance_verifier = provenance_verifier
        self._evidence_verifier = evidence_verifier
        self._artifact_store = artifact_store
        self._trusted_config = trusted_config
        self._trusted_repository_root = repository_root
        self._trusted_artifact_root = artifact_root
        self._max_bundle_bytes = max_bundle_bytes
        self._rollback_authorizations = RollbackPromotionAuthorizationJournal(artifact_store)

    def dry_run(
        self,
        request: PromotionDryRunInput,
        *,
        candidate_root: Path,
        config: PromotionControllerConfig | None = None,
    ) -> PromotionDryRunResult:
        """Evaluate and persist one immutable bundle, without changing Git state."""

        if config is not None and config != self._trusted_config:
            raise ValueError(
                "caller supplied a policy configuration different from the trusted one"
            )
        config = self._trusted_config
        candidate_path = candidate_root.resolve(strict=True)
        if _roots_overlap(candidate_path, self._trusted_repository_root):
            raise ValueError("candidate workspace must not overlap the trusted repository")
        if _roots_overlap(candidate_path, self._trusted_artifact_root):
            raise ValueError("candidate workspace must not overlap the artifact store")
        snapshot = self._repository.snapshot()
        comparison = self._repository.compare_candidate(candidate_root, snapshot)
        if comparison.base_digest != snapshot.source_tree_digest:
            raise PromotionStaleBaseError("candidate comparison is based on a stale tree")
        if comparison.candidate_digest != request.candidate_digest:
            raise ValueError("candidate digest does not match the workspace comparison")
        if not _provenance_verified(
            self._provenance_verifier,
            request.source_provenance_digest,
            request.candidate_digest,
            snapshot.source_tree_digest,
        ):
            raise PromotionProvenanceError("source provenance verification failed")
        supplied_evidence = {
            request.source_provenance_digest,
            *(item.evidence_digest for item in request.gate_attestations),
            *(item.evidence_digest for item in request.reviewer_attestations),
        }
        if request.rollback_attestation is not None:
            supplied_evidence.add(request.rollback_attestation.evidence_digest)
        if set(request.evidence_digests) != supplied_evidence:
            raise PromotionEvidenceError("input evidence manifest is incomplete or contains extras")
        external_evidence: list[tuple[str, str]] = [
            *((item.evidence_digest, item.issuer_id) for item in request.gate_attestations),
            *((item.evidence_digest, item.issuer_id) for item in request.reviewer_attestations),
        ]
        if request.rollback_attestation is not None:
            external_evidence.append(
                (
                    request.rollback_attestation.evidence_digest,
                    request.rollback_attestation.issuer_id,
                )
            )
        if any(
            not _evidence_verified(
                self._evidence_verifier,
                digest,
                issuer_id,
                request.candidate_digest,
                snapshot.source_tree_digest,
            )
            for digest, issuer_id in external_evidence
        ) or not _evidence_verified(
            self._evidence_verifier,
            snapshot.protection_evidence_digest,
            config.base_issuer_id,
            request.candidate_digest,
            snapshot.source_tree_digest,
        ):
            raise PromotionEvidenceError("attestation evidence verification failed")

        base_evidence_digest = _base_evidence_digest(snapshot, request.candidate_digest)
        base_attestation = GateAttestation(
            gate_name="base",
            candidate_digest=request.candidate_digest,
            base_digest=snapshot.source_tree_digest,
            evidence_digest=base_evidence_digest,
            issuer_id=config.base_issuer_id,
            passed=True,
            valid_from_epoch=config.policy.evaluation_epoch,
            valid_until_epoch=config.policy.evaluation_epoch,
        )
        path_digest = path_manifest_digest(comparison.changed_paths)
        path_evidence_digest = _path_evidence_digest(
            request.candidate_digest, snapshot.source_tree_digest, comparison.changed_paths
        )
        path_attestation = PathManifestAttestation(
            candidate_digest=request.candidate_digest,
            base_digest=snapshot.source_tree_digest,
            evidence_digest=path_evidence_digest,
            path_manifest_digest=path_digest,
            issuer_id=config.path_issuer_id,
            valid_from_epoch=config.policy.evaluation_epoch,
            valid_until_epoch=config.policy.evaluation_epoch,
        )
        policy_request = PromotionRequest(
            candidate_id=request.candidate_id,
            proposer_id=request.proposer_id,
            candidate_digest=request.candidate_digest,
            base_digest=snapshot.source_tree_digest,
            changed_paths=comparison.changed_paths,
            path_manifest_attestation=path_attestation,
            base_attestation=base_attestation,
            gate_attestations=sorted(
                request.gate_attestations,
                key=lambda item: canonical_bytes(item.model_dump(mode="json")),
            ),
            reviewer_attestations=sorted(
                request.reviewer_attestations,
                key=lambda item: canonical_bytes(item.model_dump(mode="json")),
            ),
            rollback_attestation=request.rollback_attestation,
            exception_requested=request.exception_requested,
        )
        _validate_gate_scope(policy_request, config)
        decision = PromotionPolicy().classify(policy_request, config.policy)
        evidence_values: set[str] = set(request.evidence_digests)
        evidence_values.update(
            {
                request.source_provenance_digest,
                snapshot.protection_evidence_digest,
                base_evidence_digest,
                path_evidence_digest,
            }
        )
        evidence_values.update(item.evidence_digest for item in request.gate_attestations)
        evidence_values.update(item.evidence_digest for item in request.reviewer_attestations)
        if request.rollback_attestation is not None:
            evidence_values.add(request.rollback_attestation.evidence_digest)
        evidence = sorted(evidence_values)
        request_digest = canonical_digest(policy_request)
        controller_config_digest = canonical_digest(_policy_payload(config))
        decision_digest = canonical_digest(decision)
        provenance = PromotionProvenanceBinding(
            candidate_digest=request.candidate_digest,
            base_digest=snapshot.source_tree_digest,
            source_provenance_digest=request.source_provenance_digest,
            request_digest=request_digest,
            controller_config_digest=controller_config_digest,
            decision_digest=decision_digest,
            path_manifest_digest=path_digest,
            evidence_manifest_digest=canonical_digest(evidence),
            verified=True,
        )
        bundle = PromotionBundle(
            snapshot=snapshot,
            comparison=comparison,
            request=policy_request,
            request_digest=request_digest,
            controller_config=config,
            controller_config_digest=controller_config_digest,
            decision=decision,
            decision_digest=decision_digest,
            provenance=provenance,
            evidence_digests=evidence,
        )
        payload = bundle_bytes(bundle)
        digest = promotion_bundle_digest(bundle)

        # This is deliberately the final read before the only side effect.  A stale
        # repository therefore leaves no promotion artifact behind.
        if self._repository.snapshot() != snapshot:
            raise PromotionStaleBaseError("repository changed before bundle write")
        artifact = self._artifact_store.put_bytes(
            payload,
            media_type="application/vnd.avo.promotion-bundle+json",
            role="promotion-bundle",
            max_bytes=self._max_bundle_bytes,
        )
        if artifact.digest != digest:
            raise RuntimeError("artifact store returned an unexpected bundle digest")
        return PromotionDryRunResult(bundle_digest=digest, bundle=bundle, artifact=artifact)

    def create_rollback_bundle(
        self,
        request: object,
        *,
        canary_package: object,
        canary_package_artifact: ArtifactRef,
        drill_authorization: object | None = None,
        authorization: object | None = None,
        candidate_root: Path,
        publication: object,
        config: PromotionControllerConfig | None = None,
    ) -> PromotionDryRunResult:
        """Create a fresh, controller-authorized rollback bundle.

        Every rollback topology value is derived from a trusted package,
        publication, or the current repository.  The request is used only as a
        typed operation identity and is checked against those derived values.
        """

        from avo_correlate.contracts.integration_campaign import IntegrationCampaignEvidencePackage
        from avo_correlate.contracts.integration_drill import (
            IntegrationDrillRollbackAuthorization,
            IntegrationRollbackRequest,
        )
        from avo_correlate.contracts.integration_promotion import CandidatePublicationBinding

        if config is not None and config != self._trusted_config:
            raise ValueError(
                "caller supplied a policy configuration different from the trusted one"
            )
        config = self._trusted_config
        if not isinstance(request, IntegrationRollbackRequest):
            raise TypeError("rollback request must be a trusted IntegrationRollbackRequest")
        if not isinstance(canary_package, IntegrationCampaignEvidencePackage):
            raise TypeError("canary package must be a trusted durable package")
        if drill_authorization is None:
            drill_authorization = authorization
        if not isinstance(drill_authorization, IntegrationDrillRollbackAuthorization):
            raise TypeError("drill authorization must be a trusted durable authorization")
        if not isinstance(publication, CandidatePublicationBinding):
            raise TypeError("publication must be a trusted CandidatePublicationBinding")
        rollback_request = IntegrationRollbackRequest.model_validate(
            request.model_dump(mode="json")
        )
        canary = IntegrationCampaignEvidencePackage.model_validate(
            canary_package.model_dump(mode="json")
        )
        drill = IntegrationDrillRollbackAuthorization.model_validate(
            drill_authorization.model_dump(mode="json")
        )
        candidate_publication = CandidatePublicationBinding.model_validate(
            publication.model_dump(mode="json")
        )
        self._validate_durable_canary(canary, canary_package_artifact)
        self._validate_drill_authorization(rollback_request, drill, config)
        candidate_path = candidate_root.resolve(strict=True)
        if _roots_overlap(candidate_path, self._trusted_repository_root):
            raise ValueError("candidate workspace must not overlap the trusted repository")
        if _roots_overlap(candidate_path, self._trusted_artifact_root):
            raise ValueError("candidate workspace must not overlap the artifact store")

        snapshot = self._repository.snapshot()
        if snapshot.target_ref != "refs/heads/integration":
            raise ValueError("rollback target must be protected integration")
        self._validate_rollback_facts(rollback_request, canary, drill, snapshot)
        comparison = self._repository.compare_candidate(candidate_root, snapshot)
        if comparison.candidate_digest != candidate_publication.candidate_digest:
            raise ValueError("rollback candidate digest differs from trusted publication")
        if (
            candidate_publication.repository_digest != snapshot.repository_digest
            or candidate_publication.base_commit != snapshot.commit
            or candidate_publication.base_tree != snapshot.tree
            or candidate_publication.candidate_tree != canary.intent.base_tree
            or candidate_publication.candidate_commit
            != rollback_request.rollback_candidate_commit
            or not candidate_publication.verified
        ):
            raise ValueError("rollback publication is not bound to the failed target and restore")
        if not _evidence_verified(
            self._evidence_verifier,
            candidate_publication.publication_evidence_digest,
            candidate_publication.controller_publisher_identity,
            comparison.candidate_digest,
            snapshot.source_tree_digest,
        ) or not _provenance_verified(
            self._provenance_verifier,
            candidate_publication.publication_evidence_digest,
            comparison.candidate_digest,
            snapshot.source_tree_digest,
        ):
            raise PromotionEvidenceError("rollback publication evidence verification failed")
        if not _evidence_verified(
            self._evidence_verifier,
            snapshot.protection_evidence_digest,
            config.base_issuer_id,
            comparison.candidate_digest,
            snapshot.source_tree_digest,
        ):
            raise PromotionEvidenceError("rollback base evidence verification failed")
        if not self._artifact_store.exists(candidate_publication.publication_evidence_digest):
            raise PromotionEvidenceError("rollback publication evidence is not durably stored")

        authorization_values = {
            "schema_version": 1,
            "operation_id": rollback_request.operation_id,
            "canary_operation_id": canary.intent.operation_id,
            "canary_package_digest": canonical_digest(canary),
            "drill_authorization_id": canonical_digest(drill),
            "repository_digest": snapshot.repository_digest,
            "target_ref": "refs/heads/integration",
            "main_before_commit": rollback_request.main_before_commit,
            "failed_integration_head_commit": snapshot.commit,
            "failed_integration_head_tree": snapshot.tree,
            "restore_to_commit": canary.intent.base_commit,
            "restore_to_tree": canary.intent.base_tree,
            "rollback_candidate_commit": rollback_request.rollback_candidate_commit,
            "rollback_candidate_tree": candidate_publication.candidate_tree,
            "rollback_candidate_parent_commit": snapshot.commit,
            "candidate_digest": comparison.candidate_digest,
            "source_tree_digest": snapshot.source_tree_digest,
            "restore_tree_digest": comparison.candidate_digest,
            "publication_evidence_digest": candidate_publication.publication_evidence_digest,
            "issuer_id": drill.issuer,
            "reason": drill.reason,
            "authorized": True,
        }
        authorization = RollbackPromotionBundleAuthorization.model_validate(
            {
                **authorization_values,
                "authorization_id": canonical_digest(authorization_values),
            }
        )
        self._rollback_authorizations.record(
            authorization,
            canary_package_artifact=canary_package_artifact,
            publication=candidate_publication,
        )

        base_evidence_digest = _base_evidence_digest(snapshot, comparison.candidate_digest)
        path_digest = path_manifest_digest(comparison.changed_paths)
        path_evidence_digest = _path_evidence_digest(
            comparison.candidate_digest, snapshot.source_tree_digest, comparison.changed_paths
        )
        base_attestation = GateAttestation(
            gate_name="base",
            candidate_digest=comparison.candidate_digest,
            base_digest=snapshot.source_tree_digest,
            evidence_digest=base_evidence_digest,
            issuer_id=config.base_issuer_id,
            passed=True,
            valid_from_epoch=config.policy.evaluation_epoch,
            valid_until_epoch=config.policy.evaluation_epoch,
        )
        path_attestation = PathManifestAttestation(
            candidate_digest=comparison.candidate_digest,
            base_digest=snapshot.source_tree_digest,
            evidence_digest=path_evidence_digest,
            path_manifest_digest=path_digest,
            issuer_id=config.path_issuer_id,
            valid_from_epoch=config.policy.evaluation_epoch,
            valid_until_epoch=config.policy.evaluation_epoch,
        )
        policy_request = PromotionRequest(
            candidate_id=f"rollback-{rollback_request.operation_id.removeprefix('sha256:')}",
            proposer_id=config.controller_identity,
            candidate_digest=comparison.candidate_digest,
            base_digest=snapshot.source_tree_digest,
            changed_paths=comparison.changed_paths,
            path_manifest_attestation=path_attestation,
            base_attestation=base_attestation,
            gate_attestations=[],
            reviewer_attestations=[],
            rollback_attestation=None,
            exception_requested=False,
        )
        decision = PromotionDecision(
            candidate_id=policy_request.candidate_id,
            outcome=PromotionOutcome.ALLOW,
            risk_class=PromotionPolicy.derive_risk(comparison.changed_paths),
            reason_codes=["authorized_rollback"],
            required_quorum=0,
        )
        evidence = sorted(
            {
                candidate_publication.publication_evidence_digest,
                snapshot.protection_evidence_digest,
                base_evidence_digest,
                path_evidence_digest,
                authorization.authorization_id,
                authorization.canary_package_digest,
            }
        )
        request_digest = canonical_digest(policy_request)
        controller_config_digest = canonical_digest(_policy_payload(config))
        decision_digest = canonical_digest(decision)
        provenance = PromotionProvenanceBinding(
            candidate_digest=comparison.candidate_digest,
            base_digest=snapshot.source_tree_digest,
            source_provenance_digest=candidate_publication.publication_evidence_digest,
            request_digest=request_digest,
            controller_config_digest=controller_config_digest,
            decision_digest=decision_digest,
            path_manifest_digest=path_digest,
            evidence_manifest_digest=canonical_digest(evidence),
            verified=True,
        )
        bundle = PromotionBundle(
            snapshot=snapshot,
            comparison=comparison,
            request=policy_request,
            request_digest=request_digest,
            controller_config=config,
            controller_config_digest=controller_config_digest,
            decision=decision,
            decision_digest=decision_digest,
            provenance=provenance,
            evidence_digests=evidence,
            rollback_operation_id=authorization.operation_id,
            rollback_authorization=authorization,
        )
        payload = bundle_bytes(bundle)
        digest = promotion_bundle_digest(bundle)
        if self._repository.snapshot() != snapshot:
            raise PromotionStaleBaseError("repository changed before bundle write")
        artifact = self._artifact_store.put_bytes(
            payload,
            media_type="application/vnd.avo.promotion-bundle+json",
            role="promotion-bundle",
            max_bytes=self._max_bundle_bytes,
        )
        if artifact.digest != digest:
            raise RuntimeError("artifact store returned an unexpected bundle digest")
        return PromotionDryRunResult(bundle_digest=digest, bundle=bundle, artifact=artifact)

    def rollback_dry_run(self, request: object, **kwargs: object) -> PromotionDryRunResult:
        """Compatibility name for the controller-owned rollback constructor."""

        return self.create_rollback_bundle(request, **kwargs)  # type: ignore[arg-type]

    def _validate_durable_canary(self, canary: Any, reference: ArtifactRef) -> None:
        if (
            reference.digest != canonical_digest(canary)
            or reference.role != "integration-campaign-package"
            or reference.media_type != "application/vnd.avo.integration-campaign+json"
            or reference.size_bytes != len(canonical_bytes(canary))
        ):
            raise ValueError("canary package artifact is not the durable canonical package")
        try:
            data = self._artifact_store.read_bytes(reference)
            parsed = json.loads(data, object_pairs_hook=_strict_object_pairs)
            if canonical_bytes(parsed) != data:
                raise ValueError("canary package artifact is not canonical JSON")
            canary.__class__.model_validate(parsed)
        except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise ValueError("durable canary package is missing or malformed") from exc

    @staticmethod
    def _validate_drill_authorization(
        request: Any,
        authorization: Any,
        config: PromotionControllerConfig,
    ) -> None:
        if (
            authorization.operation_id != request.operation_id
            or authorization.repository_digest != request.repository_digest
            or authorization.target_ref != "refs/heads/integration"
            or authorization.main_before_commit != request.main_before_commit
            or authorization.main_after_commit != request.main_before_commit
            or authorization.failed_integration_head_commit
            != request.failed_integration_head_commit
            or authorization.failed_integration_head_tree != request.failed_integration_head_tree
            or authorization.restore_to_commit != request.restore_to_commit
            or authorization.restore_to_tree != request.restore_to_tree
            or authorization.rollback_candidate_commit
            != request.rollback_candidate_commit
            or authorization.rollback_candidate_parent_commit
            != request.rollback_candidate_parent_commit
            or authorization.issuer not in config.policy.rollback_issuer_ids
            or authorization.authorization_id
            != canonical_digest(authorization.model_dump(exclude={"authorization_id"}, mode="json"))
        ):
            raise ValueError("drill rollback authorization is stale or untrusted")

    @staticmethod
    def _validate_rollback_facts(
        request: Any, canary: Any, drill: Any, snapshot: GitRefSnapshot
    ) -> None:
        canary_intent = canary.intent
        canary_receipt = canary.receipt
        if (
            request.repository_digest != snapshot.repository_digest
            or request.target_ref != "refs/heads/integration"
            or request.failed_integration_head_commit != snapshot.commit
            or request.failed_integration_head_tree != snapshot.tree
            or request.restore_to_commit != canary_intent.base_commit
            or request.restore_to_tree != canary_intent.base_tree
            or request.rollback_candidate_parent_commit != snapshot.commit
        ):
            raise ValueError("rollback request is not bound to current target or canary")
        if (
            canary.report.outcome not in {"applied", "already_applied"}
            or canary.deploy_performed
            or canary.intent.target_ref != request.target_ref
            or canary.intent.repository_digest != request.repository_digest
            or canary.main_before_commit != request.main_before_commit
            or canary.main_after_commit != request.main_before_commit
            or canary_receipt.applied_result_commit != snapshot.commit
            or canary_receipt.applied_result_tree != snapshot.tree
            or drill.target_head_commit != snapshot.commit
            or drill.target_head_tree != snapshot.tree
        ):
            raise ValueError("successful canary is not the exact current failed target")

    def replay(
        self,
        bundle: PromotionBundle | bytes,
        *,
        bundle_digest: str,
        repository: TrustedPromotionRepository | None = None,
    ) -> PromotionReplayReport:
        """Verify a bundle and replay its CAS precondition without mutation."""

        checks: list[str] = []
        errors: list[str] = []
        try:
            if isinstance(bundle, bytes):
                raw = json.loads(bundle, object_pairs_hook=_strict_object_pairs)
                if not isinstance(raw, dict) or canonical_bytes(raw) != bundle:
                    raise ValueError("bundle is not canonical JSON")
                parsed = PromotionBundle.model_validate(raw)
            else:
                # Re-validate model instances as well.  ``model_copy`` and
                # ``model_construct`` can otherwise hand us a partially
                # trusted nested object that bypassed PromotionBundle's
                # cross-record validators.
                parsed = PromotionBundle.model_validate(bundle.model_dump(mode="json"))
            if (
                parsed.rollback_authorization is None
                and parsed.snapshot.target_ref == "refs/heads/integration"
                and parsed.request.rollback_attestation is not None
            ):
                raise ValueError("legacy rollback bundles require controller authorization")
            expected = promotion_bundle_digest(parsed)
            if expected != bundle_digest:
                raise ValueError("bundle digest mismatch")
            checks.append("bundle_digest")
            if parsed.request_digest != canonical_digest(parsed.request):
                raise ValueError("request digest mismatch")
            if parsed.controller_config_digest != canonical_digest(
                _policy_payload(parsed.controller_config)
            ):
                raise ValueError("controller config digest mismatch")
            if parsed.controller_config != self._trusted_config:
                raise ValueError("bundle uses a policy configuration outside this controller")
            if parsed.decision_digest != canonical_digest(parsed.decision):
                raise ValueError("decision digest mismatch")
            if parsed.request.candidate_digest != parsed.comparison.candidate_digest:
                raise ValueError("candidate binding mismatch")
            if parsed.request.base_digest != parsed.comparison.base_digest:
                raise ValueError("base binding mismatch")
            if parsed.comparison.base_digest != parsed.snapshot.source_tree_digest:
                raise ValueError("snapshot source-tree binding mismatch")
            base_evidence = _base_evidence_digest(parsed.snapshot, parsed.request.candidate_digest)
            if parsed.request.base_attestation.evidence_digest != base_evidence:
                raise ValueError("trusted-base evidence binding mismatch")
            if (
                parsed.request.base_attestation.gate_name != "base"
                or not parsed.request.base_attestation.passed
            ):
                raise ValueError("trusted-base attestation is not a passing base result")
            path_attestation = parsed.request.path_manifest_attestation
            if path_attestation.path_manifest_digest != path_manifest_digest(
                parsed.comparison.changed_paths
            ):
                raise ValueError("path manifest binding mismatch")
            path_evidence = _path_evidence_digest(
                parsed.request.candidate_digest,
                parsed.request.base_digest,
                parsed.comparison.changed_paths,
            )
            if path_attestation.evidence_digest != path_evidence:
                raise ValueError("path evidence binding mismatch")
            if parsed.provenance.source_provenance_digest not in parsed.evidence_digests:
                raise ValueError("provenance evidence is not listed")
            if parsed.provenance.verified is not True:
                raise ValueError("provenance binding is not verified")
            expected_evidence = {
                parsed.provenance.source_provenance_digest,
                parsed.snapshot.protection_evidence_digest,
                base_evidence,
                path_evidence,
                *(item.evidence_digest for item in parsed.request.gate_attestations),
                *(item.evidence_digest for item in parsed.request.reviewer_attestations),
            }
            if parsed.request.rollback_attestation is not None:
                expected_evidence.add(parsed.request.rollback_attestation.evidence_digest)
            if parsed.rollback_authorization is not None:
                expected_evidence.update(
                    {
                        parsed.rollback_authorization.authorization_id,
                        parsed.rollback_authorization.canary_package_digest,
                    }
                )
            if set(parsed.evidence_digests) != expected_evidence:
                raise ValueError("bundle evidence manifest differs from referenced evidence")
            if parsed.provenance.evidence_manifest_digest != canonical_digest(
                parsed.evidence_digests
            ):
                raise ValueError("evidence manifest digest mismatch")
            if not _provenance_verified(
                self._provenance_verifier,
                parsed.provenance.source_provenance_digest,
                parsed.request.candidate_digest,
                parsed.request.base_digest,
            ):
                raise ValueError("provenance verification failed")
            replay_evidence: list[tuple[str, str]] = [
                *(
                    (item.evidence_digest, item.issuer_id)
                    for item in parsed.request.gate_attestations
                ),
                *(
                    (item.evidence_digest, item.issuer_id)
                    for item in parsed.request.reviewer_attestations
                ),
            ]
            if parsed.request.rollback_attestation is not None:
                replay_evidence.append(
                    (
                        parsed.request.rollback_attestation.evidence_digest,
                        parsed.request.rollback_attestation.issuer_id,
                    )
                )
            if any(
                not _evidence_verified(
                    self._evidence_verifier,
                    digest,
                    issuer_id,
                    parsed.request.candidate_digest,
                    parsed.request.base_digest,
                )
                for digest, issuer_id in replay_evidence
            ) or not _evidence_verified(
                self._evidence_verifier,
                parsed.snapshot.protection_evidence_digest,
                parsed.controller_config.base_issuer_id,
                parsed.request.candidate_digest,
                parsed.request.base_digest,
            ):
                raise ValueError("attestation evidence verification failed")
            checks.extend(("controller_config", "decision", "provenance"))
            if parsed.rollback_authorization is not None:
                authorization = parsed.rollback_authorization
                if (
                    authorization.issuer_id
                    not in parsed.controller_config.policy.rollback_issuer_ids
                    or authorization.publication_evidence_digest
                    != parsed.provenance.source_provenance_digest
                    or authorization.authorization_id
                    != canonical_digest(
                        authorization.model_dump(exclude={"authorization_id"}, mode="json")
                    )
                ):
                    raise ValueError("rollback authorization issuer or digest is invalid")
                self._rollback_authorizations.require(authorization, require_children=True)
                checks.append("rollback_authorization")
                active_repository = repository or self._repository
                if active_repository.snapshot() != parsed.snapshot:
                    return PromotionReplayReport(
                        bundle_digest=bundle_digest,
                        outcome="stale_base",
                        checks=[*checks, "cas_precondition"],
                        errors=["cas_precondition_mismatch"],
                    )
                checks.append("cas_precondition")
                return PromotionReplayReport(
                    bundle_digest=bundle_digest,
                    outcome="would_apply",
                    checks=checks,
                )
            decision = PromotionPolicy().classify(parsed.request, parsed.controller_config.policy)
            _validate_gate_scope(parsed.request, parsed.controller_config)
            if decision != parsed.decision:
                raise ValueError("classification replay differs")
            checks.append("classification")
            if decision.outcome.value != "allow":
                return PromotionReplayReport(
                    bundle_digest=bundle_digest,
                    outcome="not_applicable",
                    checks=[*checks, "cas_not_applicable"],
                    errors=[f"promotion_outcome:{decision.outcome.value}"],
                )
            active_repository = repository or self._repository
            if active_repository.snapshot() != parsed.snapshot:
                return PromotionReplayReport(
                    bundle_digest=bundle_digest,
                    outcome="stale_base",
                    checks=[*checks, "cas_precondition"],
                    errors=["cas_precondition_mismatch"],
                )
            checks.append("cas_precondition")
            return PromotionReplayReport(
                bundle_digest=bundle_digest,
                outcome="would_apply",
                checks=checks,
            )
        except (ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            errors.append(str(exc))
            return PromotionReplayReport(
                bundle_digest=bundle_digest,
                outcome="invalid_bundle",
                checks=checks or ["bundle_parse"],
                errors=errors,
            )


def _roots_overlap(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


__all__ = [
    "PromotionController",
    "PromotionEvidenceError",
    "PromotionProvenanceError",
    "PromotionStaleBaseError",
    "RollbackPromotionAuthorizationJournal",
    "TrustedPromotionRepository",
    "bundle_bytes",
]
