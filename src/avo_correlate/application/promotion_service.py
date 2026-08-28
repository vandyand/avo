"""Controller-owned, non-mutating promotion bundle generation and replay."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from avo_correlate.adapters.artifacts.filesystem import FilesystemArtifactStore
from avo_correlate.contracts.promotion_bundle import (
    GitRefSnapshot,
    PromotionBundle,
    PromotionControllerConfig,
    PromotionDryRunInput,
    PromotionDryRunResult,
    PromotionProvenanceBinding,
    PromotionReplayReport,
    WorkspaceComparison,
    promotion_bundle_bytes,
    promotion_bundle_digest,
    promotion_bundle_payload,
    promotion_policy_payload,
)
from avo_correlate.contracts.promotion_policy import (
    GateAttestation,
    PathManifestAttestation,
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
                parsed = bundle
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
    "TrustedPromotionRepository",
    "bundle_bytes",
]
