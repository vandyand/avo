"""Fail-closed quality evidence for an ordinary integration campaign.

This adapter is intentionally independent of hosted Git transport.  A trusted
controller supplies immutable ``ArtifactRef`` records and a resolver.  The
candidate cannot select the trusted policy, issuer allowlists, reviewer
domains, or the set of evidence artifacts.

Evidence is canonical JSON (RFC 8785), with a small bounded schema.  The
artifact digest is the digest of the canonical JSON bytes, while the payload
binds the result to the candidate, source base, provider synthetic merge, and
the discovered protection/check manifests.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol, cast

from pydantic import Field, StrictBool, StrictInt

from avo_correlate.application.integration_campaign_service import (
    CampaignDiscovery,
    CampaignQualityEvidence,
    IntegrationCampaignPrerequisiteError,
    IntegrationCampaignRequest,
)
from avo_correlate.contracts.base import ArtifactRef, NonEmptyString, Sha256Digest, StrictModel
from avo_correlate.contracts.promotion_bundle import PromotionControllerConfig, PromotionDryRunInput
from avo_correlate.contracts.promotion_policy import (
    GateAttestation,
    ReviewerAttestation,
    RollbackAttestation,
)
from avo_correlate.domain.canonical import canonical_bytes


class EvidenceArtifactError(ValueError):
    """Raised when content-addressed evidence is missing, malformed, or stale."""


class QualityArtifactStore(Protocol):
    """Read immutable bytes for an already-authorized artifact reference."""

    def read(self, reference: ArtifactRef) -> bytes: ...

    def resolve(self, digests: Sequence[str]) -> tuple[ArtifactRef, ...]: ...


class _EvidencePayload(StrictModel):
    """Fields every quality artifact must bind exactly."""

    schema_version: Literal[1] = 1
    candidate_digest: Sha256Digest
    base_digest: Sha256Digest
    synthetic_merge_commit: str = Field(pattern=r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
    synthetic_merge_tree: str = Field(pattern=r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
    protection_evidence_digest: Sha256Digest
    issuer_id: NonEmptyString
    evaluation_epoch: StrictInt = Field(ge=0)
    valid_from_epoch: StrictInt = Field(ge=0)
    valid_until_epoch: StrictInt = Field(ge=0)


class _GatePayload(_EvidencePayload):
    kind: Literal["gate"] = "gate"
    gate_name: Literal["private_evaluation", "provenance", "integration_soak"]
    check_evidence_manifest_digest: Sha256Digest
    passed: StrictBool


class _TrustedCheck(StrictModel):
    context: NonEmptyString
    app_id: StrictInt = Field(ge=0)


class _TrustedRun(StrictModel):
    id: StrictInt = Field(gt=0)
    name: NonEmptyString
    app_id: StrictInt = Field(ge=0)
    app_slug: NonEmptyString
    head_sha: str = Field(pattern=r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
    status: Literal["completed"]
    conclusion: Literal["success"]
    completed_at: NonEmptyString


class _TrustedCiPayload(StrictModel):
    """The provider's exact self-describing check manifest."""

    schema_version: Literal[1] = 1
    synthetic_sha: str = Field(pattern=r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
    synthetic_tree: str = Field(pattern=r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
    protection_evidence_digest: Sha256Digest
    provider_identity: NonEmptyString
    provider_api_version: NonEmptyString
    trusted_checks: list[_TrustedCheck] = Field(min_length=1)
    freshness_cutoff: NonEmptyString
    total_count: StrictInt = Field(ge=1)
    page_count: StrictInt = Field(ge=1, le=100)
    runs: list[_TrustedRun] = Field(min_length=1)


class _ReviewerPayload(_EvidencePayload):
    kind: Literal["reviewer"] = "reviewer"
    reviewer_id: NonEmptyString
    reviewer_domain: NonEmptyString
    check_evidence_manifest_digest: Sha256Digest
    approved: StrictBool


class _RollbackPayload(_EvidencePayload):
    kind: Literal["rollback"] = "rollback"
    rollback_count: StrictInt = Field(ge=0)
    check_evidence_manifest_digest: Sha256Digest
    available: StrictBool


_Payload = _TrustedCiPayload | _GatePayload | _ReviewerPayload | _RollbackPayload


@dataclass(frozen=True, slots=True)
class _StoredArtifact:
    reference: ArtifactRef
    data: bytes


class ContentAddressedEvidenceResolver:
    """Exact resolver for controller-created JSON evidence.

    The resolver verifies the reference metadata and SHA-256 bytes on every
    access.  It never substitutes a similarly-shaped artifact or silently
    ignores an unknown digest.
    """

    def __init__(
        self,
        artifacts: Mapping[str, tuple[ArtifactRef, bytes]],
        *,
        max_artifact_bytes: int = 128 * 1024,
    ) -> None:
        if max_artifact_bytes <= 0:
            raise ValueError("max_artifact_bytes must be positive")
        self._max_artifact_bytes = max_artifact_bytes
        self._artifacts: dict[str, _StoredArtifact] = {}
        for digest, (reference, data) in artifacts.items():
            if digest != reference.digest:
                raise EvidenceArtifactError("resolver key does not match artifact digest")
            self._check_bytes(reference, data)
            self._artifacts[digest] = _StoredArtifact(reference, bytes(data))

    def read(self, reference: ArtifactRef) -> bytes:
        stored = self._artifacts.get(reference.digest)
        if stored is None or stored.reference != reference:
            raise EvidenceArtifactError("artifact reference is not an exact stored reference")
        self._check_bytes(reference, stored.data)
        return stored.data

    def resolve(self, digests: Sequence[str]) -> tuple[ArtifactRef, ...]:
        """Resolve exactly the requested sorted, unique digest set."""
        requested = tuple(digests)
        if requested != tuple(sorted(set(requested))):
            raise EvidenceArtifactError("evidence digests must be sorted and unique")
        result: list[ArtifactRef] = []
        for digest in requested:
            stored = self._artifacts.get(digest)
            if stored is None:
                raise EvidenceArtifactError(f"evidence digest is unavailable: {digest}")
            self.read(stored.reference)
            result.append(stored.reference)
        return tuple(result)

    def _check_bytes(self, reference: ArtifactRef, data: bytes) -> None:
        if len(data) > self._max_artifact_bytes:
            raise EvidenceArtifactError("evidence artifact exceeds size limit")
        if reference.size_bytes != len(data):
            raise EvidenceArtifactError("evidence artifact size does not match reference")
        actual = "sha256:" + hashlib.sha256(data).hexdigest()
        if reference.digest != actual:
            raise EvidenceArtifactError("evidence artifact bytes do not match reference digest")


class TrustedCampaignQualityAdapter:
    """Turn an authorized set of evidence artifacts into campaign attestations."""

    _REQUIRED_GATES = frozenset(
        {"trusted_ci", "private_evaluation", "provenance", "integration_soak"}
    )
    _EXPECTED_ROLES = frozenset(
        {
            "trusted-ci-check-manifest",
            "private-regression",
            "provenance-reconstruction",
            "integration-soak",
            "reviewer-decision-1",
            "reviewer-decision-2",
            "rollback-proof",
        }
    )

    def __init__(
        self,
        *,
        resolver: QualityArtifactStore,
        trusted_config: PromotionControllerConfig,
        evidence_artifacts: Sequence[ArtifactRef],
        base_digest: Sha256Digest,
        max_payload_bytes: int = 128 * 1024,
    ) -> None:
        if max_payload_bytes <= 0:
            raise ValueError("max_payload_bytes must be positive")
        refs = tuple(evidence_artifacts)
        if len(refs) != len({ref.digest for ref in refs}):
            raise ValueError("quality evidence references must have unique digests")
        if len(refs) != len({ref.role for ref in refs}):
            raise ValueError("quality evidence references must have unique roles")
        if frozenset(ref.role for ref in refs) != self._EXPECTED_ROLES:
            raise ValueError("quality evidence references do not match the ordinary gate set")
        self._resolver = resolver
        self._trusted_config = trusted_config
        trusted_ci_issuers = trusted_config.policy.trusted_gate_issuers.get("trusted_ci", [])
        if len(trusted_ci_issuers) != 1:
            raise ValueError("trusted CI requires one controller-pinned issuer")
        self._trusted_ci_issuer = trusted_ci_issuers[0]
        self._base_digest = base_digest
        self._refs = refs
        self._max_payload_bytes = max_payload_bytes

    @property
    def evidence_artifacts(self) -> tuple[ArtifactRef, ...]:
        """The controller-authorized refs, in deterministic digest order."""
        return tuple(sorted(self._refs, key=lambda ref: ref.digest))

    def resolve(self, digests: Sequence[str]) -> tuple[ArtifactRef, ...]:
        """Resolve only evidence in this adapter's controller-authorized set."""
        allowed = {ref.digest for ref in self._refs}
        if any(digest not in allowed for digest in digests):
            raise EvidenceArtifactError("requested evidence is outside the authorized set")
        return self._resolver.resolve(digests)

    def evaluate(
        self,
        request: IntegrationCampaignRequest,
        intake: PromotionDryRunInput,
        discovery: CampaignDiscovery,
    ) -> CampaignQualityEvidence:
        if request.candidate_id != intake.candidate_id or request.proposer_id != intake.proposer_id:
            raise IntegrationCampaignPrerequisiteError(
                "quality input identity is not controller-bound"
            )
        if request.source_provenance_digest != intake.source_provenance_digest:
            raise IntegrationCampaignPrerequisiteError("quality provenance is not controller-bound")
        observation = discovery.observation
        refs = self.evidence_artifacts
        payloads = [(ref, self._parse(ref)) for ref in refs]
        self._validate_common(payloads, intake, discovery)

        gates: list[GateAttestation] = []
        reviewers: list[ReviewerAttestation] = []
        rollback: RollbackAttestation | None = None
        gate_names: set[str] = set()
        reviewer_ids: set[str] = set()
        reviewer_domains: set[str] = set()
        policy = self._trusted_config.policy
        proposer_domain = policy.proposer_domains.get(intake.proposer_id)
        if proposer_domain is None:
            raise IntegrationCampaignPrerequisiteError(
                "proposer is absent from trusted domain config"
            )

        for ref, payload in payloads:
            if isinstance(payload, _TrustedCiPayload):
                if "trusted_ci" in gate_names:
                    raise IntegrationCampaignPrerequisiteError("duplicate trusted gate evidence")
                gate_names.add("trusted_ci")
                if (
                    ref.role != "trusted-ci-check-manifest"
                    or ref.digest != observation.check_evidence_manifest_digest
                ):
                    raise IntegrationCampaignPrerequisiteError(
                        "check manifest digest is not discovered"
                    )
                gates.append(
                    GateAttestation(
                        gate_name="trusted_ci",
                        candidate_digest=intake.candidate_digest,
                        base_digest=self._base_digest,
                        evidence_digest=ref.digest,
                        issuer_id=self._trusted_ci_issuer,
                        passed=True,
                        valid_from_epoch=policy.evaluation_epoch,
                        valid_until_epoch=policy.evaluation_epoch,
                    )
                )
            elif isinstance(payload, _GatePayload):
                if payload.gate_name in gate_names:
                    raise IntegrationCampaignPrerequisiteError("duplicate trusted gate evidence")
                gate_names.add(payload.gate_name)
                if not payload.passed:
                    raise IntegrationCampaignPrerequisiteError("trusted quality gate failed")
                issuers = policy.trusted_gate_issuers.get(payload.gate_name, [])
                if payload.issuer_id not in issuers:
                    raise IntegrationCampaignPrerequisiteError("gate issuer is not trusted")
                gates.append(
                    GateAttestation(
                        gate_name=payload.gate_name,
                        candidate_digest=payload.candidate_digest,
                        base_digest=payload.base_digest,
                        evidence_digest=ref.digest,
                        issuer_id=payload.issuer_id,
                        passed=payload.passed,
                        valid_from_epoch=payload.valid_from_epoch,
                        valid_until_epoch=payload.valid_until_epoch,
                    )
                )
            elif isinstance(payload, _ReviewerPayload):
                if (
                    payload.reviewer_id in reviewer_ids
                    or payload.reviewer_domain in reviewer_domains
                ):
                    raise IntegrationCampaignPrerequisiteError("reviewers are not independent")
                reviewer_ids.add(payload.reviewer_id)
                reviewer_domains.add(payload.reviewer_domain)
                if not payload.approved:
                    raise IntegrationCampaignPrerequisiteError("reviewer did not approve")
                if policy.reviewer_domains.get(payload.reviewer_id) != payload.reviewer_domain:
                    raise IntegrationCampaignPrerequisiteError("reviewer domain is not trusted")
                if payload.reviewer_domain == proposer_domain:
                    raise IntegrationCampaignPrerequisiteError("reviewer domain matches proposer")
                if payload.issuer_id not in policy.trusted_reviewer_issuers:
                    raise IntegrationCampaignPrerequisiteError("reviewer issuer is not trusted")
                reviewers.append(
                    ReviewerAttestation(
                        reviewer_id=payload.reviewer_id,
                        candidate_digest=payload.candidate_digest,
                        base_digest=payload.base_digest,
                        evidence_digest=ref.digest,
                        issuer_id=payload.issuer_id,
                        approved=payload.approved,
                        valid_from_epoch=payload.valid_from_epoch,
                        valid_until_epoch=payload.valid_until_epoch,
                    )
                )
            else:
                if rollback is not None:
                    raise IntegrationCampaignPrerequisiteError("duplicate rollback evidence")
                if payload.issuer_id not in policy.rollback_issuer_ids:
                    raise IntegrationCampaignPrerequisiteError("rollback issuer is not trusted")
                if not payload.available or payload.rollback_count > policy.rollback_limit:
                    raise IntegrationCampaignPrerequisiteError("rollback proof is unavailable")
                rollback = RollbackAttestation(
                    rollback_count=payload.rollback_count,
                    candidate_digest=payload.candidate_digest,
                    base_digest=payload.base_digest,
                    evidence_digest=ref.digest,
                    issuer_id=payload.issuer_id,
                    available=payload.available,
                    valid_from_epoch=payload.valid_from_epoch,
                    valid_until_epoch=payload.valid_until_epoch,
                )

        if frozenset(gate_names) != self._REQUIRED_GATES or len(gates) != len(
            self._REQUIRED_GATES
        ):
            raise IntegrationCampaignPrerequisiteError("ordinary campaign gates are incomplete")
        if len(reviewers) != 2 or len(reviewer_domains) != 2:
            raise IntegrationCampaignPrerequisiteError("two independent reviewers are required")
        if rollback is None:
            raise IntegrationCampaignPrerequisiteError("rollback proof is missing")
        return CampaignQualityEvidence(
            gate_attestations=tuple(sorted(gates, key=lambda item: item.gate_name)),
            reviewer_attestations=tuple(sorted(reviewers, key=lambda item: item.reviewer_id)),
            rollback_attestation=rollback,
            evidence_artifacts=tuple(sorted(refs, key=lambda ref: ref.digest)),
            synthetic_merge_commit=observation.synthetic_merge_commit,
            synthetic_merge_tree=observation.synthetic_merge_tree,
            protection_evidence_digest=observation.protection_evidence_digest,
            check_evidence_manifest_digest=observation.check_evidence_manifest_digest,
        )

    def _parse(self, reference: ArtifactRef) -> _Payload:
        try:
            data = self._resolver.read(reference)
        except (EvidenceArtifactError, OSError) as exc:
            raise IntegrationCampaignPrerequisiteError(str(exc)) from exc
        if len(data) > self._max_payload_bytes:
            raise IntegrationCampaignPrerequisiteError(
                "quality evidence payload exceeds size limit"
            )
        if reference.media_type != "application/json":
            raise IntegrationCampaignPrerequisiteError("quality evidence must be JSON")
        try:
            text = data.decode("utf-8", errors="strict")
            parsed = json.loads(
                text,
                object_pairs_hook=self._reject_duplicate_keys,
                parse_constant=self._reject_constant,
            )
            if not isinstance(parsed, dict) or canonical_bytes(parsed) != data:
                raise ValueError("payload is not canonical JSON")
            payload_object = cast(dict[str, object], parsed)
            kind = payload_object.get("kind")
            model: type[_Payload]
            if reference.role == "trusted-ci-check-manifest":
                model = _TrustedCiPayload
            elif kind == "gate":
                model = _GatePayload
            elif kind == "reviewer":
                model = _ReviewerPayload
            elif kind == "rollback":
                model = _RollbackPayload
            else:
                raise ValueError("unknown quality evidence kind")
            return model.model_validate(payload_object)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise IntegrationCampaignPrerequisiteError(
                "malformed or non-canonical quality evidence"
            ) from exc

    @staticmethod
    def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    @staticmethod
    def _reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant: {value}")

    def _validate_common(
        self,
        payloads: Sequence[tuple[ArtifactRef, _Payload]],
        intake: PromotionDryRunInput,
        discovery: CampaignDiscovery,
    ) -> None:
        observation = discovery.observation
        for ref, payload in payloads:
            if isinstance(payload, _TrustedCiPayload):
                if (
                    ref.digest != observation.check_evidence_manifest_digest
                    or payload.synthetic_sha != observation.synthetic_merge_commit
                    or payload.synthetic_tree != observation.synthetic_merge_tree
                    or payload.protection_evidence_digest
                    != observation.protection_evidence_digest
                ):
                    raise IntegrationCampaignPrerequisiteError(
                        "quality evidence is stale or bound to another campaign"
                    )
                continue
            check_digest = payload.check_evidence_manifest_digest
            if (
                payload.candidate_digest != intake.candidate_digest
                or payload.base_digest != self._base_digest
                or payload.synthetic_merge_commit != observation.synthetic_merge_commit
                or payload.synthetic_merge_tree != observation.synthetic_merge_tree
                or payload.protection_evidence_digest != observation.protection_evidence_digest
                or check_digest != observation.check_evidence_manifest_digest
                or payload.evaluation_epoch
                != self._trusted_config.policy.evaluation_epoch
                or not (
                    payload.valid_from_epoch
                    <= payload.evaluation_epoch
                    <= payload.valid_until_epoch
                )
            ):
                raise IntegrationCampaignPrerequisiteError(
                    "quality evidence is stale or bound to another campaign"
                )


__all__ = [
    "ContentAddressedEvidenceResolver",
    "EvidenceArtifactError",
    "TrustedCampaignQualityAdapter",
]
