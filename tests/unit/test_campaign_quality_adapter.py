"""Adversarial tests for the trusted ordinary-campaign evidence adapter."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from avo_correlate.adapters.evidence import (
    ContentAddressedEvidenceResolver,
    EvidenceArtifactError,
    TrustedCampaignQualityAdapter,
)
from avo_correlate.application.integration_campaign_service import (
    CampaignDiscovery,
    IntegrationCampaignPrerequisiteError,
    IntegrationCampaignRequest,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_promotion import IntegrationProviderObservation
from avo_correlate.contracts.promotion_bundle import PromotionControllerConfig, PromotionDryRunInput
from avo_correlate.contracts.promotion_policy import PromotionConfig
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest

CAND = "sha256:" + "c" * 64
BASE = "sha256:" + "b" * 64
PROV = "sha256:" + "e" * 64
PROTECTION = "sha256:" + "d" * 64
GIT = "a" * 40
H = "b" * 40
NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _config() -> PromotionControllerConfig:
    policy = PromotionConfig(
        evaluation_epoch=42,
        trusted_gate_issuers={
            "trusted_ci": ["ci"],
            "private_evaluation": ["private"],
            "provenance": ["prov"],
            "integration_soak": ["soak"],
        },
        trusted_base_issuers=["base"],
        trusted_reviewer_issuers=["review-controller"],
        trusted_path_issuers=["path"],
        rollback_issuer_ids=["rollback"],
        rollback_limit=1,
        reviewer_domains={"reviewer-a": "security", "reviewer-b": "runtime"},
        proposer_domains={"proposer": "authoring"},
        candidate_proposers={CAND: "proposer"},
    )
    return PromotionControllerConfig(
        controller_identity="trusted-controller",
        controller_version="1",
        base_issuer_id="base",
        path_issuer_id="path",
        policy=policy,
    )


def _observation(check_digest: str) -> IntegrationProviderObservation:
    return IntegrationProviderObservation(
        repository_digest=PROV,
        pull_request_number=7,
        pull_request_url="https://github.com/example/avo/pull/7",
        candidate_repository_digest=PROV,
        target_repository_digest=PROV,
        base_ref="refs/heads/integration",
        base_commit=GIT,
        base_tree=GIT,
        head_ref="refs/heads/avo/candidate/entropy",
        head_commit=GIT,
        candidate_tree=GIT,
        synthetic_merge_commit=GIT,
        synthetic_merge_tree=GIT,
        protection_evidence_digest=PROTECTION,
        check_evidence_manifest_digest=check_digest,
        provider_identity="github",
        provider_api_version="2026-01-01",
        open_state="open",
    )


def _context(
    kind: str, issuer: str, *, gate_name: str | None = None, **extra: object
) -> dict[str, object]:
    value: dict[str, object] = {
        "schema_version": 1,
        "kind": kind,
        "candidate_digest": CAND,
        "base_digest": BASE,
        "synthetic_merge_commit": GIT,
        "synthetic_merge_tree": GIT,
        "protection_evidence_digest": PROTECTION,
        "issuer_id": issuer,
        "evaluation_epoch": 42,
        "valid_from_epoch": 42,
        "valid_until_epoch": 42,
    }
    if gate_name is not None:
        value["gate_name"] = gate_name
    value.update(extra)
    return value


def _artifacts() -> tuple[tuple[ArtifactRef, bytes], ...]:
    values: list[tuple[str, dict[str, object]]] = [
        (
            "trusted-ci-check-manifest",
            {
                "schema_version": 1,
                "synthetic_sha": GIT,
                "synthetic_tree": GIT,
                "protection_evidence_digest": PROTECTION,
                "provider_identity": "github",
                "provider_api_version": "2022-11-28",
                "trusted_checks": [{"context": "ci", "app_id": 7}],
                "freshness_cutoff": "2026-01-01T00:00:00Z",
                "total_count": 1,
                "page_count": 1,
                "runs": [
                    {
                        "id": 1,
                        "name": "ci",
                        "app_id": 7,
                        "app_slug": "github-actions",
                        "head_sha": GIT,
                        "status": "completed",
                        "conclusion": "success",
                        "completed_at": "2026-01-01T00:00:01Z",
                    }
                ],
            },
        ),
        (
            "private-regression",
            _context(
                "gate",
                "private",
                gate_name="private_evaluation",
                check_evidence_manifest_digest="sha256:" + "0" * 64,
                passed=True,
            ),
        ),
        (
            "provenance-reconstruction",
            _context(
                "gate",
                "prov",
                gate_name="provenance",
                check_evidence_manifest_digest="sha256:" + "0" * 64,
                passed=True,
            ),
        ),
        (
            "integration-soak",
            _context(
                "gate",
                "soak",
                gate_name="integration_soak",
                check_evidence_manifest_digest="sha256:" + "0" * 64,
                passed=True,
            ),
        ),
        (
            "reviewer-decision-1",
            _context(
                "reviewer",
                "review-controller",
                check_evidence_manifest_digest="sha256:" + "0" * 64,
                reviewer_id="reviewer-a",
                reviewer_domain="security",
                approved=True,
            ),
        ),
        (
            "reviewer-decision-2",
            _context(
                "reviewer",
                "review-controller",
                check_evidence_manifest_digest="sha256:" + "0" * 64,
                reviewer_id="reviewer-b",
                reviewer_domain="runtime",
                approved=True,
            ),
        ),
        (
            "rollback-proof",
            _context(
                "rollback",
                "rollback",
                check_evidence_manifest_digest="sha256:" + "0" * 64,
                rollback_count=0,
                available=True,
            ),
        ),
    ]
    ci_bytes = canonical_bytes(values[0][1])
    check_digest = "sha256:" + hashlib.sha256(ci_bytes).hexdigest()
    result: list[tuple[ArtifactRef, bytes]] = []
    for role, payload in values:
        if role != "trusted-ci-check-manifest":
            payload["check_evidence_manifest_digest"] = check_digest
        data = canonical_bytes(payload)
        ref = ArtifactRef(
            digest=canonical_digest(payload),
            size_bytes=len(data),
            media_type="application/json",
            role=role,
            created_at=NOW,
        )
        result.append((ref, data))
    return tuple(result)


def _adapter(
    *, refs: tuple[tuple[ArtifactRef, bytes], ...], max_payload_bytes: int = 128 * 1024
) -> TrustedCampaignQualityAdapter:
    resolver = ContentAddressedEvidenceResolver({ref.digest: (ref, data) for ref, data in refs})
    return TrustedCampaignQualityAdapter(
        resolver=resolver,
        trusted_config=_config(),
        evidence_artifacts=[ref for ref, _ in refs],
        base_digest=BASE,
        max_payload_bytes=max_payload_bytes,
    )


def _replace_payload(
    refs: list[tuple[ArtifactRef, bytes]], index: int, payload: dict[str, object]
) -> None:
    old_ref, _old_data = refs[index]
    data = canonical_bytes(payload)
    refs[index] = (
        old_ref.model_copy(update={"digest": canonical_digest(payload), "size_bytes": len(data)}),
        data,
    )


def _replace_bytes(
    refs: list[tuple[ArtifactRef, bytes]], index: int, data: bytes, **metadata: object
) -> None:
    old_ref, _old_data = refs[index]
    refs[index] = (
        old_ref.model_copy(
            update={
                "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
                "size_bytes": len(data),
                **metadata,
            }
        ),
        data,
    )


def _inputs(
    refs: tuple[tuple[ArtifactRef, bytes], ...],
) -> tuple[IntegrationCampaignRequest, PromotionDryRunInput, CampaignDiscovery]:
    check_ref = next(ref for ref, _ in refs if ref.role == "trusted-ci-check-manifest")
    observation = _observation(check_ref.digest)
    return (
        IntegrationCampaignRequest(Path("candidate"), "candidate", "proposer", PROV),
        PromotionDryRunInput.model_construct(
            candidate_id="candidate",
            proposer_id="proposer",
            candidate_digest=CAND,
            source_provenance_digest=PROV,
            evidence_digests=[PROV],
        ),
        CampaignDiscovery(observation, GIT, PROV),
    )


def test_valid_controller_evidence_produces_all_attestations() -> None:
    refs = _artifacts()
    request, intake, discovery = _inputs(refs)
    quality = _adapter(refs=refs).evaluate(request, intake, discovery)
    assert {item.gate_name for item in quality.gate_attestations} == {
        "trusted_ci",
        "private_evaluation",
        "provenance",
        "integration_soak",
    }
    assert {item.reviewer_id for item in quality.reviewer_attestations} == {
        "reviewer-a",
        "reviewer-b",
    }
    assert quality.rollback_attestation.available


def test_swapped_synthetic_evidence_is_rejected() -> None:
    refs = list(_artifacts())
    role, data = refs[1]
    payload = json.loads(data)
    payload["synthetic_merge_tree"] = "b" * 40
    replacement = canonical_bytes(payload)
    refs[1] = (
        role.model_copy(
            update={"digest": canonical_digest(payload), "size_bytes": len(replacement)}
        ),
        replacement,
    )
    request, intake, discovery = _inputs(tuple(refs))
    with pytest.raises(IntegrationCampaignPrerequisiteError, match="stale or bound"):
        _adapter(refs=tuple(refs)).evaluate(request, intake, discovery)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("issuer_id", "attacker", "issuer is not trusted"),
        ("reviewer_domain", "authoring", "reviewer domain"),
        ("evaluation_epoch", 41, "stale or bound"),
        ("passed", False, "gate failed"),
    ],
)
def test_wrong_issuer_domain_stale_epoch_and_failed_state_are_rejected(
    field: str, value: object, message: str
) -> None:
    refs = list(_artifacts())
    index = 1 if field in {"issuer_id", "evaluation_epoch", "passed"} else 4
    old_ref, old_data = refs[index]
    payload = json.loads(old_data)
    payload[field] = value
    data = canonical_bytes(payload)
    refs[index] = (
        old_ref.model_copy(update={"digest": canonical_digest(payload), "size_bytes": len(data)}),
        data,
    )
    request, intake, discovery = _inputs(tuple(refs))
    with pytest.raises(IntegrationCampaignPrerequisiteError, match=message):
        _adapter(refs=tuple(refs)).evaluate(request, intake, discovery)


def test_tampered_bytes_and_oversized_payload_are_rejected() -> None:
    refs = _artifacts()
    ref, data = refs[2]
    with pytest.raises(EvidenceArtifactError, match="digest"):
        ContentAddressedEvidenceResolver({ref.digest: (ref, data[:-1] + b" ")})
    with pytest.raises(EvidenceArtifactError, match="size limit"):
        ContentAddressedEvidenceResolver(
            {ref.digest: (ref, data)}, max_artifact_bytes=len(data) - 1
        )


def test_resolver_rejects_unknown_or_unsorted_digests() -> None:
    refs = _artifacts()
    resolver = ContentAddressedEvidenceResolver({ref.digest: (ref, data) for ref, data in refs})
    digests = sorted(ref.digest for ref, _ in refs)
    with pytest.raises(EvidenceArtifactError, match="sorted"):
        resolver.resolve(list(reversed(digests)))
    with pytest.raises(EvidenceArtifactError, match="unavailable"):
        resolver.resolve(["sha256:" + "f" * 64])


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"\xff", "malformed"),
        (b"not-json", "malformed"),
        (b'{"x": 1}', "canonical"),
        (b'{"schema_version":1,"schema_version":1}', "malformed"),
        (b'{"value":NaN}', "malformed"),
    ],
)
def test_malformed_and_noncanonical_quality_payloads_fail_closed(data: bytes, message: str) -> None:
    refs = list(_artifacts())
    _replace_bytes(refs, 1, data)
    request, intake, discovery = _inputs(tuple(refs))
    with pytest.raises(IntegrationCampaignPrerequisiteError, match=message):
        _adapter(refs=tuple(refs)).evaluate(request, intake, discovery)


def test_quality_payload_requires_json_media_type_and_known_shape() -> None:
    refs = list(_artifacts())
    _replace_bytes(
        refs, 1, canonical_bytes({"kind": "not-a-quality-kind"}), media_type="text/plain"
    )
    request, intake, discovery = _inputs(tuple(refs))
    with pytest.raises(IntegrationCampaignPrerequisiteError, match="must be JSON"):
        _adapter(refs=tuple(refs)).evaluate(request, intake, discovery)

    refs = list(_artifacts())
    _replace_bytes(refs, 1, canonical_bytes({"kind": "not-a-quality-kind"}))
    request, intake, discovery = _inputs(tuple(refs))
    with pytest.raises(IntegrationCampaignPrerequisiteError, match="malformed"):
        _adapter(refs=tuple(refs)).evaluate(request, intake, discovery)


def test_resolver_rejects_bad_keys_reads_and_configuration() -> None:
    refs = _artifacts()
    ref, data = refs[0]
    with pytest.raises(EvidenceArtifactError, match="key"):
        ContentAddressedEvidenceResolver({"sha256:" + "f" * 64: (ref, data)})
    resolver = ContentAddressedEvidenceResolver({ref.digest: (ref, data)})
    with pytest.raises(EvidenceArtifactError, match="exact"):
        resolver.read(ref.model_copy(update={"role": "different-role"}))
    with pytest.raises(ValueError, match="positive"):
        ContentAddressedEvidenceResolver({}, max_artifact_bytes=0)
    with pytest.raises(EvidenceArtifactError, match="size"):
        ContentAddressedEvidenceResolver(
            {
                ref.digest: (
                    ref.model_copy(update={"size_bytes": ref.size_bytes + 1}),
                    data,
                )
            }
        )


@pytest.mark.parametrize(
    "refs_update",
    [
        "duplicate_digest",
        "duplicate_role",
        "missing_role",
        "bad_ci_issuers",
    ],
)
def test_adapter_rejects_unauthorized_reference_sets(refs_update: str) -> None:
    refs = list(_artifacts())
    original_refs = tuple(refs)
    if refs_update == "duplicate_digest":
        refs[1] = (refs[0][0], refs[1][1])
    elif refs_update == "duplicate_role":
        refs[1] = (refs[1][0].model_copy(update={"role": refs[0][0].role}), refs[1][1])
    elif refs_update == "missing_role":
        refs = refs[:-1]
    else:
        config = _config().model_copy(
            update={
                "policy": _config().policy.model_copy(
                    update={"trusted_gate_issuers": {"trusted_ci": ["a", "b"]}}
                )
            }
        )
        resolver = ContentAddressedEvidenceResolver({ref.digest: (ref, data) for ref, data in refs})
        with pytest.raises(ValueError, match="one controller"):
            TrustedCampaignQualityAdapter(
                resolver=resolver,
                trusted_config=config,
                evidence_artifacts=[ref for ref, _ in refs],
                base_digest=BASE,
            )
        return
    resolver = ContentAddressedEvidenceResolver(
        {ref.digest: (ref, data) for ref, data in original_refs}
    )
    with pytest.raises(ValueError, match="quality evidence"):
        TrustedCampaignQualityAdapter(
            resolver=resolver,
            trusted_config=_config(),
            evidence_artifacts=[ref for ref, _ in refs],
            base_digest=BASE,
        )


def test_adapter_rejects_invalid_limits_and_out_of_set_resolution() -> None:
    refs = _artifacts()
    with pytest.raises(ValueError, match="positive"):
        _adapter(refs=refs, max_payload_bytes=0)
    adapter = _adapter(refs=refs)
    assert adapter.resolve(sorted(ref.digest for ref, _ in refs)) == adapter.evidence_artifacts
    with pytest.raises(EvidenceArtifactError, match="outside"):
        adapter.resolve(["sha256:" + "f" * 64])


def test_quality_identity_provenance_and_proposer_binding_are_required() -> None:
    refs = _artifacts()
    request, intake, discovery = _inputs(refs)
    adapter = _adapter(refs=refs)
    with pytest.raises(IntegrationCampaignPrerequisiteError, match="identity"):
        adapter.evaluate(replace(request, candidate_id="other"), intake, discovery)
    with pytest.raises(IntegrationCampaignPrerequisiteError, match="identity"):
        adapter.evaluate(request, intake.model_copy(update={"proposer_id": "other"}), discovery)
    with pytest.raises(IntegrationCampaignPrerequisiteError, match="provenance"):
        adapter.evaluate(
            request, intake.model_copy(update={"source_provenance_digest": CAND}), discovery
        )
    with pytest.raises(IntegrationCampaignPrerequisiteError, match="proposer"):
        adapter.evaluate(
            replace(request, proposer_id="unknown"),
            intake.model_copy(update={"proposer_id": "unknown"}),
            discovery,
        )


def test_quality_duplicate_gates_and_nonindependent_reviewers_are_rejected() -> None:
    refs = list(_artifacts())
    payload = json.loads(refs[2][1])
    payload["gate_name"] = "private_evaluation"
    _replace_payload(refs, 2, payload)
    request, intake, discovery = _inputs(tuple(refs))
    with pytest.raises(IntegrationCampaignPrerequisiteError, match="duplicate trusted gate"):
        _adapter(refs=tuple(refs)).evaluate(request, intake, discovery)

    refs = list(_artifacts())
    payload = json.loads(refs[5][1])
    payload["reviewer_id"] = "reviewer-a"
    _replace_payload(refs, 5, payload)
    request, intake, discovery = _inputs(tuple(refs))
    with pytest.raises(IntegrationCampaignPrerequisiteError, match="independent"):
        _adapter(refs=tuple(refs)).evaluate(request, intake, discovery)

    refs = list(_artifacts())
    payload = json.loads(refs[5][1])
    payload["reviewer_domain"] = "security"
    _replace_payload(refs, 5, payload)
    request, intake, discovery = _inputs(tuple(refs))
    with pytest.raises(IntegrationCampaignPrerequisiteError, match="independent"):
        _adapter(refs=tuple(refs)).evaluate(request, intake, discovery)


@pytest.mark.parametrize(
    ("index", "field", "value", "message"),
    [
        (1, "passed", False, "failed"),
        (1, "issuer_id", "attacker", "issuer"),
        (4, "reviewer_domain", "authoring", "domain"),
        (4, "reviewer_id", "reviewer-c", "domain"),
        (6, "issuer_id", "attacker", "rollback issuer"),
        (6, "available", False, "unavailable"),
        (6, "rollback_count", 2, "unavailable"),
    ],
)
def test_quality_attestation_policy_failures_are_rejected(
    index: int, field: str, value: object, message: str
) -> None:
    refs = list(_artifacts())
    payload = json.loads(refs[index][1])
    payload[field] = value
    _replace_payload(refs, index, payload)
    request, intake, discovery = _inputs(tuple(refs))
    with pytest.raises(IntegrationCampaignPrerequisiteError, match=message):
        _adapter(refs=tuple(refs)).evaluate(request, intake, discovery)


def test_quality_missing_rollback_and_incomplete_gates_are_rejected() -> None:
    refs = list(_artifacts())
    payload = json.loads(refs[6][1])
    payload["kind"] = "reviewer"
    payload["reviewer_id"] = "reviewer-c"
    payload["reviewer_domain"] = "runtime"
    payload["approved"] = True
    payload.pop("rollback_count")
    payload.pop("available")
    _replace_payload(refs, 6, payload)
    request, intake, discovery = _inputs(tuple(refs))
    with pytest.raises(IntegrationCampaignPrerequisiteError, match="reviewer domain"):
        _adapter(refs=tuple(refs)).evaluate(request, intake, discovery)

    refs = list(_artifacts())
    payload = json.loads(refs[2][1])
    payload["kind"] = "reviewer"
    payload["reviewer_id"] = "reviewer-c"
    payload["reviewer_domain"] = "runtime"
    payload["approved"] = True
    payload.pop("gate_name")
    payload.pop("passed")
    _replace_payload(refs, 2, payload)
    request, intake, discovery = _inputs(tuple(refs))
    with pytest.raises(IntegrationCampaignPrerequisiteError, match="reviewer domain"):
        _adapter(refs=tuple(refs)).evaluate(request, intake, discovery)


def test_quality_payload_size_and_trusted_ci_observation_binding_are_checked() -> None:
    refs = _artifacts()
    request, intake, discovery = _inputs(refs)
    with pytest.raises(IntegrationCampaignPrerequisiteError, match="size limit"):
        _adapter(refs=refs, max_payload_bytes=1).evaluate(request, intake, discovery)

    adapter = _adapter(refs=refs)
    stale_discovery = replace(
        discovery,
        observation=discovery.observation.model_copy(
            update={"check_evidence_manifest_digest": "sha256:" + "f" * 64}
        ),
    )
    with pytest.raises(IntegrationCampaignPrerequisiteError, match="stale or bound"):
        adapter.evaluate(request, intake, stale_discovery)


def test_quality_stale_trusted_ci_and_provider_read_errors_are_rejected() -> None:
    refs = list(_artifacts())
    payload = json.loads(refs[0][1])
    payload["synthetic_sha"] = H
    _replace_payload(refs, 0, payload)
    request, intake, discovery = _inputs(tuple(refs))
    with pytest.raises(IntegrationCampaignPrerequisiteError, match="stale or bound"):
        _adapter(refs=tuple(refs)).evaluate(request, intake, discovery)

    class FailingStore:
        def read(self, reference: ArtifactRef) -> bytes:
            raise OSError("provider read failed")

        def resolve(self, digests: Sequence[str]) -> tuple[ArtifactRef, ...]:
            return ()

    adapter = TrustedCampaignQualityAdapter(
        resolver=FailingStore(),
        trusted_config=_config(),
        evidence_artifacts=[ref for ref, _ in _artifacts()],
        base_digest=BASE,
    )
    request, intake, discovery = _inputs(_artifacts())
    with pytest.raises(IntegrationCampaignPrerequisiteError, match="provider read"):
        adapter.evaluate(request, intake, discovery)
