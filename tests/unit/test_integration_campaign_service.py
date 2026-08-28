import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from avo_correlate.application.integration_campaign_service import (
    CampaignDiscovery,
    CampaignFinalEvidence,
    CampaignOpened,
    CampaignPreparation,
    CampaignQualityEvidence,
    IntegrationCampaignPrerequisiteError,
    IntegrationCampaignRequest,
    IntegrationCampaignService,
    campaign_open_identity,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_promotion import (
    CandidatePublicationBinding,
    IntegrationProviderObservation,
)
from avo_correlate.contracts.promotion_bundle import (
    PromotionControllerConfig,
    PromotionDryRunInput,
    PromotionDryRunResult,
)
from avo_correlate.contracts.promotion_policy import (
    GateAttestation,
    ReviewerAttestation,
    RollbackAttestation,
)

D = "sha256:" + "a" * 64
G = "a" * 40


class Intake:
    def __init__(self, value: PromotionDryRunInput) -> None:
        self.value = value

    def collect(self, request: IntegrationCampaignRequest) -> PromotionDryRunInput:
        del request
        return self.value


class Quality:
    def __init__(self, value: CampaignQualityEvidence) -> None:
        self.value = value
        self.calls = 0

    def evaluate(
        self,
        request: IntegrationCampaignRequest,
        intake: PromotionDryRunInput,
        discovery: CampaignDiscovery,
    ) -> CampaignQualityEvidence:
        del request, intake, discovery
        self.calls += 1
        return self.value


class Provider:
    def __init__(self) -> None:
        self.prepare_calls = 0

    def prepare(self, publication: Any, bundle: Any, bundle_digest: str) -> Any:
        del publication, bundle, bundle_digest
        self.prepare_calls += 1
        raise AssertionError("provider preparation must not be reached")

    def open_or_reconcile(self, publication: CandidatePublicationBinding) -> CampaignOpened:
        opened = CampaignOpened(
            1,
            "https://github.com/o/r/pull/1",
            "refs/heads/integration",
            G,
            G,
            D,
        )
        return replace(opened, open_identity=campaign_open_identity(publication, opened))

    def discover(
        self, opened: CampaignOpened, publication: CandidatePublicationBinding
    ) -> CampaignDiscovery:
        del publication
        return CampaignDiscovery(
            IntegrationProviderObservation.model_construct(
                repository_digest=D,
                pull_request_number=opened.pull_request_number,
                pull_request_url=opened.pull_request_url,
                candidate_repository_digest=D,
                target_repository_digest=D,
                base_ref=opened.target_ref,
                base_commit=G,
                base_tree=G,
                head_ref="refs/heads/avo/candidate/x",
                head_commit=G,
                candidate_tree=G,
                synthetic_merge_commit=G,
                synthetic_merge_tree=G,
                protection_evidence_digest=D,
                check_evidence_manifest_digest=D,
                provider_identity="github",
                provider_api_version="v1",
                open_state="open",
                draft=False,
            ),
            G,
            opened.open_identity,
        )


class Controller:
    def __init__(self, result: PromotionDryRunResult) -> None:
        self.result = result
        self.calls = 0

    def dry_run(self, request: Any, *, candidate_root: Path, config: Any) -> PromotionDryRunResult:
        del request, candidate_root, config
        self.calls += 1
        return self.result


class Main:
    def head_commit(self) -> str:
        return G


class Journal:
    def read_intent(self, operation_id: str) -> None:
        del operation_id
        return None

    def read_receipt(self, operation_id: str) -> None:
        del operation_id
        return None

    def read_lease_evidence(self, operation_id: str) -> None:
        del operation_id
        return None


def request() -> IntegrationCampaignRequest:
    return IntegrationCampaignRequest(Path("candidate"), "candidate", "proposer", D)


def intake(*, with_policy: bool = False) -> PromotionDryRunInput:
    return PromotionDryRunInput.model_construct(
        candidate_id="candidate",
        proposer_id="proposer",
        candidate_digest=D,
        source_provenance_digest=D,
        evidence_digests=[D],
        gate_attestations=[object()] if with_policy else [],
        reviewer_attestations=[],
        rollback_attestation=None,
    )


def service(
    intake_value: PromotionDryRunInput,
    quality_value: CampaignQualityEvidence,
    provider: Provider,
    controller: Controller,
) -> IntegrationCampaignService:
    return IntegrationCampaignService(
        controller=controller,  # type: ignore[arg-type]
        promotion=object(),  # type: ignore[arg-type]
        journal=Journal(),  # type: ignore[arg-type]
        intake=Intake(intake_value),
        quality=Quality(quality_value),
        provider=provider,  # type: ignore[arg-type]
        publication_verifier=lambda publication, bundle: True,
        evidence_resolver=object(),  # type: ignore[arg-type]
        artifact_writer=object(),  # type: ignore[arg-type]
        main_state=Main(),
        trusted_config=object(),  # type: ignore[arg-type]
    )


def quality() -> CampaignQualityEvidence:
    return CampaignQualityEvidence((), (), object(), (), G, G, D, D)  # type: ignore[arg-type]


def dry_run() -> PromotionDryRunResult:
    bundle = object()
    return PromotionDryRunResult.model_construct(
        bundle=bundle,
        bundle_digest=D,
        artifact=ArtifactRef.model_construct(digest=D, size_bytes=0, media_type="x", role="x"),
    )


def publication() -> CandidatePublicationBinding:
    return CandidatePublicationBinding.model_construct(
        repository_digest=D,
        base_commit=G,
        base_tree=G,
        candidate_digest=D,
        candidate_ref="refs/heads/avo/candidate/x",
        candidate_commit=G,
        candidate_tree=G,
        controller_publisher_identity="controller",
        publication_evidence_digest=D,
        verified=True,
    )


def test_candidate_cannot_supply_policy_or_evidence() -> None:
    provider = Provider()
    controller = Controller(dry_run())
    with pytest.raises(IntegrationCampaignPrerequisiteError, match="cannot supply policy"):
        service(intake(with_policy=True), quality(), provider, controller).run(
            request(), publication=publication()
        )
    assert provider.prepare_calls == 0
    assert controller.calls == 0


def test_failed_quality_does_not_reach_controller_or_provider() -> None:
    provider = Provider()
    controller = Controller(dry_run())
    bad = CampaignQualityEvidence((), (), object(), (), G, G, D, D)  # type: ignore[arg-type]
    with pytest.raises(IntegrationCampaignPrerequisiteError, match="gates are incomplete"):
        service(intake(), bad, provider, controller).run(request(), publication=publication())
    assert provider.prepare_calls == 0
    assert controller.calls == 0


def test_failed_discovery_cannot_reach_promotion() -> None:
    class FailingDiscovery(Provider):
        def discover(
            self, opened: CampaignOpened, publication: CandidatePublicationBinding
        ) -> CampaignDiscovery:
            del opened, publication
            raise IntegrationCampaignPrerequisiteError("synthetic discovery failed")

    provider = FailingDiscovery()
    with pytest.raises(IntegrationCampaignPrerequisiteError, match="discovery failed"):
        service(intake(), quality(), provider, Controller(dry_run())).run(
            request(), publication=publication()
        )


def test_happy_path_promotes_once_and_persists_package() -> None:
    from tests.unit.test_integration_campaign_contracts import (  # pyright: ignore[reportPrivateUsage]
        _package,  # pyright: ignore[reportPrivateUsage]
    )

    fixture = _package()  # pyright: ignore[reportPrivateUsage]
    quality_value = CampaignQualityEvidence(
        tuple(
            GateAttestation.model_construct(
                gate_name=name,
                candidate_digest=D,
                base_digest=D,
                evidence_digest=D,
                issuer_id="issuer",
                passed=True,
                valid_from_epoch=1,
                valid_until_epoch=1,
            )
            for name in ("trusted_ci", "private_evaluation", "provenance", "integration_soak")
        ),
        tuple(
            ReviewerAttestation.model_construct(
                reviewer_id=reviewer,
                candidate_digest=D,
                base_digest=D,
                evidence_digest=D,
                issuer_id="issuer",
                approved=True,
                valid_from_epoch=1,
                valid_until_epoch=1,
            )
            for reviewer in ("r1", "r2")
        ),
        RollbackAttestation.model_construct(
            rollback_count=0,
            candidate_digest=D,
            base_digest=D,
            evidence_digest=D,
            issuer_id="rollback",
            available=True,
            valid_from_epoch=1,
            valid_until_epoch=1,
        ),
        (ArtifactRef.model_construct(digest=D, size_bytes=0, media_type="x", role="e"),),
        fixture.observation.synthetic_merge_commit,
        fixture.observation.synthetic_merge_tree,
        fixture.observation.protection_evidence_digest,
        fixture.observation.check_evidence_manifest_digest,
    )
    config = PromotionControllerConfig.model_construct(
        controller_identity="controller",
        controller_version="1",
        base_issuer_id="base",
        path_issuer_id="path",
        policy=fixture.bundle.controller_config.policy.model_copy(
            update={
                "proposer_domains": {"p": "proposer"},
                "reviewer_domains": {"r1": "a", "r2": "b"},
            }
        ),
    )

    class HappyProvider(Provider):
        def open_or_reconcile(self, publication: CandidatePublicationBinding) -> CampaignOpened:
            opened = CampaignOpened(
                7, fixture.intent.pull_request_url, fixture.intent.target_ref, G, G, D
            )
            return replace(opened, open_identity=campaign_open_identity(publication, opened))

        def discover(
            self, opened: CampaignOpened, publication: CandidatePublicationBinding
        ) -> CampaignDiscovery:
            del publication
            return CampaignDiscovery(fixture.observation, G, opened.open_identity)

        def bind(
            self,
            publication: CandidatePublicationBinding,
            bundle: Any,
            bundle_digest: str,
            opened: CampaignOpened,
            discovery: CampaignDiscovery,
        ) -> CampaignPreparation:
            del publication, bundle, bundle_digest, discovery
            values = fixture.intent.model_dump(mode="python")
            values.pop("controller_lease_digest")
            values.pop("controller_lease_identity")
            values.pop("state")
            from avo_correlate.contracts.integration_campaign import IntegrationIntentTemplate

            return CampaignPreparation(
                IntegrationIntentTemplate.model_validate(values),
                fixture.observation,
                True,
                opened.open_identity,
            )

        def final_evidence(
            self, intent: Any, report: Any, observation: Any
        ) -> CampaignFinalEvidence:
            del intent, report, observation
            return CampaignFinalEvidence(fixture.reconciliation, fixture.merge_result)

    class HappyPromotion:
        def __init__(self) -> None:
            self.calls = 0

        def promote(self, *args: Any, **kwargs: Any) -> Any:
            del args, kwargs
            self.calls += 1
            return fixture.report

    class HappyJournal(Journal):
        def read_intent(self, operation_id: str) -> Any:
            del operation_id
            return fixture.intent, ArtifactRef.model_construct(
                digest=D, size_bytes=0, media_type="x", role="i"
            )

        def read_receipt(self, operation_id: str) -> Any:
            del operation_id
            return fixture.receipt, ArtifactRef.model_construct(
                digest=D, size_bytes=0, media_type="x", role="r"
            )

        def read_lease_evidence(self, operation_id: str) -> Any:
            del operation_id
            return fixture.lease_evidence, fixture.lease_evidence_artifact

    class Resolver:
        def resolve(self, digests: Any) -> tuple[ArtifactRef, ...]:
            return tuple(
                ArtifactRef.model_construct(digest=d, size_bytes=0, media_type="x", role=f"e-{i}")
                for i, d in enumerate(digests)
            )

    class Writer:
        def put_bytes(self, data: bytes, **kwargs: Any) -> ArtifactRef:
            del kwargs
            return ArtifactRef.model_construct(
                digest="sha256:" + hashlib.sha256(data).hexdigest(),
                size_bytes=len(data),
                media_type="x",
                role="integration-campaign-evidence",
            )

    intake_value = PromotionDryRunInput.model_construct(
        candidate_id="c",
        proposer_id="p",
        candidate_digest=D,
        source_provenance_digest=D,
        evidence_digests=[D],
        gate_attestations=[],
        reviewer_attestations=[],
        rollback_attestation=None,
    )
    controller = Controller(
        PromotionDryRunResult.model_construct(
            bundle=fixture.bundle,
            bundle_digest=fixture.bundle_digest,
            artifact=fixture.evidence_artifacts[0],
        )
    )
    promotion = HappyPromotion()
    result = IntegrationCampaignService(
        controller=cast(Any, controller),
        promotion=cast(Any, promotion),
        journal=cast(Any, HappyJournal()),
        intake=Intake(intake_value),
        quality=Quality(quality_value),
        provider=HappyProvider(),
        publication_verifier=lambda publication, bundle: True,
        evidence_resolver=Resolver(),
        artifact_writer=Writer(),
        main_state=Main(),
        trusted_config=config,
    ).run(
        IntegrationCampaignRequest(Path("candidate"), "c", "p", D), publication=fixture.publication
    )
    assert result.package is not None
    assert promotion.calls == 1
