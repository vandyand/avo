from pathlib import Path
from typing import Any, cast

import pytest

from avo_correlate.adapters.artifacts import campaign_journal as campaign_journal_module
from avo_correlate.adapters.artifacts.campaign_journal import (
    CampaignCompletionJournal,
    CampaignJournalError,
)
from avo_correlate.application.integration_campaign_service import (
    CampaignFinalEvidence,
    CampaignMainState,
    IntegrationCampaignResult,
    IntegrationCampaignService,
    IntegrationCampaignUnsafeError,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_campaign import (
    CampaignCompletionPlan,
    CampaignDiscoveryEvidence,
    CampaignOpenedEvidence,
    CampaignPreparationEvidence,
    IntegrationIntentTemplate,
)
from avo_correlate.contracts.integration_promotion import PromotionMutationAuthorization
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.test_integration_campaign_contracts import (
    _package,  # pyright: ignore[reportPrivateUsage]
)

D = "sha256:" + "a" * 64
G = "a" * 40


class Journal:
    def __init__(self, fixture: Any) -> None:
        self.fixture = fixture
        self.release_matching_calls = 0

    def read_intent(self, operation_id: str) -> Any:
        assert operation_id == self.fixture.intent.operation_id
        return self.fixture.intent, self.fixture.evidence_artifacts[0]

    def read_receipt(self, operation_id: str) -> Any:
        assert operation_id == self.fixture.receipt.operation_id
        return self.fixture.receipt, self.fixture.evidence_artifacts[0]

    def read_lease_evidence(self, operation_id: str) -> Any:
        assert operation_id == self.fixture.intent.operation_id
        return self.fixture.lease_evidence, self.fixture.lease_evidence_artifact

    def release_matching_lease(self, *args: Any) -> bool:
        del args
        self.release_matching_calls += 1
        return True

    def record_receipt(self, receipt: Any) -> ArtifactRef:
        self._receipt = receipt
        return self.fixture.evidence_artifacts[0]


class Store:
    def __init__(self, plan: CampaignCompletionPlan) -> None:
        self.plan = plan
        self.package: Any = None
        self.record_calls = 0

    def record_plan(self, plan: CampaignCompletionPlan) -> ArtifactRef:
        self.plan = plan
        return ArtifactRef.model_construct(digest=D, size_bytes=0, media_type="x", role="plan")

    def read_plan(self, operation_id: str) -> Any:
        return (
            (
                self.plan,
                ArtifactRef.model_construct(digest=D, size_bytes=0, media_type="x", role="plan"),
            )
            if operation_id == self.plan.operation_id
            else None
        )

    def record_final_evidence(self, evidence: Any) -> ArtifactRef:
        self.final = evidence
        return ArtifactRef.model_construct(digest=D, size_bytes=0, media_type="x", role="final")

    def read_final_evidence(self, operation_id: str) -> Any:
        if not hasattr(self, "final") or self.final.operation_id != operation_id:
            return None
        return self.final, ArtifactRef.model_construct(
            digest=D, size_bytes=0, media_type="x", role="final"
        )

    def record_package(self, package: Any) -> ArtifactRef:
        self.record_calls += 1
        self.package = package
        return ArtifactRef.model_construct(
            digest=canonical_digest(package),
            size_bytes=0,
            media_type="x",
            role="integration-campaign-package",
        )

    def read_package(self, operation_id: str) -> Any:
        if self.package is None or operation_id != self.package.intent.operation_id:
            return None
        return self.package, ArtifactRef.model_construct(
            digest=canonical_digest(self.package),
            size_bytes=0,
            media_type="x",
            role="integration-campaign-package",
        )


class Provider:
    def __init__(self, fixture: Any) -> None:
        self.fixture = fixture
        self.final_calls = 0

    def final_evidence(self, intent: Any, report: Any, observation: Any) -> CampaignFinalEvidence:
        del intent, report, observation
        self.final_calls += 1
        return CampaignFinalEvidence(self.fixture.reconciliation, self.fixture.merge_result)


class IntentOnlyJournal(Journal):
    """Journal state representing a crash after intent, before receipt."""

    def __init__(self, fixture: Any) -> None:
        super().__init__(fixture)
        self.receipt_available = False

    def read_receipt(self, operation_id: str) -> Any:
        if not self.receipt_available and not hasattr(self, "_receipt"):
            return None
        if hasattr(self, "_receipt"):
            return self._receipt, self.fixture.evidence_artifacts[0]
        return super().read_receipt(operation_id)

    def read_mutation_authorization(self, operation_id: str) -> Any:
        assert operation_id == self.fixture.intent.operation_id
        authorization = PromotionMutationAuthorization(
            operation_id=operation_id,
            intent_digest=canonical_digest(self.fixture.intent),
            lease_identity=self.fixture.intent.controller_lease_identity,
            lease_digest=self.fixture.intent.controller_lease_digest,
            authorized_at=self.fixture.lease_evidence.acquired_at,
        )
        return authorization, self.fixture.evidence_artifacts[0]


class ResumingPromotion:
    def __init__(self, journal: IntentOnlyJournal, fixture: Any) -> None:
        self.journal = journal
        self.fixture = fixture
        self.calls = 0
        self.merge_calls = 0

    def promote(self, *args: Any, **kwargs: Any) -> Any:
        # A real IntegrationPromotionService reaches this branch by reading
        # the durable intent and reconciling; it must not invoke merge again.
        del args, kwargs
        self.calls += 1
        self.journal.receipt_available = True
        return __import__(
            "avo_correlate.contracts.integration_promotion",
            fromlist=["IntegrationPromotionReport"],
        ).IntegrationPromotionReport.model_construct(
            operation_id=self.fixture.intent.operation_id,
            outcome="applied",
            intent_digest=canonical_digest(self.fixture.intent),
            receipt_digest=canonical_digest(self.fixture.receipt),
            checks=["reconciled_once"],
            errors=[],
        )


class Main(CampaignMainState):
    def __init__(self, value: str = G) -> None:
        self.value = value

    def head_commit(self) -> str:
        return self.value


class Writer:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail
        self.calls = 0

    def put_bytes(self, data: bytes, **kwargs: Any) -> ArtifactRef:
        del kwargs
        self.calls += 1
        if self.fail:
            raise OSError("simulated package write failure")
        return ArtifactRef.model_construct(
            digest="sha256:" + __import__("hashlib").sha256(data).hexdigest(),
            size_bytes=len(data),
            media_type="x",
            role="integration-campaign-evidence",
        )


def _service(
    fixture: Any,
    journal: Journal,
    store: Store,
    provider: Provider,
    main: Main,
    writer: Writer,
    ) -> IntegrationCampaignService:
    return IntegrationCampaignService(
        controller=cast(Any, object()),
        promotion=cast(Any, object()),
        journal=cast(Any, journal),
        intake=cast(Any, object()),
        quality=cast(Any, object()),
        provider=cast(Any, provider),
        publication_verifier=lambda publication, bundle: True,
        evidence_resolver=cast(Any, object()),
        artifact_writer=writer,
        main_state=main,
        trusted_config=fixture.bundle.controller_config,
        completion_journal=store,
    )


def _plan(fixture: Any) -> CampaignCompletionPlan:
    opened_identity = D
    values = fixture.intent.model_dump(mode="python")
    for key in ("controller_lease_digest", "controller_lease_identity", "state"):
        values.pop(key)
    template = IntegrationIntentTemplate.model_validate(values)
    opened = CampaignOpenedEvidence(
        pull_request_number=fixture.intent.pull_request_number,
        pull_request_url=fixture.intent.pull_request_url,
        target_ref=fixture.intent.target_ref,
        base_commit=G,
        base_tree=G,
        open_identity=opened_identity,
    )
    discovery = CampaignDiscoveryEvidence(
        observation=fixture.observation,
        main_before_commit=G,
        open_identity=opened_identity,
    )
    preparation = CampaignPreparationEvidence(
        template=template,
        observation=fixture.observation,
        marker_verified=True,
        open_identity=opened_identity,
    )
    return CampaignCompletionPlan(
        operation_id=fixture.intent.operation_id,
        bundle=fixture.bundle,
        publication=fixture.publication,
        evidence_artifacts=fixture.evidence_artifacts,
        bundle_digest=fixture.bundle_digest,
        opened=opened,
        discovery=discovery,
        preparation=preparation,
        main_before_commit=G,
    )


def test_completion_journal_is_content_addressed_and_idempotent(tmp_path: Path) -> None:
    fixture = _package()
    journal = CampaignCompletionJournal(tmp_path)
    plan = _plan(fixture)
    first = journal.record_plan(plan)
    second = journal.record_plan(plan)
    assert first.digest == second.digest
    # This legacy fixture intentionally uses ``model_construct`` for nested
    # records; the journal must reject it when reconstructing from disk.
    with pytest.raises(CampaignJournalError, match="malformed"):
        journal.read_plan(plan.operation_id)


def test_completion_journal_flushes_object_directory_before_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = _package()
    journal = CampaignCompletionJournal(tmp_path)
    plan = _plan(fixture)
    flushed: list[Path] = []
    monkeypatch.setattr(campaign_journal_module, "_sync_directory", flushed.append)

    journal.record_plan(plan)

    assert len(flushed) == 2
    assert flushed[0].parts[-2] == "sha256"
    assert len(flushed[0].name) == 2
    assert flushed[1].name == "plan"


def test_finalize_recovers_after_package_write_failure() -> None:
    fixture = _package()
    plan = _plan(fixture)
    store = Store(plan)
    provider = Provider(fixture)
    journal = Journal(fixture)
    failing = Writer(fail=True)
    service = _service(fixture, journal, store, provider, Main(), failing)
    with pytest.raises(IntegrationCampaignUnsafeError, match="simulated package write"):
        service.finalize(fixture.intent.operation_id)
    assert store.package is None
    assert provider.final_calls == 1

    writer = Writer()
    recovered = _service(fixture, journal, store, provider, Main(), writer)
    result = recovered.finalize(fixture.intent.operation_id)
    assert isinstance(result, IntegrationCampaignResult)
    assert result.package is not None
    assert provider.final_calls == 1
    assert journal.release_matching_calls == 1
    again = recovered.finalize(fixture.intent.operation_id)
    assert again.package == result.package
    assert provider.final_calls == 1
    assert store.record_calls == 1
    assert journal.release_matching_calls == 2


def test_finalize_rejects_main_drift_before_package() -> None:
    fixture = _package()
    plan = _plan(fixture)
    provider = Provider(fixture)
    store = Store(plan)
    service = _service(fixture, Journal(fixture), store, provider, Main("b" * 40), Writer())
    with pytest.raises(IntegrationCampaignUnsafeError, match="main changed"):
        service.finalize(fixture.intent.operation_id)
    assert store.package is None


def test_finalize_rejects_missing_lease_evidence() -> None:
    fixture = _package()
    plan = _plan(fixture)

    class MissingLease(Journal):
        def read_lease_evidence(self, operation_id: str) -> None:
            del operation_id
            return None

    service = _service(
        fixture, MissingLease(fixture), Store(plan), Provider(fixture), Main(), Writer()
    )
    with pytest.raises(IntegrationCampaignUnsafeError, match="lease evidence"):
        service.finalize(fixture.intent.operation_id)


def test_resume_after_intent_reconciles_without_second_merge() -> None:
    fixture = _package()
    plan = _plan(fixture)
    journal = IntentOnlyJournal(fixture)
    promotion = ResumingPromotion(journal, fixture)
    service = _service(fixture, journal, Store(plan), Provider(fixture), Main(), Writer())
    service._promotion = promotion  # type: ignore[attr-defined]

    result = service.resume(fixture.intent.operation_id)

    assert result.package is not None
    assert promotion.calls == 1
    assert promotion.merge_calls == 0
    assert journal.release_matching_calls == 1


def test_resume_uses_real_promotion_reconciliation_without_hosted_mutation() -> None:
    fixture = _package()
    plan = _plan(fixture)
    journal = IntentOnlyJournal(fixture)

    class HostedProvider:
        def __init__(self) -> None:
            self.reconcile_calls = 0
            self.merge_calls = 0
            self.post_calls = 0
            self.patch_calls = 0

        def reconcile(self, intent: Any) -> Any:
            del intent
            self.reconcile_calls += 1
            return fixture.reconciliation

        def merge(self, *args: Any, **kwargs: Any) -> Any:
            del args, kwargs
            self.merge_calls += 1
            raise AssertionError("recovery must never submit a second merge")

    hosted = HostedProvider()
    from avo_correlate.application.integration_promotion_service import (
        IntegrationPromotionService,
    )

    promotion = IntegrationPromotionService(
        cast(Any, object()),
        cast(Any, object()),
        cast(Any, hosted),
        cast(Any, journal),
        lambda binding, bundle: True,
    )

    class FinalProvider(Provider):
        def final_evidence(
            self, intent: Any, report: Any, observation: Any
        ) -> CampaignFinalEvidence:
            del intent, report, observation
            ambiguous = __import__(
                "avo_correlate.contracts.integration_promotion",
                fromlist=["IntegrationMergeResult"],
            ).IntegrationMergeResult.model_construct(
                outcome="ambiguous", response_digest=D, error="reconciled existing intent"
            )
            return CampaignFinalEvidence(fixture.reconciliation, ambiguous)

    service = _service(fixture, journal, Store(plan), FinalProvider(fixture), Main(), Writer())
    service._promotion = promotion  # type: ignore[attr-defined]

    result = service.resume(fixture.intent.operation_id)

    assert result.package is not None
    assert hosted.reconcile_calls == 1
    assert hosted.merge_calls == 0
    assert hosted.post_calls == 0
    assert hosted.patch_calls == 0


def test_resume_rejects_plan_without_intent_before_any_hosted_mutation() -> None:
    fixture = _package()
    plan = _plan(fixture)

    class MissingIntent(Journal):
        def read_intent(self, operation_id: str) -> Any:
            del operation_id
            return None

    promotion = ResumingPromotion(IntentOnlyJournal(fixture), fixture)
    service = _service(
        fixture, MissingIntent(fixture), Store(plan), Provider(fixture), Main(), Writer()
    )
    service._promotion = promotion  # type: ignore[attr-defined]

    with pytest.raises(IntegrationCampaignUnsafeError, match="no durable promotion intent"):
        service.resume(fixture.intent.operation_id)
    assert promotion.calls == 0
