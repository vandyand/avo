from typing import Any, Literal, cast

import pytest

from avo_correlate.application.integration_promotion_service import (
    HostedIntegrationProvider,
    IntegrationPromotionJournal,
    IntegrationPromotionService,
    PromotionLease,
)
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
    IntegrationProviderObservation,
    IntegrationProviderReconciliation,
    PromotionLeaseEvidence,
    PromotionMutationAuthorization,
)
from avo_correlate.contracts.promotion_bundle import (
    GitRefSnapshot,
    PromotionBundle,
    PromotionProvenanceBinding,
    PromotionReplayReport,
)
from avo_correlate.contracts.promotion_policy import PromotionRequest
from avo_correlate.domain.canonical import canonical_digest

D = "sha256:" + "a" * 64
G = "a" * 40
H = "b" * 40
J = "c" * 40


def intent() -> IntegrationPromotionIntent:
    return IntegrationPromotionIntent.model_construct(
        operation_id=D,
        repository_digest=D,
        controller_lease_digest=D,
        controller_lease_identity="lease",
        candidate_ref="avo/candidate",
        target_ref="integration",
        base_commit=G,
        base_tree=G,
        candidate_commit=H,
        candidate_tree=H,
        candidate_repository_digest=D,
        candidate_head_ref="avo/candidate",
        candidate_head_commit=H,
        candidate_head_tree=H,
        target_repository_digest=D,
        target_base_ref="integration",
        target_base_commit=G,
        target_base_tree=G,
        synthetic_merge_commit=G,
        synthetic_merge_tree=H,
        bundle_digest=D,
        candidate_digest=D,
        controller_config_digest=D,
        protection_evidence_digest=D,
        evidence_manifest_digest=D,
        check_evidence_manifest_digest=D,
        publication_evidence_digest=D,
        pull_request_number=1,
        pull_request_url="https://github.com/x/y/pull/1",
        provider_identity="github",
        provider_api_version="v1",
        merge_method="squash",
        state="intent_recorded",
    )


def observation(i: IntegrationPromotionIntent) -> IntegrationProviderObservation:
    return IntegrationProviderObservation.model_construct(
        repository_digest=i.repository_digest,
        pull_request_number=i.pull_request_number,
        pull_request_url=i.pull_request_url,
        candidate_repository_digest=D,
        target_repository_digest=D,
        base_ref=i.target_ref,
        base_commit=G,
        base_tree=G,
        head_ref=i.candidate_ref,
        head_commit=H,
        candidate_tree=H,
        synthetic_merge_commit=G,
        synthetic_merge_tree=H,
        protection_evidence_digest=D,
        check_evidence_manifest_digest=D,
        provider_identity="github",
        provider_api_version="v1",
        open_state="open",
        draft=False,
    )


def publication() -> CandidatePublicationBinding:
    return CandidatePublicationBinding.model_construct(
        repository_digest=D,
        base_commit=G,
        base_tree=G,
        candidate_digest=D,
        candidate_ref="avo/candidate",
        candidate_commit=H,
        candidate_tree=H,
        controller_publisher_identity="controller",
        publication_evidence_digest=D,
        verified=True,
    )


def reconciliation(
    i: IntegrationPromotionIntent, *, merged: bool = True, tree: str = H, parent: str = G
) -> IntegrationProviderReconciliation:
    return IntegrationProviderReconciliation.model_construct(
        repository_digest=D,
        pull_request_number=1,
        pull_request_url=i.pull_request_url,
        provider_identity="github",
        provider_api_version="v1",
        state="closed" if merged else "open",
        merged=merged,
        merge_commit=J if merged else None,
        target_ref="integration",
        target_head_commit=J if merged else G,
        target_head_tree=tree,
        target_first_parent=parent,
        target_parents=[parent],
        protection_evidence_digest=D,
    )


def make_receipt(i: IntegrationPromotionIntent) -> IntegrationPromotionReceipt:
    return IntegrationPromotionService._receipt(  # pyright: ignore[reportPrivateUsage]
        i,
        IntegrationMergeResult(outcome="ambiguous", response_digest=D, error="x"),
        reconciliation(i),
        "already_applied",
    )


class Lease:
    identity = "lease"
    digest = D


class Journal:
    def __init__(
        self,
        *,
        receipt: tuple[IntegrationPromotionReceipt, ArtifactRef] | None = None,
        durable: tuple[IntegrationPromotionIntent, ArtifactRef] | None = None,
    ) -> None:
        self.receipt, self.durable = receipt, durable
        self.lease: PromotionLease = Lease()
        self.events: list[str] = []
        self.fail_acquire = False
        self.fail_fence_at: set[int] = set()
        self.fail_record_intent = False
        self.fail_record_receipt = False
        self._fence_count = 0
        self.release_matching_result = True
        self.authorization: tuple[PromotionMutationAuthorization, ArtifactRef] | None = None
        self.operation_id = durable[0].operation_id if durable is not None else D
        self.repository_digest = durable[0].repository_digest if durable is not None else D
        self.target_ref = durable[0].target_ref if durable is not None else "integration"

    def read_receipt(
        self, operation_id: str
    ) -> tuple[IntegrationPromotionReceipt, ArtifactRef] | None:
        del operation_id
        return self.receipt

    def read_intent(
        self, operation_id: str
    ) -> tuple[IntegrationPromotionIntent, ArtifactRef] | None:
        del operation_id
        return self.durable

    def read_lease_evidence(
        self, operation_id: str
    ) -> tuple[PromotionLeaseEvidence, ArtifactRef] | None:
        return (
            PromotionLeaseEvidence.model_construct(
                operation_id=operation_id,
                repository_digest=self.repository_digest,
                target_ref=self.target_ref,
                identity=self.lease.identity,
                digest=self.lease.digest,
            ),
            ArtifactRef.model_construct(
                digest=D,
                size_bytes=0,
                media_type="application/vnd.avo.integration-promotion+json",
                role="promotion-lease-evidence",
            ),
        )

    def read_mutation_authorization(
        self, operation_id: str
    ) -> tuple[PromotionMutationAuthorization, ArtifactRef] | None:
        if self.authorization is not None:
            return self.authorization
        if self.durable is None:
            return None
        return (
            PromotionMutationAuthorization.model_construct(
                operation_id=operation_id,
                intent_digest=canonical_digest(self.durable[0]),
                lease_identity=self.lease.identity,
                lease_digest=self.lease.digest,
            ),
            ArtifactRef.model_construct(digest=D),
        )

    def acquire_lease(
        self, repository_digest: str, target_ref: str, operation_id: str, *, lease_seconds: int
    ) -> PromotionLease:
        del lease_seconds
        self.operation_id = operation_id
        self.repository_digest = repository_digest
        self.target_ref = target_ref
        if self.fail_acquire:
            raise RuntimeError("lease unavailable")
        self.events.append("acquire")
        return self.lease

    def assert_current(self, lease: PromotionLease) -> None:
        del lease
        self._fence_count += 1
        self.events.append("fence")
        if self._fence_count in self.fail_fence_at:
            raise RuntimeError("fence lost")

    def release_lease(self, lease: PromotionLease) -> None:
        del lease
        self.events.append("release")

    def record_intent(self, intent: IntegrationPromotionIntent) -> ArtifactRef:
        del intent
        self.events.append("intent")
        if self.fail_record_intent:
            raise OSError("intent journal unavailable")
        return ArtifactRef.model_construct(digest=D)

    def record_mutation_authorization(
        self, authorization: PromotionMutationAuthorization
    ) -> ArtifactRef:
        self.authorization = (authorization, ArtifactRef.model_construct(digest=D))
        self.events.append("mutation_authorization")
        return self.authorization[1]

    def record_receipt(self, receipt: Any) -> ArtifactRef:
        self.events.append("receipt")
        if self.fail_record_receipt:
            raise OSError("receipt journal unavailable")
        self.receipt = (receipt, ArtifactRef.model_construct(digest=D))
        return self.receipt[1]

    def release_matching_lease(
        self, repository_digest: str, target_ref: str, operation_id: str, identity: str, digest: str
    ) -> bool:
        del repository_digest, target_ref, operation_id, identity, digest
        self.events.append("release_matching")
        return self.release_matching_result


class Provider:
    def __init__(
        self,
        i: IntegrationPromotionIntent,
        *,
        merge_outcome: Literal["applied", "rejected", "ambiguous"] = "applied",
        recon: IntegrationProviderReconciliation | None = None,
        merge_error: Exception | None = None,
    ) -> None:
        self.i = i
        self.merge_outcome = merge_outcome
        self.recon: IntegrationProviderReconciliation = recon or reconciliation(i)
        self.merge_error = merge_error
        self.calls: list[str] = []
        self.bad_observation = False
        self.events: list[str] | None = None
        self.invoke_lease_guard = False
        self.lease_guard_called = False
        self.lease_guard_error: Exception | None = None

    def observe(self, intent: IntegrationPromotionIntent) -> IntegrationProviderObservation:
        del intent
        self.calls.append("observe")
        result = observation(self.i)
        if self.bad_observation:
            return result.model_copy(update={"provider_identity": "evil"})
        return result

    def merge(
        self,
        intent: IntegrationPromotionIntent,
        *,
        lease_guard: Any,
        mutation_authorize: Any = None,
    ) -> IntegrationMergeResult:
        del intent
        self.calls.append("merge")
        if self.events is not None:
            self.events.append("merge")
        if self.invoke_lease_guard:
            self.lease_guard_called = True
            if self.lease_guard_error is not None:
                raise self.lease_guard_error
            lease_guard()
            if mutation_authorize is not None:
                mutation_authorize()
        if self.merge_error:
            raise self.merge_error
        return IntegrationMergeResult(
            outcome=cast(Literal["applied", "rejected", "ambiguous"], self.merge_outcome),
            result_commit=J if self.merge_outcome == "applied" else None,
            result_tree=H if self.merge_outcome == "applied" else None,
            first_parent_commit=G if self.merge_outcome == "applied" else None,
            response_digest=D,
            error=None if self.merge_outcome == "applied" else "rejected",
        )

    def reconcile(self, intent: IntegrationPromotionIntent) -> IntegrationProviderReconciliation:
        del intent
        self.calls.append("reconcile")
        return self.recon


ReplayOutcome = Literal["would_apply", "not_applicable", "stale_base", "invalid_bundle"]


class Controller:
    def __init__(self, outcome: ReplayOutcome = "would_apply") -> None:
        self.repositories: list[TrustedPromotionRepository] = []
        self.outcome: ReplayOutcome = outcome

    def replay(
        self, bundle: PromotionBundle, *, bundle_digest: str, repository: TrustedPromotionRepository
    ) -> PromotionReplayReport:
        self.repositories.append(repository)
        return PromotionReplayReport(
            bundle_digest=bundle_digest,
            outcome=self.outcome,
            checks=["replay"],
            errors=["rejected"] if self.outcome != "would_apply" else [],
        )


def service(
    provider: HostedIntegrationProvider,
    journal: IntegrationPromotionJournal,
    controller: Controller | None = None,
    publication_verified: bool = True,
) -> tuple[IntegrationPromotionService, PromotionBundle, Controller]:
    snap = GitRefSnapshot.model_construct(
        repository_digest=D,
        target_ref="integration",
        commit=G,
        tree=G,
        source_tree_digest=D,
        protection_evidence_digest=D,
    )
    request = PromotionRequest.model_construct(candidate_digest=D)
    provenance = PromotionProvenanceBinding.model_construct(
        evidence_manifest_digest=D, source_provenance_digest=D
    )
    bundle = PromotionBundle.model_construct(
        snapshot=snap,
        request=request,
        controller_config_digest=D,
        provenance=provenance,
        controller_config=type("Config", (), {"controller_identity": "controller"})(),
        evidence_digests=[D],
    )
    c = controller or Controller()
    if isinstance(provider, Provider):
        provider.events = cast(Journal, journal).events
    s = IntegrationPromotionService(
        cast(PromotionController, c),
        cast(TrustedPromotionRepository, "trusted-repo"),
        provider,
        journal,
        lambda binding, bundle: publication_verified,
    )
    return s, bundle, c


@pytest.mark.parametrize(
    "field",
    [
        "repository_digest",
        "base_commit",
        "base_tree",
        "candidate_digest",
        "candidate_ref",
        "candidate_commit",
        "candidate_tree",
        "publication_evidence_digest",
        "controller_publisher_identity",
    ],
)
def test_unbound_publication_cannot_reach_provider(field: str) -> None:
    i, p, j = intent(), Provider(intent()), Journal()
    s, b, _ = service(p, j)
    bad = publication().model_copy(update={field: "evil"})
    out = s.promote(b, publication=bad, bundle_digest=D, operation_id=D, intent_factory=lambda _: i)
    assert out.outcome == "invalid"
    assert p.calls == []


def test_unverified_publication_cannot_reach_provider() -> None:
    i, p, j = intent(), Provider(intent()), Journal()
    s, b, _ = service(p, j, publication_verified=False)
    out = s.promote(
        b, publication=publication(), bundle_digest=D, operation_id=D, intent_factory=lambda _: i
    )
    assert out.outcome == "invalid"
    assert p.calls == [] and "acquire" not in j.events


def test_allow_path_replays_injected_repo_and_merges_once_after_durable_intent():
    i, j, p = intent(), Journal(), None
    p = Provider(i)
    s, b, c = service(p, j)
    result = s.promote(
        b,
        publication=publication(),
        bundle_digest=D,
        operation_id=D,
        intent_factory=lambda _lease: i,
    )
    assert result.outcome == "applied" and p.calls == ["observe", "merge", "reconcile"]
    assert c.repositories == ["trusted-repo"]
    assert j.events.index("intent") < j.events.index("merge")
    assert j.events[-1] == "release"


def test_application_lease_guard_is_invoked_inside_provider_before_mutation():
    i, j, p = intent(), Journal(), Provider(intent())
    p.invoke_lease_guard = True
    s, b, _ = service(p, j)
    result = s.promote(
        b,
        publication=publication(),
        bundle_digest=D,
        operation_id=D,
        intent_factory=lambda _lease: i,
    )
    assert result.outcome == "applied"
    assert p.lease_guard_called


def test_existing_receipt_is_idempotent_and_does_not_merge():
    i, p = intent(), Provider(intent())
    r = IntegrationPromotionService._receipt(  # pyright: ignore[reportPrivateUsage]
        i,
        IntegrationMergeResult(outcome="ambiguous", response_digest=D, error="x"),
        reconciliation(i),
        "already_applied",
    )
    j = Journal(
        receipt=(r, ArtifactRef.model_construct(digest=D)),
        durable=(i, ArtifactRef.model_construct(digest=D)),
    )
    s, b, _ = service(p, j)
    out = s.promote(
        b, publication=publication(), bundle_digest=D, operation_id=D, intent_factory=lambda _: i
    )
    assert (
        out.outcome == "already_applied" and out.intent_digest == r.intent_digest and p.calls == []
    )


def test_existing_receipt_without_intent_is_not_trusted() -> None:
    i, p = intent(), Provider(intent())
    r = make_receipt(i)
    j = Journal(receipt=(r, ArtifactRef.model_construct(digest=D)))
    s, b, _ = service(p, j)
    out = s.promote(
        b, publication=publication(), bundle_digest=D, operation_id=D, intent_factory=lambda _: i
    )
    assert out.outcome == "reconciliation_required"
    assert p.calls == []


def test_existing_receipt_must_match_durable_intent_before_release() -> None:
    i, p = intent(), Provider(intent())
    r = make_receipt(i).model_copy(update={"observed_provider_identity": "evil"})
    j = Journal(
        receipt=(r, ArtifactRef.model_construct(digest=D)),
        durable=(i, ArtifactRef.model_construct(digest=D)),
    )
    s, b, _ = service(p, j)
    out = s.promote(
        b, publication=publication(), bundle_digest=D, operation_id=D, intent_factory=lambda _: i
    )
    assert out.outcome == "invalid"
    assert "release_matching" not in j.events


def test_existing_intent_reconciles_only_and_retains_lease_on_unresolved():
    i, p = intent(), Provider(intent(), recon=reconciliation(intent(), merged=False))
    j = Journal(durable=(i, ArtifactRef.model_construct(digest=D)))
    s, b, _ = service(p, j)
    out = s.promote(
        b, publication=publication(), bundle_digest=D, operation_id=D, intent_factory=lambda _: i
    )
    assert (
        out.outcome == "reconciliation_required"
        and p.calls == ["reconcile"]
        and "release" not in j.events
    )


@pytest.mark.parametrize("bad", ["tree", "parent"])
def test_wrong_squash_result_never_reports_applied(bad: Literal["tree", "parent"]):
    i = intent()
    r = reconciliation(i, tree=G if bad == "tree" else H, parent=H if bad == "parent" else G)
    p, j = Provider(i, recon=r), Journal()
    s, b, _ = service(p, j)
    out = s.promote(
        b, publication=publication(), bundle_digest=D, operation_id=D, intent_factory=lambda _: i
    )
    assert out.outcome == "reconciliation_required" and "release" not in j.events


def test_merge_transport_error_reconciles_and_keeps_fence_when_unresolved():
    i = intent()
    p, j = Provider(i, merge_error=RuntimeError("timeout")), Journal()
    p.recon = reconciliation(i, merged=False)
    s, b, _ = service(p, j)
    out = s.promote(
        b, publication=publication(), bundle_digest=D, operation_id=D, intent_factory=lambda _: i
    )
    assert (
        out.outcome == "reconciliation_required"
        and p.calls == ["observe", "merge", "reconcile"]
        and "release" not in j.events
    )


def test_provider_mismatch_prevents_merge_and_releases_safe_lease():
    i, p, j = intent(), Provider(intent()), Journal()
    p.bad_observation = True
    s, b, _ = service(p, j)
    out = s.promote(
        b, publication=publication(), bundle_digest=D, operation_id=D, intent_factory=lambda _: i
    )
    assert out.outcome == "invalid" and p.calls == ["observe"] and j.events[-1] == "release"


@pytest.mark.parametrize("replay_outcome", ["not_applicable", "stale_base", "invalid_bundle"])
def test_replay_non_applicable_or_invalid_never_mutates(
    replay_outcome: Literal["not_applicable", "stale_base", "invalid_bundle"],
):
    i, j, p = intent(), Journal(), Provider(intent())
    s, b, c = service(p, j, Controller(replay_outcome))
    out = s.promote(
        b, publication=publication(), bundle_digest=D, operation_id=D, intent_factory=lambda _: i
    )
    assert out.outcome == ("invalid" if replay_outcome == "invalid_bundle" else replay_outcome)
    assert p.calls == []
    assert j.events[-1] == "release"
    assert "intent" not in j.events
    assert c.repositories == ["trusted-repo"]


@pytest.mark.parametrize(
    "field",
    [
        "operation_id",
        "repository_digest",
        "target_ref",
        "bundle_digest",
        "candidate_digest",
        "base_commit",
        "base_tree",
        "protection_evidence_digest",
        "controller_config_digest",
        "evidence_manifest_digest",
    ],
)
def test_intent_binding_mismatch_never_merges(field: str):
    i = intent()
    replacement = (
        "sha256:" + "f" * 64
        if field not in {"target_ref", "base_commit", "base_tree"}
        else ("other" if field == "target_ref" else "d" * 40)
    )
    bad = i.model_copy(update={field: replacement})
    p, j = Provider(i), Journal()
    s, b, _ = service(p, j)
    out = s.promote(
        b, publication=publication(), bundle_digest=D, operation_id=D, intent_factory=lambda _: bad
    )
    assert out.outcome == "invalid"
    assert p.calls == []
    assert j.events[-1] == "release"


def test_lease_and_journal_failures_are_safe_before_mutation():
    i, p = intent(), Provider(intent())
    j = Journal()
    j.fail_acquire = True
    s, b, _ = service(p, j)
    assert (
        s.promote(
            b,
            publication=publication(),
            bundle_digest=D,
            operation_id=D,
            intent_factory=lambda _: i,
        ).outcome
        == "invalid"
    )
    assert p.calls == []

    j = Journal()
    j.fail_fence_at = {1}
    s, b, _ = service(p, j)
    assert (
        s.promote(
            b,
            publication=publication(),
            bundle_digest=D,
            operation_id=D,
            intent_factory=lambda _: i,
        ).outcome
        == "invalid"
    )
    assert p.calls == [] and "release" in j.events

    j = Journal()
    j.fail_record_intent = True
    p = Provider(i)
    s, b, _ = service(p, j)
    out = s.promote(
        b, publication=publication(), bundle_digest=D, operation_id=D, intent_factory=lambda _: i
    )
    assert out.outcome == "invalid" and p.calls == ["observe"]
    assert "release" in j.events


@pytest.mark.parametrize("lease_seconds", [0, -1])
def test_zero_or_negative_lease_is_rejected(lease_seconds: int):
    with pytest.raises(ValueError):
        IntegrationPromotionService(
            cast(PromotionController, Controller()),
            cast(TrustedPromotionRepository, "r"),
            Provider(intent()),
            Journal(),
            lambda binding, bundle: True,
            lease_seconds=lease_seconds,
        )
    i, p, j = intent(), Provider(intent()), Journal()
    s, b, _ = service(p, j)
    with pytest.raises(ValueError):
        s.promote(
            b,
            publication=publication(),
            bundle_digest=D,
            operation_id=D,
            lease_seconds=lease_seconds,
            intent_factory=lambda _: i,
        )


@pytest.mark.parametrize("outcome", ["rejected", "ambiguous"])
@pytest.mark.parametrize("target_changed", [False, True])
def test_rejected_or_ambiguous_merge_reconciles_without_false_success(
    outcome: Literal["rejected", "ambiguous"], target_changed: bool
):
    i = intent()
    recon = reconciliation(i, merged=False, parent=G)
    if target_changed:
        recon = recon.model_copy(update={"target_head_commit": J})
    p, j = Provider(i, merge_outcome=outcome, recon=recon), Journal()
    s, b, _ = service(p, j)
    out = s.promote(
        b, publication=publication(), bundle_digest=D, operation_id=D, intent_factory=lambda _: i
    )
    assert out.outcome == (
        "stale_base"
        if outcome == "rejected" and target_changed
        else "not_applicable"
        if outcome == "rejected"
        else "reconciliation_required"
    )
    assert (
        "release" in j.events
        if out.outcome != "reconciliation_required"
        else "release" not in j.events
    )


def test_ambiguous_exact_apply_is_already_applied_and_releases():
    i, p, j = intent(), Provider(intent(), merge_outcome="ambiguous"), Journal()
    s, b, _ = service(p, j)
    out = s.promote(
        b, publication=publication(), bundle_digest=D, operation_id=D, intent_factory=lambda _: i
    )
    assert out.outcome == "already_applied" and j.events[-1] == "release"


def test_provider_precondition_failure_is_invalid_without_reconciliation_or_receipt():
    i = intent()
    p, j = Provider(
        i,
        merge_error=IntegrationPromotionPreconditionError("main branch protection is weak"),
    ), Journal()
    s, b, _ = service(p, j)
    out = s.promote(
        b, publication=publication(), bundle_digest=D, operation_id=D, intent_factory=lambda _: i
    )
    assert out.outcome == "invalid"
    assert p.calls == ["observe", "merge"]
    assert j.receipt is not None and j.receipt[0].outcome == "invalid"
    assert "release" in j.events


def test_final_lease_guard_failure_is_invalid_without_reconciliation_or_receipt():
    i = intent()
    p, j = Provider(i), Journal()
    p.invoke_lease_guard = True
    p.lease_guard_error = IntegrationPromotionPreconditionError("lease expired")
    s, b, _ = service(p, j)
    out = s.promote(
        b, publication=publication(), bundle_digest=D, operation_id=D, intent_factory=lambda _: i
    )
    assert out.outcome == "invalid"
    assert p.calls == ["observe", "merge"]
    assert j.receipt is not None and j.receipt[0].outcome == "invalid"
    assert "release" in j.events


def test_precondition_receipt_is_terminal_across_restart_without_reconciliation():
    i = intent()
    p, j = Provider(
        i,
        merge_error=IntegrationPromotionPreconditionError("main branch protection is weak"),
    ), Journal()
    s, b, _ = service(p, j)
    first = s.promote(
        b, publication=publication(), bundle_digest=D, operation_id=D, intent_factory=lambda _: i
    )
    assert first.outcome == "invalid"
    j.durable = (i, ArtifactRef.model_construct(digest=D))
    p.calls.clear()
    second = s.promote(
        b, publication=publication(), bundle_digest=D, operation_id=D, intent_factory=lambda _: i
    )
    assert second.outcome == "invalid"
    assert p.calls == []


def test_applied_response_mismatch_requires_reconciliation():
    i = intent()
    p, j = Provider(i), Journal()
    p.recon = reconciliation(i)
    original = p.merge

    def mismatched_merge(
        _intent: IntegrationPromotionIntent, *, lease_guard: Any, mutation_authorize: Any
    ) -> IntegrationMergeResult:
        del lease_guard, mutation_authorize
        result = original(_intent, lease_guard=lambda: None, mutation_authorize=None)
        return result.model_copy(update={"result_tree": G})

    p.merge = mismatched_merge  # type: ignore[method-assign]
    s, b, _ = service(p, j)
    out = s.promote(
        b, publication=publication(), bundle_digest=D, operation_id=D, intent_factory=lambda _: i
    )
    assert out.outcome == "reconciliation_required" and "release" not in j.events


@pytest.mark.parametrize("stage", ["pre_observe", "pre_intent", "pre_merge", "pre_receipt"])
def test_fencing_failure_is_fail_closed_and_retains_after_mutation(stage: str):
    i, p, j = intent(), Provider(intent()), Journal()
    # Fences: before observe, before intent, before merge, before receipt.
    j.fail_fence_at = {"pre_observe": {2}, "pre_intent": {3}, "pre_merge": {4}, "pre_receipt": {5}}[
        stage
    ]
    s, b, _ = service(p, j)
    out = s.promote(
        b, publication=publication(), bundle_digest=D, operation_id=D, intent_factory=lambda _: i
    )
    assert out.outcome in {"invalid", "reconciliation_required"}
    if stage in {"pre_merge", "pre_receipt"}:
        assert "intent" in j.events and "release" not in j.events


def test_receipt_write_failure_retains_lease():
    i, p, j = intent(), Provider(intent()), Journal()
    j.fail_record_receipt = True
    s, b, _ = service(p, j)
    out = s.promote(
        b, publication=publication(), bundle_digest=D, operation_id=D, intent_factory=lambda _: i
    )
    assert out.outcome == "reconciliation_required" and "release" not in j.events


def test_existing_conflicting_receipt_or_intent_does_not_mutate():
    i, p = intent(), Provider(intent())
    conflict = make_receipt(i)
    conflict = conflict.model_copy(update={"bundle_digest": "sha256:" + "e" * 64})
    j = Journal(receipt=(conflict, ArtifactRef.model_construct(digest=D)))
    s, b, _ = service(p, j)
    assert (
        s.promote(
            b,
            publication=publication(),
            bundle_digest=D,
            operation_id=D,
            intent_factory=lambda _: i,
        ).outcome
        == "invalid"
    )
    assert p.calls == [] and "acquire" not in j.events

    j = Journal(
        durable=(
            i.model_copy(update={"target_ref": "other"}),
            ArtifactRef.model_construct(digest=D),
        )
    )
    s, b, _ = service(p, j)
    assert (
        s.promote(
            b,
            publication=publication(),
            bundle_digest=D,
            operation_id=D,
            intent_factory=lambda _: i,
        ).outcome
        == "invalid"
    )
    assert p.calls == [] and "acquire" not in j.events


def test_existing_exact_intent_recovers_receipt_and_releases_matching_lease():
    i, p = intent(), Provider(intent())
    j = Journal(durable=(i, ArtifactRef.model_construct(digest=D)))
    s, b, _ = service(p, j)
    out = s.promote(
        b, publication=publication(), bundle_digest=D, operation_id=D, intent_factory=lambda _: i
    )
    assert out.outcome == "already_applied" and p.calls == ["reconcile"]
    assert j.events == ["receipt", "release_matching"]


def test_existing_receipt_recovery_releases_matching_lease():
    i, p = intent(), Provider(intent())
    receipt = make_receipt(i)
    j = Journal(
        receipt=(receipt, ArtifactRef.model_construct(digest=D)),
        durable=(i, ArtifactRef.model_construct(digest=D)),
    )
    s, b, _ = service(p, j)
    out = s.promote(
        b, publication=publication(), bundle_digest=D, operation_id=D, intent_factory=lambda _: i
    )
    assert out.outcome == "already_applied" and p.calls == [] and j.events == ["release_matching"]
