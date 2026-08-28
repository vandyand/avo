from dataclasses import replace
from typing import Any

import pytest
import test_integration_campaign_contracts as campaign_fixtures

from avo_correlate.adapters.artifacts.synthetic_validation_journal import (
    SyntheticValidationJournal,
)
from avo_correlate.adapters.hosted_git.campaign import GitHubCampaignProvider
from avo_correlate.adapters.hosted_git.github import (
    GitHubEvidenceSnapshot,
    GitHubPullRequestBinding,
    GitHubPullRequestDiscovery,
)
from avo_correlate.application.integration_campaign_service import campaign_open_identity
from avo_correlate.application.synthetic_validation_service import SyntheticValidationService
from avo_correlate.contracts.integration_campaign import campaign_marker_digest
from avo_correlate.contracts.integration_promotion import CandidatePublicationBinding
from avo_correlate.contracts.synthetic_validation import SyntheticValidationObservation

G = "a" * 40
H = "b" * 40
J = "c" * 40
D = "sha256:" + "a" * 64


def fixture_package() -> Any:
    package_factory = getattr(campaign_fixtures, "_package")  # noqa: B009
    return package_factory()


class FakeGitHub:
    target_ref = "refs/heads/integration"
    provider_identity = "github"
    provider_api_version = "2026-01"
    trusted_checks = (("avo synthetic validate (ubuntu-latest)", 15368),)

    def __init__(self, *, head_commit: str = H) -> None:
        self.head_commit = head_commit
        self.marker_updates = 0
        self.open_base: str | None = None
        self.events: list[str] = []
        self.validation_ref: dict[str, str] | None = None

    def open_or_reconcile_campaign_pull_request(
        self,
        candidate_ref: str,
        candidate_commit: str,
        *,
        base_commit: str,
        title: str,
        body: str,
    ) -> GitHubPullRequestBinding:
        del title, body
        self.events.append("open")
        self.open_base = base_commit
        return GitHubPullRequestBinding(
            number=7,
            url="https://github.com/o/r/pull/7",
            base_ref=self.target_ref,
            base_commit=base_commit,
            head_ref=candidate_ref,
            head_commit=candidate_commit,
            body="candidate",
            state="open",
            draft=False,
        )

    def discover_campaign_evidence(
        self,
        number: int,
        *,
        candidate_ref: str,
        candidate_commit: str,
        base_commit: str,
        campaign_marker: str | None = None,
    ) -> GitHubPullRequestDiscovery:
        del campaign_marker
        self.events.append("discover")
        return GitHubPullRequestDiscovery(
            pull_request=GitHubPullRequestBinding(
                number=number,
                url="https://github.com/o/r/pull/7",
                base_ref=self.target_ref,
                base_commit=base_commit,
                head_ref=candidate_ref,
                head_commit=self.head_commit if candidate_commit == H else candidate_commit,
                body="candidate",
                state="open",
                draft=False,
            ),
            synthetic_merge_commit=J,
            synthetic_merge_tree=H,
            evidence=GitHubEvidenceSnapshot(
                synthetic_merge_commit=J,
                synthetic_merge_tree=H,
                protection_evidence_digest=D,
                check_evidence_manifest_digest=D,
                protection_evidence={},
                check_evidence_manifest={},
            ),
        )

    def update_campaign_marker(self, intent: Any) -> GitHubPullRequestBinding:
        self.marker_updates += 1
        return GitHubPullRequestBinding(
            number=intent.pull_request_number,
            url=intent.pull_request_url,
            base_ref=intent.target_ref,
            base_commit=intent.base_commit,
            head_ref=intent.candidate_ref,
            head_commit=intent.candidate_commit,
            body=f"AVO-Campaign-Marker: {campaign_marker_digest(intent)}",
            state="open",
            draft=False,
        )

    def verify_campaign_marker(self, intent: Any) -> GitHubPullRequestBinding:
        return GitHubPullRequestBinding(
            number=intent.pull_request_number,
            url=intent.pull_request_url,
            base_ref=intent.target_ref,
            base_commit=intent.base_commit,
            head_ref=intent.candidate_ref,
            head_commit=intent.candidate_commit,
            body=f"AVO-Campaign-Marker: {campaign_marker_digest(intent)}",
            state="open",
            draft=False,
        )

    def reconcile(self, intent: Any) -> Any:
        return fixture_package().reconciliation

    def observe_synthetic_validation(
        self,
        number: int,
        *,
        candidate_ref: str,
        candidate_commit: str,
        base_commit: str,
    ) -> SyntheticValidationObservation:
        del number
        self.events.append("observe")
        return SyntheticValidationObservation(
            repository_digest=D,
            base_ref=self.target_ref,
            base_commit=base_commit,
            base_tree=G,
            head_ref=candidate_ref,
            head_commit=candidate_commit,
            head_tree=H,
            synthetic_commit=J,
            synthetic_tree=H,
        )

    def read_validation_ref(self, repository_digest: str, ref: str) -> object | None:
        del repository_digest, ref
        self.events.append("validation-read")
        return self.validation_ref

    def create_validation_ref(self, repository_digest: str, ref: str, commit: str) -> object:
        del repository_digest
        self.events.append("validation-create")
        self.validation_ref = {"commit": commit, "tree": H}
        return {"commit": commit}

    def delete_validation_ref(self, repository_digest: str, ref: str) -> object:
        del repository_digest, ref
        self.events.append("validation-delete")
        self.validation_ref = None
        return {}


class BindingGitHub(FakeGitHub):
    """Configurable provider responses for adversarial campaign tests."""

    def __init__(self, *, open_updates: dict[str, object] | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.open_updates = open_updates or {}

    def open_or_reconcile_campaign_pull_request(
        self, *args: Any, **kwargs: Any
    ) -> GitHubPullRequestBinding:
        binding = super().open_or_reconcile_campaign_pull_request(*args, **kwargs)
        return replace(binding, **self.open_updates)


class MarkerGitHub(FakeGitHub):
    def __init__(self, *, update_body: str | None = None, verify_body: str | None = None) -> None:
        super().__init__()
        self.update_body = update_body
        self.verify_body = verify_body
        self.discovery_calls = 0
        self.change_on_rebind = False

    def discover_campaign_evidence(self, *args: Any, **kwargs: Any) -> GitHubPullRequestDiscovery:
        self.discovery_calls += 1
        discovery = super().discover_campaign_evidence(*args, **kwargs)
        if self.change_on_rebind and self.discovery_calls > 1:
            evidence = replace(discovery.evidence, synthetic_merge_tree="d" * 40)
            return replace(discovery, evidence=evidence)
        return discovery

    def update_campaign_marker(self, intent: Any) -> GitHubPullRequestBinding:
        binding = super().update_campaign_marker(intent)
        if self.update_body is not None:
            return replace(binding, body=self.update_body)
        return binding

    def verify_campaign_marker(self, intent: Any) -> GitHubPullRequestBinding:
        binding = super().verify_campaign_marker(intent)
        if self.verify_body is not None:
            return replace(binding, body=self.verify_body)
        return binding


class ReadGitHub(FakeGitHub):
    def __init__(self, raw: object) -> None:
        super().__init__()
        self.raw = raw

    def _path(self, value: str) -> str:
        return "/" + value

    def _call(self, method: str, path: str) -> object:
        assert method == "GET"
        assert path == "/git/ref/heads/main"
        return self.raw


def publication() -> CandidatePublicationBinding:
    package = fixture_package()
    return package.publication


def test_open_binds_exact_publication_base_and_identity() -> None:
    fake = FakeGitHub()
    provider = GitHubCampaignProvider(fake, main_head_reader=lambda: G)  # type: ignore[arg-type]
    opened = provider.open_or_reconcile(publication())
    assert fake.open_base == G
    assert opened.open_identity == campaign_open_identity(publication(), opened)


def test_validation_trigger_is_between_open_and_check_discovery(tmp_path: Any) -> None:
    fake = FakeGitHub()
    validation = SyntheticValidationService(fake, SyntheticValidationJournal(tmp_path))
    provider = GitHubCampaignProvider(
        fake, main_head_reader=lambda: G, validation_service=validation  # type: ignore[arg-type]
    )
    pub = publication()
    opened = provider.open_or_reconcile(pub)
    assert fake.events == [
        "open",
        "observe",
        "validation-read",
        "validation-create",
        "validation-read",
    ]
    plan = provider.validation_plan
    assert plan is not None
    assert plan.request.trusted_check_contexts == ["avo synthetic validate (ubuntu-latest)"]
    provider.discover(opened, pub)
    assert fake.events[-1] == "discover"


def test_non_success_validation_outcome_blocks_check_discovery(tmp_path: Any) -> None:
    fake = FakeGitHub()
    fake.validation_ref = {"commit": "d" * 40, "tree": H}
    validation = SyntheticValidationService(fake, SyntheticValidationJournal(tmp_path))
    provider = GitHubCampaignProvider(
        fake, main_head_reader=lambda: G, validation_service=validation  # type: ignore[arg-type]
    )
    with pytest.raises(ValueError, match="synthetic validation trigger"):
        provider.open_or_reconcile(publication())
    assert "discover" not in fake.events


def test_validation_replay_does_not_create_a_duplicate_ref(tmp_path: Any) -> None:
    fake = FakeGitHub()
    validation = SyntheticValidationService(fake, SyntheticValidationJournal(tmp_path))
    provider = GitHubCampaignProvider(
        fake, main_head_reader=lambda: G, validation_service=validation  # type: ignore[arg-type]
    )
    pub = publication()
    provider.open_or_reconcile(pub)
    provider.open_or_reconcile(pub)
    assert fake.events.count("validation-create") == 1


def test_discovery_rejects_head_drift_before_marker_mutation() -> None:
    fake = FakeGitHub(head_commit=J)
    provider = GitHubCampaignProvider(fake, main_head_reader=lambda: G)  # type: ignore[arg-type]
    pub = publication()
    opened = provider.open_or_reconcile(pub)
    with pytest.raises(ValueError, match="publication-bound"):
        provider.discover(opened, pub)
    assert fake.marker_updates == 0


def test_bind_updates_one_marker_and_rechecks_unchanged_evidence() -> None:
    package = fixture_package()
    fake = FakeGitHub()
    provider = GitHubCampaignProvider(fake, main_head_reader=lambda: G)  # type: ignore[arg-type]
    pub = publication()
    opened = provider.open_or_reconcile(pub)
    discovery = provider.discover(opened, pub)
    prepared = provider.bind(pub, package.bundle, package.bundle_digest, opened, discovery)
    assert prepared.marker_verified
    assert prepared.template.bundle_digest == package.bundle_digest
    assert fake.marker_updates == 1


def test_final_evidence_does_not_invent_success_for_already_applied() -> None:
    package = fixture_package()
    fake = FakeGitHub()
    provider = GitHubCampaignProvider(fake, main_head_reader=lambda: G)  # type: ignore[arg-type]
    report = package.report.model_copy(update={"outcome": "already_applied"})
    final = provider.final_evidence(package.intent, report, package.observation)
    assert final.merge_result.outcome == "ambiguous"
    assert final.merge_result.result_commit is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("base_commit", H),
        ("head_ref", "refs/heads/other"),
        ("head_commit", J),
        ("base_ref", "refs/heads/main"),
        ("state", "closed"),
        ("draft", True),
    ],
)
def test_open_rejects_every_binding_drift(field: str, value: object) -> None:
    provider = GitHubCampaignProvider(
        BindingGitHub(open_updates={field: value}),  # type: ignore[arg-type]
        main_head_reader=lambda: G,
    )  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="not bound"):
        provider.open_or_reconcile(publication())


def test_constructor_rejects_unsafe_campaign_metadata() -> None:
    fake = FakeGitHub()
    with pytest.raises(ValueError, match="main ref"):
        GitHubCampaignProvider(fake, main_ref="refs/heads/release")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="title"):
        GitHubCampaignProvider(fake, pull_request_title=" \t")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="title"):
        GitHubCampaignProvider(fake, pull_request_title="bad\x00title")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="body"):
        GitHubCampaignProvider(fake, pull_request_body="bad\x00body")  # type: ignore[arg-type]


def test_discovery_rejects_open_identity_and_provider_ref_or_base_drift() -> None:
    pub = publication()
    opened = GitHubCampaignProvider(FakeGitHub(), main_head_reader=lambda: G).open_or_reconcile(pub)  # type: ignore[arg-type]
    fake = FakeGitHub()
    provider = GitHubCampaignProvider(fake, main_head_reader=lambda: G)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="identity"):
        provider.discover(replace(opened, open_identity=D), pub)

    class DriftGitHub(FakeGitHub):
        def discover_campaign_evidence(
            self, *args: Any, **kwargs: Any
        ) -> GitHubPullRequestDiscovery:
            result = super().discover_campaign_evidence(*args, **kwargs)
            return replace(
                result,
                pull_request=replace(result.pull_request, base_ref="refs/heads/other"),
            )

    drift = GitHubCampaignProvider(DriftGitHub(), main_head_reader=lambda: G)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="target ref"):
        drift.discover(drift.open_or_reconcile(pub), pub)

    class BaseDriftCampaignProvider(GitHubCampaignProvider):
        def _observation(
            self, discovery: GitHubPullRequestDiscovery, publication: CandidatePublicationBinding
        ) -> Any:
            result = super()._observation(discovery, publication)
            return result.model_copy(update={"base_tree": H})

    base_drift = BaseDriftCampaignProvider(FakeGitHub(), main_head_reader=lambda: G)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="base drifted"):
        base_drift.discover(base_drift.open_or_reconcile(pub), pub)


@pytest.mark.parametrize(
    "raw",
    [None, {"object": None}, {"object": {"sha": None}}, {"object": {"sha": "bad"}}],
)
def test_default_main_reader_rejects_malformed_provider_responses(raw: object) -> None:
    provider = GitHubCampaignProvider(ReadGitHub(raw))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="malformed"):
        provider.discover(provider.open_or_reconcile(publication()), publication())


def test_default_main_reader_uses_encoded_read_only_ref() -> None:
    provider = GitHubCampaignProvider(ReadGitHub({"object": {"sha": G}}))  # type: ignore[arg-type]
    discovery = provider.discover(provider.open_or_reconcile(publication()), publication())
    assert discovery.main_before_commit == G


def test_bind_rejects_identity_digest_snapshot_and_marker_or_evidence_drift() -> None:
    package = fixture_package()
    pub = publication()
    fake = FakeGitHub()
    provider = GitHubCampaignProvider(fake, main_head_reader=lambda: G)  # type: ignore[arg-type]
    opened = provider.open_or_reconcile(pub)
    discovery = provider.discover(opened, pub)
    with pytest.raises(ValueError, match="identity"):
        provider.bind(
            pub, package.bundle, package.bundle_digest, opened, replace(discovery, open_identity=D)
        )
    with pytest.raises(ValueError, match="digest"):
        provider.bind(pub, package.bundle, D, opened, discovery)
    bad_bundle = package.bundle.model_copy(
        update={
            "snapshot": package.bundle.snapshot.model_copy(
                update={"repository_digest": "sha256:" + "f" * 64}
            )
        }
    )
    with pytest.raises(ValueError, match="snapshot"):
        provider.bind(
            pub,
            bad_bundle,
            __import__(
                "avo_correlate.contracts.promotion_bundle", fromlist=["promotion_bundle_digest"]
            ).promotion_bundle_digest(bad_bundle),
            opened,
            discovery,
        )

    marker = MarkerGitHub(update_body="no marker")
    marker_provider = GitHubCampaignProvider(marker, main_head_reader=lambda: G)  # type: ignore[arg-type]
    opened = marker_provider.open_or_reconcile(pub)
    with pytest.raises(ValueError, match="not persisted"):
        marker_provider.bind(
            pub,
            package.bundle,
            package.bundle_digest,
            opened,
            marker_provider.discover(opened, pub),
        )

    verify = MarkerGitHub(verify_body="no marker")
    verify_provider = GitHubCampaignProvider(verify, main_head_reader=lambda: G)  # type: ignore[arg-type]
    opened = verify_provider.open_or_reconcile(pub)
    with pytest.raises(ValueError, match="verification"):
        verify_provider.bind(
            pub,
            package.bundle,
            package.bundle_digest,
            opened,
            verify_provider.discover(opened, pub),
        )

    changed = MarkerGitHub()
    changed.change_on_rebind = True
    changed_provider = GitHubCampaignProvider(changed, main_head_reader=lambda: G)  # type: ignore[arg-type]
    opened = changed_provider.open_or_reconcile(pub)
    with pytest.raises(ValueError, match="changed"):
        changed_provider.bind(
            pub,
            package.bundle,
            package.bundle_digest,
            opened,
            changed_provider.discover(opened, pub),
        )


def test_final_evidence_rejects_mismatches_and_inexact_applied_result() -> None:
    package = fixture_package()
    provider = GitHubCampaignProvider(FakeGitHub(), main_head_reader=lambda: G)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="operation"):
        provider.final_evidence(
            package.intent,
            package.report.model_copy(update={"operation_id": D}),
            package.observation,
        )
    with pytest.raises(ValueError, match="observation"):
        provider.final_evidence(
            package.intent,
            package.report,
            package.observation.model_copy(update={"pull_request_number": 99}),
        )

    class BadReconcile(FakeGitHub):
        def reconcile(self, intent: Any) -> Any:
            return fixture_package().reconciliation.model_copy(update={"merged": False})

    bad = GitHubCampaignProvider(BadReconcile(), main_head_reader=lambda: G)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="no merged"):
        bad.final_evidence(package.intent, package.report, package.observation)

    class InexactReconcile(FakeGitHub):
        def reconcile(self, intent: Any) -> Any:
            return fixture_package().reconciliation.model_copy(update={"target_head_tree": G})

    inexact = GitHubCampaignProvider(InexactReconcile(), main_head_reader=lambda: G)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="inexact"):
        inexact.final_evidence(package.intent, package.report, package.observation)

    rejected = package.report.model_copy(update={"outcome": "rejected"})
    result = provider.final_evidence(package.intent, rejected, package.observation)
    assert result.merge_result.outcome == "rejected"
