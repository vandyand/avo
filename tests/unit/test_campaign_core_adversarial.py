"""Adversarial coverage for the AVO-004.5 campaign CORE records and recovery."""

import errno
import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from avo_correlate.adapters.artifacts import campaign_journal as journal_module
from avo_correlate.adapters.artifacts.campaign_journal import (
    CampaignCompletionJournal,
    CampaignJournalError,
)
from avo_correlate.application.integration_campaign_service import (
    CampaignDiscovery,
    CampaignOpened,
    CampaignPreparation,
    CampaignQualityEvidence,
    IntegrationCampaignPrerequisiteError,
    IntegrationCampaignRequest,
    IntegrationCampaignService,
    IntegrationCampaignUnsafeError,
)
from avo_correlate.contracts.integration_campaign import (
    CampaignCompletionPlan,
    CampaignFinalEvidenceRecord,
    IntegrationCampaignEvidencePackage,
    IntegrationIntentTemplate,
)
from avo_correlate.contracts.promotion_bundle import PromotionDryRunResult
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest
from tests.unit.test_campaign_completion_recovery import (
    Journal,
    Main,
    Provider,
    Store,
    Writer,
)
from tests.unit.test_campaign_completion_recovery import (
    _plan as make_plan,  # pyright: ignore[reportPrivateUsage]
)
from tests.unit.test_campaign_completion_recovery import (
    _service as make_service,  # pyright: ignore[reportPrivateUsage]
)
from tests.unit.test_integration_campaign_contracts import (
    _package as make_package,  # pyright: ignore[reportPrivateUsage]
)
from tests.unit.test_integration_campaign_contracts import (
    _template_values as template_values,  # pyright: ignore[reportPrivateUsage]
)

D = "sha256:" + "a" * 64
E = "sha256:" + "b" * 64
G = "a" * 40
H = "b" * 40
pytestmark = pytest.mark.filterwarnings("ignore:Pydantic serializer warnings")


def _validate_package(package: IntegrationCampaignEvidencePackage, **updates: Any) -> None:
    with pytest.raises(ValueError):
        package.model_copy(update=updates).validate_package()  # pyright: ignore[reportCallIssue]


def _validate_plan(plan: CampaignCompletionPlan, **updates: Any) -> None:
    with pytest.raises(ValueError):
        plan.model_copy(update=updates).validate_plan()  # pyright: ignore[reportCallIssue]


def _mutate_publication(package: IntegrationCampaignEvidencePackage) -> dict[str, object]:
    return {"publication": package.publication.model_copy(update={"repository_digest": E})}


def _mutate_observation(package: IntegrationCampaignEvidencePackage) -> dict[str, object]:
    return {"observation": package.observation.model_copy(update={"head_ref": "wrong"})}


def _mutate_reconciliation(package: IntegrationCampaignEvidencePackage) -> dict[str, object]:
    return {"reconciliation": package.reconciliation.model_copy(update={"target_ref": "wrong"})}


def _mutate_lease(package: IntegrationCampaignEvidencePackage) -> dict[str, object]:
    lease = package.lease_evidence.model_copy(update={"identity": "wrong"})
    return {
        "lease_evidence": lease,
        "lease_evidence_artifact": package.lease_evidence_artifact.model_copy(
            update={
                "digest": canonical_digest(lease),
                "size_bytes": len(canonical_bytes(lease)),
            }
        ),
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("bundle_digest", E),
        ("intent_digest", E),
        ("receipt_digest", E),
        ("campaign_marker_digest", E),
        ("main_before_commit", "bad"),
        ("main_after_commit", "bad"),
        ("main_after_commit", H),
        ("deploy_performed", True),
    ],
)
def test_package_rejects_top_level_tampering(field: str, value: object) -> None:
    _validate_package(make_package(), **{field: value})


def test_package_rejects_digest_and_role_tampering() -> None:
    package = make_package()
    _validate_package(package, intent=package.intent.model_copy(update={"operation_id": E}))
    _validate_package(package, receipt=package.receipt.model_copy(update={"bundle_digest": E}))
    _validate_package(
        package,
        report=package.report.model_copy(update={"intent_digest": E}),
    )
    _validate_package(
        package,
        receipt=package.receipt.model_copy(update={"intent_digest": E}),
    )
    _validate_package(
        package,
        report=package.report.model_copy(update={"outcome": "already_applied"}),
    )
    _validate_package(
        package,
        receipt=package.receipt.model_copy(update={"observation_digest": E}),
    )
    duplicate = [*package.evidence_artifacts, package.evidence_artifacts[0].model_copy()]
    _validate_package(package, evidence_artifacts=duplicate)
    role_duplicate = [
        package.evidence_artifacts[0],
        package.evidence_artifacts[0].model_copy(update={"digest": E}),
    ]
    _validate_package(package, evidence_artifacts=role_duplicate)
    _validate_package(
        package,
        lease_evidence_artifact=package.lease_evidence_artifact.model_copy(
            update={"role": "wrong"}
        ),
    )
    _validate_package(
        package,
        lease_evidence_artifact=package.lease_evidence_artifact.model_copy(
            update={"media_type": "text/plain"}
        ),
    )
    _validate_package(
        package,
        lease_evidence_artifact=package.lease_evidence_artifact.model_copy(
            update={"size_bytes": 1}
        ),
    )


@pytest.mark.parametrize(
    "mutate",
    [
        _mutate_publication,
        _mutate_observation,
        _mutate_reconciliation,
        _mutate_lease,
    ],
)
def test_package_rejects_cross_record_tampering(mutate: Any) -> None:
    package = make_package()
    _validate_package(package, **mutate(package))


def test_package_rejects_applied_result_shape_and_non_success_merge() -> None:
    package = make_package()
    _validate_package(
        package,
        reconciliation=package.reconciliation.model_copy(update={"merged": False}),
    )
    _validate_package(
        package,
        reconciliation=package.reconciliation.model_copy(update={"target_head_tree": G}),
    )
    _validate_package(
        package,
        merge_result=package.merge_result.model_copy(update={"outcome": "ambiguous"}),
    )
    _validate_package(
        package,
        merge_result=package.merge_result.model_copy(update={"result_commit": G}),
    )
    already = package.model_copy(
        update={
            "receipt": package.receipt.model_copy(
                update={"outcome": "already_applied", "error": None}
            ),
            "report": package.report.model_copy(update={"outcome": "already_applied"}),
            "merge_result": package.merge_result.model_copy(update={"outcome": "ambiguous"}),
        }
    )
    # The branch is reached before the later result checks for already-applied records.
    _validate_package(already, merge_result=package.merge_result)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("operation_id", E),
        ("bundle_digest", E),
        ("main_before_commit", "bad"),
    ],
)
def test_completion_plan_rejects_identity_tampering(field: str, value: object) -> None:
    _validate_plan(make_plan(make_package()), **{field: value})


def test_completion_plan_rejects_each_binding_boundary() -> None:
    fixture = make_package()
    plan = make_plan(fixture)
    _validate_plan(plan, evidence_artifacts=[])
    _validate_plan(plan, opened=plan.opened.model_copy(update={"open_identity": E}))
    _validate_plan(plan, discovery=plan.discovery.model_copy(update={"open_identity": E}))
    _validate_plan(plan, main_before_commit=H)
    _validate_plan(plan, opened=plan.opened.model_copy(update={"base_commit": H}))
    _validate_plan(plan, opened=plan.opened.model_copy(update={"target_ref": "wrong"}))
    _validate_plan(
        plan,
        discovery=plan.discovery.model_copy(
            update={
                "observation": plan.discovery.observation.model_copy(update={"head_ref": "wrong"})
            }
        ),
    )
    _validate_plan(
        plan,
        preparation=plan.preparation.model_copy(update={"marker_verified": False}),
    )
    _validate_plan(
        plan,
        preparation=plan.preparation.model_copy(
            update={
                "observation": plan.preparation.observation.model_copy(update={"head_ref": "wrong"})
            }
        ),
    )
    _validate_plan(
        plan,
        preparation=plan.preparation.model_copy(update={"marker_digest": E}),
    )


def test_intent_template_and_bind_lease_paths() -> None:
    values = template_values()
    with pytest.raises(ValueError, match="operation ID"):
        IntegrationIntentTemplate.model_validate(values | {"operation_id": E})
    template = IntegrationIntentTemplate.model_validate(values)
    bound = template.bind_lease("lease", D)
    assert bound.controller_lease_identity == "lease"
    with pytest.raises(ValueError):
        IntegrationIntentTemplate.model_validate(values | {"candidate_ref": ""})


def test_journal_read_and_tamper_paths(tmp_path: Path) -> None:
    fixture = make_package()
    journal = CampaignCompletionJournal(tmp_path)
    assert journal.root == tmp_path.resolve()
    assert journal.read_package(fixture.intent.operation_id) is None
    with pytest.raises(ValueError, match="SHA-256"):
        journal.read_package("bad")
    final = CampaignFinalEvidenceRecord(
        operation_id=fixture.intent.operation_id,
        reconciliation=fixture.reconciliation,
        merge_result=fixture.merge_result,
    )
    ref = journal.record_final_evidence(final)
    index = (
        tmp_path
        / "campaign-completion-index"
        / "final-evidence"
        / f"{fixture.intent.operation_id.removeprefix('sha256:')}.json"
    )
    read_final = journal.read_final_evidence(fixture.intent.operation_id)
    assert read_final is not None
    assert read_final[1] == ref
    index.write_text("not json", encoding="utf-8")
    with pytest.raises(CampaignJournalError, match="malformed"):
        journal.read_final_evidence(fixture.intent.operation_id)

    # The object itself is content-addressed; a non-canonical payload is still
    # rejected even when a test double bypasses the filesystem digest check.
    journal._store.read_bytes = lambda reference: b'{ "schema_version": 1 }'  # type: ignore[method-assign]
    index.write_text(json.dumps(ref.model_dump(mode="json")), encoding="utf-8")
    with pytest.raises(CampaignJournalError, match="malformed"):
        journal.read_final_evidence(fixture.intent.operation_id)
    index.write_text(json.dumps({**ref.model_dump(mode="json"), "role": "wrong"}), encoding="utf-8")
    with pytest.raises(CampaignJournalError, match="malformed"):
        journal.read_final_evidence(fixture.intent.operation_id)

    malformed = CampaignCompletionJournal(tmp_path / "malformed")
    malformed.record_final_evidence(final)
    malformed_index = (
        tmp_path
        / "malformed"
        / "campaign-completion-index"
        / "final-evidence"
        / f"{fixture.intent.operation_id.removeprefix('sha256:')}.json"
    )
    malformed_index.write_text("not json", encoding="utf-8")
    with pytest.raises(CampaignJournalError, match="malformed"):
        malformed.record_final_evidence(final)


def test_journal_conflict_and_fsync_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = make_package()
    final = CampaignFinalEvidenceRecord(
        operation_id=fixture.intent.operation_id,
        reconciliation=fixture.reconciliation,
        merge_result=fixture.merge_result,
    )
    journal = CampaignCompletionJournal(tmp_path)
    journal.record_final_evidence(final)
    altered = final.model_copy(
        update={"reconciliation": fixture.reconciliation.model_copy(update={"target_ref": "wrong"})}
    )
    # Bypass model validation only to simulate an in-process caller tampering with a record.
    with pytest.raises(CampaignJournalError, match="conflicting"):
        journal.record_final_evidence(altered)
    sync_calls = 0

    def fail_index_sync(path: Path) -> None:
        nonlocal sync_calls
        sync_calls += 1
        if sync_calls > 1:
            raise OSError("fsync")

    monkeypatch.setattr(journal_module, "_sync_directory", fail_index_sync)
    with pytest.raises(CampaignJournalError, match="durably indexed"):
        CampaignCompletionJournal(tmp_path / "other").record_final_evidence(final)


def test_journal_rejects_nested_construct_package_before_any_write(tmp_path: Path) -> None:
    fixture = make_package()
    journal = CampaignCompletionJournal(tmp_path)
    with pytest.raises(CampaignJournalError, match="malformed campaign package"):
        journal.record_package(fixture)
    assert not (tmp_path / "artifacts").exists()
    assert not (tmp_path / "campaign-completion-index").exists()


def test_sync_directory_platform_and_close_paths(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def unsupported(*args: Any) -> int:
        del args
        raise OSError(errno.EINVAL, "directory fsync unsupported")

    monkeypatch.setattr(journal_module.os, "open", unsupported)
    monkeypatch.setattr(journal_module.os, "name", "nt")
    sync_directory = cast(
        Callable[[Path], None],
        journal_module._sync_directory,  # pyright: ignore[reportPrivateUsage]
    )
    sync_directory(tmp_path)
    monkeypatch.setattr(journal_module.os, "name", "posix")
    with pytest.raises(OSError):
        sync_directory(tmp_path)

    calls: list[int] = []

    def fake_open(*args: object, **kwargs: object) -> int:
        del args, kwargs
        return 5

    def fake_fsync(fd: int) -> None:
        calls.append(fd)

    def fake_close(fd: int) -> None:
        calls.append(fd + 10)

    monkeypatch.setattr(journal_module.os, "open", fake_open)
    monkeypatch.setattr(journal_module.os, "fsync", fake_fsync)
    monkeypatch.setattr(journal_module.os, "close", fake_close)
    sync_directory(tmp_path)
    assert calls == [5, 15]


def test_service_static_validation_boundaries() -> None:
    fixture = make_package()
    publication = fixture.publication
    request = IntegrationCampaignRequest(Path("candidate"), "c", "p", D)
    intake = cast(
        Any,
        type(
            "I",
            (),
            {
                "candidate_id": "x",
                "proposer_id": "p",
                "source_provenance_digest": D,
                "gate_attestations": [],
                "reviewer_attestations": [],
                "rollback_attestation": None,
                "evidence_digests": [D],
                "candidate_digest": D,
            },
        )(),
    )
    with pytest.raises(IntegrationCampaignPrerequisiteError):
        IntegrationCampaignService._validate_intake(  # pyright: ignore[reportPrivateUsage]
            request, publication, intake
        )
    with pytest.raises(IntegrationCampaignPrerequisiteError):
        IntegrationCampaignService._validate_publication(  # pyright: ignore[reportPrivateUsage]
            publication.model_copy(update={"verified": False})
        )
    opened = CampaignOpened(1, "http://bad", "refs/heads/integration", G, G, D)
    with pytest.raises(IntegrationCampaignPrerequisiteError):
        IntegrationCampaignService._validate_opened(  # pyright: ignore[reportPrivateUsage]
            opened, publication
        )
    bad_discovery = CampaignDiscovery(fixture.observation, H, D)
    with pytest.raises(IntegrationCampaignPrerequisiteError):
        IntegrationCampaignService._validate_discovery(  # pyright: ignore[reportPrivateUsage]
            bad_discovery, opened, publication
        )
    with pytest.raises(ValueError, match="max_package_bytes"):
        make_service(
            fixture,
            Journal(fixture),
            Store(make_plan(fixture)),
            Provider(fixture),
            Main(),
            Writer(),
        ).__class__(
            controller=cast(Any, object()),
            promotion=cast(Any, object()),
            journal=cast(Any, Journal(fixture)),
            intake=cast(Any, object()),
            quality=cast(Any, object()),
            provider=cast(Any, object()),
            publication_verifier=lambda publication, bundle: True,
            evidence_resolver=cast(Any, object()),
            artifact_writer=Writer(),
            main_state=Main(),
            trusted_config=fixture.bundle.controller_config,
            max_package_bytes=0,
        )


def test_service_quality_and_preparation_rejection_boundaries() -> None:
    fixture = make_package()
    service = make_service(
        fixture, Journal(fixture), Store(make_plan(fixture)), Provider(fixture), Main(), Writer()
    )
    intake = cast(Any, type("I", (), {"candidate_digest": D})())
    discovery = CampaignDiscovery(fixture.observation, G, D)

    def make_gate(name: str, *, passed: bool = True, evidence: str = D) -> Any:
        return type(
            "Gate",
            (),
            {
                "gate_name": name,
                "passed": passed,
                "candidate_digest": D,
                "evidence_digest": evidence,
                "base_digest": D,
            },
        )()

    required_gates = {"trusted_ci", "private_evaluation", "provenance", "integration_soak"}
    gates = tuple(make_gate(name, passed=False) for name in required_gates)
    quality = CampaignQualityEvidence(gates, (), gates[0], (), G, G, D, D)
    with pytest.raises(IntegrationCampaignPrerequisiteError, match="gate"):
        service._validate_quality(  # pyright: ignore[reportPrivateUsage]
            intake, quality, discovery
        )
    good_gates = tuple(
        make_gate(name, evidence=(E if name == "trusted_ci" else D)) for name in required_gates
    )
    quality = replace(quality, gate_attestations=good_gates, synthetic_merge_commit=G)
    with pytest.raises(IntegrationCampaignPrerequisiteError, match="quality evidence"):
        service._validate_quality(  # pyright: ignore[reportPrivateUsage]
            intake, quality, discovery
        )
    with pytest.raises(IntegrationCampaignPrerequisiteError, match="different integration base"):
        service._validate_quality_base(  # pyright: ignore[reportPrivateUsage]
            quality, E
        )
    with pytest.raises(IntegrationCampaignPrerequisiteError, match="incomplete artifacts"):
        service._validate_artifacts(  # pyright: ignore[reportPrivateUsage]
            (), (D,)
        )
    template = make_plan(fixture).preparation.template
    opened = CampaignOpened(7, fixture.intent.pull_request_url, fixture.intent.target_ref, G, G, D)
    dry = PromotionDryRunResult.model_construct(
        bundle=cast(Any, fixture.bundle),
        bundle_digest=fixture.bundle_digest,
        artifact=cast(Any, fixture.evidence_artifacts[0]),
    )
    prepared = CampaignPreparation(template, fixture.observation, True, D)
    with pytest.raises(IntegrationCampaignPrerequisiteError, match="provider binding"):
        service._validate_preparation(  # pyright: ignore[reportPrivateUsage]
            replace(prepared, template=template.model_copy(update={"candidate_ref": "wrong"})),
            fixture.publication,
            dry,
            discovery,
        )
    with pytest.raises(IntegrationCampaignPrerequisiteError, match="intent-bound"):
        service._validate_preparation(  # pyright: ignore[reportPrivateUsage]
            replace(
                prepared, observation=fixture.observation.model_copy(update={"head_ref": "wrong"})
            ),
            fixture.publication,
            dry,
            discovery,
        )
    with pytest.raises(IntegrationCampaignUnsafeError, match="intent"):
        service._assert_plan_intent_receipt(  # pyright: ignore[reportPrivateUsage]
            make_plan(fixture),
            fixture.intent.model_copy(update={"candidate_ref": "wrong"}),
            fixture.receipt,
        )
    with pytest.raises(IntegrationCampaignUnsafeError, match="receipt"):
        service._assert_plan_intent_receipt(  # pyright: ignore[reportPrivateUsage]
            make_plan(fixture),
            fixture.intent,
            fixture.receipt.model_copy(update={"operation_id": E}),
        )
    assert opened.pull_request_number == 7


def test_service_missing_durable_records_and_release_error() -> None:
    fixture = make_package()

    class MissingJournal(Journal):
        def read_intent(self, operation_id: str) -> None:
            del operation_id
            return None

        def read_receipt(self, operation_id: str) -> None:
            del operation_id
            return None

    missing = make_service(
        fixture,
        MissingJournal(fixture),
        Store(make_plan(fixture)),
        Provider(fixture),
        Main(),
        Writer(),
    )
    with pytest.raises(IntegrationCampaignUnsafeError, match="intent"):
        missing._read_intent(  # pyright: ignore[reportPrivateUsage]
            fixture.intent.operation_id
        )
    with pytest.raises(IntegrationCampaignUnsafeError, match="receipt"):
        missing._read_receipt(  # pyright: ignore[reportPrivateUsage]
            fixture.receipt.operation_id
        )

    class BrokenJournal(Journal):
        def release_matching_lease(self, *args: Any) -> bool:
            del args
            raise OSError("release failed")

    with pytest.raises(IntegrationCampaignUnsafeError, match="released"):
        make_service(
            fixture,
            BrokenJournal(fixture),
            Store(make_plan(fixture)),
            Provider(fixture),
            Main(),
            Writer(),
        )._release_recovered_lease(  # pyright: ignore[reportPrivateUsage]
            fixture.intent
        )


def test_finalize_rejects_missing_plan_and_receipt_conflict() -> None:
    fixture = make_package()
    plan = make_plan(fixture)
    store = Store(plan)
    service = make_service(fixture, Journal(fixture), store, Provider(fixture), Main(), Writer())
    with pytest.raises(IntegrationCampaignUnsafeError, match="missing"):
        service.finalize(E)

    class ConflictingJournal(Journal):
        def read_intent(self, operation_id: str) -> Any:
            return fixture.intent.model_copy(
                update={"candidate_ref": "wrong"}
            ), self.fixture.evidence_artifacts[0]

    with pytest.raises(IntegrationCampaignUnsafeError, match="conflicts"):
        make_service(
            fixture, ConflictingJournal(fixture), store, Provider(fixture), Main(), Writer()
        ).finalize(fixture.intent.operation_id)
