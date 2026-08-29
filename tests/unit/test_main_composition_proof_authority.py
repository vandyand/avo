"""Security checks for the controller-rooted C2 proof boundary."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
    MainGraduationJournalError,
)
from avo_correlate.adapters.git.main_composition import MainBaseSnapshot, MainCompositionAdapter
from avo_correlate.contracts.integration_campaign import IntegrationCampaignEvidencePackage
from avo_correlate.contracts.main_graduation import (
    MainGraduationPlan,
    MainReleaseIssuerBinding,
    MainSourcePackageBinding,
)
from avo_correlate.domain.canonical import canonical_digest

D = "sha256:" + "1" * 64
OP = "sha256:" + "2" * 64
SOURCE_OP = "sha256:" + "3" * 64


def _binding() -> MainReleaseIssuerBinding:
    values: dict[str, Any] = {
        "operation_id": OP,
        "repository_digest": D,
        "controller_config_digest": D,
        "issuer_id": "isolated-release",
        "app_id": 9001,
        "isolation_digest": D,
        "trusted_source_issuer": "source-controller",
        "trusted_source_domain": "integration-campaign",
    }
    probe = MainReleaseIssuerBinding.model_construct(**values, binding_digest=D)
    return MainReleaseIssuerBinding.model_validate(
        {
            **values,
            "binding_digest": canonical_digest(
                probe.model_dump(exclude={"binding_digest"}, mode="json")
            ),
        }
    )


def test_noop_verifier_has_no_public_authority_seam(tmp_path: Path) -> None:
    journal = MainGraduationJournal(tmp_path, release_issuer_binding=_binding())
    assert not hasattr(journal, "bind_composition_verifier")
    with pytest.raises(TypeError):
        MainGraduationJournal(tmp_path / "other", composition_verifier=object())  # type: ignore[call-arg]


def test_self_declared_proof_has_no_public_record_authority(tmp_path: Path) -> None:
    journal = MainGraduationJournal(tmp_path, release_issuer_binding=_binding())
    assert not hasattr(journal, "record_composition_proof")


def test_hand_recorded_c2_without_proof_cannot_reach_plan_index(tmp_path: Path) -> None:
    journal = MainGraduationJournal(tmp_path, release_issuer_binding=_binding())
    plan = MainGraduationPlan.model_construct(
        operation_id=OP,
        package=SimpleNamespace(package_digest=D),
        delta=SimpleNamespace(delta_digest=D),
        composition=SimpleNamespace(composition_digest=D),
    )
    with pytest.raises(MainGraduationJournalError, match="composition authority"):
        journal._verify_plan_composition(plan)  # type: ignore[reportPrivateUsage]
    assert journal.read_plan(OP) is None


def test_rooted_adapter_proof_authorizes_plan_and_survives_main_advance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Reuse the real Git repository/source-delta setup; the source package is
    # supplied as a shape-valid immutable test double because package closure
    # validation is covered by the journal suite.
    from test_main_composition import (
        _BaseReader,  # pyright: ignore[reportPrivateUsage]
        _repo,  # pyright: ignore[reportPrivateUsage]
        _source,  # pyright: ignore[reportPrivateUsage]
    )

    root, parent, result, result_tree, parent_tree = _repo(tmp_path)
    source, package = _source(parent, result, result_tree, changed=["feature.txt"])
    config_digest = canonical_digest(
        {"repository_digest": D, "target_ref": "refs/heads/main"}
    )
    issuer_values: dict[str, Any] = {
        "operation_id": source.operation_id,
        "repository_digest": D,
        "controller_config_digest": config_digest,
        "issuer_id": "isolated-release",
        "app_id": 9001,
        "isolation_digest": D,
        "trusted_source_issuer": source.source_issuer,
        "trusted_source_domain": source.source_domain,
    }
    issuer_probe = MainReleaseIssuerBinding.model_construct(**issuer_values, binding_digest=D)
    issuer = MainReleaseIssuerBinding.model_validate(
        {
            **issuer_values,
            "binding_digest": canonical_digest(
                issuer_probe.model_dump(exclude={"binding_digest"}, mode="json")
            ),
        }
    )
    reader = _BaseReader(MainBaseSnapshot(D, parent, parent_tree))
    journal = MainGraduationJournal(
        tmp_path / "journal",
        release_issuer_binding=issuer,
        policy_epoch=D,
        composition_root=root,
        repository_digest=D,
        base_reader=reader,
    )
    def accept_source(_value: MainSourcePackageBinding) -> None:
        return None

    monkeypatch.setattr(journal, "_verify_source_package", accept_source)
    journal.record_source_package(source)
    def read_package(
        _self: MainCompositionAdapter,
        _source: MainSourcePackageBinding,
        _durable: MainSourcePackageBinding,
    ) -> IntegrationCampaignEvidencePackage:
        return package

    monkeypatch.setattr(MainCompositionAdapter, "_read_package", read_package)
    adapter = MainCompositionAdapter(
        root,
        journal,
        repository_digest=D,
        base_reader=reader,
        controller_config_digest=config_digest,
        policy_epoch=D,
    )
    composed = adapter.compose(source, base=MainBaseSnapshot(D, parent, parent_tree))
    plan = MainGraduationPlan.model_validate(
        {
            "operation_id": source.operation_id,
            "repository_digest": D,
            "target_ref": "refs/heads/main",
            "package": source,
            "delta": composed.delta,
            "composition": composed.composition,
            "composition_proof": composed.proof,
            "composition_proof_artifact": composed.proof_artifact,
            "policy_epoch": D,
            "controller_config_digest": config_digest,
            "release_issuer_binding": issuer,
            "evidence_artifacts": [source.package_artifact],
        }
    )
    def accept_plan(_value: MainGraduationPlan) -> None:
        return None

    monkeypatch.setattr(journal, "_verify_plan_evidence", accept_plan)
    for field, value in (
        ("controller_config_digest", "sha256:" + "4" * 64),
        ("base_commit", "d" * 40),
        ("base_tree", "e" * 40),
        ("candidate_tree", "f" * 40),
        ("retention_ref", "refs/avo/main-composition/" + "9" * 64),
    ):
        tampered = plan.model_copy(
            update={"composition_proof": plan.composition_proof.model_copy(update={field: value})}
        )
        with pytest.raises(MainGraduationJournalError, match="rooted recomputation"):
            journal._verify_plan_composition(tampered)  # type: ignore[reportPrivateUsage]
        assert journal.read_plan(source.operation_id) is None
    journal.record_plan(plan)
    assert journal.read_plan(source.operation_id) is not None

    # Restart/read is durable-only: advancing the observed main base and
    # making the live recomputation path explode must not affect plan reads.
    reader.snapshot = MainBaseSnapshot(D, result, result_tree)
    restarted = MainGraduationJournal(
        tmp_path / "journal",
        release_issuer_binding=issuer,
        policy_epoch=D,
        composition_root=root,
        repository_digest=D,
        base_reader=reader,
    )
    def fail_live(_value: MainGraduationPlan) -> None:
        pytest.fail("live revalidation")

    monkeypatch.setattr(restarted, "_verify_plan_composition", fail_live)
    monkeypatch.setattr(restarted, "_verify_plan_evidence", accept_plan)
    assert restarted.read_plan(source.operation_id) is not None
