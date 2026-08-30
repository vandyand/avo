"""Security checks for the controller-rooted C2 proof boundary."""

# White-box tests intentionally exercise private journal seams and reuse local
# fixture helpers from the composition test module.
# pyright: reportPrivateUsage=false, reportArgumentType=false, reportCallIssue=false, reportUnknownArgumentType=false, reportUnknownLambdaType=false

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from avo_correlate.adapters.artifacts.main_graduation_journal import (
    MainGraduationJournal,
    MainGraduationJournalError,
)
from avo_correlate.adapters.git.main_composition import (
    MainBaseSnapshot,
    MainCompositionAdapter,
    MainCompositionError,
)
from avo_correlate.contracts.integration_campaign import IntegrationCampaignEvidencePackage
from avo_correlate.contracts.main_graduation import (
    MainCompositionProof,
    MainGraduationPlan,
    MainReleaseIssuerBinding,
    MainSourcePackageBinding,
)
from avo_correlate.domain.canonical import canonical_digest

D = "sha256:" + "1" * 64
OP = "sha256:" + "2" * 64
SOURCE_OP = "sha256:" + "3" * 64


def _proof_variant(proof: MainCompositionProof, **updates: str) -> MainCompositionProof:
    values = proof.model_dump(mode="json")
    values.update(updates)
    values["proof_digest"] = canonical_digest(
        {key: value for key, value in values.items() if key != "proof_digest"}
    )
    return MainCompositionProof.model_validate(values)


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


def test_plan_authority_rejects_missing_root_capabilities_and_proof(tmp_path: Path) -> None:
    from test_main_graduation_journal_coverage import authority_plan, issuer

    value = authority_plan()
    journal = MainGraduationJournal(tmp_path, release_issuer_binding=issuer(), policy_epoch=D)
    with pytest.raises(MainGraduationJournalError, match="controller-rooted composition authority"):
        journal._verify_plan_composition(value)  # type: ignore[reportPrivateUsage]

    rooted = MainGraduationJournal(
        tmp_path / "rooted",
        release_issuer_binding=issuer(),
        policy_epoch=D,
        composition_root=tmp_path,
        repository_digest="sha256:" + "3" * 64,
        base_reader=object(),  # type: ignore[arg-type]
    )
    for field in ("composition_proof", "composition_proof_artifact"):
        missing = value.model_copy(update={field: None})
        with pytest.raises(MainGraduationJournalError, match="exact durable composition proof"):
            rooted._verify_plan_composition(missing)  # type: ignore[reportPrivateUsage]


def test_composition_proof_controller_root_checks_are_fail_closed(tmp_path: Path) -> None:
    from test_main_graduation_journal_coverage import authority_plan, issuer

    value = authority_plan()
    proof = value.composition_proof
    journal = MainGraduationJournal(
        tmp_path,
        release_issuer_binding=issuer(),
        policy_epoch=D,
    )
    for field, replacement in (
        ("verifier_identity", "forged-verifier"),
        ("verifier_version", "2"),
        ("base_observer_identity", "forged-observer"),
        ("git_root_digest", D),
    ):
        with pytest.raises(MainGraduationJournalError, match="implementation root"):
            journal._verify_composition_proof(  # type: ignore[reportPrivateUsage]
                _proof_variant(proof, **{field: replacement})
            )

    with pytest.raises(MainGraduationJournalError, match="controller root"):
        journal._verify_composition_proof(  # type: ignore[reportPrivateUsage]
            _proof_variant(proof, controller_config_digest=D)
        )
    with pytest.raises(MainGraduationJournalError, match="policy epoch"):
        journal._verify_composition_proof(  # type: ignore[reportPrivateUsage]
            _proof_variant(proof, policy_epoch="sha256:" + "4" * 64)
        )
    with pytest.raises(MainGraduationJournalError, match="lacks controller root"):
        MainGraduationJournal(tmp_path / "no-root")._verify_composition_proof(  # type: ignore[reportPrivateUsage]
            proof
        )

    mismatched_plan = value.model_copy(update={"policy_epoch": "sha256:" + "4" * 64})
    with pytest.raises(MainGraduationJournalError, match="bind exact plan"):
        journal._verify_composition_proof(  # type: ignore[reportPrivateUsage]
            proof, plan=mismatched_plan
        )


def test_durable_composition_proof_read_checks_presence_bytes_and_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from test_main_graduation_journal_coverage import authority_plan, issuer

    value = authority_plan()
    proof = value.composition_proof
    journal = MainGraduationJournal(
        tmp_path,
        release_issuer_binding=issuer(),
        policy_epoch=D,
    )
    monkeypatch.setattr(journal, "_read", lambda _kind, _key: None)
    with pytest.raises(MainGraduationJournalError, match="durable composition proof record"):
        journal._verify_plan_composition_durable(value)  # type: ignore[reportPrivateUsage]

    monkeypatch.setattr(
        journal, "_read", lambda _kind, _key: (proof, value.composition_proof_artifact)
    )
    assert journal._verify_plan_composition_durable(value) is None  # type: ignore[reportPrivateUsage]

    other = _proof_variant(proof, candidate_tree="f" * 40)
    monkeypatch.setattr(
        journal, "_read", lambda _kind, _key: (other, value.composition_proof_artifact)
    )
    with pytest.raises(MainGraduationJournalError, match="differs from durable"):
        journal._verify_plan_composition_durable(value)  # type: ignore[reportPrivateUsage]

    monkeypatch.setattr(
        journal,
        "_read",
        lambda _kind, _key: (
            proof,
            value.composition_proof_artifact.model_copy(
                update={
                    "created_at": value.composition_proof_artifact.created_at.replace(year=2027)
                }
            ),
        ),
    )
    with pytest.raises(MainGraduationJournalError, match="reference differs"):
        journal._verify_plan_composition_durable(value)  # type: ignore[reportPrivateUsage]


def test_private_composition_authorization_requires_rooted_capabilities(tmp_path: Path) -> None:
    from test_main_graduation_journal_coverage import authority_plan, issuer

    value = authority_plan()
    journal = MainGraduationJournal(tmp_path, release_issuer_binding=issuer(), policy_epoch=D)
    with pytest.raises(MainGraduationJournalError, match="trusted Git/base capabilities"):
        journal._authorize_composition(  # type: ignore[reportPrivateUsage]
            value.package,
            value.delta,
            value.composition,
            controller_config_digest=value.controller_config_digest,
            policy_epoch=value.policy_epoch,
        )


def test_composition_proof_recording_errors_are_wrapped_at_adapter_boundary(
    tmp_path: Path,
) -> None:
    from test_main_composition import _Adapter, _Journal, _repo, _source

    root, parent, result, result_tree, parent_tree = _repo(tmp_path)
    source, package = _source(parent, result, result_tree, changed=["feature.txt"])

    class AuthorizationFailureJournal(_Journal):
        def __init__(self) -> None:
            super().__init__(source)
            self._composition_root = root

        def _authorize_composition(self, *_args: Any, **_kwargs: Any) -> Any:
            raise RuntimeError("authorization interrupted")

    class RecordFailureJournal(_Journal):
        def record_composition_proof(self, _proof: MainCompositionProof) -> Any:
            raise ValueError("proof index unavailable")

    base = MainBaseSnapshot(D, parent, parent_tree)
    with pytest.raises(MainCompositionError) as authorization_error:
        _Adapter(root, AuthorizationFailureJournal(), package).compose(source, base=base)
    assert "not durably authorized" in str(authorization_error.value)

    with pytest.raises(MainCompositionError) as record_error:
        _Adapter(root, RecordFailureJournal(source), package).compose(source, base=base)
    assert "not durably recorded" in str(record_error.value)


def test_composition_adapter_rejects_missing_or_conflicting_retention_refs(
    tmp_path: Path,
) -> None:
    from test_main_composition import _Adapter, _git, _Journal, _repo, _source

    root, parent, result, result_tree, parent_tree = _repo(tmp_path)
    source, package = _source(parent, result, result_tree, changed=["feature.txt"])
    journal = _Journal(source)
    adapter = _Adapter(root, journal, package)
    composed = adapter.compose(source, base=MainBaseSnapshot(D, parent, parent_tree))

    _git(root, "update-ref", "-d", composed.composition.retention_ref)
    with pytest.raises(MainCompositionError, match="does not retain candidate"):
        adapter.verify(source, composed.delta, composed.composition)

    # Recreate the retention ref, then deliberately point the optional
    # candidate ref at the wrong commit so replay rejects a conflicting owner.
    _git(
        root,
        "update-ref",
        composed.composition.retention_ref,
        composed.composition.candidate_commit,
    )
    _git(root, "update-ref", composed.composition.candidate_ref, parent)
    with pytest.raises(MainCompositionError, match="conflicting commit"):
        adapter.verify(source, composed.delta, composed.composition)


def test_main_journal_composition_proof_record_and_read_are_durable(tmp_path: Path) -> None:
    from test_main_graduation_journal_coverage import authority_plan, issuer

    value = authority_plan()
    journal = MainGraduationJournal(
        tmp_path,
        release_issuer_binding=issuer(),
        policy_epoch=D,
    )
    reference = journal.record("composition-proof", value.composition_proof)
    stored = journal.read_composition_proof(value.operation_id)
    assert stored == (value.composition_proof, reference)


def test_main_journal_plan_authority_wraps_live_and_preserves_journal_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from test_main_graduation_journal_coverage import authority_plan, issuer

    from avo_correlate.adapters.git.main_composition import MainCompositionAdapter

    value = authority_plan()
    journal = MainGraduationJournal(
        tmp_path,
        release_issuer_binding=issuer(),
        policy_epoch=D,
        composition_root=tmp_path,
        repository_digest="sha256:" + "3" * 64,
        base_reader=object(),  # type: ignore[arg-type]
    )

    def runtime_failure(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("live Git unavailable")

    monkeypatch.setattr(MainCompositionAdapter, "verify", runtime_failure)
    with pytest.raises(MainGraduationJournalError, match="authority rejected plan"):
        journal._verify_plan_composition(value)  # type: ignore[reportPrivateUsage]

    def journal_failure(*_args: Any, **_kwargs: Any) -> Any:
        raise MainGraduationJournalError("already classified")

    monkeypatch.setattr(MainCompositionAdapter, "verify", journal_failure)
    with pytest.raises(MainGraduationJournalError, match="already classified"):
        journal._verify_plan_composition(value)  # type: ignore[reportPrivateUsage]


def test_main_journal_plan_authority_rejects_proof_reference_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from test_main_graduation_journal_coverage import authority_plan, issuer

    from avo_correlate.adapters.git.main_composition import MainCompositionAdapter

    value = authority_plan()
    journal = MainGraduationJournal(
        tmp_path,
        release_issuer_binding=issuer(),
        policy_epoch=D,
        composition_root=tmp_path,
        repository_digest="sha256:" + "3" * 64,
        base_reader=object(),  # type: ignore[arg-type]
    )
    monkeypatch.setattr(
        MainCompositionAdapter,
        "verify",
        lambda *_args, **_kwargs: value.composition_proof,
    )
    monkeypatch.setattr(journal, "_record", lambda *_args: object())
    with pytest.raises(MainGraduationJournalError, match="reference differs"):
        journal._verify_plan_composition(value)  # type: ignore[reportPrivateUsage]


def test_main_journal_authorization_wraps_live_and_preserves_journal_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from test_main_graduation_journal_coverage import authority_plan, issuer

    from avo_correlate.adapters.git.main_composition import MainCompositionAdapter

    value = authority_plan()
    journal = MainGraduationJournal(
        tmp_path,
        release_issuer_binding=issuer(),
        policy_epoch=D,
        composition_root=tmp_path,
        repository_digest="sha256:" + "3" * 64,
        base_reader=object(),  # type: ignore[arg-type]
    )

    def runtime_failure(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("live Git unavailable")

    monkeypatch.setattr(MainCompositionAdapter, "verify", runtime_failure)
    with pytest.raises(MainGraduationJournalError, match="authority rejected composition"):
        journal._authorize_composition(  # type: ignore[reportPrivateUsage]
            value.package,
            value.delta,
            value.composition,
            controller_config_digest=value.controller_config_digest,
            policy_epoch=value.policy_epoch,
        )

    def journal_failure(*_args: Any, **_kwargs: Any) -> Any:
        raise MainGraduationJournalError("already classified")

    monkeypatch.setattr(MainCompositionAdapter, "verify", journal_failure)
    with pytest.raises(MainGraduationJournalError, match="already classified"):
        journal._authorize_composition(  # type: ignore[reportPrivateUsage]
            value.package,
            value.delta,
            value.composition,
            controller_config_digest=value.controller_config_digest,
            policy_epoch=value.policy_epoch,
        )


def test_main_journal_rejects_invalid_and_noncanonical_composition_proofs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from test_main_graduation_journal_coverage import authority_plan, issuer

    from avo_correlate.adapters.artifacts import main_graduation_journal as journal_module

    journal = MainGraduationJournal(tmp_path, release_issuer_binding=issuer(), policy_epoch=D)
    with pytest.raises(MainGraduationJournalError, match="proof is invalid"):
        journal._verify_composition_proof(MainCompositionProof.model_construct())  # type: ignore[reportPrivateUsage]

    proof = authority_plan().composition_proof
    original = journal_module.canonical_bytes
    calls = 0

    def noncanonical(value: Any) -> bytes:
        nonlocal calls
        calls += 1
        return original(value) if calls == 1 else b"{}"

    monkeypatch.setattr(journal_module, "canonical_bytes", noncanonical)
    with pytest.raises(MainGraduationJournalError, match="not canonical"):
        journal._verify_composition_proof(proof)  # type: ignore[reportPrivateUsage]


def test_main_composition_identity_and_base_guards_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Reader:
        def __init__(self, value: Any) -> None:
            self.value = value

        def fresh_main_base(self) -> Any:
            if isinstance(self.value, BaseException):
                raise self.value
            return self.value

    with pytest.raises(MainCompositionError, match="SHA-256"):
        MainCompositionAdapter._require_digest("invalid", "test")  # type: ignore[reportPrivateUsage]

    with pytest.raises(ValueError, match="candidate ref prefix"):
        MainCompositionAdapter(
            tmp_path,
            object(),  # type: ignore[arg-type]
            repository_digest=D,
            base_reader=Reader(object()),
            candidate_ref_prefix="refs/heads/attacker/",
        )
    with pytest.raises(ValueError, match="timeout"):
        MainCompositionAdapter(
            tmp_path,
            object(),  # type: ignore[arg-type]
            repository_digest=D,
            base_reader=Reader(object()),
            command_timeout_seconds=0,
        )

    good = MainBaseSnapshot(D, "a" * 40, "b" * 40)
    for observed, message in (
        (RuntimeError("reader down"), "observation failed"),
        (object(), "wrong type"),
        (MainBaseSnapshot("sha256:" + "2" * 64, "a" * 40, "b" * 40), "repository"),
        (MainBaseSnapshot(D, "a" * 40, "b" * 40, "refs/heads/dev"), "protected main"),
    ):
        adapter = MainCompositionAdapter(
            tmp_path,
            object(),  # type: ignore[arg-type]
            repository_digest=D,
            base_reader=Reader(observed),
        )
        with pytest.raises(MainCompositionError, match=message):
            adapter.fresh_main_base()

    adapter = MainCompositionAdapter(
        tmp_path,
        object(),  # type: ignore[arg-type]
        repository_digest=D,
        base_reader=Reader(good),
    )
    with pytest.raises(MainCompositionError, match="protected main"):
        adapter._validate_base(  # type: ignore[reportPrivateUsage]
            good.__class__(D, good.commit, good.tree, "refs/heads/dev"), good, D
        )
    with pytest.raises(MainCompositionError, match="repository differs"):
        adapter._validate_base(  # type: ignore[reportPrivateUsage]
            good, good, "sha256:" + "2" * 64
        )

    monkeypatch.setattr(adapter, "_git_bytes", lambda *_args: b"\xff")
    with pytest.raises(MainCompositionError, match="non-UTF-8"):
        adapter._source_delta("a" * 40, "b" * 40)  # type: ignore[reportPrivateUsage]
    monkeypatch.setattr(adapter, "_git_bytes", lambda *_args: b"")
    with pytest.raises(MainCompositionError, match="empty delta"):
        adapter._source_delta("a" * 40, "b" * 40)  # type: ignore[reportPrivateUsage]


def test_main_composition_topology_and_retention_guards_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = MainCompositionAdapter(
        tmp_path,
        object(),  # type: ignore[arg-type]
        repository_digest=D,
        base_reader=object(),  # type: ignore[arg-type]
    )
    with pytest.raises(MainCompositionError, match="outside controller namespace"):
        adapter._retain_candidate("refs/heads/main", "a" * 40)  # type: ignore[reportPrivateUsage]

    monkeypatch.setattr(adapter, "_git_bytes", lambda *_args: b"tree \xff\n\n")
    with pytest.raises(MainCompositionError, match="headers are not ASCII"):
        adapter._commit_topology("a" * 40)  # type: ignore[reportPrivateUsage]
    monkeypatch.setattr(adapter, "_git_bytes", lambda *_args: b"tree malformed\n\n")
    with pytest.raises(MainCompositionError, match="topology is malformed"):
        adapter._commit_topology("a" * 40)  # type: ignore[reportPrivateUsage]

    monkeypatch.setattr(adapter, "_commit_topology", lambda _commit: ("a" * 40, []))
    with pytest.raises(MainCompositionError, match="tree observation"):
        adapter._verify_candidate("a" * 40, "b" * 40, "c" * 40)  # type: ignore[reportPrivateUsage]
    monkeypatch.setattr(adapter, "_commit_topology", lambda _commit: ("a" * 40, ["d" * 40]))
    with pytest.raises(MainCompositionError, match="sole main parent"):
        adapter._verify_candidate("a" * 40, "a" * 40, "c" * 40)  # type: ignore[reportPrivateUsage]

    monkeypatch.setattr(adapter, "_commit_topology", lambda _commit: ("a" * 40, []))
    with pytest.raises(MainCompositionError, match="tree differs"):
        adapter._verify_commit_tree("a" * 40, "b" * 40, "main")  # type: ignore[reportPrivateUsage]
    monkeypatch.setattr(adapter, "_git_bytes", lambda *_args: b"malformed\0")
    with pytest.raises(MainCompositionError, match="entry is malformed"):
        adapter._verify_commit_tree("a" * 40, None, "main")  # type: ignore[reportPrivateUsage]
    monkeypatch.setattr(
        adapter,
        "_git_bytes",
        lambda *_args: ("100120 blob " + "a" * 40 + "\tfile.txt\0").encode(),
    )
    with pytest.raises(MainCompositionError, match="VCS/reparse hazard"):
        adapter._verify_commit_tree("a" * 40, None, "main")  # type: ignore[reportPrivateUsage]


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
