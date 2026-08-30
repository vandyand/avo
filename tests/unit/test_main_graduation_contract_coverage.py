"""Additional fail-closed coverage for the main-graduation contracts.

The larger journal fixture is deliberately built with ``model_construct`` so
that journal tests can represent recovered records.  These tests explicitly
call each contract validator after one semantic mutation; this keeps the
coverage useful as a regression suite for the authority chain.
"""

# Mutation tables below intentionally keep each semantic edge together.

from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from avo_correlate.contracts.main_graduation import (
    MainCheckObservation,
    MainDeltaManifest,
    MainGraduationAttempt,
    MainGraduationEligibilityRecord,
    MainInverseDeltaArtifact,
    MainLeaseEvidence,
    MainRollbackAuthorization,
    MainRollbackIntent,
)
from avo_correlate.contracts.promotion_policy import path_manifest_digest
from avo_correlate.domain.canonical import canonical_digest
from tests.unit.test_main_graduation_journal_coverage import (
    BASE,
    D2,
    GROUP,
    HEAD,
    NOW,
    TREE,
    D,
    R,
    completion,
    composition,
    issuer,
    plan,
    ref,
    source,
)

# The fixture intentionally uses recovered model_construct records; these
# tests invoke their validators explicitly after each semantic mutation.
# pyright: reportArgumentType=false, reportUnknownArgumentType=false


def invalid(record: object, method: str, **updates: object) -> None:
    """Run a model validator against one mutated recovered record."""
    mutated = record.model_copy(update=updates)  # type: ignore[attr-defined]
    with pytest.raises(ValueError):
        getattr(mutated, method)()


def test_path_and_source_contracts_reject_normalization_and_artifact_substitution() -> None:
    delta = MainDeltaManifest.model_construct(
        operation_id=D,
        repository_digest=R,
        package_digest=D,
        source_result_commit=HEAD,
        source_result_tree=TREE,
        source_result_parent=BASE,
        changed_paths=["src/a.py"],
        path_manifest_digest=D,
        delta_digest=D2,
        ordinary_risk_digest=D,
    )
    for paths in (
        ["src/z.py", "src/a.py"],
        ["src/a.py", "src/a.py"],
        ["src/a.py", "src/A.py"],
        ["../escape.py"],
    ):
        with pytest.raises((ValidationError, ValueError)):
            MainDeltaManifest.model_validate(
                {**delta.model_dump(mode="json"), "changed_paths": paths}
            )

    package = source()
    invalid(package, "validate_source", child_artifacts=[ref(D, role="one"), ref(D, role="two")])
    invalid(package, "validate_source", child_artifacts=[ref(D2, role="one"), ref(D2, role="two")])
    invalid(
        package,
        "validate_source",
        package_artifact=ref(
            D2,
            role="integration-campaign-package",
            media_type="application/vnd.avo.integration-campaign+json",
        ),
    )
    invalid(
        package,
        "validate_source",
        package_artifact=ref(
            D, role="wrong", media_type="application/vnd.avo.integration-campaign+json"
        ),
    )
    invalid(
        package,
        "validate_source",
        package_artifact=ref(D, role="integration-campaign-package", media_type="application/json"),
    )
    invalid(package, "validate_source", source_result_parent=HEAD)


def test_release_issuer_lease_and_composition_proof_guards() -> None:
    binding = issuer()
    invalid(binding, "validate_isolation", issuer_id=binding.trusted_source_issuer)
    invalid(binding, "validate_isolation", binding_digest=D)

    lease = MainLeaseEvidence.model_construct(
        operation_id=D,
        repository_digest=R,
        identity="lease",
        acquired_at=NOW,
        expires_at=NOW + timedelta(minutes=1),
        lease_digest=D,
    )
    invalid(lease, "validate_lease_evidence", expires_at=NOW)
    invalid(lease, "validate_lease_evidence", lease_digest=D2)

    comp = composition()
    invalid(comp, "validate_composition", candidate_parent_commit=HEAD)
    invalid(comp, "validate_composition", candidate_commit=BASE)
    invalid(comp, "validate_composition", candidate_ref="refs/heads/main")
    invalid(comp, "validate_composition", retention_ref="refs/heads/main")
    invalid(comp, "validate_composition", composition_digest=D)

    proof = plan().composition_proof
    invalid(proof, "validate_proof", source_result_parent=HEAD)
    invalid(proof, "validate_proof", candidate_parent_commit=HEAD)
    invalid(proof, "validate_proof", candidate_ref="refs/heads/main")
    invalid(proof, "validate_proof", retention_ref="refs/heads/main")
    invalid(proof, "validate_proof", proof_digest=D2)


def test_observation_and_queue_contract_guards() -> None:
    check = MainCheckObservation(
        name="check",
        context="ctx",
        app_id=15368,
        sha=GROUP,
        status="completed",
        conclusion="success",
        run_id="run",
        nonce="nonce",
        observed_at=NOW,
    )
    invalid(check, "validate_check", conclusion="pending")
    invalid(check, "validate_check", status="in_progress", conclusion="success")

    queue = completion().queue_observation
    invalid(queue, "validate_queue_issuer", release_issuer_app_id=15368)
    invalid(queue, "validate_queue_issuer", expected_base_commit="")
    invalid(queue, "validate_queue_issuer", expected_group_parents=[BASE], pull_request_number=1)
    invalid(
        queue, "validate_queue_issuer", expected_group_parents=[BASE, HEAD], pull_request_number=0
    )
    invalid(queue, "validate_queue_issuer", group_topology_digest=D2)

    checks = completion().merge_group_checks
    invalid(checks, "validate_group_checks", group_sha=HEAD)
    invalid(checks, "validate_group_checks", allowlisted_contexts=["other"])
    invalid(checks, "validate_group_checks", allowlisted_contexts=["validate", "validate"])
    invalid(checks, "validate_group_checks", freshness_cutoff=NOW + timedelta(minutes=1))

    receipt = completion().hold_observation.merge_group_receipt
    invalid(receipt, "validate_receipt", group_parents=[BASE, BASE])
    invalid(receipt, "validate_receipt", receipt_digest=D2)


def test_plan_and_intent_bind_every_child_edge() -> None:
    graduation_plan = plan()
    for field, value in (
        ("operation_id", D2),
        ("repository_digest", D2),
        ("package", source().model_copy(update={"operation_id": D2})),
        ("delta", graduation_plan.delta.model_copy(update={"package_digest": D2})),
        ("composition", graduation_plan.composition.model_copy(update={"delta_digest": D})),
        ("controller_config_digest", D),
        ("release_issuer_binding", issuer().model_copy(update={"operation_id": D2})),
        ("evidence_artifacts", [ref(), ref()]),
        (
            "composition_proof",
            graduation_plan.composition_proof.model_copy(update={"composition_digest": D}),
        ),
        (
            "composition_proof_artifact",
            graduation_plan.composition_proof_artifact.model_copy(update={"role": "wrong"}),
        ),
    ):
        invalid(graduation_plan, "validate_plan", **{field: value})

    intent = completion().intent
    invalid(intent, "validate_intent", lease_identity="substituted")
    invalid(intent, "validate_intent", lease_digest=D2)
    invalid(intent, "validate_intent", lease_evidence_artifact=ref(role="wrong"))
    invalid(intent, "validate_intent", intent_digest=D2)

    # Reach the later digest/source clauses after the preceding plan clauses.
    delta = graduation_plan.delta
    expected_path = path_manifest_digest(delta.changed_paths)
    invalid(delta, "validate_delta", path_manifest_digest=expected_path)
    invalid(
        delta,
        "validate_delta",
        path_manifest_digest=expected_path,
        ordinary_risk_digest=canonical_digest(
            {
                "ordinary_risk": "ordinary",
                "changed_paths": delta.changed_paths,
                "path_manifest_digest": expected_path,
            }
        ),
    )
    valid_risk = canonical_digest(
        {
            "ordinary_risk": "ordinary",
            "changed_paths": delta.changed_paths,
            "path_manifest_digest": expected_path,
        }
    )
    delta_without_digest = delta.model_copy(
        update={"path_manifest_digest": expected_path, "ordinary_risk_digest": valid_risk}
    )
    invalid(delta_without_digest, "validate_delta", delta_digest=D)
    invalid(
        graduation_plan,
        "validate_plan",
        delta=graduation_plan.delta.model_copy(update={"source_result_commit": BASE}),
    )


def test_admission_hold_authorization_and_transition_guards() -> None:
    package = completion()
    admission = package.admission_observation
    invalid(admission, "validate_admission", admission_sha=BASE)
    invalid(admission, "validate_admission", release_issuer_app_id=15368)
    invalid(admission, "validate_admission", base_commit=HEAD)
    invalid(admission, "validate_admission", pull_request_url="http://example.test/p/1")

    hold = package.hold_observation
    invalid(hold, "validate_hold", queue_members=[2])
    invalid(hold, "validate_hold", group_parents=[HEAD, BASE])
    invalid(hold, "validate_hold", group_parents=[BASE, BASE])
    invalid(hold, "validate_hold", expected_group_parents=[BASE])
    invalid(hold, "validate_hold", group_tree=BASE)
    invalid(hold, "validate_hold", composition_tree=BASE)
    invalid(
        hold,
        "validate_hold",
        other_required_checks=package.merge_group_checks.model_copy(update={"group_sha": HEAD}),
    )
    invalid(
        hold,
        "validate_hold",
        merge_group_receipt=package.hold_observation.merge_group_receipt.model_copy(
            update={"group_sha": HEAD}
        ),
    )
    invalid(hold, "validate_hold", release_issuer_app_id=15368)

    authorization = package.release_authorization
    invalid(authorization, "validate_release_authorization", expires_at=NOW)
    invalid(authorization, "validate_release_authorization", release_issuer_app_id=15368)
    invalid(authorization, "validate_release_authorization", authorization_digest=D2)

    transition = package.transition_receipt
    invalid(transition, "validate_transition", release_issuer_app_id=15368)

    invalid(
        hold,
        "validate_hold",
        other_required_checks=package.merge_group_checks.model_copy(update={"operation_id": D2}),
    )
    release_context_check = package.merge_group_checks.checks[0].model_copy(
        update={"context": "avo-main-release"}
    )
    invalid(
        hold,
        "validate_hold",
        other_required_checks=package.merge_group_checks.model_copy(
            update={"checks": [release_context_check]}
        ),
    )


def test_provider_reconciliation_attestation_and_rollback_guards() -> None:
    package = completion()
    provider = package.provider_receipt
    invalid(provider, "validate_provider_receipt", outcome="observed", result_parents=[])
    invalid(provider, "validate_provider_receipt", outcome="rejected", result_commit=HEAD)
    invalid(provider, "validate_provider_receipt", outcome="ambiguous", result_tree=TREE)

    reconciliation = package.reconciliation
    invalid(reconciliation, "validate_reconciliation", state="completed", main_tree=BASE)
    invalid(reconciliation, "validate_reconciliation", state="completed", main_parents=[HEAD])

    attestation = package.attestation_manifest
    invalid(attestation, "validate_attestation", evaluator_identity=attestation.reviewer_identity)

    inverse_values = {
        "operation_id": D,
        "repository_digest": R,
        "completion_package_digest": D2,
        "current_main_commit": HEAD,
        "current_main_tree": TREE,
        "inverse_changed_paths": ["src/feature.py"],
        "inverse_tree": BASE,
        "policy_epoch": D,
    }
    inverse_probe = MainInverseDeltaArtifact.model_construct(
        **inverse_values, inverse_delta_digest=D
    )
    inverse = MainInverseDeltaArtifact.model_validate(
        {
            **inverse_values,
            "inverse_delta_digest": canonical_digest(
                inverse_probe.model_dump(exclude={"inverse_delta_digest"}, mode="json")
            ),
        }
    )
    invalid(inverse, "validate_inverse_delta", inverse_delta_digest=D)

    rollback_values = {
        "operation_id": D,
        "repository_digest": R,
        "completion_package_digest": D2,
        "current_main_commit": HEAD,
        "current_main_tree": TREE,
        "inverse_delta_digest": D,
        "inverse_delta_artifact_digest": D2,
        "inverse_tree": BASE,
        "lease_identity": "lease",
        "lease_digest": D,
        "policy_epoch": D,
        "authorized_at": NOW,
    }
    rollback_probe = MainRollbackAuthorization.model_construct(
        **rollback_values, authorization_digest=D
    )
    rollback = MainRollbackAuthorization.model_validate(
        {
            **rollback_values,
            "authorization_digest": canonical_digest(
                rollback_probe.model_dump(exclude={"authorization_digest"}, mode="json")
            ),
        }
    )
    invalid(rollback, "validate_rollback_authorization", authorization_digest=D2)

    rollback_intent_values = {
        "operation_id": D,
        "repository_digest": R,
        "completion_package_digest": D2,
        "inverse_delta_digest": D,
        "inverse_delta_artifact_digest": D2,
        "base_commit": BASE,
        "base_tree": TREE,
        "current_main_commit": HEAD,
        "current_main_tree": TREE,
        "candidate_commit": HEAD,
        "candidate_tree": TREE,
        "inverse_tree": BASE,
        "lease_identity": "lease",
        "lease_digest": D,
        "policy_epoch": D,
        "recorded_at": NOW,
    }
    intent_probe = MainRollbackIntent.model_construct(**rollback_intent_values, intent_digest=D)
    rollback_intent = MainRollbackIntent.model_validate(
        {
            **rollback_intent_values,
            "intent_digest": canonical_digest(
                intent_probe.model_dump(exclude={"intent_digest"}, mode="json")
            ),
        }
    )
    invalid(rollback_intent, "validate_rollback_intent", intent_digest=D2)


def test_completion_validator_rejects_each_cross_stage_substitution() -> None:
    package = completion()
    mutations = (
        ("plan", package.plan.model_copy(update={"operation_id": D2})),
        ("source_package", package.source_package.model_copy(update={"repository_digest": D2})),
        ("delta", package.delta.model_copy(update={"source_result_commit": BASE})),
        ("composition", package.composition.model_copy(update={"base_tree": BASE})),
        (
            "queue_observation",
            package.queue_observation.model_copy(update={"queue_generation_digest": D2}),
        ),
        (
            "protection_manifest",
            package.protection_manifest.model_copy(update={"issuer_isolation_digest": D2}),
        ),
        (
            "attestation_manifest",
            package.attestation_manifest.model_copy(update={"repository_digest": D2}),
        ),
        (
            "merge_group_checks",
            package.merge_group_checks.model_copy(update={"composition_digest": D}),
        ),
        (
            "release_issuer_binding",
            package.release_issuer_binding.model_copy(update={"app_id": 9002}),
        ),
        (
            "preparation_authorization",
            package.preparation_authorization.model_copy(update={"package_digest": D2}),
        ),
        (
            "admission_observation",
            package.admission_observation.model_copy(update={"head_commit": BASE}),
        ),
        ("hold_observation", package.hold_observation.model_copy(update={"group_sha": HEAD})),
        (
            "release_authorization",
            package.release_authorization.model_copy(update={"hold_nonce": "other"}),
        ),
        (
            "transition_receipt",
            package.transition_receipt.model_copy(update={"outcome": "reconciliation_required"}),
        ),
        ("provider_receipt", package.provider_receipt.model_copy(update={"result_tree": BASE})),
        ("reconciliation", package.reconciliation.model_copy(update={"main_tree": BASE})),
    )
    for field, value in mutations:
        invalid(package, "validate_completion", **{field: value})

    invalid(package, "validate_completion", artifacts=[package.artifacts[0], package.artifacts[0]])


def test_completion_validator_reaches_later_fail_closed_edges() -> None:
    package = completion()

    later = (
        ("reconciliation", package.reconciliation.model_copy(update={"expected_tree": BASE})),
        ("reconciliation", package.reconciliation.model_copy(update={"main_parents": [HEAD]})),
        ("reconciliation", package.reconciliation.model_copy(update={"main_commit": BASE})),
        (
            "reconciliation",
            package.reconciliation.model_copy(update={"expected_base_commit": HEAD}),
        ),
        ("provider_receipt", package.provider_receipt.model_copy(update={"result_tree": BASE})),
        (
            "provider_receipt",
            package.provider_receipt.model_copy(update={"result_parents": [HEAD]}),
        ),
        (
            "provider_receipt",
            package.provider_receipt.model_copy(update={"release_authorization_digest": D2}),
        ),
        (
            "reconciliation",
            package.reconciliation.model_copy(update={"transition_receipt_digest": D2}),
        ),
        (
            "reconciliation",
            package.reconciliation.model_copy(update={"queue_generation_digest": D2}),
        ),
        ("release_authorization", package.release_authorization.model_copy(update={"used": True})),
        ("source_package", package.source_package.model_copy(update={"source_issuer": "other"})),
        ("merge_group_checks", package.merge_group_checks.model_copy(update={"group_sha": BASE})),
        ("merge_group_checks", package.merge_group_checks.model_copy(update={"operation_id": D2})),
        (
            "merge_group_checks",
            package.merge_group_checks.model_copy(update={"package_digest": D2}),
        ),
        (
            "merge_group_checks",
            package.merge_group_checks.model_copy(update={"composition_digest": D}),
        ),
        (
            "queue_observation",
            package.queue_observation.model_copy(update={"queue_generation_digest": D2}),
        ),
        (
            "protection_manifest",
            package.protection_manifest.model_copy(update={"issuer_isolation_digest": D2}),
        ),
        (
            "protection_manifest",
            package.protection_manifest.model_copy(update={"release_issuer_app_id": 9002}),
        ),
        (
            "queue_observation",
            package.queue_observation.model_copy(update={"issuer_isolation_digest": D2}),
        ),
        (
            "release_issuer_binding",
            package.release_issuer_binding.model_copy(update={"isolation_digest": D2}),
        ),
        (
            "queue_observation",
            package.queue_observation.model_copy(update={"release_issuer_app_id": 9002}),
        ),
        (
            "release_issuer_binding",
            package.release_issuer_binding.model_copy(update={"app_id": 9002}),
        ),
        (
            "admission_observation",
            package.admission_observation.model_copy(update={"issuer_identity": "other"}),
        ),
        (
            "release_issuer_binding",
            package.release_issuer_binding.model_copy(update={"issuer_id": "other"}),
        ),
        (
            "admission_observation",
            package.admission_observation.model_copy(update={"queue_generation_digest": D2}),
        ),
        (
            "queue_observation",
            package.queue_observation.model_copy(update={"expected_base_commit": HEAD}),
        ),
        (
            "queue_observation",
            package.queue_observation.model_copy(update={"expected_base_tree": BASE}),
        ),
        (
            "hold_observation",
            package.hold_observation.model_copy(update={"expected_group_parents": [BASE]}),
        ),
        (
            "hold_observation",
            package.hold_observation.model_copy(update={"group_topology_digest": D2}),
        ),
        (
            "protection_manifest",
            package.protection_manifest.model_copy(update={"isolated_release_issuer": "other"}),
        ),
        (
            "provider_receipt",
            package.provider_receipt.model_copy(update={"provider_identity": "other"}),
        ),
        (
            "admission_observation",
            package.admission_observation.model_copy(update={"base_commit": HEAD}),
        ),
        (
            "admission_observation",
            package.admission_observation.model_copy(update={"head_commit": BASE}),
        ),
        (
            "admission_observation",
            package.admission_observation.model_copy(update={"head_tree": BASE}),
        ),
        (
            "release_authorization",
            package.release_authorization.model_copy(update={"hold_observation_digest": D2}),
        ),
        (
            "release_authorization",
            package.release_authorization.model_copy(update={"admission_observation_digest": D2}),
        ),
        (
            "hold_observation",
            package.hold_observation.model_copy(update={"admission_observation_digest": D2}),
        ),
        (
            "hold_observation",
            package.hold_observation.model_copy(update={"pull_request_number": 2}),
        ),
        (
            "release_authorization",
            package.release_authorization.model_copy(update={"group_sha": BASE}),
        ),
        (
            "release_authorization",
            package.release_authorization.model_copy(update={"hold_run_id": "other"}),
        ),
        (
            "release_authorization",
            package.release_authorization.model_copy(update={"hold_nonce": "other"}),
        ),
        (
            "release_authorization",
            package.release_authorization.model_copy(update={"queue_generation_digest": D2}),
        ),
        (
            "preparation_authorization",
            package.preparation_authorization.model_copy(update={"intent_digest": D2}),
        ),
        (
            "preparation_authorization",
            package.preparation_authorization.model_copy(update={"plan_digest": D2}),
        ),
        ("intent", package.intent.model_copy(update={"plan_digest": D2})),
        (
            "release_authorization",
            package.release_authorization.model_copy(
                update={"preparation_authorization_digest": D2}
            ),
        ),
        (
            "source_package",
            package.source_package.model_copy(update={"source_issuer": "different"}),
        ),
        ("intent", package.intent.model_copy(update={"package_digest": D2})),
        ("intent", package.intent.model_copy(update={"composition_digest": D})),
        (
            "preparation_authorization",
            package.preparation_authorization.model_copy(update={"package_digest": D2}),
        ),
        (
            "preparation_authorization",
            package.preparation_authorization.model_copy(update={"composition_digest": D}),
        ),
    )
    for field, value in later:
        invalid(package, "validate_completion", **{field: value})

    roles = [
        item.model_copy(update={"role": "different"}) if i == 0 else item
        for i, item in enumerate(package.artifacts)
    ]
    invalid(package, "validate_completion", artifacts=roles)


def test_eligibility_attempt_and_preparation_contract_guards() -> None:
    eligibility = MainGraduationEligibilityRecord(
        operation_id=D,
        repository_digest=R,
        scheduler_sequence=2,
        previous_scheduler_sequence=1,
        submission_digest=D,
        classification="eligible",
        ordinary=True,
        nonempty=True,
    )
    invalid(eligibility, "validate_eligibility", ordinary=False)
    invalid(eligibility, "validate_eligibility", terminal_disposition="success")
    invalid(eligibility, "validate_eligibility", previous_scheduler_sequence=0)
    invalid(eligibility, "validate_eligibility", scheduler_watermark=2)
    excluded = eligibility.model_copy(
        update={"classification": "excluded", "ordinary": False, "nonempty": False}
    )
    invalid(excluded, "validate_eligibility", exclusion_reason=None)
    invalid(excluded, "validate_eligibility", exclusion_evidence_digest=None)

    attempt = MainGraduationAttempt(
        operation_id=D,
        repository_digest=R,
        scheduler_sequence=1,
        eligibility_record_digest=D,
    )
    invalid(attempt, "validate_attempt", terminal_disposition="failed")

    preparation = completion().preparation_authorization
    invalid(preparation, "validate_authorization", authorization_digest=D2)
