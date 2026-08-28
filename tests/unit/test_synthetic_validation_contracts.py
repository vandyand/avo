import pytest
from pydantic import ValidationError

from avo_correlate.contracts.synthetic_validation import (
    SyntheticValidationCreateAuthorization,
    SyntheticValidationObservation,
    SyntheticValidationPlan,
    SyntheticValidationRequest,
    validation_ref_for,
)

D = "sha256:" + "a" * 64


def observation() -> SyntheticValidationObservation:
    return SyntheticValidationObservation(
        repository_digest=D,
        base_ref="refs/heads/integration",
        base_commit="1" * 40,
        base_tree="2" * 40,
        head_ref="refs/heads/feature/change",
        head_commit="3" * 40,
        head_tree="4" * 40,
        synthetic_commit="5" * 40,
        synthetic_tree="6" * 40,
    )


def request() -> SyntheticValidationRequest:
    return SyntheticValidationRequest(
        observation=observation(),
        target_repository_digest=D,
        target_ref="refs/heads/integration",
        target_identity="campaign-1",
        trusted_check_contexts=["validate (windows-latest)", "validate (ubuntu-latest)"],
    )


def test_plan_and_ref_are_deterministic_and_contexts_normalized() -> None:
    first = request()
    second = first.model_copy(deep=True)
    assert first == second
    from avo_correlate.contracts.synthetic_validation import synthetic_validation_operation_id

    operation = synthetic_validation_operation_id(first)
    plan = SyntheticValidationPlan(
        operation_id=operation,
        request=first,
        validation_ref=validation_ref_for(operation),
        expected_commit="5" * 40,
        expected_tree="6" * 40,
    )
    assert plan.plan_digest.startswith("sha256:")
    assert plan.validation_ref.startswith("refs/heads/avo/validation/")
    assert first.trusted_check_contexts == sorted(first.trusted_check_contexts)


def test_main_deploy_and_duplicate_contexts_are_rejected() -> None:
    with pytest.raises(ValidationError):
        SyntheticValidationRequest.model_validate(
            request().model_dump(mode="python") | {"target_ref": "refs/heads/main"}
        )
    with pytest.raises(ValidationError):
        SyntheticValidationRequest.model_validate(
            request().model_dump(mode="python") | {"trusted_check_contexts": ["same", "same"]}
        )
    with pytest.raises(ValueError):
        validation_ref_for("sha256:" + "A" * 64)


def test_create_authorization_binds_plan_and_exact_ref() -> None:
    req = request()
    from avo_correlate.contracts.synthetic_validation import synthetic_validation_operation_id

    operation = synthetic_validation_operation_id(req)
    plan = SyntheticValidationPlan(
        operation_id=operation,
        request=req,
        validation_ref=validation_ref_for(operation),
        expected_commit="5" * 40,
        expected_tree="6" * 40,
    )
    authorization = SyntheticValidationCreateAuthorization(
        operation_id=operation,
        plan_digest=plan.plan_digest,
        validation_ref=plan.validation_ref,
        expected_commit=plan.expected_commit,
        expected_tree=plan.expected_tree,
    )
    assert authorization.validation_ref == plan.validation_ref
    with pytest.raises(ValidationError):
        SyntheticValidationCreateAuthorization.model_validate(
            authorization.model_dump(mode="python")
            | {"validation_ref": "refs/heads/avo/validation/" + "b" * 64}
        )
