import pytest
from pydantic import ValidationError

from avo_correlate.contracts.integration_drill import (
    IntegrationDrillCaseResult,
    IntegrationDrillPlan,
    IntegrationDrillRollbackAuthorization,
)
from avo_correlate.domain.canonical import canonical_digest

D = "sha256:" + "a" * 64
G = "a" * 40


def test_plan_requires_eight_cases_and_exact_integration_ref():
    values = dict(
        schema_version=1,
        operation_id=D,
        repository_digest=D,
        target_ref="refs/heads/integration",
        main_before_commit=G,
        main_before_tree=G,
        case_ids=list(range(1, 9)),
        evidence_artifacts=[],
    )
    values["plan_digest"] = canonical_digest(values)
    assert IntegrationDrillPlan.model_validate(values).case_ids == list(range(1, 9))
    values["target_ref"] = "refs/heads/main"
    with pytest.raises(ValidationError):
        IntegrationDrillPlan.model_validate(values)


def test_case_rejects_success_without_evidence_and_failure_without_error():
    base = dict(
        case_id=1,
        operation_id=D,
        target_ref="refs/heads/integration",
        repository_digest=D,
        main_before_commit=G,
        main_after_commit=G,
        target_head_commit=G,
        target_head_tree=G,
        target_parents=[],
        attester_identity="attester",
    )
    with pytest.raises(ValidationError):
        IntegrationDrillCaseResult.model_validate({**base, "outcome": "passed"})
    with pytest.raises(ValidationError):
        IntegrationDrillCaseResult.model_validate({**base, "outcome": "failed"})


def test_rollback_authorization_binds_exact_git_objects():
    values = dict(
        operation_id=D,
        authorization_id=D,
        repository_digest=D,
        target_ref="refs/heads/integration",
        main_before_commit=G,
        main_after_commit=G,
        target_head_commit=G,
        target_head_tree=G,
        target_parents=[],
        failed_integration_head_commit=G,
        failed_integration_head_tree=G,
        restore_to_commit=G,
        restore_to_tree=G,
        rollback_candidate_commit="b" * 40,
        rollback_candidate_parent_commit=G,
        issuer="controller",
        reason="soak failure",
    )
    assert IntegrationDrillRollbackAuthorization.model_validate(values).authorized
    values["restore_to_commit"] = "bad"
    with pytest.raises(ValidationError):
        IntegrationDrillRollbackAuthorization.model_validate(values)
