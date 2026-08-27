from avo_correlate.contracts.base import ActorRef, VersionedComponentRef
from avo_correlate.contracts.budgets import BudgetSpec
from avo_correlate.contracts.experiment import (
    EvaluatorSpec,
    ExperimentSpec,
    HarnessSpec,
    ReviewPolicy,
    SearchSpec,
    WorkspaceSpec,
)

DIGEST_A = "sha256:" + ("a" * 64)
DIGEST_B = "sha256:" + ("b" * 64)


def component(component_id: str) -> VersionedComponentRef:
    return VersionedComponentRef(
        component_id=component_id,
        component_version="1.0.0",
        package_digest=DIGEST_A,
        capability_manifest_digest=DIGEST_B,
    )


def experiment_spec(experiment_id: str = "experiment-1") -> ExperimentSpec:
    return ExperimentSpec(
        experiment_id=experiment_id,
        title="Reference repair",
        objective="Repair the reference defect",
        success_criteria=["All admission tests pass"],
        workspace=WorkspaceSpec(
            source_uri="https://example.invalid/reference.git",
            source_revision="abc123",
            source_tree_digest=DIGEST_A,
            allowed_paths=["src", "tests"],
            forbidden_paths=["private"],
            required_paths=["pyproject.toml"],
            max_file_bytes=1_000_000,
            max_tree_bytes=10_000_000,
        ),
        search=SearchSpec(
            method_version="1.0.0",
            max_committed_candidates=3,
            stopping_rules=["first_admission"],
        ),
        harness=HarnessSpec(
            component=component("dry-run"),
            model_config_digest=DIGEST_A,
            configuration_digest=DIGEST_B,
        ),
        development_evaluators=[
            EvaluatorSpec(
                component=component("development"),
                tier="development",
                profile_digest=DIGEST_A,
                execution_image_digest=DIGEST_B,
            )
        ],
        admission_evaluators=[
            EvaluatorSpec(
                component=component("admission"),
                tier="admission",
                profile_digest=DIGEST_A,
                execution_image_digest=DIGEST_B,
            )
        ],
        budget=BudgetSpec(
            wall_clock_seconds=3600,
            model_input_tokens=10_000,
            model_output_tokens=10_000,
            model_cost_microusd=1_000_000,
            tool_calls=100,
            sandbox_cpu_seconds=3600,
            sandbox_gpu_seconds=0,
            authoritative_evaluations=10,
            variation_sessions=10,
            artifact_bytes=10_000_000,
        ),
        sandbox_profile_id="local-test",
        policy_bundle_digest=DIGEST_A,
        retention_policy_id="test",
        review_policy=ReviewPolicy(),
        created_by=ActorRef(actor_type="human", actor_id="tester"),
    )
