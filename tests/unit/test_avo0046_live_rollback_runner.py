from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

from avo_correlate.application.integration_live_rollback_completion_service import (
    LiveRollbackCompletionExecution,
    LiveRollbackCompletionInputs,
    LiveRollbackCompletionService,
)
from avo_correlate.application.integration_live_rollback_service import (
    LiveIntegrationRollbackService,
    LiveRollbackExecution,
    LiveRollbackTargetObservation,
)
from avo_correlate.contracts.base import ArtifactRef
from avo_correlate.contracts.integration_live_rollback_completion import (
    LiveRollbackCompletionPackage,
)
from avo_correlate.domain.canonical import canonical_bytes, canonical_digest
from scripts.run_avo0046_live_rollback import (
    LiveRollbackHostedRunner,
    LiveRollbackOperator,
    build_parser,
    redact_secret,
)
from tests.unit.test_integration_live_rollback_completion import (  # pyright: ignore[reportPrivateUsage]
    _completion_fixture,  # pyright: ignore[reportPrivateUsage]
)


class _DurableCompletionJournal:
    """Durable boundary fake that can cut the process after the package write."""

    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.package: LiveRollbackCompletionPackage | None = None
        self.reference: ArtifactRef | None = None
        self.crash_after_record = False

    def read_package(
        self, operation_id: str
    ) -> tuple[LiveRollbackCompletionPackage, ArtifactRef] | None:
        if self.package is None or self.package.operation_id != operation_id:
            return None
        assert self.reference is not None
        return self.package, self.reference

    def record_package(self, package: LiveRollbackCompletionPackage) -> ArtifactRef:
        self.events.append("durable-completion")
        self.package = package
        self.reference = ArtifactRef(
            digest=canonical_digest(package),
            size_bytes=len(canonical_bytes(package)),
            media_type="application/vnd.avo.integration-live-rollback-completion+json",
            role="integration-live-rollback-completion-package",
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )
        if self.crash_after_record:
            raise RuntimeError("simulated crash after durable completion write")
        return self.reference


class _LifecycleValidation:
    def __init__(self, package: LiveRollbackCompletionPackage, events: list[str]) -> None:
        self.package = package
        self.events = events
        self.trigger_calls = 0
        self.cleanup_calls = 0

    def read_durable_outcome(self, _plan: object) -> None:
        return None

    def trigger(self, _plan: object) -> object:
        self.events.append("validation-trigger")
        self.trigger_calls += 1
        return self.package.validation_outcome

    def cleanup(self, _plan: object, _proof: object) -> object:
        self.events.append("validation-cleanup")
        self.cleanup_calls += 1
        return self.package.cleanup_outcome


class _LifecycleCore:
    def __init__(self, package: LiveRollbackCompletionPackage, events: list[str]) -> None:
        self.package = package
        self.events = events
        self.run_calls = 0
        self.execution = LiveIntegrationRollbackService._execution_from_package(  # pyright: ignore[reportPrivateUsage]
            package.core_package
        )

    def read_package(self, _operation_id: str) -> None:
        return None

    def run(self, *_args: object, **_kwargs: object) -> LiveRollbackExecution:
        self.events.extend(("promotion", "core"))
        self.run_calls += 1
        return LiveRollbackExecution(
            self.execution,
            self.package.core_package,
            self.package.core_package_artifact,
            False,
        )


def _completion_inputs(package: LiveRollbackCompletionPackage) -> LiveRollbackCompletionInputs:
    return LiveRollbackCompletionInputs(
        publication_plan=package.publication_plan,
        publication_outcome=package.publication_outcome,
        publication_evidence=package.publication_evidence,
        provider_observation=package.provider_observation,
        provider_reconciliation=package.provider_reconciliation,
        check_manifest=package.check_manifest,
        protection_manifest=package.protection_manifest,
        workflow_evidence=package.workflow_evidence,
        validation_plan=package.validation_plan,
        validation_authorization=package.validation_authorization,
    )


def test_runner_redacts_tokens() -> None:
    assert redact_secret("ghp_secret") == "<redacted>"
    assert "ghp_secret" not in redact_secret("ghp_secret")
    assert redact_secret("") == "<absent>"


def test_runner_parser_requires_explicit_state_and_operation() -> None:
    args = build_parser().parse_args(
        [
            "--state-root",
            "state",
            "--operation-id",
            "sha256:" + "a" * 64,
            "--canary-operation-id",
            "sha256:" + "b" * 64,
            "--candidate-root",
            "candidate",
        ]
    )
    assert args.state_root == Path("state")
    assert args.operation_id.startswith("sha256:")


def test_operator_is_a_thin_service_boundary() -> None:
    # The constructor intentionally accepts typed hosted wiring and delegates
    # execution; no raw ref update or merge operation is exposed here.
    assert hasattr(LiveRollbackOperator, "execute")
    assert not hasattr(LiveRollbackOperator, "update_ref")


def test_completed_outer_package_prevents_lifecycle_execution(tmp_path: Path) -> None:
    package = _completion_fixture()
    runner = LiveRollbackHostedRunner(object(), tmp_path)  # type: ignore[arg-type]
    runner.completed = lambda _operation_id: (package, package.artifacts[0])  # type: ignore[method-assign]
    called = False

    def forbidden_execution() -> object:
        nonlocal called
        called = True
        raise AssertionError("a completed operation must not mutate hosted state")

    result = runner.replay_or_execute(package.operation_id, forbidden_execution)  # type: ignore[arg-type]
    assert not called
    assert result.replayed
    assert result.package == package


def test_fresh_lifecycle_durable_cut_replays_without_hosted_mutations(tmp_path: Path) -> None:
    package = _completion_fixture()
    events: list[str] = []
    durable = _DurableCompletionJournal(events)
    durable.crash_after_record = True
    validation = _LifecycleValidation(package, events)
    core = _LifecycleCore(package, events)
    current = package.provider_reconciliation
    service = LiveRollbackCompletionService(
        cast(Any, core),
        cast(Any, validation),
        cast(Any, durable),
        current_target_observation=lambda: LiveRollbackTargetObservation(
            repository_digest=current.repository_digest,
            target_ref=current.target_ref,
            commit=current.target_head_commit,
            tree=current.target_head_tree,
            parent_commits=(package.core_package.request.failed_integration_head_commit,),
        ),
        main_head_reader=lambda: package.main_before_commit,
    )
    operator = LiveRollbackOperator(cast(Any, object()), service)
    runner = LiveRollbackHostedRunner(cast(Any, object()), tmp_path)
    runner.completed = durable.read_package  # type: ignore[method-assign]

    def execute_fresh() -> LiveRollbackCompletionExecution:
        return operator.execute(
            package.core_package.request,
            canary_package=package.core_package.canary_package,
            canary_package_artifact=package.core_package.canary_package_artifact,
            authorization=package.core_package.authorization,
            bundle=package.core_package.bundle,
            publication=package.core_package.publication,
            bundle_digest=package.core_package.bundle_digest,
            intent_factory=lambda _lease: cast(Any, object()),
            inputs=_completion_inputs(package),
        )

    with pytest.raises(RuntimeError, match="after durable completion"):
        runner.replay_or_execute(package.operation_id, execute_fresh)  # type: ignore[arg-type]
    assert events == [
        "validation-trigger",
        "promotion",
        "core",
        "validation-cleanup",
        "durable-completion",
    ]
    assert validation.trigger_calls == validation.cleanup_calls == core.run_calls == 1

    replay = runner.replay_or_execute(package.operation_id, execute_fresh)  # type: ignore[arg-type]
    assert replay.replayed
    assert replay.package is durable.package
    assert events == [
        "validation-trigger",
        "promotion",
        "core",
        "validation-cleanup",
        "durable-completion",
    ]
    assert validation.trigger_calls == validation.cleanup_calls == core.run_calls == 1
