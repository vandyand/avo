from typing import Any, cast

import pytest

from avo_correlate.application.integration_live_rollback_completion_service import (
    LiveRollbackCompletionInputs,
    LiveRollbackCompletionService,
    LiveRollbackCoreCompletionProofVerifier,
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
from avo_correlate.contracts.synthetic_validation import SyntheticValidationOutcome
from tests.unit.test_integration_live_rollback_completion import (  # pyright: ignore[reportPrivateUsage]
    _completion_fixture,  # pyright: ignore[reportPrivateUsage]
)


class _CompletionJournal:
    def __init__(
        self,
        package: LiveRollbackCompletionPackage | None = None,
        events: list[str] | None = None,
    ) -> None:
        self.package = package
        self.recorded: LiveRollbackCompletionPackage | None = None
        self.events = events if events is not None else []

    def read_package(
        self, operation_id: str
    ) -> tuple[LiveRollbackCompletionPackage, ArtifactRef] | None:
        if self.package is None or operation_id != self.package.operation_id:
            return None
        return self.package, self.package.core_package_artifact

    def record_package(self, package: LiveRollbackCompletionPackage) -> ArtifactRef:
        self.events.append("outer")
        self.recorded = package
        return package.core_package_artifact


class _Validation:
    def __init__(
        self, package: LiveRollbackCompletionPackage, events: list[str] | None = None
    ) -> None:
        self.package = package
        self.trigger_calls = 0
        self.cleanup_calls = 0
        self.events = events if events is not None else []

    def read_durable_outcome(self, _plan: object) -> SyntheticValidationOutcome | None:
        return None

    def trigger(self, _plan: object) -> SyntheticValidationOutcome:
        self.events.append("validation")
        self.trigger_calls += 1
        return self.package.validation_outcome

    def cleanup(self, _plan: object, _proof: object) -> SyntheticValidationOutcome:
        self.events.append("cleanup")
        self.cleanup_calls += 1
        return self.package.cleanup_outcome


class _Core:
    def __init__(
        self,
        package: LiveRollbackCompletionPackage,
        events: list[str] | None = None,
        expose_read: bool = False,
    ) -> None:
        self.execution = LiveIntegrationRollbackService._execution_from_package(  # pyright: ignore[reportPrivateUsage]
            package.core_package
        )
        self.package = package
        self.events = events if events is not None else []
        self.expose_read = expose_read

    def read_package(
        self, operation_id: str
    ) -> tuple[LiveRollbackCompletionPackage, ArtifactRef] | None:
        if self.expose_read and operation_id == self.package.operation_id:
            return self.package, self.package.core_package_artifact
        return None

    def run(self, *_args: object, **_kwargs: object) -> LiveRollbackExecution:
        self.events.extend(("promotion", "core"))
        return LiveRollbackExecution(
            self.execution,
            self.package.core_package,
            self.package.core_package_artifact,
            False,
        )


def _inputs(package: LiveRollbackCompletionPackage) -> LiveRollbackCompletionInputs:
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


def test_completion_service_cleans_then_indexes_outer_package() -> None:
    package = _completion_fixture()
    events: list[str] = []
    validation = _Validation(package, events)
    journal = _CompletionJournal(events=events)
    current = LiveRollbackTargetObservation(
        repository_digest=package.provider_reconciliation.repository_digest,
        target_ref=package.provider_reconciliation.target_ref,
        commit=package.provider_reconciliation.target_head_commit,
        tree=package.provider_reconciliation.target_head_tree,
        parent_commits=(package.core_package.request.failed_integration_head_commit,),
    )
    service = LiveRollbackCompletionService(
        cast(Any, _Core(package, events)),
        cast(Any, validation),
        cast(Any, journal),
        current_target_observation=lambda: current,
        main_head_reader=lambda: package.core_package.request.main_before_commit,
    )
    result = service.run(
        package.core_package.request,
        canary_package=package.core_package.canary_package,
        canary_package_artifact=package.core_package.canary_package_artifact,
        authorization=package.core_package.authorization,
        bundle=package.core_package.bundle,
        publication=package.core_package.publication,
        bundle_digest=package.core_package.bundle_digest,
        intent_factory=lambda _lease: cast(Any, object()),
        inputs=_inputs(package),
    )
    assert result.package is not None
    assert journal.recorded == result.package
    assert validation.trigger_calls == validation.cleanup_calls == 1
    assert events == ["validation", "promotion", "core", "cleanup", "outer"]


def test_completion_service_replay_reads_outer_and_does_not_cleanup() -> None:
    package = _completion_fixture()
    validation = _Validation(package)
    journal = _CompletionJournal(package)
    current = LiveRollbackTargetObservation(
        repository_digest=package.provider_reconciliation.repository_digest,
        target_ref=package.provider_reconciliation.target_ref,
        commit=package.provider_reconciliation.target_head_commit,
        tree=package.provider_reconciliation.target_head_tree,
        parent_commits=(package.core_package.request.failed_integration_head_commit,),
    )
    service = LiveRollbackCompletionService(
        cast(Any, _Core(package)),
        cast(Any, validation),
        cast(Any, journal),
        current_target_observation=lambda: current,
        main_head_reader=lambda: package.core_package.request.main_before_commit,
    )
    result = service.run(
        package.core_package.request,
        canary_package=package.core_package.canary_package,
        canary_package_artifact=package.core_package.canary_package_artifact,
        authorization=package.core_package.authorization,
        bundle=package.core_package.bundle,
        publication=package.core_package.publication,
        bundle_digest=package.core_package.bundle_digest,
        intent_factory=lambda _lease: cast(Any, object()),
        inputs=_inputs(package),
    )
    assert result.replayed
    assert result.package == package
    assert validation.trigger_calls == validation.cleanup_calls == 0


def test_completion_service_replay_rejects_stale_provider_target() -> None:
    package = _completion_fixture()
    current = LiveRollbackTargetObservation(
        repository_digest=package.provider_reconciliation.repository_digest,
        target_ref=package.provider_reconciliation.target_ref,
        commit=package.provider_observation.base_commit,
        tree=package.provider_observation.base_tree,
        parent_commits=(),
    )
    service = LiveRollbackCompletionService(
        cast(Any, _Core(package)),
        cast(Any, _Validation(package)),
        cast(Any, _CompletionJournal(package)),
        current_target_observation=lambda: current,
        main_head_reader=lambda: package.core_package.request.main_before_commit,
    )
    with pytest.raises(RuntimeError, match="stale"):
        service.run(
            package.core_package.request,
            canary_package=package.core_package.canary_package,
            canary_package_artifact=package.core_package.canary_package_artifact,
            authorization=package.core_package.authorization,
            bundle=package.core_package.bundle,
            publication=package.core_package.publication,
            bundle_digest=package.core_package.bundle_digest,
            intent_factory=lambda _lease: cast(Any, object()),
            inputs=_inputs(package),
        )


def test_completion_service_recovers_core_before_outer_without_retriggering() -> None:
    package = _completion_fixture()
    events: list[str] = []
    validation = _Validation(package, events)
    validation.read_durable_outcome = lambda _plan: package.validation_outcome  # type: ignore[method-assign]
    journal = _CompletionJournal(events=events)
    current = LiveRollbackTargetObservation(
        repository_digest=package.provider_reconciliation.repository_digest,
        target_ref=package.provider_reconciliation.target_ref,
        commit=package.provider_reconciliation.target_head_commit,
        tree=package.provider_reconciliation.target_head_tree,
        parent_commits=(package.core_package.request.failed_integration_head_commit,),
    )
    service = LiveRollbackCompletionService(
        cast(Any, _Core(package, events, expose_read=True)),
        cast(Any, validation),
        cast(Any, journal),
        current_target_observation=lambda: current,
        main_head_reader=lambda: package.core_package.request.main_before_commit,
    )
    result = service.run(
        package.core_package.request,
        canary_package=package.core_package.canary_package,
        canary_package_artifact=package.core_package.canary_package_artifact,
        authorization=package.core_package.authorization,
        bundle=package.core_package.bundle,
        publication=package.core_package.publication,
        bundle_digest=package.core_package.bundle_digest,
        intent_factory=lambda _lease: cast(Any, object()),
        inputs=_inputs(package),
    )
    assert result.package is not None
    assert validation.trigger_calls == 0


def test_core_completion_verifier_rejects_forged_digest() -> None:
    package = _completion_fixture()
    verifier = LiveRollbackCoreCompletionProofVerifier(
        package.core_package, package.core_package_artifact
    )
    forged = package.cleanup_proof.model_copy(update={"completion_digest": "sha256:" + "f" * 64})
    with pytest.raises(ValueError, match="durable rollback core"):
        verifier.verify(package.validation_plan, forged)
