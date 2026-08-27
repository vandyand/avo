from avo_correlate.application.validation_service import (
    RuntimeCapabilities,
    ValidationService,
)
from tests.conftest import DIGEST_A, experiment_spec


def test_dry_run_validates_without_persisting_or_starting() -> None:
    report = ValidationService(
        RuntimeCapabilities(
            sandbox_profiles=frozenset({"local-test"}),
            component_ids=frozenset({"dry-run", "development", "admission"}),
            policy_bundle_digests=frozenset({DIGEST_A}),
        )
    ).dry_run(experiment_spec())
    assert report.outcome == "ready"
    assert all(check.outcome == "pass" for check in report.checks)


def test_dry_run_fails_closed_on_missing_capability() -> None:
    report = ValidationService(
        RuntimeCapabilities(
            sandbox_profiles=frozenset(),
            component_ids=frozenset(),
            policy_bundle_digests=frozenset(),
        )
    ).dry_run(experiment_spec())
    assert report.outcome == "blocked"
    assert any(check.check_id == "sandbox_profile" for check in report.checks)
