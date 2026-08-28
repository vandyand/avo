from pathlib import Path

from scripts.run_avo0046_live_rollback import (
    LiveRollbackHostedRunner,
    LiveRollbackOperator,
    build_parser,
    redact_secret,
)
from tests.unit.test_integration_live_rollback_completion import (  # pyright: ignore[reportPrivateUsage]
    _completion_fixture,  # pyright: ignore[reportPrivateUsage]
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
