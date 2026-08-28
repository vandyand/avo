from pathlib import Path

from scripts.run_avo0046_live_rollback import (
    LiveRollbackOperator,
    build_parser,
    redact_secret,
)


def test_runner_redacts_tokens() -> None:
    assert redact_secret("ghp_secret") == "<redacted>"
    assert "ghp_secret" not in redact_secret("ghp_secret")
    assert redact_secret("") == "<absent>"


def test_runner_parser_requires_explicit_state_and_operation() -> None:
    args = build_parser().parse_args(
        ["--state-root", "state", "--operation-id", "sha256:" + "a" * 64]
    )
    assert args.state_root == Path("state")
    assert args.operation_id.startswith("sha256:")


def test_operator_is_a_thin_service_boundary() -> None:
    # The constructor intentionally accepts typed hosted wiring and delegates
    # execution; no raw ref update or merge operation is exposed here.
    assert hasattr(LiveRollbackOperator, "execute")
    assert not hasattr(LiveRollbackOperator, "update_ref")
