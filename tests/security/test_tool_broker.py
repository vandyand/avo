from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from avo_correlate.adapters.tools.workspace import ToolPolicyError, WorkspaceToolBroker
from avo_correlate.application.capabilities import CapabilityIssuer, InvalidCapabilityToken
from avo_correlate.contracts.tools import CapabilityClaims
from tests.conftest import DIGEST_A, experiment_spec


def broker_and_token(tmp_path: Path) -> tuple[WorkspaceToolBroker, str, CapabilityIssuer]:
    (tmp_path / "src").mkdir()
    (tmp_path / "private").mkdir()
    (tmp_path / "src" / "module.py").write_text(
        "needle = 1\n", encoding="utf-8", newline="\n"
    )
    (tmp_path / "private" / "hidden.py").write_text(
        "secret = 1\n", encoding="utf-8", newline="\n"
    )
    issuer = CapabilityIssuer(b"k" * 32)
    claims = CapabilityClaims(
        token_id="token-1",
        session_id="session-1",
        actor_id="harness-1",
        workspace_digest=DIGEST_A,
        tools=["read_file", "search_workspace"],
        policy_decision_id="policy-1",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    token = issuer.issue(claims)
    broker = WorkspaceToolBroker(
        tmp_path,
        experiment_spec().workspace,
        issuer=issuer,
        session_id="session-1",
        workspace_digest=DIGEST_A,
    )
    return broker, token, issuer


def test_capability_scopes_tools_session_and_workspace(tmp_path: Path) -> None:
    broker, token, issuer = broker_and_token(tmp_path)
    assert broker.read_file(token, "src/module.py") == b"needle = 1\n"
    assert broker.search_workspace(token, "needle") == ["src/module.py:1:needle = 1"]
    with pytest.raises(InvalidCapabilityToken, match="tool is not granted"):
        issuer.verify(
            token,
            session_id="session-1",
            workspace_digest=DIGEST_A,
            tool_id="apply_patch",
        )
    with pytest.raises(InvalidCapabilityToken, match="another session"):
        issuer.verify(
            token,
            session_id="session-2",
            workspace_digest=DIGEST_A,
            tool_id="read_file",
        )


@pytest.mark.parametrize(
    "path",
    ["../private/hidden.py", "private/hidden.py", "/etc/passwd", "C:/Windows/win.ini"],
)
def test_path_escape_and_forbidden_paths_are_blocked(tmp_path: Path, path: str) -> None:
    broker, token, _ = broker_and_token(tmp_path)
    with pytest.raises((ValueError, ToolPolicyError)):
        broker.read_file(token, path)


def test_tampered_and_expired_tokens_are_blocked(tmp_path: Path) -> None:
    _, token, issuer = broker_and_token(tmp_path)
    with pytest.raises(InvalidCapabilityToken):
        issuer.verify(
            token + "x",
            session_id="session-1",
            workspace_digest=DIGEST_A,
            tool_id="read_file",
        )
    expired = CapabilityClaims(
        token_id="expired",
        session_id="session-1",
        actor_id="harness-1",
        workspace_digest=DIGEST_A,
        tools=["read_file"],
        policy_decision_id="policy-1",
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    with pytest.raises(InvalidCapabilityToken, match="expired"):
        issuer.verify(
            issuer.issue(expired),
            session_id="session-1",
            workspace_digest=DIGEST_A,
            tool_id="read_file",
        )


def test_vcs_free_broker_inspects_diff_with_external_metadata(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    candidate = tmp_path / "candidate"
    metadata = tmp_path / "metadata"
    for root, value in ((baseline, "before\n"), (candidate, "after\n")):
        (root / "src").mkdir(parents=True)
        (root / "src" / "module.py").write_text(value, encoding="utf-8")
    metadata.mkdir()
    issuer = CapabilityIssuer(b"k" * 32)
    token = issuer.issue(
        CapabilityClaims(
            token_id="diff-token",
            session_id="session-1",
            actor_id="harness-1",
            workspace_digest=DIGEST_A,
            tools=["inspect_diff"],
            policy_decision_id="policy-1",
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    )
    broker = WorkspaceToolBroker(
        candidate,
        experiment_spec().workspace,
        issuer=issuer,
        session_id="session-1",
        workspace_digest=DIGEST_A,
        baseline_root=baseline,
        git_metadata_parent=metadata,
    )
    patch = broker.inspect_diff(token)
    assert b"-before" in patch and b"+after" in patch
    assert not (candidate / ".git").exists()


def test_replace_text_is_atomic_and_preserves_newline_convention(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "src").mkdir(parents=True)
    target = workspace / "src" / "module.py"
    target.write_bytes(b"def value():\r\n    return 1\r\n")
    issuer = CapabilityIssuer(b"k" * 32)
    token = issuer.issue(
        CapabilityClaims(
            token_id="replace-token",
            session_id="session-1",
            actor_id="harness-1",
            workspace_digest=DIGEST_A,
            tools=["replace_text"],
            policy_decision_id="policy-1",
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    )
    broker = WorkspaceToolBroker(
        workspace,
        experiment_spec().workspace,
        issuer=issuer,
        session_id="session-1",
        workspace_digest=DIGEST_A,
    )

    updated = broker.replace_text(
        token,
        "src/module.py",
        "    return 1\n",
        "    return 2\n\n",
    )

    assert updated == b"def value():\r\n    return 2\r\n"
    assert target.read_bytes() == updated


def test_replace_text_rejects_non_unique_old_text_without_mutation(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "src").mkdir(parents=True)
    target = workspace / "src" / "module.py"
    target.write_text("same\nsame\n", encoding="utf-8")
    issuer = CapabilityIssuer(b"k" * 32)
    token = issuer.issue(
        CapabilityClaims(
            token_id="replace-token",
            session_id="session-1",
            actor_id="harness-1",
            workspace_digest=DIGEST_A,
            tools=["replace_text"],
            policy_decision_id="policy-1",
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
    )
    broker = WorkspaceToolBroker(
        workspace,
        experiment_spec().workspace,
        issuer=issuer,
        session_id="session-1",
        workspace_digest=DIGEST_A,
    )

    with pytest.raises(ToolPolicyError, match="found 2 occurrences"):
        broker.replace_text(token, "src/module.py", "same", "new")
    assert target.read_text(encoding="utf-8") == "same\nsame\n"
