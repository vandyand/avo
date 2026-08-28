"""Static guardrails for the candidate-tree-triggered integration soak."""

from pathlib import Path

WORKFLOW = Path(__file__).parents[2] / ".github" / "workflows" / "integration-soak.yml"
MARKER_PATH = "docs/avo-0046-live-rollback-canary.txt"
MARKER_DIGEST = "84e940a02be358b4d7abc4d6fb1b83b723adce8fbd0feaa8c193919a0e28a318"


def workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_soak_trigger_is_exact_candidate_path_and_hash() -> None:
    text = workflow_text()
    assert f"marker_path='{MARKER_PATH}'" in text
    assert f"marker_digest='{MARKER_DIGEST}'" in text
    assert "grep -Fqx \"$marker\" \"$marker_path\"" in text
    assert "sha256sum \"$marker_path\"" in text
    assert "git log" not in text


def test_soak_trigger_fails_closed_for_symlink_or_malformed_file() -> None:
    text = workflow_text()
    assert "[[ -L \"$marker_path\" || ! -f \"$marker_path\"" in text
    assert "marker path exists but is not the exact standalone marker" in text
    assert "\"$lines\" -ne 1" in text


def test_trusted_workflow_verification_precedes_marker_evaluation() -> None:
    text = workflow_text()
    workflow_check = text.index("Verify trusted base workflow blob")
    marker_check = text.index("Fail only for the exact AVO live-rollback marker")
    assert workflow_check < marker_check

