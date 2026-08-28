"""Static guardrails for the untrusted, exact-commit validation workflow."""

from pathlib import Path

WORKFLOW = Path(__file__).parents[2] / ".github" / "workflows" / "synthetic-validation.yml"


def _workflow_text() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_workflow_has_only_validation_push_trigger_and_read_permissions() -> None:
    text = _workflow_text()
    assert "on:\n  push:\n    branches:\n      - \"avo/validation/**\"" in text
    assert "permissions:\n  contents: read" in text
    assert "pull_request" not in text
    assert "workflow_run" not in text
    assert "pull_request_target" not in text
    assert "contents: write" not in text
    assert "actions: write" not in text


def test_workflow_uses_fixed_public_matrix_contexts() -> None:
    text = _workflow_text()
    assert "name: avo synthetic validate (${{ matrix.os }})" in text
    assert "- ubuntu-latest" in text
    assert "- windows-latest" in text
    assert "runs-on: ${{ matrix.os }}" in text
    assert "self-hosted" not in text


def test_workflow_checks_ref_and_exact_commit_before_candidate_commands() -> None:
    text = _workflow_text()
    identity = text.index("- name: Verify exact synthetic commit identity")
    digest = text.index("- name: Verify externally pinned trusted workflow")
    setup = text.index("- uses: astral-sh/setup-uv@")
    assert identity < setup
    assert digest < setup
    assert "^refs/heads/avo/validation/[0-9a-f]{64}$" in text
    assert 'git rev-parse HEAD' in text
    assert '"$GITHUB_SHA"' in text
    assert 'AVO_TRUSTED_WORKFLOW_SHA256: ${{ vars.AVO_TRUSTED_WORKFLOW_SHA256 }}' in text
    assert 'git show "$GITHUB_SHA:.github/workflows/synthetic-validation.yml"' in text
    assert 'sha256sum' in text
    assert '^[0-9a-f]{64}$' in text
    assert "timeout-minutes: 45" in text
    assert 'persist-credentials: false' in text


def test_workflow_actions_are_immutable_commit_pins() -> None:
    text = _workflow_text()
    assert "actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4" in text
    assert "astral-sh/setup-uv@d0cc045d04ccac9d8b7881df0226f9e82c39688e # v6" in text
    assert "actions/checkout@v4" not in text
    assert "astral-sh/setup-uv@v6" not in text


def test_workflow_contains_complete_trusted_validation_surface() -> None:
    text = _workflow_text()
    for command in (
        "validate_roadmap.py",
        "uv run ruff check .",
        "uv run pyright",
        "Dockerfile.development",
        "Dockerfile.admission",
        "avoctl platform benchmark",
        "uv run pytest --cov=avo_correlate",
        "tests/e2e/test_reference_scenario.py",
        "export_schemas",
        "git diff --exit-code -- schemas",
    ):
        assert command in text
    assert "actions/upload-artifact" not in text
