import json
from pathlib import Path

from typer.testing import CliRunner

from avo_correlate.cli.app import app

runner = CliRunner()


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == "0.1.0"


def test_doctor_json_has_actionable_shape() -> None:
    result = runner.invoke(app, ["doctor", "--json"])
    assert result.exit_code in {0, 2}
    report = json.loads(result.stdout)
    assert report["schema_version"] == 1
    assert report["overall"] in {"pass", "warn", "fail"}
    assert all({"name", "status", "detail", "next_action"} <= set(c) for c in report["checks"])


def test_cli_experiment_and_run_lifecycle(tmp_path: Path) -> None:
    spec = Path("examples/reference-experiment.json")
    data = tmp_path / "state"
    created = runner.invoke(
        app,
        [
            "experiment",
            "create",
            str(spec),
            "--data-dir",
            str(data),
            "--idempotency-key",
            "create-1",
        ],
    )
    assert created.exit_code == 0, created.stdout
    started = runner.invoke(
        app,
        [
            "run",
            "start",
            "reference-python-repair-v1",
            "--data-dir",
            str(data),
            "--idempotency-key",
            "run-1",
        ],
    )
    assert started.exit_code == 0, started.stdout
    run = json.loads(started.stdout)
    assert run["state"] == "running"
    status = runner.invoke(
        app,
        ["run", "status", run["run_id"], "--data-dir", str(data), "--json"],
    )
    assert status.exit_code == 0, status.stdout
    assert json.loads(status.stdout)["revision"] == run["revision"]
    paused = runner.invoke(
        app,
        ["run", "pause", run["run_id"], "--data-dir", str(data)],
    )
    assert paused.exit_code == 0, paused.stdout
    assert json.loads(paused.stdout)["state"] == "paused"


def test_policy_test_command_checks_reference_security_cases() -> None:
    result = runner.invoke(app, ["policy", "test"])
    assert result.exit_code == 0, result.stdout
    report = json.loads(result.stdout)
    assert report["passed"] is True
    assert [item["actual_outcome"] for item in report["results"]] == [
        "allow",
        "deny",
        "deny",
        "allow",
    ]


def test_harness_inventory_and_invalid_profile_are_actionable(tmp_path: Path) -> None:
    listed = runner.invoke(app, ["harness", "list"])
    assert listed.exit_code == 0
    runtimes = json.loads(listed.stdout)["runtimes"]
    assert {item["runtime_id"] for item in runtimes} == {
        "native-structured-model",
        "recorded-runtime-v1",
        "openai-codex-sdk",
    }
    invalid = tmp_path / "invalid-profile.json"
    invalid.write_text("{}", encoding="utf-8")
    checked = runner.invoke(app, ["harness", "doctor", str(invalid)])
    assert checked.exit_code == 2
    assert "Invalid harness profile" in checked.stderr
