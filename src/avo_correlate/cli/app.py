"""Operator-facing CLI with actionable diagnostics."""

import asyncio
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Annotated, Literal
from uuid import NAMESPACE_URL, uuid4, uuid5

import typer

from avo_correlate.adapters.persistence import Database
from avo_correlate.adapters.policy import BuiltinPolicyEngine
from avo_correlate.application.provenance_service import ProvenanceService
from avo_correlate.application.query_service import QueryService
from avo_correlate.application.run_service import RunService
from avo_correlate.application.runtime_service import RuntimeService
from avo_correlate.contracts.base import StrictModel
from avo_correlate.contracts.experiment import ExperimentSpec
from avo_correlate.contracts.lifecycle import RunState
from avo_correlate.contracts.operations import CheckStatus, DoctorCheck, DoctorReport
from avo_correlate.contracts.policy import PolicyRequest
from avo_correlate.contracts.policy_bundle import PolicyBundle
from avo_correlate.contracts.runtime import HarnessRuntimeProfile
from avo_correlate.domain.canonical import canonical_digest

app = typer.Typer(name="avoctl", help="Control and diagnose AVO-Correlate.", no_args_is_help=True)
platform_app = typer.Typer(help="Inspect host and canonical runtime support.")
experiment_app = typer.Typer(help="Validate and persist immutable experiment specs.")
run_app = typer.Typer(help="Control and inspect durable runs.")
candidate_app = typer.Typer(help="Inspect frozen candidates and evidence.")
provenance_app = typer.Typer(help="Export and verify lineage evidence.")
policy_app = typer.Typer(help="Validate policy bundles against deterministic cases.")
test_app = typer.Typer(help="Run the required validation layers.")
api_app = typer.Typer(help="Run the authenticated local control API.")
harness_app = typer.Typer(help="Inspect coding-agent runtime compatibility.")
session_app = typer.Typer(help="Inspect and reconcile variation sessions.")
app.add_typer(platform_app, name="platform")
app.add_typer(experiment_app, name="experiment")
app.add_typer(run_app, name="run")
app.add_typer(candidate_app, name="candidate")
app.add_typer(provenance_app, name="provenance")
app.add_typer(policy_app, name="policy")
app.add_typer(test_app, name="test")
app.add_typer(api_app, name="api")
app.add_typer(harness_app, name="harness")
app.add_typer(session_app, name="session")


class PolicyTestCase(StrictModel):
    name: str
    request: PolicyRequest
    expected_outcome: Literal["allow", "deny", "review"]


class PolicyTestSuite(StrictModel):
    schema_version: Literal[1] = 1
    cases: list[PolicyTestCase]


def build_doctor_report(*, strict: bool = False) -> DoctorReport:
    checks: list[DoctorCheck] = []
    python_ok = sys.version_info[:2] == (3, 12)
    checks.append(
        DoctorCheck(
            name="python",
            status=CheckStatus.PASS if python_ok else CheckStatus.FAIL,
            detail=f"{platform.python_version()} at {sys.executable}",
            next_action=None if python_ok else "Install and select Python 3.12.",
        )
    )
    system = platform.system().lower()
    in_wsl = "microsoft" in platform.release().lower() or "WSL_DISTRO_NAME" in os.environ
    if system == "linux":
        host = DoctorCheck(
            name="host_topology",
            status=CheckStatus.PASS,
            detail="Linux host" + (" under WSL 2" if in_wsl else ""),
        )
    elif system == "windows":
        host = DoctorCheck(
            name="host_topology",
            status=CheckStatus.FAIL if strict else CheckStatus.WARN,
            detail="Native Windows shell; canonical execution is WSL-first",
            next_action="Run avoctl inside WSL 2 or use scripts/avoctl.ps1.",
        )
    else:
        host = DoctorCheck(
            name="host_topology",
            status=CheckStatus.FAIL,
            detail=f"Unsupported host: {platform.system()}",
            next_action="Use Linux x86-64 or Windows 11 with WSL 2.",
        )
    checks.append(host)
    for executable, required in (("uv", True), ("git", True), ("docker", False)):
        location = shutil.which(executable)
        checks.append(
            DoctorCheck(
                name=executable,
                status=(
                    CheckStatus.PASS
                    if location
                    else CheckStatus.FAIL
                    if required
                    else CheckStatus.WARN
                ),
                detail=location or "not found",
                next_action=None if location else f"Install {executable} and add it to PATH.",
            )
        )
    architecture = platform.machine().lower()
    architecture_ok = architecture in {"amd64", "x86_64"}
    checks.append(
        DoctorCheck(
            name="architecture",
            status=CheckStatus.PASS if architecture_ok else CheckStatus.FAIL,
            detail=architecture,
            next_action=None if architecture_ok else "Use an x86-64 host for v1.",
        )
    )
    statuses = {check.status for check in checks}
    overall = (
        CheckStatus.FAIL
        if CheckStatus.FAIL in statuses
        else CheckStatus.WARN
        if CheckStatus.WARN in statuses
        else CheckStatus.PASS
    )
    return DoctorReport(overall=overall, checks=checks)


def _render(report: DoctorReport, json_output: bool) -> None:
    if json_output:
        typer.echo(json.dumps(report.model_dump(mode="json"), sort_keys=True))
        return
    typer.echo(f"AVO-Correlate platform status: {report.overall.value}")
    for check in report.checks:
        typer.echo(f"[{check.status.value.upper():4}] {check.name}: {check.detail}")
        if check.next_action:
            typer.echo(f"       Next: {check.next_action}")


@app.command()
def doctor(
    json_output: Annotated[bool, typer.Option("--json")] = False,
    strict: Annotated[bool, typer.Option("--strict")] = False,
) -> None:
    """Show readiness and the next safe action for failed checks."""
    report = build_doctor_report(strict=strict)
    _render(report, json_output)
    if report.overall == CheckStatus.FAIL:
        raise typer.Exit(code=2)


@platform_app.command("verify")
def platform_verify(
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Strict verification for canonical execution and release gates."""
    report = build_doctor_report(strict=True)
    _render(report, json_output)
    if report.overall != CheckStatus.PASS:
        raise typer.Exit(code=2)


@platform_app.command("benchmark")
def platform_benchmark(
    project_root: Annotated[Path, typer.Option("--project-root")] = Path("."),
    image: Annotated[str, typer.Option("--image")] = "avo-reference-development:1.0.0",
) -> None:
    """Measure evaluator workload time separately from platform overhead."""
    from avo_correlate.application.performance import measure_platform_overhead

    _emit(measure_platform_overhead(project_root.resolve(), image=image))


@app.command()
def version() -> None:
    """Print the package version."""
    from avo_correlate import __version__

    typer.echo(__version__)


def _service(data_dir: Path) -> RunService:
    database = Database(data_dir / "avo.db")
    database.initialize()
    return RunService(database)


def _database(data_dir: Path) -> Database:
    database = Database(data_dir / "avo.db")
    database.initialize()
    return database


@harness_app.command("list")
def harness_list() -> None:
    """List built-in and optional runtime adapters."""
    from avo_correlate.adapters.harness.codex import (
        CODEX_CLI_VERSION,
        REQUIRED_CODEX_ACCOUNT_EMAIL,
        REQUIRED_CODEX_ACCOUNT_PLAN,
    )

    try:
        import openai_codex

        codex_sdk = f"installed:{openai_codex.__version__}"
    except ImportError:
        codex_sdk = "not-installed"
    _emit(
        {
            "schema_version": 1,
            "runtimes": [
                {"runtime_id": "native-structured-model", "status": "available"},
                {"runtime_id": "recorded-runtime-v1", "status": "available"},
                {
                    "runtime_id": "openai-codex-sdk",
                    "status": codex_sdk,
                    "required_cli_version": CODEX_CLI_VERSION,
                    "authentication": "chatgpt-subscription-only",
                    "required_account": REQUIRED_CODEX_ACCOUNT_EMAIL,
                    "required_plan": REQUIRED_CODEX_ACCOUNT_PLAN,
                },
            ],
        }
    )


@harness_app.command("doctor")
def harness_doctor(
    profile_path: Path,
    trusted_key_file: Annotated[Path | None, typer.Option("--trusted-key-file")] = None,
    live_canaries: Annotated[bool, typer.Option("--live-canaries")] = False,
) -> None:
    """Fail-closed compatibility check for a Codex runtime profile."""
    from avo_correlate.adapters.harness.codex import CodexCodingAgentRuntime
    from avo_correlate.adapters.harness.codex_canary import CodexLiveCanaryRunner

    try:
        profile = HarnessRuntimeProfile.model_validate_json(
            profile_path.read_text(encoding="utf-8")
        )
    except (OSError, ValueError) as exc:
        typer.echo(f"Invalid harness profile: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    trusted_keys: dict[str, bytes] = {}
    if trusted_key_file is not None:
        try:
            trusted_keys[profile.plugin.signer_key_id] = trusted_key_file.read_bytes()
        except OSError as exc:
            typer.echo(f"Cannot read trusted plugin key: {exc}", err=True)
            raise typer.Exit(code=2) from exc
    adapter = CodexCodingAgentRuntime(
        artifact_sink=lambda payload, role: canonical_digest(
            {"role": role, "payload_hex": payload.hex()}
        ),
        canary_runner=CodexLiveCanaryRunner() if live_canaries else None,
        trusted_plugin_keys=trusted_keys,
    )
    report = asyncio.run(adapter.preflight(profile))
    _emit(report)
    if not report.compatible:
        raise typer.Exit(code=2)


@session_app.command("runtime")
def session_runtime(
    session_id: str,
    data_dir: Annotated[Path, typer.Option("--data-dir")] = Path(".avo"),
) -> None:
    """Show runtime invocations and reconciliation cases for a session."""
    database = _database(data_dir)
    try:
        _emit(QueryService(database).session_runtime(session_id))
    finally:
        database.dispose()


@session_app.command("reconcile")
def session_reconcile(
    reconciliation_id: str,
    resolution: Annotated[str, typer.Option("--resolution")],
    note: Annotated[str, typer.Option("--note")],
    result_digest: Annotated[str | None, typer.Option("--result-digest")] = None,
    actor_id: Annotated[str, typer.Option("--actor-id")] = "local-operator",
    data_dir: Annotated[Path, typer.Option("--data-dir")] = Path(".avo"),
) -> None:
    """Resolve ambiguous external state with an explicit audited decision."""
    database = _database(data_dir)
    try:
        record = RuntimeService(database).resolve_reconciliation(
            reconciliation_id,
            resolution=resolution,
            note=note,
            actor_id=actor_id,
            result_digest=result_digest,
        )
        _emit(record)
    finally:
        database.dispose()


def _read_spec(path: Path) -> ExperimentSpec:
    try:
        return ExperimentSpec.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        typer.echo(f"Invalid experiment spec: {exc}", err=True)
        raise typer.Exit(code=2) from exc


def _emit(value: StrictModel | dict[str, object]) -> None:
    payload = value.model_dump(mode="json") if isinstance(value, StrictModel) else value
    typer.echo(json.dumps(payload, sort_keys=True))


@experiment_app.command("validate")
def experiment_validate(path: Path) -> None:
    """Validate a spec without writing state."""
    spec = _read_spec(path)
    from avo_correlate.domain.canonical import canonical_digest

    _emit({"schema_version": 1, "valid": True, "spec_digest": canonical_digest(spec)})


@experiment_app.command("create")
def experiment_create(
    path: Path,
    data_dir: Annotated[Path, typer.Option("--data-dir")] = Path(".avo"),
    actor_id: Annotated[str, typer.Option("--actor-id")] = "local-operator",
    idempotency_key: Annotated[str | None, typer.Option("--idempotency-key")] = None,
) -> None:
    """Persist an immutable experiment revision."""
    spec = _read_spec(path)
    key = idempotency_key or str(uuid4())
    digest = _service(data_dir).create_experiment(
        spec, actor_id=actor_id, idempotency_key=key
    )
    _emit({"schema_version": 1, "experiment_id": spec.experiment_id, "spec_digest": digest})


def _run_payload(service: RunService, run_id: str) -> dict[str, object]:
    run = service.get_run(run_id)
    return {
        "schema_version": 1,
        "run_id": run.run_id,
        "experiment_id": run.experiment_id,
        "state": run.state,
        "revision": run.revision,
        "event_sequence": run.event_sequence,
        "champion_id": run.champion_id,
    }


@run_app.command("start")
def run_start(
    experiment_id: str,
    data_dir: Annotated[Path, typer.Option("--data-dir")] = Path(".avo"),
    actor_id: Annotated[str, typer.Option("--actor-id")] = "local-operator",
    idempotency_key: Annotated[str | None, typer.Option("--idempotency-key")] = None,
) -> None:
    """Create and start a run for an experiment."""
    key = idempotency_key or str(uuid4())
    run_id = str(uuid5(NAMESPACE_URL, f"avo:{actor_id}:{experiment_id}:{key}"))
    service = _service(data_dir)
    service.create_run(
        experiment_id,
        actor_id=actor_id,
        run_id=run_id,
        prepare=True,
        idempotency_key=key,
    )
    run = service.get_run(run_id)
    service.transition(
        run_id,
        RunState.RUNNING,
        actor_id=actor_id,
        expected_revision=run.revision,
        idempotency_key=key,
        endpoint_scope=f"runs.{run_id}.start",
    )
    _emit(_run_payload(service, run_id))


@run_app.command("status")
def run_status(
    run_id: str,
    data_dir: Annotated[Path, typer.Option("--data-dir")] = Path(".avo"),
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Print durable run state as stable JSON."""
    del json_output  # The v1 machine-readable representation is the only status format.
    _emit(_run_payload(_service(data_dir), run_id))


def _transition_command(
    run_id: str,
    target: RunState,
    *,
    action: str,
    data_dir: Path,
    actor_id: str,
    idempotency_key: str | None,
) -> None:
    service = _service(data_dir)
    run = service.get_run(run_id)
    service.transition(
        run_id,
        target,
        actor_id=actor_id,
        expected_revision=run.revision,
        idempotency_key=idempotency_key or str(uuid4()),
        endpoint_scope=f"runs.{run_id}.{action}",
    )
    if action in {"pause", "cancel"}:
        service.settle_control_request(run_id, actor_id="control-plane")
    _emit(_run_payload(service, run_id))


@run_app.command("pause")
def run_pause(
    run_id: str,
    data_dir: Annotated[Path, typer.Option("--data-dir")] = Path(".avo"),
    actor_id: Annotated[str, typer.Option("--actor-id")] = "local-operator",
    idempotency_key: Annotated[str | None, typer.Option("--idempotency-key")] = None,
) -> None:
    _transition_command(
        run_id,
        RunState.PAUSING,
        action="pause",
        data_dir=data_dir,
        actor_id=actor_id,
        idempotency_key=idempotency_key,
    )


@run_app.command("resume")
def run_resume(
    run_id: str,
    data_dir: Annotated[Path, typer.Option("--data-dir")] = Path(".avo"),
    actor_id: Annotated[str, typer.Option("--actor-id")] = "local-operator",
    idempotency_key: Annotated[str | None, typer.Option("--idempotency-key")] = None,
) -> None:
    _transition_command(
        run_id,
        RunState.READY,
        action="resume",
        data_dir=data_dir,
        actor_id=actor_id,
        idempotency_key=idempotency_key,
    )


@run_app.command("cancel")
def run_cancel(
    run_id: str,
    data_dir: Annotated[Path, typer.Option("--data-dir")] = Path(".avo"),
    actor_id: Annotated[str, typer.Option("--actor-id")] = "local-operator",
    idempotency_key: Annotated[str | None, typer.Option("--idempotency-key")] = None,
) -> None:
    service = _service(data_dir)
    run = service.get_run(run_id)
    target = (
        RunState.CANCELLED
        if RunState(run.state) in {RunState.CREATED, RunState.READY, RunState.PAUSED}
        else RunState.CANCELLING
    )
    _transition_command(
        run_id,
        target,
        action="cancel",
        data_dir=data_dir,
        actor_id=actor_id,
        idempotency_key=idempotency_key,
    )


@run_app.command("events")
def run_events(
    run_id: str,
    after: Annotated[int, typer.Option("--after", min=0)] = 0,
    data_dir: Annotated[Path, typer.Option("--data-dir")] = Path(".avo"),
) -> None:
    events = _service(data_dir).list_events(run_id, after=after)
    _emit(
        {
            "schema_version": 1,
            "events": [
                {
                    "event_id": item.event_id,
                    "sequence": item.sequence,
                    "event_type": item.event_type,
                    "actor_id": item.actor_id,
                    "payload": json.loads(item.payload_json),
                }
                for item in events
            ],
        }
    )


@candidate_app.command("inspect")
def candidate_inspect(
    candidate_id: str,
    data_dir: Annotated[Path, typer.Option("--data-dir")] = Path(".avo"),
) -> None:
    database = Database(data_dir / "avo.db")
    database.initialize()
    _emit(QueryService(database).candidate(candidate_id))


@provenance_app.command("verify")
def provenance_verify(
    candidate_id: str,
    data_dir: Annotated[Path, typer.Option("--data-dir")] = Path(".avo"),
) -> None:
    database = Database(data_dir / "avo.db")
    database.initialize()
    candidate = QueryService(database).candidate(candidate_id)
    provenance = ProvenanceService(database)
    exported = provenance.export_run(candidate.run_id)
    report = provenance.verify(exported)
    _emit(report)
    if not report.verified:
        raise typer.Exit(code=3)


@policy_app.command("test")
def policy_test(
    bundle_path: Annotated[
        Path, typer.Option("--bundle")
    ] = Path("examples/reference-policy.json"),
    cases_path: Annotated[
        Path, typer.Option("--cases")
    ] = Path("examples/reference-policy-cases.json"),
) -> None:
    """Run deterministic allow/deny/review cases against a policy bundle."""
    try:
        bundle = PolicyBundle.model_validate_json(bundle_path.read_text(encoding="utf-8"))
        suite = PolicyTestSuite.model_validate_json(cases_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        typer.echo(f"Invalid policy test input: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    engine = BuiltinPolicyEngine(bundle)
    results: list[dict[str, object]] = []
    passed = True
    for case in suite.cases:
        decision = engine.decide(case.request)
        case_passed = decision.outcome == case.expected_outcome
        passed = passed and case_passed
        results.append(
            {
                "name": case.name,
                "expected_outcome": case.expected_outcome,
                "actual_outcome": decision.outcome,
                "reason_codes": decision.reason_codes,
                "passed": case_passed,
            }
        )
    _emit(
        {
            "schema_version": 1,
            "passed": passed,
            "policy_bundle_digest": engine.bundle_digest,
            "results": results,
        }
    )
    if not passed:
        raise typer.Exit(code=3)


def _run_test_layer(path: str) -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", path],
        stdin=subprocess.DEVNULL,
        check=False,
        shell=False,
    )
    if completed.returncode:
        raise typer.Exit(code=completed.returncode)


@test_app.command("unit")
def test_unit() -> None:
    _run_test_layer("tests/unit")


@test_app.command("integration")
def test_integration() -> None:
    _run_test_layer("tests/integration")


@test_app.command("parity")
def test_parity() -> None:
    _run_test_layer("tests/parity")


@api_app.command("serve")
def api_serve(
    data_dir: Annotated[Path, typer.Option("--data-dir")] = Path(".avo"),
    host: Annotated[str, typer.Option("--host")] = "127.0.0.1",
    port: Annotated[int, typer.Option("--port", min=1, max=65535)] = 8000,
) -> None:
    """Serve the API; AVO_API_TOKEN must be set before readiness succeeds."""
    import uvicorn

    from avo_correlate.api import create_app

    uvicorn.run(create_app(data_dir), host=host, port=port, log_level="info")
