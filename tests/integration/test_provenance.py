from pathlib import Path

from avo_correlate.adapters.persistence import Database
from avo_correlate.application.provenance_service import ProvenanceService
from avo_correlate.application.run_service import RunService
from avo_correlate.domain.canonical import canonical_digest
from tests.conftest import experiment_spec


def test_lineage_export_verifies_and_detects_tampering(tmp_path: Path) -> None:
    database = Database(tmp_path / "state.db")
    database.initialize()
    runs = RunService(database)
    runs.create_experiment(experiment_spec())
    runs.create_run("experiment-1", actor_id="tester", run_id="run-1", prepare=True)
    provenance = ProvenanceService(database)
    exported = provenance.export_run("run-1")
    report = provenance.verify(exported)
    assert report.verified
    tampered_manifest = dict(exported.manifest)
    tampered_run = dict(tampered_manifest["run"])
    tampered_run["champion_id"] = "forged"
    tampered_manifest["run"] = tampered_run
    tampered = exported.model_copy(update={"manifest": tampered_manifest})
    failed = provenance.verify(tampered)
    assert not failed.verified
    assert "manifest_digest_mismatch" in failed.errors
    assert "champion_lineage_mismatch" in failed.errors

    terminal_manifest = dict(exported.manifest)
    terminal_run = dict(terminal_manifest["run"])
    terminal_run["state"] = "failed"
    terminal_manifest["run"] = terminal_run
    terminal_manifest["reconciliations"] = [{"state": "open"}]
    terminal = exported.model_copy(
        update={
            "manifest": terminal_manifest,
            "manifest_digest": canonical_digest(terminal_manifest),
        }
    )
    terminal_failure = provenance.verify(terminal)
    assert not terminal_failure.verified
    assert "terminal_run_has_open_reconciliation" in terminal_failure.errors
