from pathlib import Path

import pytest

from avo_correlate.adapters.export import to_ro_crate, to_slsa_provenance
from avo_correlate.adapters.persistence import Database
from avo_correlate.application.provenance_service import ProvenanceService
from avo_correlate.application.run_service import RunService
from tests.conftest import experiment_spec


def test_ro_crate_and_slsa_views_reference_immutable_digests(tmp_path: Path) -> None:
    database = Database(tmp_path / "state.db")
    database.initialize()
    runs = RunService(database)
    runs.create_experiment(experiment_spec())
    runs.create_run("experiment-1", actor_id="tester", run_id="run-1")
    exported = ProvenanceService(database).export_run("run-1")
    crate = to_ro_crate(exported)
    assert crate["avoManifestDigest"] == exported.manifest_digest
    graph = crate["@graph"]
    assert any(item.get("@type") == "SoftwareSourceCode" for item in graph)
    with pytest.raises(ValueError, match="committed lineage"):
        to_slsa_provenance(exported, "not-in-lineage")
    slsa = to_slsa_provenance(exported, runs.get_run("run-1").champion_id or "")
    assert slsa["predicateType"] == "https://slsa.dev/provenance/v1"
    assert slsa["subject"][0]["digest"]["sha256"]
