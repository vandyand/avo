from pathlib import Path

from avo_correlate.contracts.experiment import ExperimentSpec
from avo_correlate.domain.workspace import validate_workspace


def test_reference_experiment_and_workspace_are_self_consistent() -> None:
    spec = ExperimentSpec.model_validate_json(
        Path("examples/reference-experiment.json").read_text(encoding="utf-8")
    )
    digest = validate_workspace(Path("fixtures/reference_project/seed"), spec.workspace)
    assert digest == spec.workspace.source_tree_digest
    assert spec.search.method == "single_lineage_agentic"
    assert spec.development_evaluators[0].tier == "development"
    assert spec.admission_evaluators[0].tier == "admission"
