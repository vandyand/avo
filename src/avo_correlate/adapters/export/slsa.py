"""SLSA provenance v1-compatible projection for an admitted candidate."""

from typing import Any, cast

from avo_correlate.contracts.provenance import ProvenanceExport


def to_slsa_provenance(exported: ProvenanceExport, candidate_id: str) -> dict[str, Any]:
    manifest = exported.manifest
    candidates = cast(list[dict[str, Any]], manifest.get("candidates", []))
    candidate = next(
        (item for item in candidates if item.get("candidate_id") == candidate_id), None
    )
    lineage = cast(list[dict[str, Any]], manifest.get("lineage", []))
    lineage_entry = next(
        (item for item in lineage if item.get("candidate_id") == candidate_id), None
    )
    if lineage_entry is None:
        raise ValueError("SLSA export requires a committed lineage candidate")
    run = cast(dict[str, Any], manifest["run"])
    experiment = cast(dict[str, Any], manifest["experiment"])
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": candidate_id,
                "digest": {
                    "sha256": cast(str, lineage_entry["source_tree_digest"]).removeprefix(
                        "sha256:"
                    )
                },
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://avo-correlate.dev/build-types/agentic-variation/v1",
                "externalParameters": {
                    "experimentSpecDigest": experiment["spec_digest"],
                    "candidateManifest": candidate,
                },
                "resolvedDependencies": [],
            },
            "runDetails": {
                "builder": {"id": "https://avo-correlate.dev/builder/v1"},
                "metadata": {
                    "invocationId": run["run_id"],
                    "finishedOn": lineage_entry["committed_at"],
                },
            },
        },
    }
