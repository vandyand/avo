"""Minimal RO-Crate 1.1 research-artifact projection."""

from typing import Any, cast

from avo_correlate.contracts.provenance import ProvenanceExport


def to_ro_crate(exported: ProvenanceExport) -> dict[str, Any]:
    manifest = exported.manifest
    experiment = cast(dict[str, Any], manifest["experiment"])
    spec = cast(dict[str, Any], experiment["spec"])
    lineage = cast(list[dict[str, Any]], manifest["lineage"])
    graph: list[dict[str, Any]] = [
        {
            "@id": "ro-crate-metadata.json",
            "@type": "CreativeWork",
            "about": {"@id": "./"},
            "conformsTo": {"@id": "https://w3id.org/ro/crate/1.1"},
        },
        {
            "@id": "./",
            "@type": "Dataset",
            "name": spec.get("title", exported.run_id),
            "description": spec.get("objective", "AVO-Correlate run"),
            "identifier": exported.run_id,
            "hasPart": [
                {"@id": f"urn:avo:candidate:{item['candidate_id']}"} for item in lineage
            ],
        },
    ]
    graph.extend(
        {
            "@id": f"urn:avo:candidate:{item['candidate_id']}",
            "@type": "SoftwareSourceCode",
            "identifier": item["candidate_id"],
            "sha256": cast(str, item["source_tree_digest"]).removeprefix("sha256:"),
            "position": item["sequence"],
        }
        for item in lineage
    )
    return {
        "@context": "https://w3id.org/ro/crate/1.1/context",
        "@graph": graph,
        "avoManifestDigest": exported.manifest_digest,
    }
