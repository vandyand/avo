"""Hermetic reference evaluator entrypoint; standard library only."""

import importlib
import json
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, "/workspace/src")


def main() -> int:
    started = datetime.now(UTC)
    tests_path = Path("/evaluator/tests.json")
    cases = json.loads(tests_path.read_text(encoding="utf-8"))
    target = importlib.import_module("reference_target").best_window
    passed = 0
    failures: list[str] = []
    trial_times: list[float] = []
    for case in cases:
        before = time.perf_counter_ns()
        try:
            actual = target(case["values"], case["width"])
            expected = tuple(case["expected"])
            if actual == expected:
                passed += 1
            else:
                failures.append(case["id"])
        except Exception:
            failures.append(case["id"])
        trial_times.append((time.perf_counter_ns() - before) / 1_000_000)
    correctness = 100.0 * passed / len(cases)
    samples = [correctness - 0.1, correctness, correctness + 0.1]
    now = datetime.now(UTC)
    digest_a = "sha256:" + ("a" * 64)
    digest_b = "sha256:" + ("b" * 64)
    candidate_id = os.environ["AVO_CANDIDATE_ID"]
    tier = os.environ["AVO_EVALUATOR_TIER"]
    report = {
        "schema_version": 1,
        "evaluation_id": os.environ["AVO_EVALUATION_ID"],
        "candidate_id": candidate_id,
        "evaluator_ref": {
            "schema_version": 1,
            "component_id": f"reference-{tier}",
            "component_version": "1.0.0",
            "package_digest": digest_a,
            "capability_manifest_digest": digest_b,
        },
        "evaluator_tier": tier,
        "evaluator_profile_digest": digest_a,
        "execution_image_digest": os.environ["AVO_IMAGE_DIGEST"],
        "hardware_class": os.environ.get("AVO_HARDWARE_CLASS", "linux-x86-64"),
        "input_artifact_digests": [os.environ["AVO_WORKSPACE_DIGEST"]],
        "trial_records": [
            {
                "schema_version": 1,
                "trial_index": index,
                "seed": index,
                "metrics": {"correctness_score": sample},
                "workload_time_ms": trial_times[index % len(trial_times)],
                "sandbox_setup_time_ms": 0,
                "queue_time_ms": 0,
                "host_overhead_time_ms": 0,
            }
            for index, sample in enumerate(samples)
        ],
        "aggregate_metrics": {"correctness_score": correctness},
        "uncertainty": {
            "correctness_score": {
                "schema_version": 1,
                "method": "seeded-fixture-envelope",
                "lower": min(samples),
                "upper": max(samples),
                "confidence_level": 0.95,
            }
        },
        "constraints": [
            {
                "schema_version": 1,
                "name": "private_correctness" if tier == "admission" else "public_correctness",
                "passed": not failures,
                "severity": "hard",
            }
        ],
        "outcome": "passed" if not failures else "failed",
        "evidence_artifacts": [],
        "started_at": started.isoformat(),
        "completed_at": now.isoformat(),
    }
    output = Path("/output/report.json")
    output.write_text(json.dumps(report, allow_nan=False, separators=(",", ":")), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
