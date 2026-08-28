"""Run the deterministic offline AVO-004.6 cases 1-8.

The runner has no Git, network, credential, subprocess, or time dependency.
Its JSON output is a compact pointer to the immutable plan and aggregate
records in the supplied journal root.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from avo_correlate.application.integration_drill_service import IntegrationDrillService


def run(root: Path) -> dict[str, Any]:
    """Run/replay the drill and return a canonical, machine-readable summary."""
    execution = IntegrationDrillService(root).run()
    return {
        "schema_version": 1,
        "status": execution.status,
        "pending_case_ids": list(execution.pending_case_ids),
        "operation_id": execution.plan.operation_id,
        "plan_digest": execution.plan.plan_digest,
        "result_digest": execution.result.result_digest if execution.result is not None else None,
        "case_ids": [case.case_id for case in execution.cases],
        "outcomes": {str(case.case_id): case.outcome for case in execution.cases},
        "main_before_commit": execution.plan.main_before_commit,
        "main_after_commit": execution.plan.main_before_commit,
        "deploy_performed": False,
        "aggregate_result": (
            execution.result.result_digest if execution.result is not None else None
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(".avo-runtime") / "avo0046-drills",
        help="journal/artifact root (default: .avo-runtime/avo0046-drills)",
    )
    args = parser.parse_args()
    print(json.dumps(run(args.root), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
