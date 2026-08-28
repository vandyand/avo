import json
from pathlib import Path

from scripts.run_avo0046_drills import run


def test_runner_emits_incomplete_canonical_summary_and_replays(tmp_path: Path) -> None:
    first = run(tmp_path)
    second = run(tmp_path)
    assert first == second
    assert first["status"] == "complete"
    assert first["pending_case_ids"] == []
    assert first["case_ids"] == list(range(1, 9))
    assert first["main_before_commit"] == first["main_after_commit"]
    assert first["deploy_performed"] is False
    assert first["aggregate_result"] == first["result_digest"]
    assert json.dumps(first, sort_keys=True, separators=(",", ":"))
