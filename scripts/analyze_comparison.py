"""Aggregate frozen paired-comparison summaries into paired statistics."""

import argparse
import json
import math
import statistics
from collections import Counter, defaultdict
from decimal import Decimal
from pathlib import Path
from typing import Any, cast


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-root", type=Path, required=True)
    parser.add_argument("--pilot-id", required=True)
    parser.add_argument("--repetitions", type=int, required=True)
    return parser.parse_args()


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected an object: {path}")
    return cast(dict[str, Any], value)


def _summaries(
    root: Path, pilot_id: str, repetitions_per_task: int
) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for path in root.rglob("summary.json"):
        summary = _read_json(path)
        if (
            summary.get("pilot_id") != pilot_id
            or summary.get("purpose") != "comparison"
        ):
            continue
        arm = summary.get("arm")
        if arm in {"codex", "openrouter-native"}:
            summary["_summary_path"] = str(path)
            grouped[cast(str, arm)].append(summary)
    for arm in ("codex", "openrouter-native"):
        repetitions = sorted(
            cast(int, summary["repetition"]) for summary in grouped[arm]
        )
        expected = list(range(1, repetitions_per_task + 1))
        if repetitions != expected:
            raise RuntimeError(f"{arm} repetitions are incomplete: {repetitions}")
    return grouped


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * fraction) - 1)
    return ordered[index]


def _latency(values: list[float]) -> dict[str, float]:
    return {
        "total_seconds": round(sum(values), 6),
        "mean_seconds": round(statistics.fmean(values), 6),
        "median_seconds": round(statistics.median(values), 6),
        "p95_nearest_rank_seconds": round(_percentile(values, 0.95), 6),
        "maximum_seconds": round(max(values), 6),
    }


def _exact_mcnemar(codex_only: int, openrouter_only: int) -> float:
    discordant = codex_only + openrouter_only
    if discordant == 0:
        return 1.0
    lower = min(codex_only, openrouter_only)
    tail = sum(math.comb(discordant, value) for value in range(lower + 1))
    return min(1.0, 2 * tail / (2**discordant))


def _invocation_records(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for result in results:
        path = Path(cast(str, result["model_invocations_artifact"]))
        for line in path.read_text(encoding="utf-8").splitlines():
            value = json.loads(line)
            if not isinstance(value, dict):
                raise RuntimeError(f"invalid invocation record: {path}")
            record = cast(dict[str, Any], value)
            record["_artifacts_root"] = str(path.parent / "artifacts")
            records.append(record)
    return records


def _invocation_usage(record: dict[str, Any]) -> tuple[int, int, int, str]:
    usage = cast(dict[str, int], record["usage"])
    if record.get("error_class") is None:
        return (
            usage["model_input_tokens"],
            usage["model_output_tokens"],
            usage["model_cost_microusd"],
            cast(str, record["cost_source"]),
        )
    digest = cast(str, record["response_artifact_digest"]).removeprefix("sha256:")
    artifact = Path(cast(str, record["_artifacts_root"])) / digest
    response = _read_json(artifact)
    provider_usage = cast(dict[str, Any], response["usage"])
    return (
        cast(int, provider_usage["prompt_tokens"]),
        cast(int, provider_usage["completion_tokens"]),
        int(Decimal(str(provider_usage["cost"])) * 1_000_000),
        "provider_recovered_from_response_artifact",
    )


def analyze(root: Path, *, pilot_id: str, repetitions_per_task: int) -> dict[str, Any]:
    if repetitions_per_task < 1:
        raise ValueError("repetitions_per_task must be positive")
    grouped = _summaries(root.resolve(strict=True), pilot_id, repetitions_per_task)
    by_pair: dict[tuple[int, str], dict[str, dict[str, Any]]] = defaultdict(dict)
    arm_results: dict[str, list[dict[str, Any]]] = {}
    for arm, summaries in grouped.items():
        results: list[dict[str, Any]] = []
        for summary in summaries:
            repetition = cast(int, summary["repetition"])
            for raw in cast(list[dict[str, Any]], summary["results"]):
                result = dict(raw)
                key = (repetition, cast(str, result["task_id"]))
                if arm in by_pair[key]:
                    raise RuntimeError(f"duplicate pair result: {arm} {key}")
                by_pair[key][arm] = result
                results.append(result)
        arm_results[arm] = results
    task_ids = {
        cast(str, result["task_id"])
        for results in arm_results.values()
        for result in results
    }
    expected_results = len(task_ids) * repetitions_per_task
    for arm, results in arm_results.items():
        if len(results) != expected_results:
            raise RuntimeError(
                f"{arm} result count is {len(results)}, expected {expected_results}"
            )
    if len(by_pair) != expected_results or any(
        len(value) != 2 for value in by_pair.values()
    ):
        raise RuntimeError("paired result coverage is incomplete")

    pair_counts: Counter[str] = Counter()
    per_task: dict[str, dict[str, int]] = defaultdict(
        lambda: {"codex": 0, "openrouter-native": 0}
    )
    for (_, task_id), pair in by_pair.items():
        codex = bool(pair["codex"]["admitted"])
        openrouter = bool(pair["openrouter-native"]["admitted"])
        label = (
            "both_admitted"
            if codex and openrouter
            else "codex_only"
            if codex
            else "openrouter_only"
            if openrouter
            else "neither_admitted"
        )
        pair_counts[label] += 1
        per_task[task_id]["codex"] += int(codex)
        per_task[task_id]["openrouter-native"] += int(openrouter)

    arms: dict[str, Any] = {}
    for arm, results in arm_results.items():
        data: dict[str, Any] = {
            "attempts": len(results),
            "admitted": sum(bool(item["admitted"]) for item in results),
            "public_succeeded": sum(
                cast(dict[str, Any], item["public_evaluation"])["outcome"]
                == "succeeded"
                for item in results
            ),
            "runtime_errors": sum(item.get("runtime_error") is not None for item in results),
            "latency": _latency(
                [cast(float, item["wall_time_seconds"]) for item in results]
            ),
        }
        if arm == "codex":
            data["input_tokens_observed"] = sum(
                cast(dict[str, int], item["usage_observation"]).get(
                    "total.input_tokens", 0
                )
                for item in results
            )
            data["output_tokens_observed"] = sum(
                cast(dict[str, int], item["usage_observation"]).get(
                    "total.output_tokens", 0
                )
                for item in results
            )
            data["charged_cost_usd"] = None
        else:
            invocations = _invocation_records(results)
            invocation_usage = [_invocation_usage(item) for item in invocations]
            data["input_tokens"] = sum(item[0] for item in invocation_usage)
            data["output_tokens"] = sum(item[1] for item in invocation_usage)
            cost_microusd = sum(item[2] for item in invocation_usage)
            data["provider_cost_microusd"] = cost_microusd
            data["provider_cost_usd"] = round(cost_microusd / 1_000_000, 6)
            data["model_invocations"] = len(invocations)
            data["failed_model_invocations"] = sum(
                item.get("error_class") is not None for item in invocations
            )
            data["cost_sources"] = dict(
                Counter(item[3] for item in invocation_usage)
            )
            data["tool_calls"] = sum(
                cast(int, item["tool_call_count"]) for item in results
            )
            data["development_evaluator_calls"] = sum(
                cast(int, item["development_evaluator_calls"]) for item in results
            )
            data["session_outcomes"] = dict(
                Counter(
                    cast(str, item["session_outcome"])
                    if item["session_outcome"] is not None
                    else "runtime_error"
                    for item in results
                )
            )
        arms[arm] = data

    codex_only = pair_counts["codex_only"]
    openrouter_only = pair_counts["openrouter_only"]
    task_comparison = {
        task: {
            **counts,
            "difference": counts["codex"] - counts["openrouter-native"],
        }
        for task, counts in sorted(per_task.items())
    }
    return {
        "schema_version": 1,
        "pilot_id": pilot_id,
        "arms": arms,
        "paired_outcomes": dict(sorted(pair_counts.items())),
        "paired_exact_mcnemar_p_value": _exact_mcnemar(
            codex_only, openrouter_only
        ),
        "task_results": task_comparison,
        "task_level_direction": {
            "codex_better": sum(
                item["difference"] > 0 for item in task_comparison.values()
            ),
            "openrouter_better": sum(
                item["difference"] < 0 for item in task_comparison.values()
            ),
            "tied": sum(item["difference"] == 0 for item in task_comparison.values()),
        },
        "caveat": (
            "One repetition cannot estimate run-to-run variance; the paired exact result "
            "is descriptive, and the small frozen suite limits inferential claims."
            if repetitions_per_task == 1
            else "Attempt-level McNemar treats repetitions as independent; task clustering "
            "and the small frozen suite limit inferential claims."
        ),
    }


def main() -> None:
    arguments = _arguments()
    print(
        json.dumps(
            analyze(
                arguments.results_root,
                pilot_id=arguments.pilot_id,
                repetitions_per_task=arguments.repetitions,
            ),
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
