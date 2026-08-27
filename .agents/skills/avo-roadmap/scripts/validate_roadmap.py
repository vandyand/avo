from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path

MILESTONE_HEADER = (
    "| ID | Horizon | Status | Risk | Outcome | Exit gate | Depends on | Evidence |"
)
REQUIRED_HEADINGS = {
    "# AVO Roadmap",
    "## Authority and maintenance",
    "## North star",
    "## Current position",
    "## Milestone register",
}
HORIZONS = {"done", "now", "next", "later", "gated"}
STATUSES = {"complete", "in_progress", "ready", "planned", "gated", "deferred"}
RISKS = {"low", "standard", "protected", "production"}
MILESTONE_ID = re.compile(r"AVO-\d{3}")
LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


class RoadmapError(ValueError):
    pass


@dataclass(frozen=True)
class Milestone:
    milestone_id: str
    horizon: str
    status: str
    risk: str
    outcome: str
    exit_gate: str
    dependencies: tuple[str, ...]
    evidence: str


def _parse_date(text: str, label: str) -> date:
    match = re.search(rf"^{re.escape(label)}: (\d{{4}}-\d{{2}}-\d{{2}})\.$", text, re.MULTILINE)
    if match is None:
        raise RoadmapError(f"missing or malformed '{label}: YYYY-MM-DD.'")
    return date.fromisoformat(match.group(1))


def _table_cells(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def _parse_milestones(lines: list[str]) -> list[Milestone]:
    try:
        header_index = lines.index(MILESTONE_HEADER)
    except ValueError as exc:
        raise RoadmapError("missing the canonical milestone table header") from exc

    if header_index + 2 >= len(lines):
        raise RoadmapError("milestone table has no data rows")

    separator = _table_cells(lines[header_index + 1])
    if len(separator) != 8 or any(re.fullmatch(r":?-{3,}:?", cell) is None for cell in separator):
        raise RoadmapError("milestone table separator must contain eight Markdown columns")

    milestones: list[Milestone] = []
    for line in lines[header_index + 2 :]:
        if not line.startswith("|"):
            break
        cells = _table_cells(line)
        if len(cells) != 8:
            raise RoadmapError(f"milestone row must contain eight columns: {line}")
        milestone_id, horizon, status, risk, outcome, exit_gate, depends_on, evidence = cells
        if MILESTONE_ID.fullmatch(milestone_id) is None:
            raise RoadmapError(f"invalid milestone ID: {milestone_id}")
        dependencies = () if depends_on == "—" else tuple(
            dependency.strip() for dependency in depends_on.split(",")
        )
        milestones.append(
            Milestone(
                milestone_id=milestone_id,
                horizon=horizon,
                status=status,
                risk=risk,
                outcome=outcome,
                exit_gate=exit_gate,
                dependencies=dependencies,
                evidence=evidence,
            )
        )

    if not milestones:
        raise RoadmapError("milestone register must contain at least one milestone")
    return milestones


def _validate_milestones(milestones: list[Milestone], text: str) -> str:
    by_id: dict[str, Milestone] = {}
    for milestone in milestones:
        if milestone.milestone_id in by_id:
            raise RoadmapError(f"duplicate milestone ID: {milestone.milestone_id}")
        by_id[milestone.milestone_id] = milestone
        if milestone.horizon not in HORIZONS:
            raise RoadmapError(
                f"{milestone.milestone_id} has invalid horizon: {milestone.horizon}"
            )
        if milestone.status not in STATUSES:
            raise RoadmapError(
                f"{milestone.milestone_id} has invalid status: {milestone.status}"
            )
        if milestone.risk not in RISKS:
            raise RoadmapError(f"{milestone.milestone_id} has invalid risk: {milestone.risk}")
        if len(milestone.outcome) < 12 or len(milestone.exit_gate) < 12:
            raise RoadmapError(
                f"{milestone.milestone_id} needs a substantive outcome and exit gate"
            )
        if LINK.search(milestone.evidence) is None:
            raise RoadmapError(f"{milestone.milestone_id} needs linked evidence")
        if milestone.horizon == "done" and milestone.status != "complete":
            raise RoadmapError(f"{milestone.milestone_id}: done requires complete status")
        if milestone.status == "complete" and milestone.horizon != "done":
            raise RoadmapError(f"{milestone.milestone_id}: complete requires done horizon")
        if milestone.horizon == "gated" and milestone.status not in {"gated", "deferred"}:
            raise RoadmapError(
                f"{milestone.milestone_id}: gated horizon requires gated or deferred status"
            )

    active = [item for item in milestones if item.horizon == "now" and item.status == "in_progress"]
    if len(active) != 1:
        raise RoadmapError("exactly one milestone must be both now and in_progress")
    active_id = active[0].milestone_id
    if f"## Active milestone: {active_id}" not in text:
        raise RoadmapError(f"missing active milestone section for {active_id}")

    for milestone in milestones:
        for dependency in milestone.dependencies:
            if MILESTONE_ID.fullmatch(dependency) is None:
                raise RoadmapError(
                    f"{milestone.milestone_id} has malformed dependency: {dependency}"
                )
            if dependency == milestone.milestone_id:
                raise RoadmapError(f"{milestone.milestone_id} cannot depend on itself")
            if dependency not in by_id:
                raise RoadmapError(
                    f"{milestone.milestone_id} references unknown dependency: {dependency}"
                )

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(milestone_id: str) -> None:
        if milestone_id in visiting:
            raise RoadmapError(f"milestone dependency cycle contains {milestone_id}")
        if milestone_id in visited:
            return
        visiting.add(milestone_id)
        for dependency in by_id[milestone_id].dependencies:
            visit(dependency)
        visiting.remove(milestone_id)
        visited.add(milestone_id)

    for milestone_id in by_id:
        visit(milestone_id)
    return active_id


def _find_project_root(roadmap_path: Path) -> Path:
    for candidate in (roadmap_path.parent, *roadmap_path.parents):
        if (candidate / "pyproject.toml").is_file():
            return candidate
    raise RoadmapError("could not find project root containing pyproject.toml")


def _validate_links(text: str, roadmap_path: Path, project_root: Path) -> None:
    for raw_target in LINK.findall(text):
        target = raw_target.strip().strip("<>").split("#", 1)[0]
        if not target or re.match(r"^[a-z][a-z0-9+.-]*:", target, re.IGNORECASE):
            continue
        resolved = (roadmap_path.parent / target).resolve()
        if not resolved.is_relative_to(project_root.resolve()):
            raise RoadmapError(f"local link escapes the project root: {raw_target}")
        if not resolved.exists():
            raise RoadmapError(f"local link does not exist: {raw_target}")


def validate_roadmap(path: Path, max_review_age_days: int = 0) -> tuple[int, str]:
    roadmap_path = path.resolve()
    if not roadmap_path.is_file():
        raise RoadmapError(f"roadmap does not exist: {roadmap_path}")
    text = roadmap_path.read_text(encoding="utf-8")
    lines = text.splitlines()

    headings = {line for line in lines if line.startswith("#")}
    missing_headings = sorted(REQUIRED_HEADINGS - headings)
    if missing_headings:
        raise RoadmapError(f"missing required headings: {', '.join(missing_headings)}")
    if (
        "Authority: This file is AVO's sole authority for outcomes, priority, sequencing, "
        "milestone status, and decision gates."
    ) not in text:
        raise RoadmapError("missing the canonical authority declaration")

    status_date = _parse_date(text, "Status date")
    review_date = _parse_date(text, "Review date")
    today = date.today()
    if status_date > today or review_date > today:
        raise RoadmapError("roadmap dates cannot be in the future")
    if review_date < status_date:
        raise RoadmapError("Review date cannot precede Status date")
    if max_review_age_days > 0 and (today - review_date).days > max_review_age_days:
        raise RoadmapError(
            f"roadmap review is {(today - review_date).days} days old; "
            f"maximum is {max_review_age_days}"
        )

    milestones = _parse_milestones(lines)
    active_id = _validate_milestones(milestones, text)
    _validate_links(text, roadmap_path, _find_project_root(roadmap_path))
    return len(milestones), active_id


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate AVO's authoritative roadmap")
    parser.add_argument("roadmap", type=Path)
    parser.add_argument(
        "--max-review-age-days",
        type=int,
        default=0,
        help="fail when Review date is older than this many days; zero disables the age check",
    )
    args = parser.parse_args()
    if args.max_review_age_days < 0:
        parser.error("--max-review-age-days cannot be negative")
    try:
        milestone_count, active_id = validate_roadmap(
            args.roadmap, max_review_age_days=args.max_review_age_days
        )
    except (OSError, RoadmapError, UnicodeError, ValueError) as exc:
        print(f"roadmap validation failed: {exc}", file=sys.stderr)
        return 1
    print(f"roadmap validation passed: {milestone_count} milestones; active={active_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
