---
name: avo-roadmap
description: Maintain, audit, or report AVO's authoritative roadmap when asked what is next, where the project stands, how milestones should be sequenced, or whether roadmap work is complete.
---

# AVO roadmap

Use `docs/roadmap.md` as the sole authority for AVO's outcomes, priority, sequencing, milestone
status, and decision gates. Treat implementation plans, ADRs, status snapshots, and result records as
supporting evidence rather than competing roadmaps.

## Start here

1. Locate the project root containing `docs/roadmap.md` and `pyproject.toml`.
2. Read `docs/roadmap.md` before opening supporting records.
3. Run:

   ```text
   uv run python .agents/skills/avo-roadmap/scripts/validate_roadmap.py docs/roadmap.md
   ```

4. Follow links only for the milestones or claims relevant to the request.

## Report, audit, or update

- For a status or sequencing question, report the roadmap's current position, active milestone,
  blockers, and next decision gate. Do not reconstruct a second roadmap from older plans.
- For an audit, compare roadmap claims with their linked evidence. Report inconsistencies; do not
  silently reinterpret historical result records.
- For an authorized update, make the smallest evidence-backed roadmap change. Preserve milestone
  IDs, vocabulary, and dependencies, then rerun the validator.

## Authority rules

- Completion requires the milestone's stated exit gate and durable linked evidence. A candidate,
  model response, passing candidate-owned test, or prose claim cannot mark itself complete.
- For AVO-on-AVO work, the independent promotion result updates completion after admission,
  provenance verification, and the applicable merge gate. The proposing campaign does not.
- Preserve immutable ADRs and experiment/result records. Add a supersession notice rather than
  rewriting historical facts when current direction changes.
- Keep exactly one `now` / `in_progress` milestone. Move work among `now`, `next`, `later`, and
  `gated` only when evidence, dependencies, or an explicit user decision changes priority.
- Add a milestone only with a stable ID, outcome, exit gate, dependency set, risk class, and at
  least one supporting evidence link.
- Update `Status date` for a material roadmap change. Update `Review date` only after validating
  the file and checking the evidence relevant to current and newly changed claims.
- Do not invent delivery dates, completion percentages, GitHub issues, or external tracker state.
- Do not create or mutate GitHub Projects, Issues, or another external system without
  explicit authorization. Those systems are derived execution views, not roadmap authority.

## Validation

The validator checks required sections and dates, milestone vocabulary, the single active
milestone invariant, dependency references and cycles, evidence links, and review freshness when
`--max-review-age-days` is supplied. Treat a validation failure as roadmap drift and resolve it
before claiming the roadmap is current.
