# AVO improves AVO: capstone v2 admitted result

Status: admitted on 2026-08-26. This is the first AVO-on-AVO candidate to pass the complete live
variation, independent evaluation, policy, admission, lineage, and provenance lifecycle. The
admitted patch has not been applied to the real working project; that remains a human decision.

## Frozen experiment

- Runtime: Codex SDK 0.147.0 controlling exact CLI 0.149.1 through the isolated
  `vandyand@gmail.com` ChatGPT Pro login. No API token was supplied.
- Model: `gpt-5.6-luna`; neither Terra nor Sol was used.
- Scope: require `RuntimeInspection(state="completed")` to carry an `AgentCompletion` while
  preserving the inverse invariant for every non-completed state.
- One provider thread and one turn.
- Immutable model-input-token limit: 350,000, selected from the first run's observed 277,350 with
  bounded headroom.
- Frozen private evaluator digest:
  `sha256:90f7a3adff435587a0a958ee9b596750e61b3204afaa216447b6d8ceacf9db50`.
- Baseline digest:
  `sha256:5cd24dc6505c3c9e3b82b422a51d6d9127aedded0a0e580639032f07a25f9cf5`.

The retained review bundle is
`/var/lib/avo/recursive-runs/20260826-runtime-inspection-luna-v2-admission` in WSL. Run ID:
`recursive-20260826T171904Z-b44ced81`.

## Candidate and evaluation

Luna added the missing two-line validator branch and one focused regression test. Changed paths
were exactly:

- `src/avo_correlate/contracts/runtime.py`
- `tests/unit/test_contracts.py`

The 2,146-byte frozen patch has digest
`sha256:fc3ad61cf2f72ea37732664586e1c9c03207489a80bceee7d33a8d66cbfe1c73`.
The candidate digest is
`sha256:43e514aed400907a94ea2713ff0ba5f67793f5119d195cb4932b4215e48bbfc8`.

Independent evaluation produced:

- Ruff: passed.
- strict Pyright: passed with zero errors and warnings.
- Linux suite: 176 passed.
- frozen private completion-state invariant: passed.
- changed-path scope: passed.
- hidden-evaluator reference scan: passed.

Applying the frozen patch with the POSIX `patch` consumer to a clean retained baseline reproduced
the candidate digest exactly at `control/reconstructed-workspace`.

## Budget, admission, and provenance

Codex reported 197,800 cumulative input tokens and 3,743 output tokens. The run used two
authoritative evaluations, left every reservation at zero, and remained within its immutable
350,000/50,000 token limits.

The frozen policy returned `allow` with `all_frozen_controls_passed`. Admission concluded
`improved`, appended candidate `fdf17fa5-e0e0-5b79-8d70-6abc6a0db7c7` to lineage, and made it the
run champion. The run completed with no reconciliation cases.

- Provider thread: `01a03f15-4216-7432-a211-7a3f11d13f52`.
- Provider turn: `01a03f15-42a8-7ba0-b170-e693ce421db9`.
- Provenance digest:
  `sha256:eb3b75c30e8027e20f5d81a0509fc6451ec7184f1281980d5b244e7f018adb39`.
- Provenance verification: passed with no errors.
- `result.json` SHA-256:
  `45a2da67bdf8a16cf9a2b8c2250e7411a7e472ded1885632446fc3d09d1f695c`.
- `provenance.json` SHA-256:
  `ce08fa802c2f294be4726d1a33bcc79f224c6e1d4ec560317932343313ef74ee`.

## Interpretation and review boundary

This closes the first full recursive loop: AVO constrained a live Luna variation of AVO, evaluated
it independently, enforced immutable budget and policy, admitted it through lineage CAS, and
verified its provenance and reconstruction. Admission is not deployment. The Windows workspace
remains unchanged until a human reviews and explicitly applies the retained two-file patch.
