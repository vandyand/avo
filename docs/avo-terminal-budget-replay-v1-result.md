# Recursive terminal-budget replay v1 result

Status: passed on 2026-08-26. This was a deterministic local replay of the first sanitized
AVO-on-AVO campaign. It contacted neither Codex nor any other model provider and consumed no model
or subscription quota.

## Source evidence

The replay used the immutable retained bundle at
`/var/lib/avo/recursive-runs/20260826-runtime-inspection-luna-v1` in WSL:

- Source run: `recursive-20260826T135630Z-8de19c18`.
- Source provenance digest:
  `sha256:71e0dc4e7f31720ee02e0b95c6b196014b3344ae6796b1e090fb2d0bc774f6a5`.
- Source provider thread: `01a03e5b-d701-7023-bb5a-e8f21fc45faf`.
- Source provider turn: `01a03e5b-d787-78d1-bf91-e4f93cfd9eac`.
- Recorded runtime events: 578.
- Candidate digest:
  `sha256:a7604e95b083b6f4f42b8f51d126ef7ee255ff78cab549d8f7521d7810d6cea7`.
- Recorded usage: 277,350 input tokens and 5,341 output tokens.

The command copied and normalized the retained baseline and candidate into a new review bundle,
verified both tree digests, relabeled the runtime as a local recorded-evidence adapter, rewrote only
event invocation IDs for the fresh activity, and drove the ordinary campaign handler and scheduler.
The source provider identifiers are trace metadata only; they were never resumed.

## Result

The fresh run `recursive-terminal-replay-a82744d611ba` passed every preregistered assertion:

- Actual input/output usage was preserved exactly in the ledger.
- The variation reservation became `exceeded`.
- The variation activity became `completed`.
- The frozen candidate became `policy_blocked` without becoming champion.
- The queued evaluation became `cancelled` and its reservation became `released`.
- Remaining reserved usage became zero.
- The terminal budget policy denied evaluation with
  `model_input_token_budget_exceeded`.
- The run became `failed`.
- No reconciliation case was created.
- Exactly one local recorded turn and one completed local invocation were recorded.
- The current verifier rejected the historical source export with
  `terminal_run_has_open_reconciliation` and verified the fresh replay export without errors.

Fresh replay provenance digest:
`sha256:3a3049aeeb7825d135122ac1535b78a1beed0875f16f6ef9ab86bb43fcd473d6`.

The retained replay bundle is
`/var/lib/avo/recursive-runs/20260826-runtime-inspection-terminal-replay-v1`. Its control-file
SHA-256 digests are:

- `result.json`: `af3561fc1a28ad647ea996d7158e554c78392704bdcdaa3c070f7c3da9d6624a`
- `provenance.json`: `21deca0ead480446aefdbe6db9a2bba7bce8d1cabee2e7c6acb3b3b61e89b178`
- `source-envelope.json`: `7d596a383fad490bf024fbe49cea1924183a7dc3d240dfbf2c8e91c295e274c6`

## Reproduction

From the project root in WSL, using the project environment:

```text
python scripts/replay_recursive_terminal_budget.py \
  --source-run /var/lib/avo/recursive-runs/20260826-runtime-inspection-luna-v1 \
  --run-root <new-empty-review-bundle-path>
```

The command refuses to reuse an existing output path and fails closed if any source digest,
sequence, terminal state, usage value, policy decision, or provenance invariant differs.
