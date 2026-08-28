# AVO-004.5 sanitized live campaign

`scripts/run_sanitized_integration_campaign.py` is the bounded operator
entrypoint for the first ordinary automatic promotion campaign. It is scoped
to the public repository `https://github.com/vandyand/avo.git` and exactly
`refs/heads/integration`. It cannot promote `main`, deploy, or production.

## Inputs

The operator supplies:

- a controller-owned `--state-root` outside the checkout;
- a trusted checkout containing the exact integration ref;
- a VCS-free sanitized candidate directory (`--candidate-root`);
- a controller-owned canonical JSON policy (`--controller-config`); and
- exactly these six canonical controller evidence files under `--evidence-root`:
  `private-regression.json`,
  `provenance-reconstruction.json`, `integration-soak.json`,
  `reviewer-decision-1.json`, `reviewer-decision-2.json`, and
  `rollback-proof.json`.

The trusted-CI file is intentionally not a pre-created input: after the
controller opens the pull request, the runner captures the provider's exact
synthetic-merge check manifest and persists it under the state root. A
discovery context is also persisted so a restart can identify the same
evidence request.

Evidence is content-addressed and validated by the trusted quality adapter.
The two reviewer artifacts must represent independent trusted domains. The
hosted check evidence is additionally read from the exact synthetic merge
commit and must contain the configured Ubuntu and Windows checks, completed
successfully within the freshness window.

## Preflight

Run the command with `--preflight` first. This reads the local integration
checkout and candidate and writes `result.json` beneath the state root. It
does not require the six post-discovery evidence files, perform a GitHub
request, or mutate a remote. `--dry-run` has the same no-remote-mutation
guarantee.

Example shape (the check names and App IDs are configuration, not defaults):

```text
uv run python scripts/run_sanitized_integration_campaign.py \
  --state-root ../avo-0045-state \
  --repository-root . \
  --candidate-root ../avo-0045-fixture \
  --evidence-root ../avo-0045-evidence \
  --controller-config ../avo-0045-evidence/controller-config.json \
  --candidate-id sanitized-live-001 \
  --proposer-id avo-controller \
  --trusted-check "validate (ubuntu-latest)=15368" \
  --trusted-check "validate (windows-latest)=15368" \
  --freshness-cutoff 2026-08-27T00:00:00Z \
  --preflight
```

The command refuses alternate remotes and targets, a state root inside the
trusted checkout, candidate/state overlap, symlinks and VCS metadata in the
candidate, malformed canonical JSON, unbounded waits, or a missing
`GITHUB_TOKEN` for a live run. During a live run it writes
`discovery-context.json`, then waits within the configured bound for all six
controller evidence files to appear and validate against that context.

Each of the six files is canonical JSON: UTF-8, no insignificant whitespace,
and no trailing newline. Gate files use `kind: "gate"` and the matching
`gate_name` (`private_evaluation`, `provenance`, or `integration_soak`);
reviewer files use `kind: "reviewer"`, a distinct trusted `reviewer_id`, and
its configured `reviewer_domain`; the rollback file uses `kind: "rollback"`,
`rollback_count`, and `available`. Every file also binds the discovery
context's candidate, base, synthetic commit/tree, protection and check-manifest
digests, plus the configured issuer and evaluation epoch/window. The strict
models reject extra fields, stale epochs, substituted issuers, and context
drift.

## Live execution and recovery

Set `GITHUB_TOKEN` in the process environment. The runner creates a secret-free
askpass helper under the state root and passes the token only in memory to Git
subprocesses. The token is never written to a file, printed, or included in
`result.json`. Do not place credentials in the repository URL.

After preflight, omit `--preflight` and `--dry-run` to execute the lifecycle:

1. snapshot the exact integration base and publish one verified candidate to a
   fresh controller-owned ref;
2. open or reconcile exactly one same-repository pull request;
3. poll the exact trusted synthetic merge/check/protection observation within
   the configured bound;
4. consume controller-owned private evaluation, provenance, soak, reviewer,
   and rollback evidence;
5. perform the controller dry-run, bind the marker, and make exactly one
   promotion attempt; and
6. persist/recover the completion package, verify `main` is unchanged, and
   emit the sanitized result JSON.

The promotion and completion journals are durable beneath the state root.
If the process exits after a provider call, rerun with the same state root;
the application recovery path reconciles the durable intent/receipt and does
not blindly repeat the merge. An ambiguous publication or merge must remain
visible for reconciliation rather than being retried by an operator with a
new state root.

## Stop conditions

This is an evidence gate, not a production release. Stop and preserve the
state root if the base moves, a pull request is retargeted, a check is stale or
substituted, a reviewer domain is duplicated, provenance cannot be rebuilt,
rollback proof is unavailable, `main` changes, or any result is ambiguous.
The campaign is not complete until the resulting evidence package is reviewed
and the protected feature branch containing this runner is merged through the
normal repository controls.
