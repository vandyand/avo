# Codex WSL live-gate record

Historical status: passed for bounded development use on 2026-08-25. The comparative benchmark and OpenRouter gates referenced below were subsequently completed; see the [authoritative roadmap](roadmap.md) for current status and sequencing. This record is not a production or hostile-code security approval.

## Provisioned topology

- WSL 2 distribution: Ubuntu 24.04, Linux x86-64.
- Canonical ext4 repository: `/home/kingjames/avo`.
- Python protocol client: exact-locked `openai-codex==0.147.0`.
- Runtime: exact-checked Linux-native `codex-cli 0.149.1` at an absolute path under the user's WSL NVM installation. The SDK-bundled 0.147.0 CLI and the broken Windows npm shim are not selected.
- Runtime executable SHA-256: `73dc5888888f411c1f0fa7b81d866e721dcc86b527ce8e3b2cf4708661e823ba`.
- Dedicated authentication/configuration root: `/home/kingjames/.avo-codex`, mode 0700. Authentication was performed directly in WSL using ChatGPT; no API token or Windows credential cache was copied.
- Dedicated runtime temporary directory: `/home/kingjames/.local/state/avo/codex-tmp`, mode 0700. The sandbox may write there while `/tmp` remains denied.
- Candidate workspaces: `/var/lib/avo/workspaces`, mode 0700 and outside every parent Git repository.
- External Git metadata: `/var/lib/avo/git-metadata`; Codex never receives candidate-owned Git metadata.
- Active signed runtime profile: `/home/kingjames/.config/avo/profiles/codex-live-wsl-v6.json`.
- Active profile digest: `sha256:c19923c07e29314a9cefdfb9aafa1b3fa88a2d7327352149ba573b5b83c066e5`.
- Host-local trust key: `/home/kingjames/.config/avo/trust/codex-plugin-v1.key`, mode 0600 and outside the repository. Its contents were never printed or copied.

The Python SDK and CLI release streams are intentionally independent. SDK 0.147.0 supplies the typed local app-server client; AVO's explicit `codex_bin` selects reviewed CLI 0.149.1 instead of the SDK bundle.

## Fail-closed controls verified

The v6 live doctor passed every check:

- Linux/WSL enforcement and subscription-only authentication.
- Trusted signed plugin manifest, exact SDK version, exact CLI version, and signed executable digest.
- Provider-valid strict completion schema with every declared property required.
- Recomputed permission-contract digest, preventing stored policy drift.
- Exact app-server identity: type `chatgpt`, email `vandyand@gmail.com`, plan `pro`.
- Isolated `CODEX_HOME` and private `TMPDIR`.
- Workspace read/write allowed; root, AVO state, private evaluator data, `/tmp`, external TCP, and undeclared Unix sockets denied.
- Hosted web search, project instructions, hooks, apps, plugins, memories, multi-agent, computer use, browser use, and update checks disabled.
- Candidate-controlled `.codex` and `.agents` configuration rejected; parent and nested Git metadata rejected.
- Empty `.git`, `.codex`, and `.agents` mount scaffolds removed after a turn; non-empty, symlinked, or otherwise unsafe scaffolds fail closed.

## Live-turn evidence

The read-only and mutation gates used v5, whose effective runtime policy, CLI, account, workspace root, and completion schema are identical to v6. v6 adds verification that the stored permission digest matches that policy.

- Read-only session: `01a039cb-ae7c-71d1-aebb-3364df96c494:01a039cb-aede-7443-ab50-419913669eda`.
  - 94 normalized events and a schema-valid `stop` completion.
  - Full workspace topology remained `sha256:62a48fe2b7fe0bb65bfdb54e14b286c878ba61137f1ea7a71daeb955c3dc9620` before and after.
  - Codex correctly identified that the fixture optimizer examined only the first window.
- Controlled mutation session: `01a039cc-843b-7d63-b0ca-4313b85c1928:01a039cc-84a2-71b2-b732-628784be6199`.
  - 160 normalized events and a schema-valid `proposal` completion.
  - Source digest changed from `sha256:2b57ae94b539dacafd4a04afeb1643e1eb42f249c5af0fea4a31631a8a8a0643` to `sha256:e0179d5cb2d5f09b113bcac84d5569467a8c648907a23fc19d9322d1c79ad6cb`.
  - Public tests: 4 passed. Independent private evaluator: 3 passed.
  - External VCS-free patch: 1,415 bytes, digest `sha256:8b9cfd0c5baf7aaa2ddb72f6402e8c7c3afc5f5282f3ceb5b81bfd8a2212836d`.
  - The patch contained only the rolling-window fix and public regression tests; no project source outside the disposable workspace was modified.
- Interruption session: `01a039cf-090a-7d60-9620-1ca464e6e443:01a039cf-0981-7272-9223-cf5379a3e393`.
  - Provider status persisted as `interrupted`.
  - A cold runtime could not reattach, forcing explicit reconciliation.
  - The workspace remained unchanged and no runtime scaffolds remained.
- Hard provider-process failure session: `01a039d6-774b-7ad1-9a33-118148f02512:01a039d6-77bb-7c50-91ae-d20a4d0af1c0`.
  - The probe revalidated the exact executable, `app-server --listen stdio://` command line, and direct parent PID immediately before signaling only that PID.
  - The event stream surfaced `TransportClosedError`; no failed turn was misreported as missing JSON.
  - Runtime detached the session, `recover()` returned `None`, the workspace remained unchanged, and no runtime scaffolds remained.

## Regression gates

- Native Windows: 149 passed, 2 expected platform skips, 85.13% branch-aware coverage.
- WSL ext4: 151 passed with no skips. The suites also pass concurrently against the shared Docker daemon after unique per-attempt evaluator container names removed a cross-topology name race.
- Ruff: clean in both trees.
- Strict Pyright: clean in both trees.

## Remaining promotion work

A three-task, one-repetition Codex-only calibration admitted 3/3 candidates; see `docs/codex-pilot-v1.md`. Freeze the remaining five tasks, then run the preregistered equal-budget AVO-native versus AVO-plus-Codex benchmark and assess quality, cost, latency, reliability, and operator burden. Production-only infrastructure and the OpenAI-compatible/OpenRouter baseline stay deferred until their documented triggers or an explicit model/account decision.
