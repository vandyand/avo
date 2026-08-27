# AVO-004 Git baseline v1 result

Status: recovery-verified; remote protection blocked by provider plan

Recorded: 2026-08-27

## Controlling baseline

- Canonical repository root: `C:\Users\vandy\avo`
- Remote: `https://github.com/vandyand/avo.git` (private)
- Branch: `main`
- Baseline tag: `avo-004.2-baseline-v1`
- Commit: `acdf49a595deea522e7419c2bedbebf9c17133e5`
- Tree: `5f85c298a83d51d753d3b084ef40715ab3860008`
- Remote identity digest:
  `sha256:49e3f552f65779fe45c9f772b8979bc4903c7358c8d45c208e8676dcd6ce6672`

The baseline was created only after the complete Windows test suite, Ruff, strict Pyright,
schema regeneration, secret-pattern scan, and roadmap validation passed. Runtime data, virtual
environments, caches, local coverage data, and candidate workspaces remain excluded by
`.gitignore`.

## Recovery rehearsal

A fresh disposable clone was created from the authenticated remote. The read-only verifier in
`scripts/verify_git_baseline.py` checked the clone against the recorded branch, remote, commit,
and tree. It returned a clean working tree with exact commit and tree equality. The disposable
clone was then removed.

## Remote protection result

GitHub accepted the private repository and baseline push but rejected protected-branch
configuration with HTTP 403: private-repository branch protection requires an eligible paid
GitHub plan, or the repository must be public. AVO will not make the repository public merely to
bypass this gate. Until the account or repository placement provides server-side protected
branches, AVO-004.2 remains in progress and autonomous promotion remains disabled.

## Quality evidence

- Hosted CI: [run 33113102611](https://github.com/vandyand/avo/actions/runs/33113102611) passed
  on Ubuntu and Windows at commit `809dea3d57264f37c9d6ea110660635330094c27`.
- Canonical Linux suite: 373 passed with no skips.
- Native Windows portability suite: 365 passed, 1 expected platform skip.
- Branch coverage: 85.40% on the canonical Linux gate, above the 85% threshold.
- Local Windows/Docker verification: 370 passed, 3 expected platform skips, 85.41% coverage.
- Ruff: passed.
- Strict Pyright: 0 errors and 0 warnings.
- Generated schema parity: passed.
- Roadmap validation: passed before this evidence update and must pass again with the update.
