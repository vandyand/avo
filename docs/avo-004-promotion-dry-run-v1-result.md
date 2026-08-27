# AVO-004 promotion dry-run v1 result

Status: local verification and independent review passed; protected hosted promotion pending

Recorded: 2026-08-27

## Scope

This gate implements the no-merge controller from ADR 0008. It produces and replays a canonical,
content-addressed promotion bundle while leaving the trusted repository, target ref, and VCS-free
candidate unchanged. It does not authorize automatic merge or deployment.

## Implemented boundary

- Trusted Git snapshots bind the sanitized remote identity, target ref, commit, tree, canonical
  source digest, and branch-protection evidence digest.
- Candidate comparison is bounded, portable, VCS-free, mode-aware, and resistant to symlink,
  hardlink, reparse-point, path-collision, and file-replacement attacks.
- Controller configuration is pinned outside candidate input. Repository, candidate, and artifact
  roots must be disjoint.
- The controller reconstructs base and path attestations, verifies provenance and external evidence,
  closes the evidence manifest, classifies through ADR 0007, and performs a final snapshot check
  before its only write.
- Replay requires strict canonical JSON, recomputes every linked digest and decision, re-verifies
  evidence and the base snapshot, and reports only an allowed current-base bundle as `would_apply`.

## Adversarial review

The first independent review blocked acceptance on six issues: caller-weakened gate policy, denied
bundles replaying as applicable, artifact-store overlap mutation, candidate scan TOCTOU and Windows
reparse handling, lost Git executable-mode changes, and unbounded entry counts. Each issue was
remediated with a regression test. A second review found mode absent from the candidate digest,
non-exact replay evidence closure, whole-tree scan instability, and incomplete URI credential
redaction. Those issues were also remediated. The final independent re-review passed with no
remaining acceptance-critical AVO-004.4 bypass.

## Verification

- Focused promotion, Git, policy, schema, and artifact tests: 171 passed, 6 expected Windows or
  filesystem capability skips.
- Complete local Windows/Docker suite: 445 passed, 9 expected platform skips, with 85.93% branch
  coverage against the 85% project floor.
- Ruff: passed.
- Strict Pyright: 0 errors and 0 warnings.
- Generated schema parity: passed.
- Authoritative roadmap validation: passed.

The first complete coverage run measured 84.83%, below the project floor after adding the new
security branches. Additional adversarial tests raised coverage to 85.93%. The protected hosted CI
result remains pending; this implementation candidate therefore does not mark AVO-004.4 complete.
