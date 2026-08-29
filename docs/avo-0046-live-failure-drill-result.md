# AVO-004.6 live failure-drill result

Status: complete and independently approved on 2026-08-29.

## Outcome

AVO completed a real, no-deploy failure and rollback drill against the protected
`integration` branch. An ordinary AVO campaign added the inert, exact marker file
`src/avo_correlate/live_rollback_marker.txt`. The pinned GitHub Actions App 15368 ran
the base-controlled soak workflow, which observed the marker at the promoted integration
SHA and failed as designed.
A separately authorized rollback then promoted the exact immediate-parent tree through
a second protected pull request. Protected `main` remained unchanged throughout the
final canary and rollback, and replay performed no additional mutation.

Terra's final authority review independently parsed the durable core and completion
journals and every referenced child artifact. It found no P0/P1 authority, recovery,
topology, evidence-durability, or false-success issue.

## Exact final identities

| Record | Identity |
| --- | --- |
| Protected main before/after | `8778bc89161ea0e1931b1f0a5eb18714ce34ca51` |
| Known-good integration base | `ad89309ce16a79a013871b52a6c9b3af897ff630` / tree `e06619deb8b9ca9ab010b1b78d1eed153d9b694b` |
| Canary operation | `sha256:45440dde5d8eda5ace757c7726b098a5355f0a24c37e895bf5b98408ac24db19` |
| Canary package | `sha256:9ad901cf5cfe7f5c735071e2dc10c2372ef8c0c24c6b5141b2a13ff6597d7f02` |
| Canary PR/result | PR #43 / `48876ccdaf23a0943855d9260f4d435e7f9be612` / tree `08889ae814fd16328bbba357655298c6bb2659c9` |
| Canary result parent | `ad89309ce16a79a013871b52a6c9b3af897ff630` |
| Failed soak | App 15368 check `99050404660`, completed `failure` at `2026-08-29T04:19:26Z` |
| Rollback operation | `sha256:795e920dcf1e45953378d6ec5a21719395dcdbd6c70368cbf3ce11f1621151e9` |
| Rollback core package | `sha256:f271315cdadc86c44147ab3dc215f317bd68b728aa9de4dec090a637c80990a3` |
| Rollback completion package | `sha256:1ab6139f5812b435c42cf837f9f20b13d7ae5c0f17d96fa12dc40ee0a93f698e` |
| Rollback PR/result | PR #44 / `ed38098ee8451206c9f44e9e525b65c9d47b9ef9` / tree `e06619deb8b9ca9ab010b1b78d1eed153d9b694b` |
| Rollback result parent | `48876ccdaf23a0943855d9260f4d435e7f9be612` |
| Post-rollback soak | App 15368 check `99051414644`, completed `success` at `2026-08-29T04:28:51Z` |

The canary candidate digest was
`sha256:14be1451bcf1864ed5796a9677dfe23468b99000921172b320ec65a3eac4ddad`.
The restore candidate digest was
`sha256:914c2c32e355cd6978cfebdb1197ea3ecdf8c62b18a41a78e11e29d0bafd3cc7`.
Each comparison contained exactly one changed path: the marker addition for the canary
and the same marker deletion for rollback.

## Attestation and recovery evidence

- PR #43's exact synthetic merge was `3059e4b51195b95d683b074d4b4f35a0702c1796`;
  both `avo synthetic validate (...)` checks from App 15368 passed on that SHA.
- PR #44's exact synthetic merge was `989ca9e09c65801f17348c7cb6100862fddfa63c`;
  both trusted exact-SHA checks and both protection-required head checks passed.
- The base-controlled integration-soak workflow and the protected repository variable
  were independently verified at the same workflow digest. The workflow had
  `contents: read` only and no deployment authority.
- The canary validation operation `sha256:532c438b68a67c2c9d9a19c75309db99cf8c62747009f3a6a3a09342be3c503e`
  and rollback validation operation `sha256:62df7a6d749aac3247f8823d11cef2de4346b11efbcbc6030208448cd92e0457`
  both recorded `cleaned`; authenticated reads confirmed their validation refs absent.
- Replaying rollback operation `795e920d...` returned `already_completed` with the
  same core and completion digests in about two seconds and caused no new PR, ref,
  authorization, or merge.
- Every live package records `deploy_performed=false` and exact equality of the bound
  `main_before_commit` and `main_after_commit`.

## Defects exposed and closed

The drill provided useful implementation pressure before the successful final run:

1. Recovery initially regenerated publication metadata and could not resume from all
   durable crash windows. Recovery was changed to prefer durable plans, intent, final
   evidence, packages, and immutable mutation authorization before preflight.
2. Pre-mutation GitHub failures could be misclassified as post-mutation ambiguity.
   Typed precondition failures and a durable mutation-authorization marker now prevent
   false `already_applied` success, including across restart.
3. Rollback authorization incorrectly used the restore-candidate digest as the failed
   source-tree digest. PR #41 (`8778bc8...`) made the finalizer read and verify the
   durable canary child, retain distinct source/restore digests, and agree with the
   controller's independent repository scan.
4. Two operations whose immutable main fence became stale during protected fixes were
   terminated rather than rewritten. Their exact orphan refs were verified, deleted,
   re-read as absent, and bound into create-once quarantine records. No historical
   authorization or content-addressed artifact was altered.
5. GitHub can briefly return a null synthetic merge SHA immediately after PR creation.
   The current runner fails closed and resumes the same durable PR once GitHub exposes
   the SHA. This is safe but unnecessarily operator-visible; bounded internal polling
   is a follow-up reliability improvement.
6. Controller-generated check-manifest evidence includes invocation freshness data.
   Static advisory evidence therefore had to be created while the runner waited on the
   exact persisted discovery context. Future automation should make this handoff an
   explicit controller activity rather than an operator-coordinated file arrival.

## Gate decision

AVO-004.6 passes. The offline eight-case package, pinned GitHub Actions check identity
executing the base-controlled exact-SHA workflow,
real failed soak, separately authorized protected rollback, content-addressed completion
evidence, cleanup proof, and completed-state replay jointly satisfy the gate. A dedicated
GitHub App is not required for this trusted public-repository boundary because GitHub
Actions App 15368 executes the pinned, base-controlled workflow and supplies the required
exact-SHA check identity; a dedicated
or isolated attester remains an AVO-008 escalation option if trust domains or production
deployment authority expand.

AVO-004.7 may begin, subject to its own preregistered clean-run threshold and the
remaining reliability improvements recorded above.
