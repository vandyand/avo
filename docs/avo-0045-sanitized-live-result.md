# AVO-004.5 sanitized live campaign result

Date: 2026-08-28  
Status: complete  
Scope: one sanitized ordinary-change promotion through the protected `integration` branch

## Outcome

The live gate promoted the two-file candidate from PR #5 through independent review, private
regression evaluation, exact reconstruction, protected integration merge, and durable receipt
recovery. The candidate changed only `src/avo_correlate/application/activity_service.py` and
`tests/recovery/test_activity_journal.py`. The patch is now present on `integration` but remains
absent from `main`; the result below records the controlled integration operation.

| Item | Recorded value |
| --- | --- |
| Pull request | #5, “AVO candidate for protected integration” |
| Base branch / commit | `integration` / `3ba46dca226e27d48adb8699aeb682b9e4c50a50` |
| Candidate commit | `92981c9482dba9c7587dc4a804ca1c952edaa91f` |
| Synthetic validation commit | `f53da347663c0dcb6a5d4ed595c6e1d5473e70a1` |
| Resulting integration commit | `9365358a37b96cae004e460d6fac5140f4894932` |
| Result tree | `bc1e3584165f38078c9d2ba4365eabc1447c25f3` |
| Result parents | exactly `[3ba46dca226e27d48adb8699aeb682b9e4c50a50]` |
| `main` before and after | `9b23fbbc16d4762d6fff5ec5a134261fd21f1440` (unchanged) |

The one-parent result and unchanged `main` establish that this campaign did not create an
external two-parent merge or bypass the main-branch boundary.

## Durable identities

The controller's content-addressed result record (`result.json` in the campaign state root)
records:

| Record | Digest |
| --- | --- |
| Operation | `sha256:deae9fb67117f9e3ec69185f292b05a6077a3d23d76fb8330b805e810241bbd7` |
| Promotion package | `sha256:db4a7524d933ea64cad6eb9162bfb1bf8e8cfe178b6bec1bcca6e23bee7739ba` |
| Intent | `sha256:2a43bcab81e9e0c1e111a237489332c7f27acf3ddcff2e130e99c3043f448ae6` |
| Receipt | `sha256:11a3d8a138ea48f4a0d3c8ab0b451c0213ec85dbb99265351eb255e0f4f1f266` |

The recorded outcome was `applied`, with recovery and durable-receipt checks both present.

## Quality and review evidence

- The private-evaluation artifact attested that the regression gate passed. A separate complete
  candidate-suite run reported **757 passed / 7 skipped**.
- Luna and Terra independently reviewed the exact candidate and both returned **APPROVE**.
- GitHub Actions checks from App **15368** were captured with the exact names
  `validate (ubuntu-latest)` and `validate (windows-latest)`; both passed for the synthetic
  validation commit used by the gate.
- The candidate itself was reviewed as a VCS-free artifact, and its focused Windows checks passed
  (`17 passed`) without candidate cache creation.

## Recovery and boundary observations

The first candidate push was operationally ambiguous at the authentication/transport boundary.
The exact planned commit was reconstructed and pushed to the already-recorded ref, after which a
rerun using the same durable state reconciled publication rather than minting another candidate.
Two runner invocations later overlapped: one completed and the duplicate failed closed on the
already-recorded plan. A subsequent replay of the completed state returned the same completed
package and receipt without replaying the merge.

The ordinary PR workflow initially exposed its checks on the candidate head SHA, while the
promotion invariant requires evidence on the exact synthetic SHA. The campaign therefore used a
temporary exact-validation ref plus `workflow_dispatch` bridge to attach the two App 15368 checks
to the synthetic commit. After the result was durably recorded, the temporary validation ref was
deleted and its otherwise-pending workflow run was cancelled; the content-addressed campaign
state and evidence were intentionally retained.

This bridge is a live-gate recovery mechanism, **not the long-term production attester**. It does
not justify weakening exact synthetic-commit validation or treating head-SHA checks as equivalent.
The recommended hardening is a base-controlled workflow that produces an auditable attestation for
the exact synthetic SHA without privileged checkout of untrusted code, or a dedicated GitHub App
that creates and verifies those check runs. Relevant GitHub security and Checks API references are
[workflow events](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows),
[check runs](https://docs.github.com/en/rest/checks/runs),
[`GITHUB_TOKEN`](https://docs.github.com/en/actions/concepts/security/github_token), and
[secure use](https://docs.github.com/en/actions/reference/security/secure-use).

## Gate decision

AVO-004.5 is complete: one sanitized ordinary change passed the required live promotion,
recovery, topology, protected-branch, and durable-evidence checks. AVO-004 remains in progress;
the next gate is AVO-004.6, which must turn the observed recovery cases into repeatable failure
drills and replace the temporary exact-SHA bridge with production-grade attestation before any
graduation to automatic `main` promotion.
