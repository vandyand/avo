# Threat model

**Status:** Implemented trusted-team baseline, reviewed 2026-08-24

The model, generated code, user repository, retrieved content, and variation workspace are untrusted. The control plane, policy bundle, and private evaluator package are trusted computing-base components. Standard Docker is not a hostile-code security boundary.

| Threat | Required control | Verification |
|---|---|---|
| Path traversal or normalization collision | POSIX paths, NFC, collision and post-materialization scans | Property and adversarial tests |
| Hidden evaluator disclosure | Separate images and mounts | Image inspection and read attempts |
| Host escape | No secrets, host mounts, socket, capabilities, or network | Sandbox contract |
| Resource exhaustion | External CPU, memory, PID, disk, inode, output, and time limits | Adversarial evaluator |
| Forged evaluator result | Schema, size, identity, and digest validation | Malformed-report suite |
| Duplicate admission or charges | Idempotency, reservations, compare-and-swap, transactions | Crash-boundary suite |
| Supply-chain substitution | Lockfile and image digest pinning | CI verification |
| Secret leakage | Deterministic redaction before persistence | Canary-secret tests |
| Wrong Codex billing identity | Force ChatGPT login; reject API credential profiles and inherited tokens; verify exact email and Pro plan | Account preflight and negative identity tests |

Local Docker development still exposes the host kernel and daemon attack surface. V1 must refuse projects requiring hostile-code containment. The threat model must be reviewed before network access, native host commands, multi-tenancy, evaluator credentials, or another execution host is enabled.

## Data flow and trust boundaries

~~~text
operator -> authenticated API/CLI -> control-plane state + append-only evidence
                                      | signed session capability
                                      v
                               variation workspace
                               (no DB credential,
                                no private evaluator,
                                brokered tools only)
                                      | frozen candidate digest
                                      v
                           authoritative Docker evaluator
                           (network none, read-only root,
                            private tier image, bounded /output)
                                      | validated report
                                      v
                         deterministic admission CAS + lineage
~~~

Protected assets are the SQLite state database, policy bundles, capability signing key, model credential, Codex ChatGPT login cache, admission/audit fixtures, Docker daemon socket, artifact store, and immutable event/evidence records. Model credentials are fetched at call time and are neither placed in model request artifacts nor mounted into a variation or evaluator container. AVO does not read or copy the Codex login cache; the Codex app server owns it under the configured `CODEX_HOME`, while AVO receives only the non-secret account identity response.

Implemented deny proofs cover path traversal, case/Unicode collision, symlink and hardlink handling, archive escape and expansion, hidden evaluator reads, root-filesystem writes, network egress, unauthorized executable and mount selection, capability tampering/expiry/scope, duplicate JSON keys, non-finite numbers, undeclared metrics, oversized reports, forged digests, duplicate admission, and late admission after cancellation.

## Residual risks and refusal boundary

Standard Docker shares a host kernel and is not approved for hostile multi-tenant code. The local subprocess adapter is explicitly a convenience for trusted development and cannot prove network denial. A compromised control plane, Docker daemon, signing key, or host administrator can defeat the model. Hosted model calls are auditable and reconstructable but are not deterministic replay. Timing and hardware variation remain for noisy evaluators and must be handled by paired trials and declared hardware classes.

Projects requiring hostile-code containment, host secrets in evaluator scope, unrestricted network, mutable evaluator packages, or direct plugin database access are blocked until an approved VM/gVisor/Kata profile and security review exist.
