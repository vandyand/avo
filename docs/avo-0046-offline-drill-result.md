# AVO-004.6 offline failure-drill result

Status: deterministic offline proof recorded; AVO-004.6 gate remains open.

The local harness completed cases 1--8 using controlled provider transports and
faults. Three executions (fresh A, replay A, and fresh B) produced identical
content-addressed identities:

| Evidence | Digest |
| --- | --- |
| Operation | `sha256:b0309f521a56f4a2fabf438d7f203deea8d00d49ecb35cbc5adfb3bad24996c8` |
| Plan | `sha256:e09ae69810ef096eff316ce4f8749d46f6933315f4dfe35628816e3c82d782a5` |
| Result | `sha256:a7176851aa1cdc1a7d615439b8e4dc23aa39fb2e493ddbe0b89dce6e6498ac7e` |

The aggregate contains each case exactly once. The main synthetic invariant
`111...` was unchanged in every execution and `deploy_performed` was false.
Replay was read-only and introduced no additional controlled provider mutation.

Verification evidence: Windows full suite 844 passed / 7 skipped with 86.03%
branch coverage; focused suite 153 passed; concurrency soak 20/20; Ruff,
Pyright, schema export, and schema diff checks were clean. Final Terra
adversarial review was **APPROVE** after remediations.

This result exercises the real local promotion, policy, provider-parser,
synthetic-validation, rollback, attester, and journal boundaries. Controlled
transports establish deterministic state-machine and idempotence evidence only;
they do not establish behavior of a hosted GitHub account, workflow,
branch-protection configuration, credentials, or network boundary. A hosted
canary and protected live rollback remain required before the gate can be
closed.

See the [failure-drill runbook](avo-0046-failure-drill-runbook.md), [ADR 0010](adr/0010-exact-sha-attestation-and-failure-drills.md), and the
[drill runner](../scripts/run_avo0046_drills.py) for procedure and implementation.
