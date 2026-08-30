# AVO-004.7 C4 Phase A contract and journal result

Status: complete as of 2026-08-30; live coordinator/provider executor remains the next
ready implementation gate.

## Decision

C4 Phase A is complete at code HEAD `0cb20c50c43cd78f75b23da025e3bbe4e0f5ee78`.
Terra approved the Phase A contract and journal boundary at this head. The boundary covers
the contract-first coordinator journal, atomic intent/fence ordering, controller-owned receipt
verification, durable lease fencing, deterministic external identities, one-use release claims,
capability separation, and read-only reconciliation for ambiguous external mutations.

This result records only the Phase A contract/journal gate. It does not claim live
coordinator/provider executor readiness, authorize provider or GitHub mutation, establish
hosting or release authority, or complete AVO-004.7.

## Next ready gate

Implement the live coordinator/provider executor using the frozen Phase A contracts. The
executor must enforce the preparation-auth → publication/PR → PR-head admission → enqueue
→ distinct group pending hold → one-use release-auth → last-moment issuer revalidation
chronology, with lease fencing and read-only crash reconciliation. P2 also requires an
end-to-end on-disk recovery fixture covering durable journal restart, an ambiguous provider
boundary, and replay. This is required P2 coverage, not live readiness by itself.

No provider writes, hosted queue changes, release transitions, or `main` mutations are part
of this result.

## Related authority

* [AVO roadmap](roadmap.md)
* [AVO-004.7 implementation plan](avo-0047-main-graduation-plan.md)
* [AVO-004.7 runbook](avo-0047-main-graduation-runbook.md)
* [ADR 0011](adr/0011-protected-main-graduation.md)
