# ADR 0007: Controller-owned promotion policy

Status: accepted for AVO-004.3 (contract only; controller deferred)

Risk is derived from normalized, relative POSIX changed paths; a proposal cannot select
its tier. Drive-qualified, colon-containing, backslash, absolute, empty-segment, and
traversal paths are invalid. Comparisons are case-insensitive. Production scope is denied.
Paths must be NFC-normalized and cannot contain case- or Unicode-equivalent collisions. The
complete, canonical path set is bound to the candidate and base by a trusted controller-issued
path-manifest attestation; a missing or mismatched manifest quarantines before promotion.
Constitutional scope is routed to a separately authorized maintenance path and escalates;
it never enters ordinary automatic promotion. Constitutional scope includes roadmap
governance, policy and promotion/controller files, admission/lifecycle/budget/provenance
controls, CI, schemas, dependency manifests and common lockfiles, migrations, private
evaluators, sandboxing, and credential or secret paths. Documentation/tests alone are low
risk only if no changed path is constitutional. Every remaining valid path is ordinary.

Low risk requires deterministic and provenance gates plus one independent approval.
Ordinary changes require trusted CI, frozen private evaluation, provenance reconstruction,
integration soak, and two independent approvals. Quorum counts distinct authorized reviewer
identities and distinct reviewer domains. More valid approvals from an already represented
domain do not invalidate a sufficient independent quorum. A proposer cannot approve its own
candidate; approvals from the proposer domain do not count toward quorum. Controller-owned
configuration binds each candidate digest to its proposer identity and domain; unknown or
mismatched proposer identity quarantines.

Every base, gate, rollback, and reviewer attestation carries a schema-validated evidence digest,
must bind the candidate and base digests, come from its configured trusted issuer, and include
the evaluation epoch in the inclusive
`valid_from_epoch <= epoch <= valid_until_epoch` window. The base attestation additionally
means exactly `gate_name == "base"` and `passed == true`. Each required gate must be attested
by the issuer configured for that exact gate. The policy config, not request evidence, owns
trusted issuers, reviewer identities and domains, proposer domains, evaluation epoch, and the
rollback limit. Equality with the rollback limit remains valid.

The precedence is intentionally conservative. Production is denied first. Self-approval and a
trusted explicitly failed required gate are hard denials even for constitutional proposals;
otherwise constitutional scope escalates as immutable risk routing. For promotable scope, a
trusted unavailable rollback and a trusted rollback count above the configured limit deny.
Missing, malformed, duplicate, mismatched, untrusted, stale, or expired base, gate, rollback,
or reviewer evidence quarantines for reconciliation; such evidence cannot be used to manufacture
a hard failure. Duplicate or conflicting trusted results for the same gate and missing reviewer
evidence also quarantine. After reconciliation, an operator exception or trusted reviewer disagreement
escalates. Only then can independent quorum allow; insufficient independent approvals deny.

This module is side-effect-free and accepts only config and evidence assembled by an
independently trusted controller. It does not itself validate signatures, retrieve evidence,
perform compare-and-swap, merge, or deploy. Those controller responsibilities must ensure that
candidate workspaces cannot author policy inputs or forge trusted attestations. Production
deployment and irreversible external effects remain outside autonomous source promotion until
AVO-008.
