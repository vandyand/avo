# Implementation status against Draft 3

Status date: 2026-08-27. This is a development-complete v1 reference implementation, not a production or hostile-code security approval. Current priority, sequencing, and milestone status are governed by the [authoritative roadmap](roadmap.md); this document is an evidence snapshot.

## Roadmap coverage

| Phase | Status | Evidence |
|---|---|---|
| 0 — contracts | Complete | Strict versioned Pydantic records, 49 checked-in schemas, RFC 8785 hashing, closed transition tables, dependency/threat records, CLI diagnostics, Linux/Windows CI. |
| 1 — local vertical slice | Complete | SQLite/Alembic ledger, outbox, leases, budgets, filesystem CAS, deny-first policy, recorded harness, API/CLI lifecycle, crash recovery. |
| 2 — evaluator integrity | Complete for the declared trusted-team boundary | Digest-pinned, tier-separated Docker images; reproducible native/WSL manifests; hardened runtime; hidden-read, host-write, egress, malformed-report, archive, path, Unicode, and collision tests. |
| 3 — agentic variation | Complete for the bounded reference defect | Native structured harness, HTTPS model gateway, capability tokens, tool broker, private attempts, frozen candidate, single lineage, admission CAS, provenance, and deterministic supervisor. |
| Bounded structured inference | Implemented, experimental; live canary and offline evidence gate passed | Generic strict-JSON input/output boundary, exact raw wire validation, source/wire schema digests, OpenRouter routing defaults, invocation provenance, and advisory patch-review contracts are present. The first one-call/no-retry Luna review passed its preregistered schema, semantic, provenance, and quality gates. A frozen ten-case offline corpus now covers four substantive categories plus malformed, refusal, truncation, omitted-field, fabricated-evidence, and insufficient-evidence boundaries with deterministic scoring and content-addressed reports. Repeated live model evidence remains outstanding. |
| 4 — production hardening | Selectively implemented | Authenticated mutation API, strong revision ETags, two-person role-gated review, retention tombstones, RO-Crate and SLSA exports are present. Production adapters and isolation remain gated below. |
| 5 — alternatives | Experimental contract implementations | Hybrid archive and population strategies exist behind the equal-budget/ADR gate, plus signed plugin compatibility checks. They are not the v1 default and make no superiority claim. |
| Coding-agent integration | First full recursive admission and replay-proven terminal hardening complete | Generic async runtime lifecycle, recorded contract adapter, SDK 0.147.0 plus signed/absolute CLI 0.149.1, exact ChatGPT Pro identity, strict schema and permission digests, isolated home/tmp, live boundary canaries, VCS/config-free workspaces, normalized evidence, cancellation, reconciliation, economics, and provenance are implemented. The frozen comparison admitted 8/8 Codex and 6/8 native candidates. The first Luna AVO-on-AVO attempt was correctly rejected at 277,350/200,000 input tokens; deterministic replay of all 578 retained events proves the corrected terminal path with no provider contact or reconciliation. A second one-turn Luna campaign used 197,800/350,000 input tokens, passed Ruff, strict Pyright, 176 tests, and the frozen private evaluator, reconstructed exactly, verified provenance, and admitted the two-file candidate as the run champion. The real workspace remains unchanged pending explicit human review. |

## Mandatory acceptance evidence

| Packet criterion | Automated evidence |
|---|---|
| Fresh Linux and Windows/WSL reference scenario | `tests/e2e/test_reference_scenario.py`, CI matrix, and `docs/release-verification.md` |
| Crash after external completion without duplicate effects | `tests/recovery/test_scheduler.py` |
| Mutation idempotency and stale-write rejection | `tests/integration/test_api.py`, `tests/integration/test_reviews.py`, `tests/integration/test_persistence.py` |
| Cancellation fences admission | `tests/integration/test_admission.py` |
| Hidden evaluator and host boundary | `tests/integration/test_docker_evaluator.py`, Dockerfile-specific build contexts |
| Workspace and archive escape resistance | `tests/security/test_workspace_ingestion.py`, `tests/security/test_tool_broker.py` |
| Malformed/oversized report quarantine | `tests/security/test_evaluator_reports.py` |
| Reservation-based budget enforcement | `tests/unit/test_budget_service.py` |
| Reconstructable admitted candidate | `tests/integration/test_provenance.py`, full end-to-end scenario |
| Workload/platform overhead decomposition | `tests/performance/test_platform_overhead.py`, `avoctl platform benchmark` |
| Coding-agent crash ambiguity and stale-worker fencing | `tests/recovery/test_runtime_reconciliation.py`, live exact-PID failure probe |
| Atomic post-result budget exhaustion and crash recovery | `tests/integration/test_coding_agent_campaign.py`, `tests/integration/test_provenance.py`, `scripts/replay_recursive_terminal_budget.py`, and the [retained replay result](avo-terminal-budget-replay-v1-result.md) |
| VCS-free workspaces and external Git metadata | `tests/security/test_vcs_free_diff.py`, `tests/security/test_tool_broker.py` |
| OpenAI-compatible/OpenRouter strict JSON and Codex deny-first profile | `tests/unit/test_coding_agent_runtime.py`, `tests/unit/test_openrouter_gateway.py`, live result in `docs/openrouter-interface.md` |
| Offline advisory-review boundary and rubric evaluation | `tests/unit/test_advisory_evaluation.py`, `tests/unit/test_advisory_evaluation_cli.py`, `pilots/structured-inference-v2/`, and the [v2 result](structured-inference-evaluation-v2-result.md) |
| Control-plane-only evaluator credential | `tests/security/test_evaluator_socket.py` |

The full suite enforces 85% branch-aware coverage, strict Pyright, Ruff, schema regeneration parity, tier-image execution, and exact frozen dependencies. The detailed live evidence is recorded in `docs/codex-live-gate.md`.

## Deliberately gated production work

The packet says Phase 4 adapters are delivered only when their promotion criteria are met. A single-host greenfield reference workload does not justify PostgreSQL, S3/MinIO, OPA, Temporal/DBOS, OpenTelemetry infrastructure, or a second worker. Standard Docker is also explicitly not represented as hostile-code containment. Those additions remain blocked until the corresponding load, multi-host, independent-policy, observability, or security-review trigger occurs.

Accordingly, backup/restore drills, PostgreSQL/S3 transaction parity, centralized signed Rego distribution, and gVisor/Kata/VM-worker approval are release blockers for any future production claim—not missing prerequisites for this declared local trusted-team v1 boundary. The sanitized recursive capstone is complete; autonomous source promotion remains experimental pending AVO-004 in the [authoritative roadmap](roadmap.md).
