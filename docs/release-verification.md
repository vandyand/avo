# Release verification record

Verification date: 2026-08-25. This is a historical development-gate snapshot, not the current roadmap or a production security approval. See the [authoritative roadmap](roadmap.md) for current status and sequencing.

## Coding-agent integration gate

- Host: native Windows portability topology with live Codex and Unix-socket enforcement restricted to Linux/WSL.
- Dependencies: exact-pinned Python protocol SDK `openai-codex==0.147.0` and explicitly provisioned absolute-path `codex-cli 0.149.1`. AVO verifies both versions and the signed CLI digest and never discovers the execution runtime from ambient `PATH`.
- Authentication: fail-closed ChatGPT subscription only. Preflight rejects API credential profiles and verifies the app-server account response is exactly `vandyand@gmail.com`, plan `pro`, type `chatgpt`. The Codex child receives no API key or access-token injection from AVO.
- Isolation: dedicated `CODEX_HOME`, private 0700 `TMPDIR`, VCS- and agent-config-free workspaces under `/var/lib/avo/workspaces`, external Git metadata, deny-all approvals, disabled ambient Codex capabilities, and live filesystem/network/socket canaries.
- Contracts: 45 regenerated, checked-in JSON Schemas, including runtime profile/capability/session/event/completion, invocation economics, reconciliation, and operator projection records.
- Native result: 149 tests passed and 2 expected platform cases skipped at 85.13% branch-aware coverage; Ruff and strict Pyright are clean.
- WSL result: 151 tests passed with no skips; Ruff and strict Pyright are clean. Native and WSL suites also pass concurrently against the shared Docker daemon after unique per-attempt container names removed a deterministic-name race.
- Live result: full doctor, read-only structured completion, controlled mutation, independent public/private evaluation, interruption, and exact-PID provider-process failure all passed. Failed transports detach and force explicit reconciliation. See `docs/codex-live-gate.md` for identifiers and digests.
- Promotion status: bounded development live gate passed. No production or superiority claim is made; the preregistered comparative benchmark remains outstanding. OpenRouter is deferred.
- Calibration: the first three-task Codex-only pilot admitted 3/3 candidates in one repetition each. Full methodology, usage, raw-evidence caveats, and normalization corrections are in `docs/codex-pilot-v1.md`.

## Native Windows portability gate

- Host workspace: `C:\Users\vandy\avo` (portability checks only, not canonical evaluator topology)
- Python: 3.12.10
- uv: 0.11.14, build `3fdfdc7d4`
- Docker client/server: 28.5.1 / 28.5.1 via Docker Desktop
- Git: 2.54.0.windows.1
- ripgrep: 15.2.0
- Evaluator manifests: development `sha256:586dcc790c714be468b38874eeb8e48fca53b9b85b3d3e30f3f70ee526d401b2`; admission `sha256:972c6afef64519a1f36513d389f62a0d86bb0c7ca10eb53c5eba3103260137c3`
- Platform benchmark: 1,077.286 ms wall clock, 0.040226 ms reported workload, 1,077.245774 ms platform overhead (single warm-host sample; diagnostic, not a service-level objective)

## Windows 11 / WSL 2 canonical parity gate

- Distribution: Ubuntu 24.04 under WSL version 2
- Canonical repository: `/home/kingjames/avo` on the WSL ext4 filesystem; evaluator workloads do not run from `/mnt/c`
- Python: 3.12.3
- uv: 0.11.14
- Docker client: 29.1.3, linux/amd64
- Docker server: 28.5.1, Docker Desktop 4.49.0
- OCI base: linux/amd64 manifest `sha256:97983fa8cc88343512862c62307159a82261c3528dc025f79e5a3f7af43e50b4`
- Tier images: file modes and timestamps normalized in a staging layer, then built with `SOURCE_DATE_EPOCH=0` and BuildKit provenance disabled
- Cross-builder parity: clean native and WSL builds produced the evaluator manifests listed above
- Platform benchmark: 804.394 ms wall clock, 0.029736 ms reported workload, 804.364264 ms platform overhead (single warm-host sample; diagnostic, not a service-level objective)
- PowerShell wrapper: structured argument forwarding successfully runs project-local WSL commands without requiring a global WSL `uv`
