# AVO-Correlate

AVO-Correlate is an evaluator-grounded system for sustained autonomous software improvement. The implementation follows [Draft 3](docs/avo-correlate-implementation-packet-v3.md).

See the [authoritative roadmap](docs/roadmap.md) for current priority and sequencing, and
[implementation status](docs/implementation-status.md) for phase coverage, acceptance-test
evidence, and the explicit production boundary.

## Development

~~~text
uv sync --all-groups
uv run avoctl doctor
uv run pytest --cov=avo_correlate --cov-report=term
uv run ruff check .
uv run pyright
~~~

Install the optional, exact-pinned Codex Python SDK with `uv sync --extra codex`. AVO currently pins the latest stable Python SDK, 0.147.0, as its app-server protocol client, while the configured execution binary must be an absolute-path, exact-checked `codex-cli 0.149.1`. The portable native path can target an OpenAI Chat Completions compatible server using strict `json_schema` responses; local servers may use loopback HTTP, while remote endpoints must use HTTPS. The generic typed strict-inference boundary and advisory-only semantics are documented in the [structured inference guide](docs/structured-inference.md); OpenRouter routing defaults and the existing native live probe are documented in the [inference interface guide](docs/openrouter-interface.md). The first one-call Luna [generic advisory canary](docs/structured-inference-canary-v1-result.md) and the ten-case [offline evaluation gate](docs/structured-inference-evaluation-v2-result.md) passed their preregistered boundaries.

Generated code and user workspaces are untrusted. The current package does not claim hostile-code isolation.

## Local operator flow

~~~text
uv sync --all-groups --frozen
uv run avoctl doctor
uv run avoctl experiment validate path/to/experiment.json
uv run avoctl experiment create path/to/experiment.json --data-dir .avo
uv run avoctl run start <experiment-id> --data-dir .avo
uv run avoctl run status <run-id> --data-dir .avo
uv run avoctl run events <run-id> --after 0 --data-dir .avo
uv run avoctl harness list
uv run avoctl session runtime <session-id> --data-dir .avo
AVO_API_TOKEN=<secret> uv run avoctl api serve --data-dir .avo
~~~

Mutating API calls require `Idempotency-Key` and `X-Actor-ID`. Reusing the same actor/endpoint/key with a different canonical request is rejected. Run responses expose state, revision, champion, hard budget, usage, reservations, blockers, and safe next actions.

Run reads and mutations return a strong revision `ETag`; run mutations additionally require the current value in `If-Match`. This makes stale operator actions fail visibly instead of silently overwriting concurrent progress. `uv run avoctl policy test` runs the reference bundle's deterministic allow/deny corpus.

The canonical Windows topology is a Linux repository inside WSL 2. `scripts/avoctl.ps1` forwards an argument array through `wsl.exe` and prefers the synchronized project-local executable, with `uv run` as its bootstrap fallback; native Windows is limited to portability checks.

The live Codex adapter is fail-closed and experimental. It requires a trusted signed plugin manifest, SDK 0.147.0, an explicitly configured CLI 0.149.1 executable, isolated `CODEX_HOME`, a private runtime `TMPDIR`, Linux/WSL enforcement, deny-all approvals, a VCS- and agent-config-free candidate workspace, and successful filesystem/network/socket/authentication canaries. Preflight recomputes both strict completion-schema and permission-contract digests. Authentication is ChatGPT-subscription-only: it must identify `vandyand@gmail.com` with plan `pro`; API-key profiles and credential injection are rejected. Provider threads are journaled before mutating turns; ambiguous transport state forces reconciliation. A durable result that exhausts its budget instead follows an atomic terminal path, including lease-crash recovery and terminal/open-reconciliation provenance enforcement. The first capstone's 578 retained events passed that corrected lifecycle in a fresh [no-provider replay](docs/avo-terminal-budget-replay-v1-result.md). A second bounded Luna campaign then completed the first full [AVO-on-AVO admission](docs/avo-improves-avo-capstone-v2-result.md): public and private gates passed, the patch reconstructed exactly, provenance verified, and the candidate became the run champion. The patch remains unapplied to the real workspace pending human review; production approval also remains deferred. See the [v2 integration plan](docs/avo-coding-agent-integration-plan-v2.md), [recursive milestone](docs/avo-improves-avo-milestone.md), and [SDK-first ADR](docs/adr/0006-sdk-first-codex-control.md).

Evaluator sandboxes appear in Docker Desktop as short-lived `avo-<digest>` containers and use `docker run --rm`; bursts during tests or evaluation are expected. Container labels identify the AVO execution and sandbox role. The first three-task [Codex calibration pilot](docs/codex-pilot-v1.md) admitted 3/3 candidates. The frozen eight-task, one-repetition [comparison](docs/comparison-v2-results.md) admitted 8/8 Codex and 6/8 native/OpenRouter candidates; it guides architecture but is not a statistical superiority claim.

## Evaluator images

~~~text
docker build --provenance=false --build-arg SOURCE_DATE_EPOCH=0 --file evaluators/reference/Dockerfile.development --tag avo-reference-development:1.0.0 .
docker build --provenance=false --build-arg SOURCE_DATE_EPOCH=0 --file evaluators/reference/Dockerfile.admission --tag avo-reference-admission:1.0.0 .
uv run pytest tests/integration/test_docker_evaluator.py
~~~

Development and admission fixtures use separate Dockerfile-specific build contexts and image layers. The runtime adds a read-only root filesystem, no network, no Linux capabilities, `no-new-privileges`, PID/CPU/memory limits, read-only workspace mount, and bounded writable `/output` mount.
