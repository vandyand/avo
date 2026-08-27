# AVO-Correlate
## Cross-Platform Open-Ended Software Development and Research System

**Document status:** Draft 2 implementation packet  
**Audience:** Junior developer, technical lead, security reviewer, platform engineer  
**Supported host operating systems:** Windows 11+ and Linux x86_64  
**Explicitly unsupported host operating system:** macOS  
**Primary implementation language:** Python 3.12+  
**Primary local execution model:** native Python control plane plus OCI/Linux containers through a runtime adapter  
**Primary Windows runtime:** Docker Desktop using the WSL 2 backend and Linux containers  
**Primary Linux runtime:** Docker Engine with rootless mode where practical  
**Scope:** open-ended software engineering, scientific/computational research, reproducible experiments, algorithm discovery, debugging, optimization, documentation, data-analysis pipelines, and controlled web/application research.

---

# 1. Revision summary

This draft intentionally removes the prior trading- and quant-finance-specific framing. AVO-Correlate is a **general-purpose software development and research platform**: it evolves versioned workspaces against user-supplied evaluators, records complete provenance, and supports bounded long-horizon work.

The cross-platform requirement is treated as a first-class architecture constraint:

- Every control-plane and developer command must work from both Windows and Linux.
- Business/domain code must not depend on POSIX shell semantics, `/bin/bash`, Unix-only paths, `fork`, Linux signals, or a Linux-only executable.
- Linux containers are the canonical reproducible sandbox format on both hosts. On Windows, this means Docker Desktop’s WSL 2 backend and **Linux container mode**, not native Windows containers. Docker documents that its WSL 2 backend provides a Linux kernel and lets developers use Linux workspaces rather than maintain parallel Windows/Linux build scripts. [web:68]
- “Equal performance” is defined in measurable terms: equivalent algorithms, configuration, budgets, container images, evaluator inputs, and acceptance criteria, with platform-specific overhead recorded separately. Absolute wall-clock equality between bare-metal Linux and a Windows WSL 2 virtualization stack cannot be guaranteed, so performance comparison must distinguish **workload performance** from **host/runtime overhead**.

The design remains modular: harnesses, model gateways, evaluators, sandboxes, workflow engines, storage backends, policy engines, selectors, telemetry exporters, and user interfaces are replaceable through explicit contracts and contract tests.

---

# 2. Executive specification

AVO-Correlate is an autonomous, evaluator-grounded development and research system. It does not assume a domain such as finance, web development, GPU kernels, scientific computing, or data science. Instead, a project defines:

1. A source workspace or research workspace.
2. A task charter and scope policy.
3. One or more evaluator packages.
4. Objective functions, hard constraints, budgets, and review gates.
5. A selected agentic harness and model configuration.
6. A reproducible execution environment.

The system repeatedly creates immutable candidate workspace revisions, evaluates them in isolated environments, admits useful and/or novel candidates into a population, and uses a supervisor to change search strategy when progress stalls.

```text
Project specification
  -> Reproducible workspace materialization
  -> Candidate/parent selection
  -> Context and evidence assembly
  -> Interchangeable harness proposes a patch or research artifact
  -> Isolated evaluator(s) run
  -> Results are validated, normalized, and policy-checked
  -> Candidate is admitted, rejected, quarantined, or routed to review
  -> Supervisor issues a constrained next-step directive
  -> Full provenance is persisted
```

## 2.1 What the platform can support

| Project type | Candidate artifact | Typical evaluators | Example objective |
|---|---|---|---|
| Application feature work | Source diff + tests | Unit/integration/E2E tests, API contract tests | Pass all tests; reduce defects or latency |
| Bug fixing | Source diff + regression test | Reproducer test, static analysis, full suite | Fix issue with no regressions |
| Refactoring | Source diff + architecture report | Tests, type check, lint, dependency analysis | Preserve behavior; reduce complexity |
| Algorithm research | Program/code + experiment report | Correctness suite, benchmark, property tests | Improve throughput or solution quality |
| Scientific/computational research | Notebook/script + data/report artifacts | Reproducible pipeline, statistical checks, simulations | Improve fit/accuracy while meeting validity gates |
| Data engineering | Pipeline diff + schema artifacts | Data quality, schema, freshness, deterministic replay | Improve quality/cost/reliability |
| Documentation research | Documentation diff + citations | Link checks, build checks, source validation | Correctness, coverage, readability |
| Web/application research | Structured findings + reproducible capture | Playwright tests, parser checks, evidence validation | Complete research tasks within approved source policy |
| Infrastructure-as-code | IaC diff + plan/test report | Lint, policy, plan, ephemeral environment test | Compliant, repeatable deployment changes |

## 2.2 Explicit non-goals for v1

- No autonomous production deployment or privileged infrastructure mutation.
- No production database migration execution by an agent.
- No unrestricted internet browser, shell, cloud CLI, or credential-bearing tool by default.
- No promise that LLM output is correct without evaluator evidence.
- No macOS host support or macOS binary release target.
- No multi-tenant hostile-code isolation guarantee in the initial trusted-team deployment.

---

# 3. Cross-platform compatibility contract

## 3.1 Supported compatibility matrix

| Capability | Windows 11+ | Linux x86_64 | Required behavior |
|---|---|---|---|
| Control-plane API and workers | Native Python or containerized | Native Python or containerized | Same API, schemas, workflows, and results |
| CLI | PowerShell and Windows Terminal | Bash, Zsh, Fish-compatible command invocation | Same command verbs and exit-code meaning |
| Local container runtime | Docker Desktop WSL 2 backend, Linux containers | Docker Engine; rootless recommended where feasible | Same OCI images and Compose configuration |
| Optional container alternative | Podman Desktop/Podman machine through WSL 2 | Podman | Adapter compatibility test required |
| Test environment | Native unit tests and containerized integration tests | Native unit tests and containerized integration tests | Same test suite and fixtures |
| Reproducible evaluator | Linux OCI image under WSL 2 | Same Linux OCI image | Same image digest, commands, inputs |
| Native research tool | Windows build/profile | Linux build/profile | Same port contract; OS capability declared |
| CI | Windows runner | Linux runner | Required matrix coverage |

Docker’s WSL 2 backend uses a Linux kernel and supports Linux workspaces; Docker also notes that users must select Linux container mode if Docker is in Windows-container mode. [web:68] Podman Desktop is a valid alternative, but Windows usage similarly requires a WSL 2 or Hyper-V-backed machine, so it does not eliminate virtualization from the Windows path. [web:97]

## 3.2 Definition of “equally performant”

The architecture must ensure that the **same work** receives the same operational budgets and equivalent execution conditions. Do not use a vague claim that two hosts will have identical wall-clock results.

For every benchmark/evaluator, report:

```text
workload_time_ms             Time inside the evaluator workload
sandbox_setup_time_ms        Image/workspace/materialization overhead
queue_time_ms                Scheduling delay
host_runtime                 windows-wsl2-docker | linux-docker | linux-podman
cpu_model                    Host CPU identifier
logical_cpu_limit            Container or native process limit
memory_limit_mb              Container or native process limit
container_image_digest       Exact OCI image
input_artifact_digests       Immutable inputs
seed                         Random seed
```

**Acceptance rule:** a candidate’s score must compare only runs from the same benchmark profile and hardware class, or apply an explicitly versioned normalization policy. Cross-host benchmark data may be displayed for diagnostics but must not silently enter the same Pareto comparison unless the evaluator declares it valid.

## 3.3 Cross-platform coding rules

1. Use `pathlib.Path`, never hand-built strings containing `/` or `\\`.
2. Use `subprocess.run([...], shell=False)`, never shell-concatenated command strings.
3. Use Python/Node task runners rather than Bash-only scripts.
4. Provide PowerShell (`.ps1`) and POSIX shell (`.sh`) convenience wrappers only; both call the same Python `task` CLI.
5. Use environment variables and typed config, not OS-specific files under home directories.
6. Do not use `os.fork`, Unix signals as primary control flow, `fcntl`, Unix domain sockets as mandatory integration protocols, or symbolic links without fallback behavior.
7. Treat path case sensitivity as a test dimension: Windows default filesystems are commonly case-insensitive; Linux is commonly case-sensitive.
8. Do not depend on executable-bit semantics for project scripts; invoke interpreters explicitly.
9. Normalize text files to UTF-8 and LF in Git using `.gitattributes`; test line-ending robustness.
10. Pin all external executables by container image digest or versioned distribution.

## 3.4 File-system and WSL performance policy

On Windows, repositories used for Docker/WSL workloads should live in the WSL distribution filesystem (for example `~/src/avo-correlate`), not under `/mnt/c/...`, unless an explicit benchmark proves the alternative sufficient. Docker’s WSL guidance emphasizes working in Linux workspaces to avoid parallel scripts and obtain efficient integration. [web:68]

This is a **developer-location policy**, not an API requirement: the source remains accessible from Windows editors through WSL integration, while build/test/container operations run against the Linux filesystem.

---

# 4. Architecture

## 4.1 Logical layers

```text
+------------------------- Interfaces ------------------------------+
| FastAPI/OpenAPI | Typer CLI | optional web UI | webhooks         |
+----------------------------+-------------------------------------+
                             |
+------------------------- Application -----------------------------+
| ExperimentService | RunService | ReviewService | PluginService   |
+----------------------------+-------------------------------------+
                             |
+--------------------------- Domain -------------------------------+
| EvolutionEngine | Population | Selector | Admission | Supervisor |
| ContextPlanner | BudgetGuard | ScoreNormalizer | State Machine   |
+----------------------------+-------------------------------------+
                             |
+---------------------- Stable Port Contracts ----------------------+
| AgentHarness | Evaluator | Sandbox | Workspace | ArtifactStore  |
| ModelGateway | PolicyEngine | WorkflowRuntime | EventPublisher   |
+----------------------------+-------------------------------------+
                             |
+--------------------------- Adapters ------------------------------+
| PydanticAI | OpenHands | LangGraph | Docker | Podman | Native    |
| Temporal | Prefect | PostgreSQL | MinIO | OPA | OTel | Git       |
+-------------------------------------------------------------------+
```

## 4.2 Architectural invariant

The core loop is not a framework-specific “agent graph.” It is a deterministic domain lifecycle with external adapters:

\[
P_t \xrightarrow{select} A_t \xrightarrow{context} C_t \xrightarrow{harness} x' \xrightarrow{evaluate} m(x') \xrightarrow{policy/admission} P_{t+1}
\]

- \(P_t\): accepted population.
- \(A_t\): selected ancestry/reference candidates.
- \(C_t\): evidence-bounded context packet.
- \(x'\): immutable candidate patch/workspace/artifact set.
- \(m(x')\): evaluator-validated metric and constraint vector.

An LLM may propose, explain, inspect, or recommend. It may not directly admit candidates, override policy, alter budgets, modify audit logs, or grant itself tools.

---

# 5. Technology decisions and alternatives

## 5.1 Core language and development tooling

**Decision:** Python 3.12+ with `uv`, `pyproject.toml`, Ruff, Pyright, pytest, and a Python-native task CLI.

| Option | Advantages | Drawbacks | Decision |
|---|---|---|---|
| **Python + uv** | Broadest ecosystem for agents, scientific/research code, code analysis, web APIs, containers, and orchestration; `uv` supports Windows and Linux installation and Python management. | Dynamic language demands strict typing/testing. | **Selected.** Best common denominator for software and research workflows. [web:82][web:83] |
| Python + Poetry | Mature package workflow and familiar lockfiles. | Often slower/more cumbersome than uv for large iterative environments. | Supported alternative if organizational standard requires it. |
| TypeScript + pnpm | Excellent web tooling and type system; good for UI-heavy products. | Research/scientific/evaluator ecosystem would often still require Python. | Use for optional UI, not primary core. |
| Go | Efficient binaries and concurrency. | Higher cost for rapid research/evaluator prototyping. | Future high-throughput worker adapter only. |

**Cross-platform rule:** no Makefile is the sole task interface. Provide `python -m avo_correlate_dev tasks ...` as canonical; `make` and PowerShell scripts are optional delegates.

## 5.2 API and CLI

**Decision:** FastAPI + Pydantic v2 for API; Typer for CLI; generated OpenAPI is the published control-plane contract.

| Option | Advantages | Drawbacks | Decision |
|---|---|---|---|
| **FastAPI + Pydantic + Typer** | Shared typed models, OpenAPI, easy async integration, clear CLI for Windows/Linux terminals. | Must separate API schemas from persistence models. | **Selected.** |
| Django/DRF | Strong admin/ORM ecosystem. | More monolithic and less direct for adapter-heavy control plane. | Use only if business admin CRUD dominates. |
| Litestar | Typed, fast, modular. | Smaller ecosystem. | Valid API adapter alternative. |
| gRPC only | Efficient worker RPC. | Poor human/debug usability and no native OpenAPI. | Optional internal plugin-host transport later. |

## 5.3 Agent harness

**Decision:** Native `AgentHarness` port; ship `native_pydanticai`, `openhands_sdk`, and `dry_run` adapters. Maintain optional LangGraph integration.

| Option | Advantages | Drawbacks | Decision |
|---|---|---|---|
| **Native contract + PydanticAI** | Typed tools/output; model-provider flexibility; small inspectable implementation; avoids binding domain to an agent framework. PydanticAI describes itself as typed, extensible, and model-agnostic. | Build and maintain the agent loop/tool behavior ourselves. | **Default adapter.** [web:41][web:37] |
| OpenHands Software Agent SDK | Specialized composable SDK for agents that work with code; strong fit for software-engineering workflows. | Additional runtime semantics and versioning; must remain an adapter, not source of truth. | **Optional first-class adapter.** [web:23][web:32] |
| LangGraph + supervisor | Explicit state graphs and hierarchical supervisor patterns. | Framework-specific state may contaminate domain logic; can encourage LLM-driven control flow where deterministic lifecycle is safer. | Optional adapter for experiments. [web:27] |
| SWE-agent | Proven issue-resolution orientation. | More opinionated around SWE task shape. | Optional benchmark or issue-fixing adapter. |
| AutoGen/CrewAI | Quick multi-agent prototyping. | Less ideal for strict reproducibility, durable candidate lifecycle, and auditability. | Research-only adapters, not baseline. |

## 5.4 Workflow durability

**Decision:** Temporal Python SDK in production; local in-process runtime in unit tests; Prefect adapter considered for pipeline-heavy projects.

| Option | Advantages | Drawbacks | Decision |
|---|---|---|---|
| **Temporal** | Durable workflows, activity retries, timeout controls, worker recovery, long-lived execution model. | Operational overhead and deterministic workflow rules. | **Selected** for long-horizon runs. [web:38][web:39][web:73] |
| Prefect | Excellent Python data/research flow ergonomics, state tracking and caching. | Less tailored to signal-driven durable agent control. | Strong optional runtime for data-pipeline-oriented deployments. [web:40] |
| Dagster | Strong data asset lineage. | Asset model is not always a natural fit for interactive iteration. | Alternative for data-science-heavy installations. |
| Celery + Redis | Familiar and lightweight. | Requires custom correctness for workflow state, recovery, and idempotency. | Not acceptable for core durable lifecycle. |

## 5.5 Sandbox runtime

**Decision:** `Sandbox` port with Docker as the canonical Linux-OCI adapter; Windows runs the same Linux containers through Docker Desktop WSL 2. Provide Podman compatibility adapter. Add native process sandbox only for explicitly declared host-native evaluators.

| Option | Advantages | Drawbacks | Decision |
|---|---|---|---|
| **Docker Engine / Docker Desktop WSL 2** | Same OCI/Linux images on Linux and Windows; broad ecosystem; Compose; WSL 2 backend uses Linux kernel and supports GPU options. | Windows has virtualization/setup overhead; Docker Desktop licensing/operations may matter for some organizations. | **Selected default.** [web:68] |
| Podman / Podman Desktop | Rootless-first design, daemonless approach, Docker-compatible workflows. | On Windows still needs WSL 2/Hyper-V VM; minor compatibility differences. | **Supported alternative adapter.** [web:97][web:99] |
| gVisor | Stronger container isolation. | Compatibility/performance overhead. | Production hardened runtime option on Linux; Windows developers test via WSL 2 stack. |
| Kata/Firecracker | Strong isolation. | Substantially more operational engineering and less uniform desktop path. | Future high-assurance worker implementation. |
| Native subprocess only | Best access to Windows/Linux-specific research tools. | Weak isolation/reproducibility; OS variation. | Permitted only in an explicit `native_process` sandbox profile with review gate. |

**Critical compatibility decision:** canonical evaluators must target Linux OCI images. This produces the closest possible cross-host equivalence because Windows uses the same Linux container artifact through WSL 2 rather than a separate Windows-specific evaluator.

## 5.6 Testing and compatibility infrastructure

**Decision:** pytest plus Testcontainers for integration tests; GitHub Actions (or equivalent) Windows/Linux matrix; container integration suite is mandatory on both hosts.

| Option | Advantages | Drawbacks | Decision |
|---|---|---|---|
| **pytest + Testcontainers** | Temporary, on-demand dependency containers; Docker environments on Linux and Docker Desktop Windows are actively supported/detected. | Requires a Docker-compatible runtime in CI/dev. | **Selected.** [web:69][web:74][web:76] |
| Docker Compose fixtures only | Familiar, visible services. | Less test isolation and parallelism. | Use for end-to-end environment only. |
| pytest mocks only | Fast, deterministic. | Cannot catch real service/runtime incompatibilities. | Required for unit tests but insufficient alone. |
| LocalStack-style emulation | Useful for cloud-compatible services. | Adds abstractions and possible divergence. | Optional when cloud adapters are introduced. |

## 5.7 Research/browser automation

**Decision:** a `ResearchTool` port; web automation uses Playwright only in an explicit network-enabled profile with allowlists and evidence capture.

| Option | Advantages | Drawbacks | Decision |
|---|---|---|---|
| **Playwright Python** | One API for Chromium, Firefox, and WebKit; supports Windows and Linux; robust browser automation. | Browser execution is security/cost intensive; live web content is untrusted. | **Selected optional adapter.** [web:98][web:100] |
| Selenium | Mature and widely understood. | More driver/grid management and less integrated modern browser tooling. | Valid alternative. |
| Requests/httpx + parsers | Lightweight and deterministic for APIs/static pages. | Cannot handle dynamic app workflows. | Default for approved HTTP research APIs where browser is unnecessary. |
| Browser-use style agent frameworks | Fast agentic browsing prototypes. | Higher prompt-injection risk and weaker deterministic audit control. | Not baseline; wrap only behind ResearchTool contract. |

## 5.8 Database, artifact storage, policy, and observability

Selections remain:

- PostgreSQL + SQLAlchemy 2.x + Alembic for durable state and append-only event ledger.
- S3-compatible artifact storage; MinIO locally.
- Open Policy Agent for policy-as-code. OPA is an open-source, general-purpose policy engine designed to decouple policy enforcement from application code. [web:56][web:59]
- OpenTelemetry + Prometheus/Grafana/Loki/Tempo for correlated observability. OpenTelemetry supports Python SDK initialization and automatic/manual instrumentation. [web:52][web:53]

All four are host-independent services, normally run as Linux containers on both supported host OS families.

---

# 6. Repository layout

```text
avo-correlate/
├── README.md
├── ARCHITECTURE.md
├── CROSS_PLATFORM.md
├── SECURITY.md
├── CONTRIBUTING.md
├── pyproject.toml
├── uv.lock
├── compose.yaml
├── compose.windows.yaml          # only host-specific volume/credential overrides if unavoidable
├── compose.linux.yaml            # only host-specific resource/security overrides if unavoidable
├── .gitattributes
├── .editorconfig
├── .env.example
├── scripts/
│   ├── bootstrap.ps1
│   ├── bootstrap.sh
│   ├── verify-platform.ps1
│   └── verify-platform.sh
├── packages/
│   ├── contracts/
│   ├── domain/
│   ├── application/
│   ├── adapters/
│   ├── api/
│   └── devtools/
├── workers/
├── evaluators/
│   ├── command/
│   ├── pytest/
│   ├── static-analysis/
│   ├── benchmark/
│   ├── research-pipeline/
│   └── browser-research/
├── policies/
├── migrations/
├── tests/
│   ├── unit/
│   ├── contract/
│   ├── integration/
│   ├── e2e/
│   ├── cross_platform/
│   └── chaos/
├── docs/
│   ├── adr/
│   ├── runbooks/
│   ├── evaluator-authoring.md
│   ├── harness-authoring.md
│   ├── research-project-authoring.md
│   └── windows-linux-parity.md
└── infra/
```

## 6.1 Cross-platform repository files

`.gitattributes`:

```gitattributes
* text=auto eol=lf
*.ps1 text eol=crlf
*.bat text eol=crlf
*.png binary
*.jpg binary
*.pdf binary
```

`.editorconfig`:

```editorconfig
root = true

[*]
charset = utf-8
end_of_line = lf
insert_final_newline = true
indent_style = space
indent_size = 4

[*.{yml,yaml,json,md}]
indent_size = 2

[*.ps1]
end_of_line = crlf
```

Do not make a file executable as a required project behavior. Document invocation as `uv run python path/to/script.py` or `uv run avoctl ...`.

---

# 7. Domain model and stable contracts

The domain model remains deliberately generic. There is no `strategy`, `trade`, `market`, `broker`, or domain-specific financial entity.

## 7.1 Universal project model

```python
class ProjectKind(StrEnum):
    SOFTWARE = "software"
    RESEARCH = "research"
    DATA_PIPELINE = "data_pipeline"
    DOCUMENTATION = "documentation"
    INFRASTRUCTURE = "infrastructure"
    CUSTOM = "custom"

class TaskCharter(BaseModel):
    title: str
    project_kind: ProjectKind
    objective: str
    success_criteria: list[str]
    allowed_paths: list[PurePosixPath]
    forbidden_paths: list[PurePosixPath]
    assumptions: list[str]
    out_of_scope: list[str]
    required_artifacts: list[str]
```

Use POSIX-style relative paths **inside workspace manifests** regardless of host. The workspace adapter maps those paths to native host/container paths using `pathlib` and rejects escapes (`..`, absolute paths, drive-qualified paths).

## 7.2 General candidate manifest

```python
class CandidateManifest(BaseModel):
    candidate_id: CandidateId
    experiment_id: ExperimentId
    parent_candidate_ids: list[CandidateId]
    base_workspace_digest: str
    source_tree_digest: str
    patch_artifact_digest: str | None
    research_artifact_digests: list[str]
    harness_id: str
    harness_version: str
    model_ref: str
    context_digest: str
    tool_trace_digest: str | None
    execution_profile_id: str
    execution_image_digest: str | None
    host_runtime_class: str
    config_digest: str
    policy_revision: str
    random_seed: int
    created_at: datetime
```

A candidate may be code-only, research-artifact-only, or both. Examples of research artifacts: experiment plan, executable notebook converted to a script, dataset transformation manifest, benchmark report, literature evidence bundle, simulation result, or design document.

## 7.3 Evaluator model

```python
class EvaluationRecord(BaseModel):
    evaluation_id: EvaluationId
    candidate_id: CandidateId
    evaluator_id: str
    evaluator_version: str
    evaluator_profile_digest: str
    execution_image_digest: str | None
    host_runtime_class: str
    input_artifact_digests: list[str]
    seed: int
    outcome: Literal["passed", "failed", "errored", "timed_out", "policy_blocked"]
    raw_metrics: dict[str, Scalar]
    normalized_scores: dict[str, float]
    constraints: list[ConstraintResult]
    evidence_artifacts: list[ArtifactRef]
    started_at: datetime
    completed_at: datetime | None
```

---

# 8. Harness and tool architecture

## 8.1 Required ports

```python
class AgentHarness(Protocol):
    harness_id: str
    version: str
    async def run(self, request: HarnessRequest) -> HarnessResult: ...

class Evaluator(Protocol):
    evaluator_id: str
    version: str
    async def evaluate(self, request: EvaluationRequest) -> EvaluationRecord: ...

class Sandbox(Protocol):
    sandbox_id: str
    version: str
    async def execute(self, request: SandboxExecutionSpec) -> SandboxExecutionResult: ...

class WorkspaceProvider(Protocol):
    async def materialize(self, ref: WorkspaceRef, destination: Path) -> MaterializedWorkspace: ...

class ResearchTool(Protocol):
    tool_id: str
    version: str
    async def execute(self, request: ResearchToolRequest) -> ResearchToolResult: ...
```

## 8.2 Tool broker

The tool broker is an enforcement point independent of harness technology. It exposes a carefully scoped set of tools:

| Tool | Default state | Cross-platform implementation | Purpose |
|---|---|---|---|
| `read_file` | enabled | Python `pathlib` | Read an allowlisted workspace file |
| `search_workspace` | enabled | Python ripgrep adapter with fallback | Search code/text safely |
| `apply_patch` | enabled | Unified diff parser in Python | Apply validated patch |
| `run_command` | limited | argv list, no shell | Invoke allowlisted commands in sandbox |
| `run_tests` | enabled | Evaluator-defined command profile | Pre-check candidate changes |
| `inspect_git` | enabled | Git CLI adapter | Inspect status/diff/log in workspace |
| `retrieve_evidence` | optional | Artifact/index adapter | Retrieve approved prior results/docs |
| `http_research` | disabled by default | httpx adapter/proxy | Approved API/document requests |
| `browser_research` | disabled by default | Playwright adapter | Approved browser task with capture |
| `request_review` | optional | Application service | Request human gate |

### Tool safety requirements

- `run_command` always receives `list[str]`; no `shell=True`.
- All command tools run within the selected sandbox, not in the API/worker host process.
- Path validation happens before sandbox execution and again inside sandbox workspace boundaries.
- Tool result output is capped, redacted, and stored as an artifact.
- Network is denied by default; a network-enabled research profile must specify allowed domains, methods, rate limits, and artifact capture requirements.
- Tool permissions are evaluated by OPA on every invocation.

## 8.3 Research context and evidence

A research context packet must distinguish assertions from evidence:

```python
class EvidenceItem(BaseModel):
    evidence_id: str
    source_type: Literal["repository", "artifact", "web", "dataset", "human_note"]
    source_locator: str
    captured_at: datetime
    content_digest: str
    excerpt: str
    trust_level: Literal["untrusted", "user_supplied", "verified", "derived"]
    citation_label: str
```

All web or external research content is untrusted. It may be summarized for the harness but cannot issue control instructions, alter policy, access new tools, or become a truth claim without an evaluator/verification step.

---

# 9. Evaluation system

## 9.1 General evaluator types

| Evaluator | Purpose | Runs where | Output |
|---|---|---|---|
| `command` | Run deterministic command and parse result | Linux OCI container by default | JSON metrics/report |
| `pytest` | Execute Python tests | Linux OCI container | Pass/fail, coverage, timings |
| `static_analysis` | Lint/type/security/dependency checks | Container or native profile | Structured findings |
| `benchmark` | Repeat performance experiment | Hardware-classed worker | Distribution metrics |
| `property_test` | Invariant/fuzz tests | Container | Counterexamples/statistics |
| `research_pipeline` | Execute reproducible computational analysis | Container | Data/report/figures/metadata |
| `documentation` | Build/lint/link/citation checks | Container | Coverage/findings |
| `browser_research` | Execute approved, evidence-capturing browser workflow | Dedicated browser sandbox | HAR/screenshots/extracted data/report |
| `human_review` | Expert judgment gate | Application workflow | Signed decision |

## 9.2 Evaluator authoring package

```text
evaluators/my-evaluator/
├── evaluator.yaml
├── Dockerfile
├── entrypoint.py
├── report.schema.json
├── requirements.lock
├── fixtures/
├── tests/
└── README.md
```

Every evaluator emits a schema-validated `report.json` to `/output/report.json`. The system validates that report before any score or admission decision.

Example:

```json
{
  "schema_version": 1,
  "outcome": "passed",
  "metrics": {
    "correctness": 1.0,
    "runtime_seconds_median": 3.22,
    "memory_mb_peak": 412
  },
  "constraints": [
    {"name": "all_tests_pass", "passed": true},
    {"name": "network_disabled", "passed": true}
  ],
  "artifacts": ["sha256:..."]
}
```

## 9.3 Reproducibility rules

An evaluator is reproducible only when it declares:

- evaluator package version and image digest;
- exact base workspace/source digest;
- input dataset/artifact digests;
- command and environment allowlist;
- random seed(s);
- expected hardware class, if performance claims are included;
- network policy;
- report schema version.

No evaluator may silently download mutable dependencies during scoring. Dependency resolution must happen at image build time from pinned lockfiles, or downloads must be a separately approved and recorded acquisition step.

---

# 10. Cross-platform sandbox profiles

## 10.1 Profiles

| Profile | Windows support | Linux support | Security/reproducibility | Intended use |
|---|---|---|---|---|
| `oci_linux_standard` | Docker Desktop WSL 2 | Docker Engine | High reproducibility, normal container isolation | Default code/research evaluation |
| `oci_linux_hardened` | WSL 2 development validation; production ideally Linux worker | Docker + gVisor/Kata | Higher isolation | Untrusted/generated code where supported |
| `native_windows_restricted` | Yes | No | Lower reproducibility; explicit OS profile | Windows-only toolchain research |
| `native_linux_restricted` | No | Yes | Lower reproducibility; explicit OS profile | Linux-only hardware/tool research |
| `browser_oci` | Docker Desktop WSL 2 | Docker Engine | Dedicated network-policy sandbox | Approved browser research |

The default project must use `oci_linux_standard`. Host-native profiles are exceptions and are explicitly non-comparable to canonical Linux-container benchmark profiles.

## 10.2 Hardened OCI settings

```yaml
read_only: true
cap_drop: ["ALL"]
security_opt:
  - no-new-privileges:true
pids_limit: 256
mem_limit: 4g
cpus: 2.0
network_mode: none
user: "10001:10001"
tmpfs:
  - /tmp:rw,noexec,nosuid,size=1g
```

Do not mount Docker socket, user home directories, cloud credentials, SSH configuration, host Git configuration, or arbitrary host project paths.

---

# 11. Evolution, supervisor, and research lifecycle

## 11.1 Population and selection

The population is generic: it may contain code solutions, research plans, execution artifacts, or mixed deliverables. The archive uses a feasible Pareto frontier plus diversity preservation.

| Strategy | Pros | Cons | Selection |
|---|---|---|---|
| **Pareto + novelty tournament** | Preserves quality and diversity across multiple metrics; prevents immediate convergence. | Requires stable novelty descriptors. | **Default.** |
| MAP-Elites | High coverage across behavior descriptors. | Requires meaningful bins/features. | Use for algorithm/design-space research. |
| Epsilon-greedy incumbent | Very simple and debuggable. | Premature convergence risk. | Baseline/debug profile. |
| UCB/bandit selection | Allocates budget adaptively. | Reward definition/nonstationarity complexity. | Later advanced selector. |
| Random selection | Simple control. | Inefficient. | Test/control only. |

## 11.2 Supervisor design

A deterministic supervisor detects:

- no feasible improvement for `N` iterations;
- repeated test failure signatures;
- evaluator flakiness;
- runaway cost per accepted improvement;
- diversity collapse;
- tool-policy denials;
- repeated no-op or oversized patches;
- exhausted research evidence or conflicting evidence.

An optional critic LLM may recommend a strategy, but it cannot directly execute a policy-changing action. Allowed directives:

```text
continue
switch_parent
increase_exploration
focus_exploitation
reduce_patch_scope
add_regression_test
request_human_review
pause
terminate
```

All directives pass through deterministic budget and OPA policy checks.

---

# 12. API, CLI, and developer experience

## 12.1 API endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/v1/experiments` | Create experiment from immutable validated spec |
| `GET` | `/v1/experiments/{id}` | Get spec, state, provenance, budget |
| `POST` | `/v1/experiments/{id}/runs` | Start durable run |
| `POST` | `/v1/runs/{id}/pause` | Request safe pause |
| `POST` | `/v1/runs/{id}/resume` | Resume paused run |
| `POST` | `/v1/runs/{id}/cancel` | Request cancellation |
| `GET` | `/v1/runs/{id}/events` | Immutable event stream |
| `GET` | `/v1/candidates/{id}` | Candidate manifest, lineage, evaluation evidence |
| `POST` | `/v1/reviews/{id}/decision` | Submit human approval/rejection |
| `GET` | `/v1/plugins` | Discover installed adapter capability manifests |
| `GET` | `/healthz` | Liveness |
| `GET` | `/readyz` | Dependency readiness |

All mutating endpoints require an `Idempotency-Key` and authenticated actor. Generate OpenAPI from FastAPI models and snapshot-test it in CI.

## 12.2 Canonical CLI

```text
avoctl bootstrap
avoctl doctor
avoctl platform verify
avoctl infra up
avoctl infra down
avoctl db migrate
avoctl policy test
avoctl experiment validate config/experiments/example.yaml
avoctl experiment create config/experiments/example.yaml
avoctl run start <experiment-id>
avoctl run status <run-id>
avoctl run events <run-id>
avoctl test unit
avoctl test integration
avoctl test cross-platform
```

### Windows PowerShell usage

```powershell
uv run avoctl platform verify
uv run avoctl infra up
uv run avoctl test cross-platform
```

### Linux shell usage

```bash
uv run avoctl platform verify
uv run avoctl infra up
uv run avoctl test cross-platform
```

The verbs, output JSON fields, exit codes, and config behavior must be identical.

---

# 13. CI/CD and platform parity

## 13.1 Mandatory matrix

Run every pull request against:

```yaml
strategy:
  fail-fast: false
  matrix:
    os: [ubuntu-latest, windows-latest]
    python: ["3.12"]
```

GitHub Actions matrix strategy creates runs for each specified configuration combination; equivalent matrix systems are acceptable if they provide the same coverage. [web:103][web:106]

## 13.2 Required Windows/Linux checks

1. Package install from lockfile.
2. Unit tests.
3. Static type/lint checks.
4. CLI `platform verify` assertions.
5. API schema snapshot.
6. Path normalization tests.
7. File case-sensitivity conflict fixture.
8. Unicode filename fixture.
9. Line-ending fixture.
10. Integration tests using PostgreSQL/MinIO/OPA/Temporal containers.
11. OCI evaluator test using same image digest.
12. Worker restart/recovery test.
13. `dry_run` end-to-end candidate lifecycle.

## 13.3 Platform verification command

`avoctl platform verify` must fail fast and print actionable diagnostics:

- operating system and architecture;
- Python version and executable;
- `uv` version;
- container runtime availability/version;
- Linux container mode check on Windows;
- WSL 2 availability/version on Windows;
- repository location warning if under `/mnt/<drive>` in WSL;
- Postgres/MinIO/OPA/Temporal connectivity;
- filesystem case/Unicode/long-path capability;
- optional GPU availability only when an experiment requires it.

---

# 14. Security, reliability, and provenance

## 14.1 Policy enforcement

OPA remains the policy authority for experiment creation, tool invocation, sandbox launch, network access, evaluator execution, artifact export, candidate admission, budget changes, and review bypass attempts. OPA is specifically designed as a decoupled general-purpose policy engine. [web:56]

## 14.2 Reliability requirements

- Database mutations, event-log append, and outbox insert occur in one transaction.
- Artifact objects are SHA-256 content-addressed.
- All external calls have explicit timeout, retry classification, and idempotency key.
- A process/worker crash must recover at the next durable workflow boundary without duplicate admission.
- Candidate records, evaluator reports, policy decisions, and approval records are immutable; corrections supersede rather than overwrite.
- No configuration is mutable within a run: store canonical JSON, digest, plugin versions, images, and policy revision at run creation.

## 14.3 Evidence and citation policy for research

Research projects must preserve source provenance. External evidence artifacts include capture time, digest, source locator, excerpt, source type, and trust level. A generated report must distinguish:

- direct source observation;
- evaluator-verified result;
- derived computation;
- model hypothesis;
- unresolved uncertainty.

No model-generated citation is considered valid unless it maps to a captured evidence artifact or approved source record.

---

# 15. Testing plan

| Layer | Objective | Windows | Linux |
|---|---|---|---|
| Unit | Domain logic, state machine, selection, scoring | Required | Required |
| Contract | Every adapter meets stable semantics | Required | Required |
| Integration | Real dependencies via containers | Required through Docker Desktop WSL 2 | Required through Docker/Podman |
| End-to-end | Full seeded experiment lifecycle | Required | Required |
| Cross-platform | Paths, encodings, line endings, process behavior, CLI parity | Required | Required |
| Sandbox | Network/mount/capability/resource controls | Required canonical OCI profile | Required canonical OCI profile |
| Chaos | Worker kill, duplicate message, delayed artifact service | Required | Required |
| Performance | Workload benchmark plus overhead decomposition | Required; labeled WSL 2 runtime | Required; labeled native container runtime |

Testcontainers provides disposable on-demand containers for integration testing and is designed to detect Docker environments, including Docker Desktop on Windows and Docker on Linux. [web:69][web:74]

---

# 16. Implementation roadmap

## Phase 0: Cross-platform foundation

Deliver:

- Python/uv project, typed contracts, FastAPI/Typer skeleton.
- Windows PowerShell and Linux shell bootstrap wrappers delegating to one Python CLI.
- `.gitattributes`, `.editorconfig`, platform verification command.
- GitHub Actions Windows/Linux matrix.
- Docker Desktop WSL 2 and Linux Docker setup documentation.

Done when: a fresh Windows WSL 2 install and a fresh Linux host can clone, install, execute `avoctl platform verify`, and pass unit tests with the same commands.

## Phase 1: Deterministic general-purpose vertical slice

Deliver:

- PostgreSQL ledger, MinIO artifacts, OPA, local workflow runtime.
- `dry_run` harness.
- Generic `command` evaluator.
- Candidate lifecycle, immutable provenance, state machine, budget checks.

Done when: a fixture software or research workspace creates/evaluates/adopts a candidate and resumes safely after process termination on both platforms.

## Phase 2: Container evaluator parity

Deliver:

- Docker sandbox adapter.
- Canonical Linux OCI evaluator image.
- Testcontainers integration suite.
- Path, line-ending, Unicode, case-sensitivity fixtures.

Done when: same evaluator image digest and inputs succeed on Windows Docker Desktop WSL 2 and Linux Docker, producing schema-equivalent reports.

## Phase 3: Evolution engine and supervisor

Deliver:

- Pareto/novelty archive, selection, score normalization, admission reason codes.
- Deterministic stagnation detector and safe directives.
- Experiment/project templates for software and research.

Done when: fixtures demonstrate quality improvement, novelty retention, constraint failure, and supervisor strategy change.

## Phase 4: Native harness and research tools

Deliver:

- PydanticAI harness, model gateway, tool broker, context planner.
- Static analysis, pytest, benchmark, and research-pipeline evaluator templates.
- Optional HTTP/Playwright research adapters gated by OPA.

Done when: the system can complete a bounded code fix and a reproducible computational research task with full artifacts/evidence.

## Phase 5: Additional harnesses and hardening

Deliver:

- OpenHands adapter and contract suite.
- Podman adapter validation.
- gVisor/Kata option for Linux worker fleet.
- Dashboards, alerting, backup/restore and incident runbooks.

Done when: harness swap requires only an experiment configuration change and contract tests; a recovery drill rebuilds an admitted candidate from provenance.

---

# 17. Junior developer checklist

1. Start with `dry_run`, never a paid or local LLM call.
2. Read `contracts/ports.py` before writing any adapter.
3. Use `pathlib`; do not add Bash-only behavior.
4. Use the canonical Python CLI; do not rely on Make alone.
5. Add contract tests before adding a second implementation of a port.
6. All host interactions go through adapters; no direct Docker/DB/HTTP calls in domain code.
7. Every external call needs timeout, failure class, and idempotency treatment.
8. Every new tool requires OPA policy coverage and a deny-case test.
9. Every new evaluator must emit a versioned JSON report and pass evaluator contract tests.
10. Every feature PR must pass Windows and Linux CI.
11. Do not put secrets, mutable environment dumps, or unredacted model traffic in logs/artifacts.
12. If an implementation is OS-specific, declare it in a capability manifest and add a policy gate; do not pretend it is portable.

---

# 18. Final design principles

1. **Open-ended, not domain-bound:** the system evolves software and research artifacts against project-defined evaluators.
2. **Canonical reproducibility:** Linux OCI workloads provide a shared evaluator substrate for Windows and Linux.
3. **Cross-platform by design:** platform-neutral core; host details confined to adapters and verified continuously in CI.
4. **Evaluator sovereignty:** only evaluated, policy-compliant evidence can admit a candidate.
5. **Interchangeability is contractual:** ports, manifests, schema versions, and contract tests—not informal conventions—make components swappable.
6. **Reliability is durable:** workflow state, idempotency, append-only provenance, and transactional outbox protect long-running work.
7. **Security is mechanical:** sandboxing, tool brokerage, policy-as-code, and approval gates do not rely on model obedience.
8. **Performance is measurable:** compare equivalent workloads and preserve runtime/host overhead metadata rather than claiming impossible wall-clock identity across operating systems.

---

# 19. References

1. NVIDIA Technical Blog, “NVIDIA AVO Reaches 100% on ARC-AGI-3, Demonstrating a Frontier-Level General-Purpose Architecture for Long-Horizon Autonomous Agents.” Provides the high-level harness framing around long-horizon work, memory, and supervision.
2. “AVO: Agentic Variation Operators for Autonomous Evolutionary Search,” arXiv:2603.24517. Defines the agentic variation-operator approach to evolutionary search.
3. OpenEvolve. Open-source evolutionary coding-agent pattern and reference for evaluator-grounded iterative optimization.
4. OpenHands Software Agent SDK documentation. Composable Python/REST APIs for code-working agents.
5. PydanticAI documentation. Typed, extensible, provider-flexible agent framework.
6. Temporal Python SDK documentation. Durable workflows, timeout and retry behavior, Python implementation guidance.
7. Prefect v3 documentation. Alternative tracked Python orchestration with retries and caching.
8. Docker Desktop WSL 2 documentation. Windows WSL 2 backend, Linux container mode, workspace recommendations, and setup requirements.
9. Podman Desktop Windows documentation. WSL 2/Hyper-V-backed Podman machine model on Windows.
10. Testcontainers documentation. Docker-API-compatible runtime requirements and Windows/Linux Docker Desktop support.
11. Playwright Python documentation. Cross-platform browser automation API on Windows and Linux.
12. uv documentation. Windows/Linux installation and managed Python environments.
13. Open Policy Agent documentation. General-purpose policy-as-code engine.
14. OpenTelemetry Python documentation. Python instrumentation and tracing SDK.
15. GitHub Actions matrix strategy documentation/community examples. OS matrix CI design.

**Pinning requirement:** Before implementation, create `docs/dependency-inventory.md` recording exact package versions, licenses, supported Python/runtime versions, container image digests, CVE-review status, upgrade cadence, and rollback procedure. Do not use `latest` tags for any evaluator, dependency, or container image.
