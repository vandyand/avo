# AVO-Correlate
## Draft 3 — Executable Implementation Packet

**Document status:** Proposed implementation baseline  
**Revision date:** 2026-08-23  
**Supersedes:** Draft 2 for new implementation work; Draft 2 remains historical context  
**Audience:** Implementers, technical leads, security reviewers, evaluator authors, and platform operators  
**Canonical implementation language:** Python 3.12+  
**Canonical workload format:** Linux OCI images on x86-64  
**Supported development hosts:** Linux x86-64 and Windows 11+ through WSL 2  
**Initial deployment model:** Single trusted team; generated code is still treated as untrusted input  

---

# 1. Purpose and revision outcome

AVO-Correlate is an evaluator-grounded system for sustained autonomous software improvement. A project supplies an immutable workspace, a task charter, budgets, policy, and evaluators. An agentic variation session may inspect lineage and evidence, create and test multiple working revisions, and eventually propose a candidate. An independent authoritative evaluator and deterministic admission service decide whether that candidate enters the committed lineage.

Draft 3 makes these changes:

1. Narrows v1 to one reference workload: improving a small software repository against deterministic tests and metrics.
2. Restores the paper's AVO boundary: the agent controls the internal edit–evaluate–diagnose loop, while final admission remains independent.
3. Uses a single committed lineage in v1; population and archive methods are later interchangeable search strategies.
4. Defines authoritative lifecycle states, transitions, failure behavior, and concurrency rules.
5. Adds versioned contracts for experiments, budgets, variation sessions, attempts, candidates, evaluation, policy, and admission.
6. Separates development feedback from private admission and audit evaluation to reduce evaluator gaming.
7. Defines reproducibility levels instead of promising exact replay for nondeterministic systems.
8. Adds a threat model, trust zones, network controls, supply-chain requirements, and retention rules.
9. Establishes one canonical Windows topology and a feasible CI strategy.
10. Replaces mandatory early infrastructure with promotable adapters and explicit promotion criteria.

# 2. Normative language and design authority

The words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative.

When prose, examples, and schemas disagree, authority is:

1. Versioned schema and state-transition definitions.
2. Explicit invariants.
3. Contract tests.
4. Normative prose.
5. Examples and diagrams.

Every stable serialized record MUST contain `schema_version`. Breaking changes require a new major schema version and a migration or compatibility adapter.

# 3. Product boundary

## 3.1 v1 reference scenario

The v1 system MUST complete this scenario:

> Given an immutable Git workspace containing a small Python project, a task charter, a development evaluator, a private admission evaluator, a model budget, and a sandbox policy, run a single-lineage agentic variation session that creates multiple private working attempts, proposes a candidate patch, evaluates it independently, admits it only if all constraints and improvement rules pass, records complete provenance, and resumes safely after a worker crash.

The fixture project MUST include:

- a reproducible defect or optimization target;
- visible unit tests available to the harness;
- hidden admission tests unavailable to the harness;
- at least one numeric metric with a noisy-test fixture;
- an attempted path escape and attempted hidden-test read;
- a seeded successful candidate and seeded rejected candidate.

## 3.2 v1 user outcomes

A user can:

1. Validate an experiment specification without starting work.
2. Start, inspect, pause, resume, and cancel a run.
3. Inspect every committed event, policy decision, budget charge, candidate, evaluation, and admission reason.
4. Reconstruct the exact workspace and evaluator inputs used for an admitted candidate.
5. Export a machine-readable provenance bundle.
6. Verify that a crash or duplicate request cannot cause duplicate admission or duplicate budget charging.

## 3.3 Explicit v1 non-goals

The following are not v1 requirements:

- Browser research or unrestricted internet access.
- Scientific notebooks, data pipelines, infrastructure mutation, or production deployment.
- Multiple simultaneous harness implementations.
- Pareto archives, MAP-Elites, island models, or multi-agent debate.
- Temporal, Prefect, MinIO, OPA, Kubernetes, gVisor, Kata, or a full observability stack as mandatory local dependencies.
- Native Windows execution of the control plane or evaluator.
- Multi-tenant hostile-code isolation.
- A graphical user interface.
- Autonomous changes to evaluators, policies, budgets, or the AVO-Correlate control plane itself.

These remain planned extension points, not implied v1 functionality.

# 4. Methodology decision

## 4.1 Selected v1 method: single-lineage agentic variation

The v1 search method is `single_lineage_agentic`.

The committed lineage is:

~~~text
seed -> admitted candidate 1 -> admitted candidate 2 -> ... -> champion
~~~

A variation session starts from the current champion and receives:

- a bounded initial context packet;
- read access to the permitted committed lineage through retrieval tools;
- read access to the development evaluator interface;
- a private writable working copy;
- a finite budget;
- a finite tool capability set.

Within that session, the harness decides what to inspect, edit, test, diagnose, and retry. Intermediate attempts are recorded for audit but do not enter the committed lineage. The session finishes with exactly one of:

`proposal_ready`, `exhausted`, `policy_blocked`, `cancelled`, or `failed`.

This preserves the central AVO idea that variation is an autonomous agent loop rather than a single model call. The independent admission evaluator is intentionally outside the agent's authority.

## 4.2 Why population search is deferred

The AVO paper describes the method as orthogonal to population structure and studies a single lineage to isolate the effect of the agentic operator. Starting with Pareto plus novelty would add descriptor design, archive pruning, parent selection, and concurrency before the core operator is validated.

Population methods MAY be added after the single-lineage baseline produces stable measurements. They MUST implement a `SearchStrategy` port and MUST be compared against the baseline using equal model, evaluator, and compute budgets.

## 4.3 Alternative methodology matrix

| Method | Best fit | Strength | Primary risk | Decision |
|---|---|---|---|---|
| Single-lineage AVO | Deep iterative engineering | Simple attribution; long coherent sessions | Local optimum; lower breadth | v1 default |
| AlphaEvolve/OpenEvolve-style population pipeline | High-throughput algorithm search | Breadth, diversity, parallel evaluation | Reintroduces fixed sampling/generation pipeline | Phase 5 adapter |
| Hybrid archive plus agentic variation | Multi-objective search | Combines deep variation with diversity | More state and evaluator queries | Preferred later experiment |
| Best-first or tree search | Tasks with cheap branching and state rollback | Explicit alternatives and backtracking | Explosive cost for repository-scale work | Research adapter only |
| Multi-agent proposal/critique | Ambiguous qualitative work | Diverse hypotheses | Cost, correlated errors, unclear authority | Not baseline |

No method is declared universally superior. Method selection MUST be an experiment property and results MUST identify the method and version.

# 5. Architecture and trust boundaries

## 5.1 Logical architecture

~~~text
User / CLI / API
        |
        v
+---------------------- Control plane ----------------------+
| validation | lifecycle | budget ledger | policy | audit  |
| admission  | reviews   | scheduler     | projections     |
+----------------------------+------------------------------+
                             |
                    signed execution request
                             |
                             v
+---------------------- Worker plane -----------------------+
| variation session | tool broker | workspace materializer |
| sandbox adapter   | development evaluator interface      |
+----------------------------+------------------------------+
                             |
                candidate proposal + artifacts
                             |
                             v
+---------------- Authoritative evaluation ----------------+
| private evaluator material | isolated run | report check |
+----------------------------+------------------------------+
                             |
                  deterministic admission
~~~

The control plane, variation worker, and authoritative evaluator are separate logical trust zones even when v1 runs them on one machine.

## 5.2 Core invariant

An LLM or harness MAY:

- inspect approved context and committed lineage;
- create private working revisions;
- invoke permitted development tools and development evaluators;
- propose a candidate and explain its rationale;
- recommend a supervisor directive.

An LLM or harness MUST NOT:

- read private admission or audit evaluator material;
- mark an authoritative evaluation as passed;
- admit or reject a candidate;
- change policy, budgets, evaluator packages, or audit records;
- grant tools or credentials to itself;
- write directly to control-plane persistence;
- choose whether its own output is retained or redacted.

## 5.3 Agentic variation boundary

~~~text
Control plane:
  create variation session with champion reference and immutable envelope

Variation session:
  inspect context/lineage
  -> materialize private working revision
  -> edit
  -> invoke development evaluator
  -> diagnose
  -> repeat within budget
  -> propose one candidate or stop

Control plane:
  freeze candidate
  -> authoritative evaluation
  -> report validation
  -> policy and budget check
  -> deterministic admission decision
  -> append lineage entry if admitted
~~~

The development evaluator MAY expose detailed failures. The admission evaluator SHOULD expose only the result detail needed for audit and MUST NOT feed hidden cases back into the active session.

# 6. Canonical deployment topology

## 6.1 Linux

On Linux x86-64:

- the repository and control plane run on the native Linux filesystem;
- Docker Engine runs canonical OCI sandboxes;
- SQLite plus filesystem artifact storage is the default local profile;
- PostgreSQL and S3-compatible storage are production adapters.

Rootless Docker or Podman MAY be evaluated later, but v1 contract behavior targets Docker Engine.

## 6.2 Windows

The canonical Windows topology is **WSL-first**, not native-Windows Python:

1. Windows 11 runs an approved WSL 2 Linux distribution.
2. The repository lives in the WSL ext4 filesystem, such as `~/src/avo-correlate`.
3. Python, `uv`, `avoctl`, the control plane, and Git run inside WSL.
4. Docker Desktop uses its WSL 2 backend and Linux-container mode.
5. Windows editors access the repository through WSL integration.
6. A PowerShell wrapper invokes `wsl.exe --exec` using an argument array; it MUST NOT construct a shell command string.

Native Windows adapters are future exceptions for Windows-only tools. They are not comparable to canonical Linux-container evaluator profiles.

## 6.3 Cross-host comparability

An evaluation is comparable only when all of these match:

- evaluator package and schema version;
- OCI image manifest digest;
- source and input artifact digests;
- hardware class;
- resource limits;
- benchmark procedure and repetition count;
- normalization policy;
- seed policy.

Every performance report separates:

`workload_time_ms`, `sandbox_setup_time_ms`, `queue_time_ms`, and `host_overhead_time_ms`.

Results from different hardware classes MUST NOT enter the same admission comparison unless a versioned evaluator-specific normalization policy explicitly permits it.

# 7. Authoritative lifecycle

## 7.1 Run states

| State | May enter from | May leave to | Meaning |
|---|---|---|---|
| `created` | — | `validating`, `cancelled` | Immutable run envelope exists |
| `validating` | `created` | `ready`, `failed`, `cancelled` | Schemas, policy, capabilities, and budgets checked |
| `ready` | `validating`, `paused` | `running`, `cancelled` | Eligible to schedule |
| `running` | `ready` | `pausing`, `cancelling`, `blocked_review`, `completed`, `failed` | Work may be scheduled |
| `pausing` | `running` | `paused`, `cancelling`, `failed` | No new session starts; active activity reaches safe boundary |
| `paused` | `pausing` | `ready`, `cancelled` | Durable state retained; no work scheduled |
| `cancelling` | `running`, `pausing`, `blocked_review` | `cancelled`, `failed` | No new work; active sandbox terminated after grace period |
| `blocked_review` | `running` | `running`, `cancelling`, `failed` | Authorized human decision required |
| `completed` | `running` | — | Terminal success or configured stopping condition |
| `cancelled` | nonterminal state | — | Terminal user or policy cancellation |
| `failed` | nonterminal state | — | Terminal unrecoverable system failure |

Pause and cancel requests are commands, not immediate state assignments. Once `cancelling` is committed, no later candidate admission is permitted for that run.

## 7.2 Variation-session states

| State | Allowed next states |
|---|---|
| `queued` | `running`, `cancelled` |
| `running` | `proposal_ready`, `exhausted`, `policy_blocked`, `cancelled`, `failed` |
| `proposal_ready` | terminal |
| `exhausted` | terminal |
| `policy_blocked` | terminal |
| `cancelled` | terminal |
| `failed` | terminal |

Only one variation session MAY be `running` for a v1 run. A session owns a renewable lease. After lease expiry, another worker MAY resume it from the last committed activity boundary.

## 7.3 Candidate states

| State | Allowed next states |
|---|---|
| `staged` | `evaluating`, `policy_blocked`, `cancelled` |
| `evaluating` | `rejected`, `quarantined`, `review_required`, `admitted` |
| `review_required` | `admitted`, `rejected`, `cancelled` |
| `admitted` | terminal |
| `rejected` | terminal |
| `quarantined` | terminal; a new evaluation record may supersede it |
| `policy_blocked` | terminal |
| `cancelled` | terminal |

An admitted candidate MUST have exactly one successful admission decision, at least one authoritative evaluation set, and a committed lineage sequence number.

## 7.4 Evaluation states

`queued -> running -> passed | failed | errored | timed_out | policy_blocked | invalid_report`

`errored`, `timed_out`, and `invalid_report` never mean the candidate failed its objective. They produce quarantine or a bounded retry according to the evaluator's retry policy.

## 7.5 Transaction and concurrency invariants

1. Every command has an idempotency key unique within its actor and endpoint scope.
2. State transition, event append, budget charge or reservation, and outbox insert occur in one database transaction.
3. Admission uses compare-and-swap on the expected champion and lineage sequence.
4. An admitted candidate digest can appear only once in a lineage.
5. External activity completion is recorded under a stable activity key; retries return the prior result when safe.
6. A worker lease does not confer admission authority.
7. Timestamps are UTC and informational; ordering uses monotonic per-run sequence numbers.
8. Corrections append superseding records and never overwrite evidence.

# 8. Stable schemas

The following models define required fields. Concrete Pydantic models and generated JSON Schemas are the implementation authority.

## 8.1 Common records

~~~python
class ArtifactRef(BaseModel):
    schema_version: Literal[1] = 1
    digest: str                 # sha256:<lowercase hex>
    size_bytes: int
    media_type: str
    role: str
    created_at: datetime

class ActorRef(BaseModel):
    schema_version: Literal[1] = 1
    actor_type: Literal["human", "service", "harness", "evaluator"]
    actor_id: str

class VersionedComponentRef(BaseModel):
    schema_version: Literal[1] = 1
    component_id: str
    component_version: str
    package_digest: str
    capability_manifest_digest: str
~~~

## 8.2 Experiment specification

~~~python
class ExperimentSpec(BaseModel):
    schema_version: Literal[1] = 1
    experiment_id: str
    title: str
    objective: str
    success_criteria: list[str]
    workspace: WorkspaceSpec
    search: SearchSpec
    harness: HarnessSpec
    development_evaluators: list[EvaluatorSpec]
    admission_evaluators: list[EvaluatorSpec]
    audit_evaluators: list[EvaluatorSpec]
    budget: BudgetSpec
    sandbox_profile_id: str
    policy_bundle_digest: str
    retention_policy_id: str
    review_policy: ReviewPolicy
    created_by: ActorRef
~~~

The experiment spec is canonicalized and digested at creation. A run references the digest and cannot mutate it. A changed spec creates a new experiment revision.

## 8.3 Workspace and path rules

~~~python
class WorkspaceSpec(BaseModel):
    schema_version: Literal[1] = 1
    source_uri: str
    source_revision: str
    source_tree_digest: str
    allowed_paths: list[str]
    forbidden_paths: list[str]
    required_paths: list[str]
    max_file_bytes: int
    max_tree_bytes: int
    submodules: Literal["deny", "pinned_only"]
    symlinks: Literal["deny", "internal_only"]
~~~

Manifest paths are UTF-8, POSIX-style, relative paths. They MUST NOT contain `..`, an absolute prefix, a drive designator, NUL, or a Unicode-normalization collision. Matching uses normalized path segments, not string prefix tests.

Forbidden paths take precedence over allowed paths. Case-collision and symlink-resolution checks occur during ingestion and again after candidate materialization.

## 8.4 Search and harness contracts

~~~python
class SearchSpec(BaseModel):
    schema_version: Literal[1] = 1
    method: Literal["single_lineage_agentic"]
    method_version: str
    max_committed_candidates: int
    stopping_rules: list[StoppingRule]

class VariationSessionRequest(BaseModel):
    schema_version: Literal[1] = 1
    session_id: str
    run_id: str
    champion: CandidateRef
    lineage_index_digest: str
    initial_context_digest: str
    tool_capability_token: str
    development_evaluator_refs: list[VersionedComponentRef]
    budget_reservation_id: str
    random_seed: int

class VariationSessionResult(BaseModel):
    schema_version: Literal[1] = 1
    session_id: str
    outcome: Literal[
        "proposal_ready", "exhausted", "policy_blocked", "cancelled", "failed"
    ]
    proposed_workspace_digest: str | None
    proposed_patch_digest: str | None
    rationale_artifact: ArtifactRef | None
    attempt_index_digest: str
    usage: UsageRecord
~~~

The harness receives a capability token scoped to one session, one workspace, named tools, and an expiry. It never receives control-plane database credentials.

## 8.5 Attempt and candidate distinction

~~~python
class VariationAttemptRecord(BaseModel):
    schema_version: Literal[1] = 1
    attempt_id: str
    session_id: str
    parent_workspace_digest: str
    result_workspace_digest: str | None
    patch_digest: str | None
    development_evaluation_ids: list[str]
    tool_trace_digest: str
    outcome: Literal[
        "improved", "no_improvement", "invalid", "errored",
        "abandoned", "policy_blocked"
    ]
    started_at: datetime
    completed_at: datetime

class CandidateManifest(BaseModel):
    schema_version: Literal[1] = 1
    candidate_id: str
    run_id: str
    session_id: str
    parent_candidate_ids: list[str]
    base_workspace_digest: str
    source_tree_digest: str
    patch_artifact: ArtifactRef | None
    result_artifacts: list[ArtifactRef]
    harness_ref: VersionedComponentRef
    model_config_digest: str
    context_digest: str
    attempt_index_digest: str
    execution_profile_digest: str
    policy_bundle_digest: str
    created_at: datetime
~~~

An attempt is private search work. A candidate is a frozen proposal sent to authoritative evaluation. A lineage entry is an admitted candidate. These terms MUST NOT be used interchangeably.

## 8.6 Evaluation and admission

~~~python
class EvaluationRecord(BaseModel):
    schema_version: Literal[1] = 1
    evaluation_id: str
    candidate_id: str
    evaluator_ref: VersionedComponentRef
    evaluator_tier: Literal["development", "admission", "audit"]
    evaluator_profile_digest: str
    execution_image_digest: str
    hardware_class: str
    input_artifact_digests: list[str]
    trial_records: list[TrialRecord]
    aggregate_metrics: dict[str, Decimal]
    uncertainty: dict[str, UncertaintyRecord]
    constraints: list[ConstraintResult]
    outcome: Literal[
        "passed", "failed", "errored", "timed_out",
        "policy_blocked", "invalid_report"
    ]
    evidence_artifacts: list[ArtifactRef]
    started_at: datetime
    completed_at: datetime

class AdmissionDecision(BaseModel):
    schema_version: Literal[1] = 1
    admission_id: str
    candidate_id: str
    expected_champion_id: str
    evaluation_ids: list[str]
    policy_decision_ids: list[str]
    outcome: Literal["admit", "reject", "quarantine", "review_required"]
    reason_codes: list[str]
    comparison: ComparisonRecord
    decided_by: ActorRef
    decided_at: datetime
~~~

Admission reason codes are stable API values. Human-readable explanations are additional fields, not replacements.

# 9. Budget and cost accounting

## 9.1 Budget dimensions

~~~python
class BudgetSpec(BaseModel):
    schema_version: Literal[1] = 1
    wall_clock_seconds: int
    model_input_tokens: int
    model_output_tokens: int
    model_cost_microusd: int
    tool_calls: int
    sandbox_cpu_seconds: int
    sandbox_gpu_seconds: int
    authoritative_evaluations: int
    variation_sessions: int
    artifact_bytes: int
~~~

All monetary values use integer micro-USD. Floating-point currency is forbidden.

## 9.2 Reservation protocol

Before an external activity starts:

1. Estimate its maximum charge.
2. Atomically reserve that amount.
3. Reject the activity if the hard limit would be exceeded.
4. On completion, convert the reservation to actual usage and release the remainder.
5. On unknown completion, retain the reservation until reconciliation.

Retries with the same activity key MUST NOT double-charge. Provider-reported token and cost data take precedence over estimates and are preserved with the invocation record.

## 9.3 Stop behavior

A hard-budget breach triggers `pausing` or `cancelling` according to policy. The system MUST define a bounded sandbox termination grace period. No supervisor or reviewer can increase a budget without creating a signed, append-only budget amendment permitted by experiment policy.

# 10. Evaluator integrity and statistical admission

## 10.1 Evaluator tiers

| Tier | Harness access | Purpose |
|---|---|---|
| Development | Callable; detailed feedback | Iterative debugging and optimization |
| Admission | Not readable or directly callable by harness | Candidate acceptance |
| Audit | Never exposed during active run | Periodic generalization and integrity check |

The same test MAY appear in multiple tiers only when the overlap is declared. Hidden evaluator source, fixtures, expected outputs, and credentials MUST be mounted only into the authoritative evaluator sandbox.

## 10.2 Evaluator package

~~~text
evaluator/
├── evaluator.yaml
├── Dockerfile
├── lockfile
├── report.schema.json
├── entrypoint
├── public-fixtures/
├── private-fixtures/
└── tests/
~~~

The built image MUST contain only the tier-specific files required for that invocation. Development images MUST NOT contain private fixtures in unused layers.

Every evaluator declares:

- package version and content digest;
- OCI manifest digest;
- tier;
- report schema;
- input partitions and their digests;
- command and environment allowlist;
- network policy;
- hardware class and resource limits;
- warm-up, trial, aggregation, and outlier procedure;
- retryable and terminal failure classes;
- comparison and admission policy;
- maximum result and artifact sizes.

## 10.3 Admission rules

For deterministic correctness:

- every hard constraint must pass;
- the evaluator report must validate;
- no forbidden workspace change may exist;
- the candidate must pass the private admission suite.

For noisy metrics:

- trials MUST be paired with the incumbent on the same worker allocation where practical;
- the number of warm-ups and measured trials is evaluator-defined and immutable within the run;
- admission requires the configured minimum effect and uncertainty rule;
- `within_noise` is not an improvement;
- a newly admitted champion is re-evaluated according to the champion-confirmation policy.

The default comparison rule is:

~~~text
admit only if:
  all hard constraints pass
  AND candidate lower confidence bound
      >= incumbent upper confidence bound + minimum_effect
~~~

Evaluators MAY define another statistically justified rule, but it must be versioned and tested.

## 10.4 Adaptive overfitting controls

Repeated feedback creates an adaptive test-selection problem. Each project MUST declare:

- which information development evaluation releases;
- admission query budget;
- whether admission failures reveal categories, counts, or no detail;
- audit holdout rotation policy;
- evaluator revision policy after leakage;
- promotion rules from admission to development regressions.

The harness MUST NOT receive raw private counterexamples during the active run. A human MAY intentionally promote a sanitized private failure into a new development regression in a new experiment revision.

## 10.5 Evaluator-gaming tests

Contract tests MUST attempt:

- reading private fixture paths;
- inspecting sibling containers or the Docker socket;
- detecting expected outputs through environment variables;
- replacing the evaluator entrypoint;
- emitting NaN, infinity, duplicate keys, oversized JSON, or undeclared metrics;
- manipulating clocks or benchmark processes;
- writing outside `/output`;
- exploiting symlinks, hardlinks, archives, or path normalization;
- forging artifact digests or evaluation IDs.

# 11. Policy and human review

## 11.1 Policy decision contract

~~~python
class PolicyDecision(BaseModel):
    schema_version: Literal[1] = 1
    decision_id: str
    policy_engine_id: str
    policy_bundle_digest: str
    action: str
    resource: str
    input_digest: str
    outcome: Literal["allow", "deny", "review"]
    reason_codes: list[str]
    obligations: list[PolicyObligation]
    decided_at: datetime
~~~

Undefined policy results, engine errors, stale policy bundles, and invalid outputs fail closed.

## 11.2 v1 policy implementation

V1 uses a small in-process, deny-by-default policy interpreter over a versioned JSON policy schema. It supports only:

- actor and role checks;
- workspace path rules;
- tool and command capabilities;
- sandbox profile selection;
- network denial;
- evaluator tier separation;
- budget limits;
- artifact export rules;
- review gates.

The engine MUST return structured decisions and pass the same `PolicyEngine` contract suite intended for OPA.

OPA becomes the preferred distributed adapter when policy authors need independently deployed Rego, signed bundles, or centralized policy distribution. Promotion requires fail-close behavior, decision-log redaction, bundle revision pinning, and parity tests against the v1 policy corpus.

## 11.3 Human review

Review policy defines:

- eligible reviewer roles;
- whether the proposer may review;
- required evidence;
- decision expiry;
- whether one or two approvals are required;
- actions allowed after approval;
- whether approval applies to one candidate or a digest-equivalent class.

Review decisions are signed by an authenticated actor and immutable. A review can authorize an already-defined action; it cannot silently broaden the experiment charter.

# 12. Threat model

## 12.1 Trust classification

| Input/component | Default trust |
|---|---|
| Model output and generated code | Untrusted |
| User-supplied repository | Untrusted until ingested and scanned |
| Web or retrieved content | Untrusted data, never control instructions |
| Development evaluator | Project-trusted but visible to harness |
| Admission/audit evaluator | High integrity; hidden from harness |
| Policy bundle | High integrity; administrator-controlled |
| Control-plane service | Trusted computing base |
| Standard Docker sandbox | Isolation aid, not hostile-code security boundary |
| gVisor/Kata/VM worker | Stronger isolation boundary, subject to its documented limits |

## 12.2 Protected assets

- Host and control-plane integrity.
- Evaluator secrecy and integrity.
- Source code and research artifacts.
- Model and service credentials.
- Budget and billing integrity.
- Audit and lineage integrity.
- Other projects and workers.
- Private or regulated data.

## 12.3 Required controls

1. Control-plane and evaluator credentials never enter variation sandboxes.
2. Sandboxes receive a copied, scoped workspace rather than an arbitrary host mount.
3. The root filesystem is read-only; writable locations are explicit tmpfs and output volumes.
4. All capabilities are dropped; no privileged mode, Docker socket, host PID, host network, devices, or user home mounts.
5. CPU, memory, process, file-size, disk, inode, output, and time limits are enforced outside the guest process.
6. Outputs are scanned and size-checked before artifact ingestion.
7. Evaluator images and policy bundles are digest-pinned and verified.
8. Tool outputs and model traffic pass deterministic redaction before persistence.
9. Untrusted workloads from separate projects do not share a sandbox.
10. Production execution of potentially hostile code requires a stronger runtime such as gVisor, Kata, or an isolated VM worker.

## 12.4 Residual risk statement

Local Docker execution on a developer machine does not guarantee containment of malicious code. The local profile is for trusted-team development with no host secrets exposed and network disabled. Projects requiring hostile-code isolation MUST be blocked unless a stronger approved worker profile is available.

# 13. Tool and network broker

## 13.1 Tool contract

Every tool invocation includes:

- invocation and activity ID;
- session and actor ID;
- tool and version;
- structured arguments;
- policy decision ID;
- deadline;
- input and output byte limits;
- redaction profile;
- resulting artifact digests;
- usage charge.

Commands use argument arrays and `shell=False`. The allowlist matches executable identity plus argument schema, not a raw string prefix.

## 13.2 Initial tool set

| Tool | v1 default | Notes |
|---|---|---|
| `read_file` | enabled | Allowlisted paths; byte cap |
| `search_workspace` | enabled | ripgrep adapter; safe fallback |
| `apply_patch` | enabled | Validated patch; post-apply path scan |
| `inspect_diff` | enabled | No mutation |
| `run_development_evaluator` | enabled | Named evaluator only |
| `run_command` | disabled | Enable only per command schema |
| `retrieve_lineage` | enabled | Bounded metadata and artifact retrieval |
| `http_research` | disabled | Phase 5 |
| `browser_research` | disabled | Phase 5 |
| `request_review` | enabled when configured | No implicit approval |

## 13.3 Future network-enabled profile

Domain allowlists alone are insufficient. A network broker MUST:

- resolve DNS outside the sandbox;
- deny loopback, link-local, private, metadata-service, and reserved address ranges;
- revalidate every redirect and resolved address;
- restrict scheme, port, method, request body, response size, and MIME type;
- enforce TLS verification and an approved certificate policy;
- rate-limit by project and destination;
- record request metadata and content digests;
- prevent arbitrary CONNECT tunnels and non-HTTP protocols.

# 14. Reproducibility and provenance

## 14.1 Reproducibility levels

| Level | Guarantee |
|---|---|
| `R0_auditable` | Original records and evidence can be inspected |
| `R1_reconstructable` | Inputs, configuration, code, prompts, tools, and artifacts can be reconstructed |
| `R2_deterministic_replay` | Re-execution is expected to produce identical declared outputs |
| `R3_statistical_reproduction` | Repeated execution is expected to satisfy a declared distributional criterion |

Each evaluator and run declares its target and achieved level. Hosted model calls and live web retrieval normally cannot claim `R2`.

## 14.2 Model invocation record

Preserve:

- provider and endpoint class;
- requested model identifier and provider-reported model revision;
- system, developer, user, and tool-schema digests;
- sampling and reasoning parameters;
- provider request ID;
- input, output, cached, and reasoning token counts when reported;
- start and completion timestamps;
- retry lineage;
- finish reason and error class;
- redacted request/response artifact digests;
- cost source and amount.

Provider seed fields are evidence, not proof of deterministic replay.

## 14.3 Canonical hashing

JSON records use RFC 8785 JSON Canonicalization Scheme before hashing. Digests are lowercase SHA-256 with the `sha256:` prefix.

A source-tree digest is computed from a sorted sequence of:

~~~text
normalized_path NUL file_type NUL mode_class NUL size NUL content_digest LF
~~~

Platform-specific executable bits are normalized into a declared mode class. Unicode normalization form is NFC. Duplicate normalized paths are rejected.

## 14.4 Provenance export

The internal event and artifact model is authoritative. Export adapters SHOULD provide:

- an RO-Crate profile for research artifacts;
- SLSA-compatible provenance for built software artifacts;
- a plain JSON manifest containing the complete AVO-Correlate lineage.

Export formats do not replace internal records and MUST reference immutable digests.

# 15. Persistence, artifacts, and recovery

## 15.1 v1 persistence

V1 uses:

- SQLite in WAL mode for lifecycle, ledger, leases, and outbox;
- SQLAlchemy plus Alembic;
- a local filesystem content-addressed artifact store;
- a single scheduler process and one or more local worker processes.

This is a single-host topology, not a distributed availability claim.

## 15.2 Durable execution approach

The domain state machine is persisted directly; v1 does not implement general workflow replay.

Each external action is an activity with:

`activity_id`, `activity_key`, `state`, `attempt_count`, `lease_owner`, `lease_expires_at`, `input_digest`, and `result_digest`.

After a crash:

1. Expired `running` activities are inspected.
2. Activities with a durable result are completed without re-execution.
3. Safely retryable activities return to `queued`.
4. Activities with uncertain non-idempotent side effects become `reconciliation_required`.
5. Admission and budget invariants are rechecked before progress continues.

## 15.3 Artifact commit protocol

1. Write to a store-controlled temporary file.
2. Enforce streaming size limits while writing.
3. Flush, hash, and verify declared media constraints.
4. Atomically move to the digest path.
5. In one database transaction, create metadata and references plus the event/outbox record.
6. A reconciler removes unreferenced temporary or orphaned objects after a grace period.

Artifact reads verify digest unless a previously verified immutable storage layer supplies that guarantee.

## 15.4 Retention and deletion

Each experiment selects a retention policy covering:

- model traffic;
- tool traces;
- rejected attempts;
- evaluator evidence;
- admitted candidates;
- web captures;
- personal or regulated data.

Garbage collection is mark-and-sweep over durable references, followed by a delay and deletion tombstone. Admitted lineage artifacts and active legal holds are never collected. Deletion events state whether bytes were removed, retained elsewhere, or could not be verified.

## 15.5 Promotion path

| Need | Adapter candidate | Promotion criterion |
|---|---|---|
| Multi-host database | PostgreSQL | Single-host limits reached; transaction parity passes |
| Object storage | S3/MinIO | Artifact volume or remote workers require it |
| Library-managed durability | DBOS | Spike proves clean port boundary and recovery parity |
| Distributed long-lived workflows | Temporal | Multiple services/workers require signals and durable timers |
| Central policy distribution | OPA | Independent policy operations or multi-service enforcement needed |

Temporal or DBOS workflow state MUST NOT become the domain source of truth. Adapters orchestrate authoritative domain transitions.

# 16. Supervisor

The deterministic supervisor observes committed events, not hidden model reasoning. It detects:

- no admitted improvement within configured sessions or budget;
- repeated development failure signatures;
- repeated authoritative evaluator quarantine;
- duplicate or no-op patches;
- budget cost per admitted improvement;
- repeated policy denials;
- attempt diversity collapse;
- infrastructure flakiness.

Allowed directives are:

`continue`, `reduce_scope`, `request_more_evidence`, `revisit_lineage`, `change_hypothesis`, `pause`, `request_review`, and `terminate`.

Each directive has a typed payload and version. A critic model MAY recommend a directive, but the deterministic supervisor validates it against budget and policy. In v1 the supervisor does not change search methods or model configuration during a run.

# 17. Ports, plugins, and compatibility

Required ports:

~~~python
class AgentHarness(Protocol):
    async def run_session(
        self, request: VariationSessionRequest
    ) -> VariationSessionResult: ...

class DevelopmentEvaluator(Protocol):
    async def evaluate(self, request: EvaluationRequest) -> EvaluationRecord: ...

class AuthoritativeEvaluator(Protocol):
    async def evaluate(self, request: EvaluationRequest) -> EvaluationRecord: ...

class Sandbox(Protocol):
    async def execute(
        self, request: SandboxExecutionSpec
    ) -> SandboxExecutionResult: ...

class PolicyEngine(Protocol):
    async def decide(self, request: PolicyRequest) -> PolicyDecision: ...

class ArtifactStore(Protocol):
    async def put(self, stream: AsyncIterator[bytes], metadata: PutMetadata) -> ArtifactRef: ...

class SearchStrategy(Protocol):
    async def next_session(self, state: SearchState) -> VariationSessionRequest | None: ...
~~~

Every plugin provides a signed capability manifest containing:

- plugin ID and semantic version;
- package and source digest;
- supported contract and schema versions;
- operating-system and architecture capabilities;
- required executables and network access;
- configuration JSON Schema;
- declared side effects;
- security classification;
- health check;
- license.

Compatibility is proven by contract tests. Matching a Python protocol structurally is insufficient.

# 18. API and CLI

## 18.1 API

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/v1/experiments/validate` | Validate without persistence |
| POST | `/v1/experiments` | Create immutable experiment revision |
| GET | `/v1/experiments/{id}` | Get spec, revisions, and capabilities |
| POST | `/v1/experiments/{id}/runs` | Create run |
| GET | `/v1/runs/{id}` | State, budget, champion, and blockers |
| POST | `/v1/runs/{id}:start` | Start ready run |
| POST | `/v1/runs/{id}:pause` | Request safe pause |
| POST | `/v1/runs/{id}:resume` | Resume paused run |
| POST | `/v1/runs/{id}:cancel` | Request cancellation |
| GET | `/v1/runs/{id}/events` | Cursor-based immutable event stream |
| GET | `/v1/sessions/{id}` | Session attempts and usage |
| GET | `/v1/candidates/{id}` | Manifest, evaluation, and admission |
| POST | `/v1/reviews/{id}/decisions` | Submit authorized review |
| GET | `/v1/artifacts/{digest}/metadata` | Metadata; bytes require separate authorization |
| GET | `/healthz` | Process liveness |
| GET | `/readyz` | Dependency and policy readiness |

Every mutating request requires authentication and an `Idempotency-Key`. Optimistic concurrency uses an ETag or expected revision.

## 18.2 CLI

~~~text
avoctl doctor
avoctl platform verify
avoctl experiment validate <spec>
avoctl experiment create <spec>
avoctl run start <experiment-id>
avoctl run status <run-id> --json
avoctl run pause <run-id>
avoctl run resume <run-id>
avoctl run cancel <run-id>
avoctl run events <run-id> --after <sequence>
avoctl candidate inspect <candidate-id>
avoctl provenance verify <candidate-id>
avoctl policy test
avoctl test unit
avoctl test integration
avoctl test parity
~~~

Exit codes and JSON output schemas are stable contracts. Human-formatted output may evolve.

# 19. Repository layout

~~~text
avo-correlate/
├── README.md
├── pyproject.toml
├── uv.lock
├── compose.yaml
├── .gitattributes
├── .editorconfig
├── src/avo_correlate/
│   ├── contracts/
│   ├── domain/
│   │   ├── lifecycle/
│   │   ├── admission/
│   │   ├── budgets/
│   │   └── events/
│   ├── application/
│   ├── adapters/
│   │   ├── harness/
│   │   ├── evaluators/
│   │   ├── sandbox/
│   │   ├── persistence/
│   │   ├── artifacts/
│   │   └── policy/
│   ├── api/
│   ├── cli/
│   └── devtools/
├── evaluators/
│   └── reference_python_fix/
├── policies/
├── migrations/
├── schemas/
├── tests/
│   ├── unit/
│   ├── contract/
│   ├── integration/
│   ├── e2e/
│   ├── security/
│   ├── recovery/
│   └── parity/
├── docs/
│   ├── adr/
│   ├── runbooks/
│   ├── threat-model.md
│   ├── evaluator-authoring.md
│   └── dependency-inventory.md
└── scripts/
    ├── avoctl.ps1
    └── avoctl.sh
~~~

Domain code MUST NOT import an adapter, FastAPI, SQLAlchemy, Docker SDK, model SDK, or workflow SDK.

# 20. Testing and CI

## 20.1 Required test layers

| Layer | Required proof |
|---|---|
| Unit | Transition guards, admission, comparison, budgets, canonicalization |
| Schema | Valid/invalid fixtures and backward compatibility |
| Contract | Every port adapter against shared semantics |
| Integration | SQLite, filesystem CAS, Docker sandbox, evaluator images |
| Recovery | Kill at every durable boundary; resume without duplicate effects |
| Security | Path escape, hidden-test access, egress, resource and report abuse |
| End-to-end | Complete reference scenario with dry-run and recorded harness |
| Parity | Identical contracts and canonical OCI evaluation on Linux and Windows/WSL |
| Performance | Workload versus platform-overhead decomposition |

Property-based tests SHOULD generate command arguments, paths, state transitions, budget sequences, and malformed reports.

## 20.2 CI topology

Every pull request runs:

1. `ubuntu-latest`: complete unit, schema, contract, integration, OCI, and end-to-end suite.
2. `windows-latest`: native package import, schema, path, Unicode, PowerShell-wrapper, and CLI-contract tests that do not require WSL nested virtualization.

A scheduled and release-gating job runs on an organization-controlled Windows 11 machine with WSL 2 and Docker Desktop:

- full WSL-first bootstrap;
- canonical OCI evaluator;
- crash recovery;
- filesystem and path parity;
- host-overhead benchmark;
- PowerShell-to-WSL wrapper behavior.

GitHub-hosted nested virtualization is not a required dependency. Release notes MUST identify the exact self-hosted parity environment.

## 20.3 Mandatory acceptance tests

1. A fresh Linux clone completes the reference scenario.
2. A fresh supported Windows/WSL clone completes the same scenario.
3. Killing the worker after sandbox completion but before admission does not rerun or duplicate admission.
4. Repeating every mutating API call with the same idempotency key produces one effect.
5. Cancelling while evaluation runs prevents later admission.
6. A candidate cannot read hidden evaluator material.
7. Path, symlink, archive, Unicode, and case-collision escapes are blocked.
8. Malformed and oversized evaluator reports are quarantined.
9. Budget reservations prevent overshoot within the declared termination bound.
10. An admitted candidate can be reconstructed and its provenance verified.

# 21. Implementation roadmap

## Phase 0 — Contracts before framework

Deliver:

- repository skeleton and Python toolchain;
- JSON Schemas and Pydantic models for all v1 records;
- state-transition tables encoded as tests;
- canonical hashing implementation and fixtures;
- threat model and dependency inventory;
- CLI `doctor` and platform verification;
- Linux and Windows-hosted CI jobs.

Done when all schema, state-machine, canonicalization, and portability tests pass without Docker or an LLM.

## Phase 1 — Deterministic local vertical slice

Deliver:

- SQLite repositories, event ledger, budget ledger, activity journal, and outbox;
- filesystem content-addressed artifact store;
- v1 policy interpreter;
- in-process scheduler and worker leases;
- `dry_run` and recorded harness;
- reference workspace and deterministic command evaluator;
- API and CLI lifecycle.

Done when a seeded candidate is admitted, rejected, cancelled, and recovered after injected crashes without duplicate effects.

## Phase 2 — Sandbox and evaluator integrity

Deliver:

- Docker sandbox adapter;
- development and private admission evaluator images;
- resource, mount, path, output, and network-denial controls;
- noisy metric comparison and champion confirmation;
- evaluator-gaming and malformed-report suite.

Done when the reference adversarial fixtures are blocked and the same evaluator image produces schema-equivalent results on Linux and Windows/WSL.

## Phase 3 — Real agentic variation

Deliver:

- one native agent harness and model gateway;
- session capability tokens;
- lineage retrieval, context packet, tool broker, and attempt records;
- model invocation provenance and cost accounting;
- deterministic supervisor.

Done when the harness resolves the bounded reference defect through multiple internal attempts, private admission passes, and the complete run remains reconstructable after crash recovery.

## Phase 4 — Production hardening

Deliver only as justified:

- PostgreSQL and S3-compatible adapters;
- authenticated roles and reviewer workflows;
- OPA adapter with signed bundles and redacted decision logs;
- gVisor/Kata/VM worker profile;
- OpenTelemetry export, operational dashboards, backup/restore, retention, and incident runbooks;
- SLSA and RO-Crate exports.

Done when a recovery drill rebuilds an admitted candidate from backups and a security review approves the declared threat model.

## Phase 5 — Alternative methodologies and broader domains

Candidate experiments:

- hybrid archive plus agentic variation;
- AlphaEvolve/OpenEvolve-compatible population adapter;
- DBOS and Temporal workflow-runtime adapters;
- Podman compatibility;
- research-pipeline evaluators;
- controlled HTTP and browser research;
- second harness implementation.

Each addition requires a decision record, contract suite, deny-case security tests, and a measured improvement over the simpler baseline.

# 22. Decision gates

The project MUST pause for an architecture decision if any of these occur:

- v1 cannot express a lifecycle change without adapter-specific state;
- a second worker is required before lease and idempotency tests are complete;
- private evaluator content must be exposed to the harness;
- standard Docker is proposed as a hostile-code security guarantee;
- Windows support requires repositories under `/mnt/c` for evaluator workloads;
- model or tool cost cannot be reconciled to the budget ledger;
- an evaluator metric lacks a comparison/noise policy;
- an artifact cannot be assigned a retention class;
- a plugin requires direct control-plane database access.

# 23. Junior implementer checklist

1. Start from the reference scenario, not an optional adapter.
2. Implement transitions from the table; do not assign state ad hoc.
3. Use canonical schemas and reason codes at boundaries.
4. Treat attempts, candidates, and lineage entries as different records.
5. Never expose admission or audit fixtures to a harness workspace.
6. Reserve budget before external work.
7. Put every external action behind an activity key and timeout.
8. Use `pathlib` and structured argument arrays; never shell concatenation.
9. Add a deny test for every new tool or policy capability.
10. Do not claim exact replay for a hosted model call.
11. Do not log secrets, raw credentials, hidden tests, or unredacted model traffic.
12. Do not add Temporal, OPA, MinIO, or another harness until its promotion criterion is met.
13. Test the crash boundary immediately after implementing each external activity.
14. Update the dependency inventory and ADR for every new executable or service.

# 24. Final principles

1. **Agentic inside, deterministic outside.** The agent owns exploration; deterministic services own authority.
2. **Prove the operator before enriching the population.**
3. **Attempts are evidence, candidates are proposals, admission creates lineage.**
4. **The evaluator is an attack surface as well as a source of truth.**
5. **Reconstruction and auditability are honest defaults; stronger reproducibility is declared and tested.**
6. **Durability comes from explicit transitions, idempotency, and journals before it comes from a workflow product.**
7. **Security claims follow the threat model, not the presence of containers.**
8. **Cross-platform means one tested Windows topology and one tested Linux topology, not every possible topology.**
9. **Infrastructure is promoted by demonstrated need.**
10. **Every authority decision is versioned, explainable, and immutable.**

# 25. Sources and implementation references

All links were checked on 2026-08-23.

1. [AVO: Agentic Variation Operators for Autonomous Evolutionary Search](https://arxiv.org/html/2603.24517v1) — agentic variation boundary, single-lineage study, continuous evolution, and supervisor.
2. [NVIDIA AVO long-horizon architecture and ARC-AGI-3 results](https://developer.nvidia.com/blog/nvidia-avo-reaches-100-on-arc-agi-3-demonstrating-a-frontier-level-general-purpose-architecture-for-long-horizon-autonomous-agents/) — transfer of persistent memory, tools, feedback, and supervision across domains.
3. [AlphaEvolve technical report](https://arxiv.org/abs/2506.13131) and [Google DeepMind overview](https://deepmind.google/blog/alphaevolve-a-gemini-powered-coding-agent-for-designing-advanced-algorithms/) — population-pipeline alternative and automated evaluator framing.
4. [OpenEvolve repository](https://github.com/codelion/openevolve) — open population/archive implementation reference; evaluate as an adapter, not a source of domain authority.
5. [Generalization in Adaptive Data Analysis and Holdout Reuse](https://arxiv.org/abs/1506.02629) — risk of adaptive overfitting from repeated holdout feedback.
6. [DBOS Python programming guide](https://docs.dbos.dev/python/programming-guide) — database-backed durable workflow alternative with SQLite and PostgreSQL.
7. [Temporal documentation](https://docs.temporal.io/) — distributed durable execution alternative for later promotion.
8. [Open Policy Agent integration](https://www.openpolicyagent.org/docs/integration), [bundles](https://www.openpolicyagent.org/docs/management-bundles), and [decision logs](https://www.openpolicyagent.org/docs/management-decision-logs) — later distributed policy adapter requirements.
9. [Docker Engine security](https://docs.docker.com/engine/security/) and [Docker seccomp profiles](https://docs.docker.com/engine/security/seccomp/) — standard container controls and limits.
10. [gVisor security introduction](https://gvisor.dev/docs/architecture_guide/intro/) and [security model](https://gvisor.dev/docs/architecture_guide/security/) — stronger untrusted-workload isolation option and residual risks.
11. [GitHub-hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) and [self-hosted runner reference](https://docs.github.com/en/actions/reference/runners/self-hosted-runners) — CI topology and container-runner constraints.
12. [RFC 8785: JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785) — canonical JSON hashing.
13. [SLSA specification 1.2](https://slsa.dev/spec/v1.2/) — software artifact and source provenance.
14. [RO-Crate specification](https://www.researchobject.org/ro-crate/specification.html) — portable research artifact packaging and provenance.

# 26. Required follow-on documents

Before Phase 1 code begins, create:

- `docs/threat-model.md` with data-flow diagrams and reviewed residual risks;
- `docs/dependency-inventory.md` with exact versions, licenses, hashes, support windows, CVE status, upgrade cadence, and rollback;
- `docs/adr/0001-single-lineage-avo.md`;
- `docs/adr/0002-explicit-state-machine.md`;
- `docs/adr/0003-wsl-first-windows.md`;
- `docs/evaluator-authoring.md` with complete schemas and integrity guidance;
- checked-in JSON Schema fixtures and state-transition fixtures.

No dependency or container image may use an unpinned `latest` tag.
