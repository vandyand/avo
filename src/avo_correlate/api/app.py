"""Versioned HTTP API for experiment and run lifecycle."""

# Decorated route handlers are registered by FastAPI rather than called in this module.
# pyright: reportUnusedFunction=false

import json
import os
import secrets
from pathlib import Path
from typing import Annotated, Literal, cast
from uuid import NAMESPACE_URL, uuid5

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse

from avo_correlate.adapters.persistence import Database
from avo_correlate.application.provenance_service import ProvenanceService
from avo_correlate.application.query_service import QueryService
from avo_correlate.application.review_service import (
    ReviewAuthorizationError,
    ReviewConflictError,
    ReviewService,
)
from avo_correlate.application.run_service import (
    DuplicateExperimentError,
    NotFoundError,
    RevisionConflictError,
    RunService,
)
from avo_correlate.application.runtime_service import RuntimeConflictError, RuntimeService
from avo_correlate.contracts.base import NonEmptyString, Sha256Digest, StrictModel
from avo_correlate.contracts.budgets import BudgetSpec, UsageRecord
from avo_correlate.contracts.experiment import ExperimentSpec
from avo_correlate.contracts.lifecycle import RunState
from avo_correlate.contracts.projections import (
    ArtifactMetadataProjection,
    CandidateProjection,
    SessionProjection,
    SessionRuntimeProjection,
)
from avo_correlate.contracts.provenance import ProvenanceExport, VerificationReport
from avo_correlate.contracts.review import ReviewDecision, ReviewStatus
from avo_correlate.contracts.runtime import ReconciliationCaseRecord
from avo_correlate.domain.canonical import canonical_digest
from avo_correlate.domain.lifecycle import InvalidTransitionError


class ValidationResponse(StrictModel):
    schema_version: Literal[1] = 1
    valid: Literal[True] = True
    experiment_id: str
    spec_digest: Sha256Digest


class ExperimentResponse(StrictModel):
    schema_version: Literal[1] = 1
    experiment_id: str
    spec_digest: Sha256Digest


class RunResponse(StrictModel):
    schema_version: Literal[1] = 1
    run_id: str
    experiment_id: str
    state: RunState
    revision: int
    event_sequence: int
    champion_id: str | None
    budget_limit: BudgetSpec
    budget_used: UsageRecord
    budget_reserved: UsageRecord
    blockers: list[str]
    next_actions: list[str]


class EventResponse(StrictModel):
    schema_version: Literal[1] = 1
    event_id: str
    sequence: int
    event_type: str
    actor_id: str
    payload: dict[str, object]


class ReconciliationResolutionRequest(StrictModel):
    schema_version: Literal[1] = 1
    resolution: Literal["retry", "accept_result", "cancel", "fail"]
    note: NonEmptyString
    result_digest: Sha256Digest | None = None


def _services(request: Request) -> RunService:
    return cast(RunService, request.app.state.run_service)


def _authenticated_actor(
    request: Request,
    authorization: Annotated[str, Header(alias="Authorization")],
    actor_id: Annotated[NonEmptyString, Header(alias="X-Actor-ID")],
) -> str:
    configured = cast(str | None, request.app.state.api_token)
    if configured is None:
        raise HTTPException(status_code=503, detail="API authentication is not configured")
    scheme, separator, supplied = authorization.partition(" ")
    if separator != " " or scheme.lower() != "bearer" or not secrets.compare_digest(
        supplied, configured
    ):
        raise HTTPException(status_code=401, detail="invalid bearer credential")
    return actor_id


def _run_response(service: RunService, run_id: str) -> RunResponse:
    run = service.get_run(run_id)
    state = RunState(run.state)
    actions: dict[RunState, list[str]] = {
        RunState.CREATED: ["start", "cancel"],
        RunState.VALIDATING: ["cancel"],
        RunState.READY: ["start", "cancel"],
        RunState.RUNNING: ["pause", "cancel"],
        RunState.PAUSING: ["cancel"],
        RunState.PAUSED: ["resume", "cancel"],
        RunState.CANCELLING: [],
        RunState.BLOCKED_REVIEW: ["submit_review", "cancel"],
        RunState.BLOCKED_RECONCILIATION: ["inspect_reconciliation", "cancel"],
        RunState.COMPLETED: ["inspect_provenance"],
        RunState.CANCELLED: ["inspect_events"],
        RunState.FAILED: ["inspect_events", "create_revised_experiment"],
    }
    limit, used, reserved = service.get_budget(run_id)
    blockers = (
        ["human_review_required"]
        if state == RunState.BLOCKED_REVIEW
        else ["external_state_reconciliation_required"]
        if state == RunState.BLOCKED_RECONCILIATION
        else ["safe_boundary_pending"]
        if state in {RunState.PAUSING, RunState.CANCELLING}
        else []
    )
    return RunResponse(
        run_id=run.run_id,
        experiment_id=run.experiment_id,
        state=state,
        revision=run.revision,
        event_sequence=run.event_sequence,
        champion_id=run.champion_id,
        budget_limit=limit,
        budget_used=used,
        budget_reserved=reserved,
        blockers=blockers,
        next_actions=actions[state],
    )


def _set_run_etag(response: Response, revision: int) -> None:
    response.headers["ETag"] = f'"{revision}"'


def _parse_if_match(value: str) -> int:
    normalized = value.strip()
    if normalized.startswith("W/"):
        raise HTTPException(status_code=400, detail="weak ETags are not valid for run mutation")
    if len(normalized) >= 2 and normalized[0] == normalized[-1] == '"':
        normalized = normalized[1:-1]
    try:
        revision = int(normalized)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="If-Match must contain a run revision") from exc
    if revision < 1:
        raise HTTPException(status_code=400, detail="If-Match revision must be positive")
    return revision


def create_app(data_dir: Path | None = None, *, api_token: str | None = None) -> FastAPI:
    directory = data_dir or Path(".avo")
    database = Database(directory / "avo.db")
    database.initialize()
    service = RunService(database)
    api = FastAPI(title="AVO-Correlate", version="1.0.0")
    api.state.database = database
    api.state.run_service = service
    api.state.query_service = QueryService(database)
    api.state.provenance_service = ProvenanceService(database)
    api.state.review_service = ReviewService(database)
    api.state.runtime_service = RuntimeService(database)
    api.state.api_token = api_token or os.environ.get("AVO_API_TOKEN")

    @api.exception_handler(NotFoundError)
    async def _not_found(_: Request, exc: NotFoundError) -> JSONResponse:
        return _problem(404, "not_found", str(exc), "Check the identifier and list events.")

    async def _conflict(_: Request, exc: Exception) -> JSONResponse:
        return _problem(
            409,
            "conflict",
            str(exc),
            "Refresh run status before choosing the next action.",
        )

    for conflict_type in (
        RevisionConflictError,
        DuplicateExperimentError,
        InvalidTransitionError,
    ):
        api.add_exception_handler(conflict_type, _conflict)

    @api.exception_handler(ReviewAuthorizationError)
    async def _review_forbidden(
        _: Request, exc: ReviewAuthorizationError
    ) -> JSONResponse:
        return _problem(403, "review_forbidden", str(exc), "Check reviewer role and evidence.")

    api.add_exception_handler(ReviewConflictError, _conflict)
    api.add_exception_handler(RuntimeConflictError, _conflict)

    @api.get("/healthz")
    def _health() -> dict[str, str]:
        return {"status": "ok"}

    @api.get("/readyz")
    def _ready(request: Request) -> dict[str, str]:
        if request.app.state.api_token is None:
            raise HTTPException(status_code=503, detail="AVO_API_TOKEN is not configured")
        return {"status": "ready"}

    @api.post("/v1/experiments/validate", response_model=ValidationResponse)
    def _validate_experiment(spec: ExperimentSpec) -> ValidationResponse:
        return ValidationResponse(
            experiment_id=spec.experiment_id,
            spec_digest=canonical_digest(spec),
        )

    @api.post("/v1/experiments", response_model=ExperimentResponse, status_code=201)
    def _create_experiment(
        spec: ExperimentSpec,
        request: Request,
        idempotency_key: Annotated[NonEmptyString, Header(alias="Idempotency-Key")],
        actor_id: Annotated[str, Depends(_authenticated_actor)],
    ) -> ExperimentResponse:
        digest = _services(request).create_experiment(
            spec, actor_id=actor_id, idempotency_key=idempotency_key
        )
        return ExperimentResponse(experiment_id=spec.experiment_id, spec_digest=digest)

    @api.get("/v1/experiments/{experiment_id}", response_model=ExperimentSpec)
    def _get_experiment(experiment_id: str, request: Request) -> ExperimentSpec:
        return _services(request).get_experiment(experiment_id)

    @api.post(
        "/v1/experiments/{experiment_id}/runs",
        response_model=RunResponse,
        status_code=201,
    )
    def _create_run(
        experiment_id: str,
        request: Request,
        response: Response,
        idempotency_key: Annotated[NonEmptyString, Header(alias="Idempotency-Key")],
        actor_id: Annotated[str, Depends(_authenticated_actor)],
    ) -> RunResponse:
        run_id = str(
            uuid5(NAMESPACE_URL, f"avo:{actor_id}:{experiment_id}:create-run:{idempotency_key}")
        )
        service = _services(request)
        service.create_run(
            experiment_id,
            actor_id=actor_id,
            run_id=run_id,
            prepare=True,
            idempotency_key=idempotency_key,
        )
        projected = _run_response(service, run_id)
        _set_run_etag(response, projected.revision)
        return projected

    @api.get("/v1/runs/{run_id}", response_model=RunResponse)
    def _get_run(run_id: str, request: Request, response: Response) -> RunResponse:
        projected = _run_response(_services(request), run_id)
        _set_run_etag(response, projected.revision)
        return projected

    @api.post("/v1/runs/{run_id}:start", response_model=RunResponse)
    def _start_run(
        run_id: str,
        request: Request,
        response: Response,
        if_match: Annotated[str, Header(alias="If-Match")],
        idempotency_key: Annotated[NonEmptyString, Header(alias="Idempotency-Key")],
        actor_id: Annotated[str, Depends(_authenticated_actor)],
    ) -> RunResponse:
        service = _services(request)
        service.transition(
            run_id,
            RunState.RUNNING,
            actor_id=actor_id,
            expected_revision=_parse_if_match(if_match),
            idempotency_key=idempotency_key,
            endpoint_scope=f"runs.{run_id}.start",
        )
        projected = _run_response(service, run_id)
        _set_run_etag(response, projected.revision)
        return projected

    @api.post("/v1/runs/{run_id}:pause", response_model=RunResponse)
    def _pause_run(
        run_id: str,
        request: Request,
        response: Response,
        if_match: Annotated[str, Header(alias="If-Match")],
        idempotency_key: Annotated[NonEmptyString, Header(alias="Idempotency-Key")],
        actor_id: Annotated[str, Depends(_authenticated_actor)],
    ) -> RunResponse:
        service = _services(request)
        service.transition(
            run_id,
            RunState.PAUSING,
            actor_id=actor_id,
            expected_revision=_parse_if_match(if_match),
            idempotency_key=idempotency_key,
            endpoint_scope=f"runs.{run_id}.pause",
        )
        service.settle_control_request(run_id, actor_id="control-plane")
        projected = _run_response(service, run_id)
        _set_run_etag(response, projected.revision)
        return projected

    @api.post("/v1/runs/{run_id}:resume", response_model=RunResponse)
    def _resume_run(
        run_id: str,
        request: Request,
        response: Response,
        if_match: Annotated[str, Header(alias="If-Match")],
        idempotency_key: Annotated[NonEmptyString, Header(alias="Idempotency-Key")],
        actor_id: Annotated[str, Depends(_authenticated_actor)],
    ) -> RunResponse:
        service = _services(request)
        service.transition(
            run_id,
            RunState.READY,
            actor_id=actor_id,
            expected_revision=_parse_if_match(if_match),
            idempotency_key=idempotency_key,
            endpoint_scope=f"runs.{run_id}.resume",
        )
        projected = _run_response(service, run_id)
        _set_run_etag(response, projected.revision)
        return projected

    @api.post("/v1/runs/{run_id}:cancel", response_model=RunResponse)
    def _cancel_run(
        run_id: str,
        request: Request,
        response: Response,
        if_match: Annotated[str, Header(alias="If-Match")],
        idempotency_key: Annotated[NonEmptyString, Header(alias="Idempotency-Key")],
        actor_id: Annotated[str, Depends(_authenticated_actor)],
    ) -> RunResponse:
        service = _services(request)
        run = service.get_run(run_id)
        state = RunState(run.state)
        if state not in {RunState.CANCELLED, RunState.CANCELLING}:
            target = (
                RunState.CANCELLED
                if state
                in {
                    RunState.CREATED,
                    RunState.READY,
                    RunState.PAUSED,
                    RunState.BLOCKED_RECONCILIATION,
                }
                else RunState.CANCELLING
            )
            service.transition(
                run_id,
                target,
                actor_id=actor_id,
                expected_revision=_parse_if_match(if_match),
                idempotency_key=idempotency_key,
                endpoint_scope=f"runs.{run_id}.cancel",
            )
            service.settle_control_request(run_id, actor_id="control-plane")
        projected = _run_response(service, run_id)
        _set_run_etag(response, projected.revision)
        return projected

    @api.get("/v1/runs/{run_id}/events", response_model=list[EventResponse])
    def _events(
        run_id: str,
        request: Request,
        after: Annotated[int, Query(ge=0)] = 0,
    ) -> list[EventResponse]:
        return [
            EventResponse(
                event_id=event.event_id,
                sequence=event.sequence,
                event_type=event.event_type,
                actor_id=event.actor_id,
                payload=cast(dict[str, object], json.loads(event.payload_json)),
            )
            for event in _services(request).list_events(run_id, after=after)
        ]

    @api.get("/v1/sessions/{session_id}", response_model=SessionProjection)
    def _session(session_id: str, request: Request) -> SessionProjection:
        service = cast(QueryService, request.app.state.query_service)
        return service.session(session_id)

    @api.get(
        "/v1/sessions/{session_id}/runtime", response_model=SessionRuntimeProjection
    )
    def _session_runtime(session_id: str, request: Request) -> SessionRuntimeProjection:
        service = cast(QueryService, request.app.state.query_service)
        return service.session_runtime(session_id)

    @api.post(
        "/v1/reconciliations/{reconciliation_id}:resolve",
        response_model=ReconciliationCaseRecord,
    )
    def _resolve_reconciliation(
        reconciliation_id: str,
        body: ReconciliationResolutionRequest,
        request: Request,
        idempotency_key: Annotated[NonEmptyString, Header(alias="Idempotency-Key")],
        actor_id: Annotated[str, Depends(_authenticated_actor)],
    ) -> ReconciliationCaseRecord:
        del idempotency_key  # The reconciliation record itself is idempotent by resolution.
        service = cast(RuntimeService, request.app.state.runtime_service)
        return service.resolve_reconciliation(
            reconciliation_id,
            resolution=body.resolution,
            note=body.note,
            actor_id=actor_id,
            result_digest=body.result_digest,
        )

    @api.get("/v1/candidates/{candidate_id}", response_model=CandidateProjection)
    def _candidate(candidate_id: str, request: Request) -> CandidateProjection:
        service = cast(QueryService, request.app.state.query_service)
        return service.candidate(candidate_id)

    @api.get(
        "/v1/artifacts/{digest}/metadata", response_model=ArtifactMetadataProjection
    )
    def _artifact(digest: str, request: Request) -> ArtifactMetadataProjection:
        service = cast(QueryService, request.app.state.query_service)
        return service.artifact(digest)

    @api.get("/v1/runs/{run_id}/provenance", response_model=ProvenanceExport)
    def _provenance(run_id: str, request: Request) -> ProvenanceExport:
        service = cast(ProvenanceService, request.app.state.provenance_service)
        return service.export_run(run_id)

    @api.post("/v1/provenance:verify", response_model=VerificationReport)
    def _verify_provenance(
        exported: ProvenanceExport, request: Request
    ) -> VerificationReport:
        service = cast(ProvenanceService, request.app.state.provenance_service)
        return service.verify(exported)

    @api.post("/v1/reviews/{review_id}/decisions", response_model=ReviewStatus)
    def _review_decision(
        review_id: str,
        decision: ReviewDecision,
        request: Request,
        idempotency_key: Annotated[NonEmptyString, Header(alias="Idempotency-Key")],
        reviewer_role: Annotated[NonEmptyString, Header(alias="X-Actor-Role")],
        actor_id: Annotated[str, Depends(_authenticated_actor)],
    ) -> ReviewStatus:
        if decision.review_id != review_id:
            raise ReviewAuthorizationError("review path and decision do not match")
        if decision.reviewer.actor_id != actor_id or decision.reviewer_role != reviewer_role:
            raise ReviewAuthorizationError("authenticated reviewer identity does not match body")
        service = cast(ReviewService, request.app.state.review_service)
        return service.submit(
            decision, actor_id=actor_id, idempotency_key=idempotency_key
        )

    return api


def _problem(status: int, code: str, detail: str, next_action: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={
            "type": f"urn:avo-correlate:problem:{code}",
            "title": code.replace("_", " "),
            "status": status,
            "detail": detail,
            "next_action": next_action,
        },
    )
