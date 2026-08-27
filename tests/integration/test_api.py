from pathlib import Path
from typing import Any, cast

from starlette.testclient import TestClient

from avo_correlate.api import create_app
from tests.conftest import experiment_spec

HEADERS = {
    "Authorization": "Bearer test-token",
    "Idempotency-Key": "request-1",
    "X-Actor-ID": "tester",
}


def test_operator_lifecycle_has_visible_states_and_recovery(tmp_path: Path) -> None:
    app = create_app(tmp_path, api_token="test-token")
    with cast(Any, TestClient(app)) as client:
        spec = experiment_spec().model_dump(mode="json")
        validated = client.post("/v1/experiments/validate", json=spec)
        assert validated.status_code == 200
        assert validated.json()["valid"] is True

        created = client.post("/v1/experiments", json=spec, headers=HEADERS)
        assert created.status_code == 201
        repeated = client.post("/v1/experiments", json=spec, headers=HEADERS)
        assert repeated.status_code == 201

        run = client.post("/v1/experiments/experiment-1/runs", headers=HEADERS)
        assert run.status_code == 201
        run_id = run.json()["run_id"]
        assert run.json()["state"] == "ready"
        assert run.json()["next_actions"] == ["start", "cancel"]
        assert run.json()["budget_used"]["tool_calls"] == 0
        assert run.json()["blockers"] == []
        assert run.headers["etag"] == '"3"'

        started = client.post(
            f"/v1/runs/{run_id}:start",
            headers={
                "Authorization": "Bearer test-token",
                "Idempotency-Key": "start-1",
                "If-Match": run.headers["etag"],
                "X-Actor-ID": "tester",
            },
        )
        assert started.json()["state"] == "running"
        assert "pause" in started.json()["next_actions"]
        assert started.headers["etag"] == '"4"'

        repeated_start = client.post(
            f"/v1/runs/{run_id}:start",
            headers={
                "Authorization": "Bearer test-token",
                "Idempotency-Key": "start-1",
                "If-Match": run.headers["etag"],
                "X-Actor-ID": "tester",
            },
        )
        assert repeated_start.status_code == 200
        assert repeated_start.json()["state"] == "running"

        paused = client.post(
            f"/v1/runs/{run_id}:pause",
            headers={
                "Authorization": "Bearer test-token",
                "Idempotency-Key": "pause-1",
                "If-Match": started.headers["etag"],
                "X-Actor-ID": "tester",
            },
        )
        assert paused.json()["state"] == "paused"
        assert paused.json()["next_actions"] == ["resume", "cancel"]

        resumed = client.post(
            f"/v1/runs/{run_id}:resume",
            headers={
                "Authorization": "Bearer test-token",
                "Idempotency-Key": "resume-1",
                "If-Match": paused.headers["etag"],
                "X-Actor-ID": "tester",
            },
        )
        assert resumed.json()["state"] == "ready"

        events = client.get(f"/v1/runs/{run_id}/events?after=0")
        assert [event["sequence"] for event in events.json()] == [1, 2, 3, 4, 5, 6, 7]
        provenance = client.get(f"/v1/runs/{run_id}/provenance")
        assert provenance.status_code == 200
        verified = client.post("/v1/provenance:verify", json=provenance.json())
        assert verified.json()["verified"] is True


def test_mutation_headers_and_not_found_are_actionable(tmp_path: Path) -> None:
    app = create_app(tmp_path, api_token="test-token")
    with cast(Any, TestClient(app)) as client:
        missing_headers = client.post(
            "/v1/experiments", json=experiment_spec().model_dump(mode="json")
        )
        assert missing_headers.status_code == 422
        missing = client.get("/v1/runs/unknown")
        assert missing.status_code == 404
        assert missing.json()["next_action"]


def test_run_mutations_require_and_validate_strong_revision_etags(tmp_path: Path) -> None:
    app = create_app(tmp_path, api_token="test-token")
    with cast(Any, TestClient(app)) as client:
        client.post(
            "/v1/experiments",
            json=experiment_spec().model_dump(mode="json"),
            headers=HEADERS,
        )
        created = client.post("/v1/experiments/experiment-1/runs", headers=HEADERS)
        run_id = created.json()["run_id"]
        mutation_headers = {
            "Authorization": "Bearer test-token",
            "Idempotency-Key": "start-2",
            "X-Actor-ID": "tester",
        }

        assert client.post(f"/v1/runs/{run_id}:start", headers=mutation_headers).status_code == 422
        weak = client.post(
            f"/v1/runs/{run_id}:start",
            headers={**mutation_headers, "If-Match": 'W/"3"'},
        )
        assert weak.status_code == 400
        stale = client.post(
            f"/v1/runs/{run_id}:start",
            headers={**mutation_headers, "If-Match": '"2"'},
        )
        assert stale.status_code == 409

        fetched = client.get(f"/v1/runs/{run_id}")
        assert fetched.headers["etag"] == '"3"'
