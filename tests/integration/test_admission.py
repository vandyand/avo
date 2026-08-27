from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from avo_correlate.adapters.persistence import Database
from avo_correlate.adapters.persistence.models import LineageRow
from avo_correlate.application.evidence_service import (
    EvidenceService,
    InvalidAdmissionError,
)
from avo_correlate.application.query_service import QueryService
from avo_correlate.application.run_service import RunService
from avo_correlate.application.session_service import SessionService
from avo_correlate.contracts.base import ActorRef
from avo_correlate.contracts.evaluation import AdmissionDecision, ComparisonRecord
from avo_correlate.contracts.lifecycle import RunState
from avo_correlate.contracts.policy import PolicyDecision
from avo_correlate.contracts.variation import (
    CandidateManifest,
    CandidateRef,
    VariationSessionRequest,
)
from tests.conftest import DIGEST_A, DIGEST_B, component, experiment_spec
from tests.unit.test_statistical_admission import evaluation


def setup_candidate(tmp_path: Path) -> tuple[Database, RunService, EvidenceService, str, str]:
    database = Database(tmp_path / "state.db")
    database.initialize()
    runs = RunService(database)
    runs.create_experiment(experiment_spec())
    runs.create_run("experiment-1", actor_id="tester", run_id="run-1", prepare=True)
    run = runs.get_run("run-1")
    assert run.champion_id is not None
    runs.transition("run-1", RunState.RUNNING, actor_id="tester")
    session_id = "session-1"
    sessions = SessionService(database)
    sessions.enqueue(
        VariationSessionRequest(
            session_id=session_id,
            run_id="run-1",
            champion=CandidateRef(
                candidate_id=run.champion_id,
                source_tree_digest=DIGEST_A,
                lineage_sequence=0,
            ),
            lineage_index_digest=DIGEST_A,
            initial_context_digest=DIGEST_B,
            tool_capability_token="token",
            development_evaluator_refs=[component("development")],
            budget_reservation_id="reservation-1",
            random_seed=1,
        )
    )
    evidence = EvidenceService(database)
    evidence.stage_candidate(
        CandidateManifest(
            candidate_id="candidate-1",
            run_id="run-1",
            session_id=session_id,
            parent_candidate_ids=[run.champion_id],
            base_workspace_digest=DIGEST_A,
            source_tree_digest=DIGEST_B,
            result_artifacts=[],
            harness_ref=component("recorded"),
            model_config_digest=DIGEST_A,
            context_digest=DIGEST_A,
            attempt_index_digest=DIGEST_B,
            execution_profile_digest=DIGEST_A,
            policy_bundle_digest=DIGEST_A,
            created_at=datetime.now(UTC),
        )
    )
    evidence.record_evaluation(
        evaluation("candidate-1", "14", "13", "15"), evaluator_key="admission:1"
    )
    policy = PolicyDecision(
        decision_id="policy-1",
        policy_engine_id="builtin-v1",
        policy_bundle_digest=DIGEST_A,
        action="candidate.admit",
        resource="run-1/candidate-1",
        input_digest=DIGEST_B,
        outcome="allow",
        reason_codes=["explicit_allow"],
        decided_at=datetime.now(UTC),
    )
    evidence.record_policy_decision("run-1", policy, candidate_id="candidate-1")
    return database, runs, evidence, run.champion_id, session_id


def decision(expected: str) -> AdmissionDecision:
    return AdmissionDecision(
        admission_id="admission-1",
        candidate_id="candidate-1",
        expected_champion_id=expected,
        evaluation_ids=["eval-candidate-1"],
        policy_decision_ids=["policy-1"],
        outcome="admit",
        reason_codes=["constraints_passed", "statistical_improvement"],
        comparison=ComparisonRecord(
            metric="score",
            direction="maximize",
            incumbent_value=Decimal("10"),
            candidate_value=Decimal("14"),
            minimum_effect=Decimal("2"),
            conclusion="improved",
        ),
        decided_by=ActorRef(actor_type="service", actor_id="admission-controller"),
        decided_at=datetime.now(UTC),
    )


def test_admission_is_cas_committed_once(tmp_path: Path) -> None:
    database, runs, evidence, champion, _ = setup_candidate(tmp_path)
    admission = decision(champion)
    assert evidence.commit_admission("run-1", admission) == 1
    assert evidence.commit_admission("run-1", admission) == 1
    assert runs.get_run("run-1").champion_id == "candidate-1"
    with database.session() as session:
        assert len(list(session.query(LineageRow))) == 2


def test_cancellation_fence_prevents_late_admission(tmp_path: Path) -> None:
    _, runs, evidence, champion, _ = setup_candidate(tmp_path)
    run = runs.get_run("run-1")
    runs.transition(
        "run-1", RunState.CANCELLING, actor_id="tester", expected_revision=run.revision
    )
    with pytest.raises(InvalidAdmissionError, match="cancellation fence"):
        evidence.commit_admission("run-1", decision(champion))


def test_non_improving_candidate_is_rejected_without_lineage_change(tmp_path: Path) -> None:
    database, runs, evidence, champion, _ = setup_candidate(tmp_path)
    rejected = decision(champion).model_copy(
        update={
            "admission_id": "admission-rejected",
            "outcome": "reject",
            "reason_codes": ["not_improved"],
            "comparison": ComparisonRecord(
                metric="score",
                direction="maximize",
                incumbent_value=Decimal("14"),
                candidate_value=Decimal("14"),
                minimum_effect=Decimal("2"),
                conclusion="not_improved",
            ),
        }
    )
    assert evidence.commit_admission("run-1", rejected) is None
    assert runs.get_run("run-1").champion_id == champion
    assert QueryService(database).candidate("candidate-1").state == "rejected"
