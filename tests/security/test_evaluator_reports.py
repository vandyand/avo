import json

import pytest

from avo_correlate.domain.evaluator_reports import (
    InvalidEvaluatorReport,
    parse_evaluation_report,
)
from tests.unit.test_statistical_admission import evaluation


def valid_payload() -> bytes:
    record = evaluation("candidate", "2", "1", "3")
    return record.model_dump_json().encode()


def test_valid_report_is_accepted() -> None:
    assert (
        parse_evaluation_report(
            valid_payload(), max_bytes=100_000, declared_metrics=frozenset({"score"})
        ).candidate_id
        == "candidate"
    )


@pytest.mark.parametrize(
    "payload,match",
    [
        (b'{"schema_version":1,"schema_version":1}', "duplicate"),
        (b'{"metric":NaN}', "non-finite"),
        (b"{}", "schema validation"),
    ],
)
def test_malformed_reports_fail_closed(payload: bytes, match: str) -> None:
    with pytest.raises(InvalidEvaluatorReport, match=match):
        parse_evaluation_report(payload, max_bytes=1_000, declared_metrics=frozenset())


def test_oversized_and_undeclared_metrics_are_rejected() -> None:
    with pytest.raises(InvalidEvaluatorReport, match="byte limit"):
        parse_evaluation_report(
            valid_payload(), max_bytes=5, declared_metrics=frozenset({"score"})
        )
    document = json.loads(valid_payload())
    document["aggregate_metrics"]["undeclared"] = "1"
    with pytest.raises(InvalidEvaluatorReport, match="declaration mismatch"):
        parse_evaluation_report(
            json.dumps(document).encode(),
            max_bytes=100_000,
            declared_metrics=frozenset({"score"}),
        )
