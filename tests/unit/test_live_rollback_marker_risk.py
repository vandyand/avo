"""The fixed soak marker must remain an ordinary-risk candidate path."""

from avo_correlate.contracts.integration_soak import SOAK_MARKER_PATH
from avo_correlate.contracts.promotion_policy import PromotionPolicy, RiskClass


def test_fixed_live_rollback_marker_is_ordinary_risk() -> None:
    assert SOAK_MARKER_PATH == "src/avo_correlate/live_rollback_marker.txt"
    assert PromotionPolicy.derive_risk([SOAK_MARKER_PATH]) is RiskClass.ORDINARY

