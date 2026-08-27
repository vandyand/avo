import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from pilot_target import reconcile_events


class EventPublicTests(unittest.TestCase):
    def test_unique_events_are_sorted(self) -> None:
        events = [
            {"event_id": "b", "sequence": 2, "payload": {"value": 2}},
            {"event_id": "a", "sequence": 1, "payload": {"value": 1}},
        ]
        self.assertEqual(reconcile_events(events), [events[1], events[0]])

    def test_empty_history(self) -> None:
        self.assertEqual(reconcile_events([]), [])


if __name__ == "__main__":
    unittest.main()
