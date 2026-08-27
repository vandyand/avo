import sys
import unittest

sys.path.insert(0, "/workspace/src")

from pilot_target import reconcile_events


class EventHiddenTests(unittest.TestCase):
    def test_exact_duplicate_collapses(self) -> None:
        event = {"event_id": "a", "sequence": 1, "payload": {"value": 1}}
        self.assertEqual(reconcile_events([event, dict(event)]), [event])

    def test_conflicting_duplicate_is_invalid(self) -> None:
        with self.assertRaises(ValueError):
            reconcile_events([
                {"event_id": "a", "sequence": 1, "payload": {"value": 1}},
                {"event_id": "a", "sequence": 2, "payload": {"value": 2}},
            ])

    def test_shared_sequence_is_invalid(self) -> None:
        with self.assertRaises(ValueError):
            reconcile_events([
                {"event_id": "a", "sequence": 1, "payload": {}},
                {"event_id": "b", "sequence": 1, "payload": {}},
            ])

    def test_output_does_not_alias_inputs(self) -> None:
        source = {"event_id": "a", "sequence": 1, "payload": {"nested": [1]}}
        result = reconcile_events([source])
        self.assertIsNot(result[0], source)
        self.assertIsNot(result[0]["payload"], source["payload"])

    def test_invalid_shape_and_types(self) -> None:
        invalid = [
            {"event_id": "", "sequence": 1, "payload": {}},
            {"event_id": "a", "sequence": -1, "payload": {}},
            {"event_id": "a", "sequence": True, "payload": {}},
            {"event_id": "a", "sequence": 1, "payload": {}, "extra": 1},
        ]
        for event in invalid:
            with self.subTest(event=event), self.assertRaises(ValueError):
                reconcile_events([event])


if __name__ == "__main__":
    unittest.main()
