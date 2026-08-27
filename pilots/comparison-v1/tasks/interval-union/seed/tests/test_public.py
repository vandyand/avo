import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from pilot_target import union_intervals


class IntervalPublicTests(unittest.TestCase):
    def test_disjoint_intervals(self) -> None:
        self.assertEqual(union_intervals([(1, 2), (5, 8)]), [(1, 2), (5, 8)])

    def test_overlapping_intervals(self) -> None:
        self.assertEqual(union_intervals([(1, 4), (3, 7)]), [(1, 7)])

    def test_invalid_interval(self) -> None:
        with self.assertRaises(ValueError):
            union_intervals([(3, 2)])


if __name__ == "__main__":
    unittest.main()
