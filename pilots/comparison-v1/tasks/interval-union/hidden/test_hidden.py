import sys
import unittest

sys.path.insert(0, "/workspace/src")

from pilot_target import union_intervals


class IntervalHiddenTests(unittest.TestCase):
    def test_touching_intervals_coalesce(self) -> None:
        self.assertEqual(union_intervals([(1, 3), (3, 5)]), [(1, 5)])

    def test_empty_intervals_are_omitted(self) -> None:
        self.assertEqual(union_intervals([(2, 2), (1, 4), (9, 9)]), [(1, 4)])

    def test_unsorted_nested_intervals(self) -> None:
        source = [(8, 10), (1, 9), (2, 3)]
        self.assertEqual(union_intervals(source), [(1, 10)])
        self.assertEqual(source, [(8, 10), (1, 9), (2, 3)])

    def test_negative_coordinates(self) -> None:
        self.assertEqual(union_intervals([(-2, 0), (-5, -2)]), [(-5, 0)])


if __name__ == "__main__":
    unittest.main()
