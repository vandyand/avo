import sys
import unittest

sys.path.insert(0, "/workspace/src")

from pilot_target import best_window


class BestWindowHiddenTests(unittest.TestCase):
    def test_later_window_can_win(self) -> None:
        self.assertEqual(best_window([-4, 1, 8, 2], 2), (2, 10))

    def test_ties_choose_earliest(self) -> None:
        self.assertEqual(best_window([2, 2, 2], 2), (0, 4))

    def test_negative_values(self) -> None:
        self.assertEqual(best_window([-9, -4, -7], 1), (1, -4))

    def test_overlapping_windows(self) -> None:
        self.assertEqual(best_window([5, -10, 7, 7], 2), (2, 14))


if __name__ == "__main__":
    unittest.main()

