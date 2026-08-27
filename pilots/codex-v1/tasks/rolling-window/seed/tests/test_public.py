import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from pilot_target import best_window


class BestWindowPublicTests(unittest.TestCase):
    def test_single_window(self) -> None:
        self.assertEqual(best_window([1, 2, 3], 3), (0, 6))

    def test_invalid_width(self) -> None:
        with self.assertRaises(ValueError):
            best_window([1], 0)


if __name__ == "__main__":
    unittest.main()

