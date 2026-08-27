import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from pilot_target import allocate_integer


class AllocationPublicTests(unittest.TestCase):
    def test_even_split(self) -> None:
        self.assertEqual(allocate_integer(10, [1, 1]), [5, 5])

    def test_zero_total(self) -> None:
        self.assertEqual(allocate_integer(0, [4, 1]), [0, 0])

    def test_negative_total_is_invalid(self) -> None:
        with self.assertRaises(ValueError):
            allocate_integer(-1, [1])


if __name__ == "__main__":
    unittest.main()

