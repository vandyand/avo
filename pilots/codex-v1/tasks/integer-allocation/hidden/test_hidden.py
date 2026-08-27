import sys
import unittest

sys.path.insert(0, "/workspace/src")

from pilot_target import allocate_integer


class AllocationHiddenTests(unittest.TestCase):
    def test_equal_remainders_favor_lower_indexes(self) -> None:
        self.assertEqual(allocate_integer(2, [1, 1, 1]), [1, 1, 0])

    def test_largest_remainder_preserves_total(self) -> None:
        self.assertEqual(allocate_integer(7, [5, 3, 2]), [4, 2, 1])

    def test_zero_weight_receives_nothing(self) -> None:
        self.assertEqual(allocate_integer(7, [0, 5, 0]), [0, 7, 0])

    def test_invalid_weight_sets(self) -> None:
        for total, weights in ((1, []), (1, [0, 0]), (2, [1, -1])):
            with self.subTest(total=total, weights=weights), self.assertRaises(ValueError):
                allocate_integer(total, weights)

    def test_large_integer_weights_do_not_lose_precision(self) -> None:
        self.assertEqual(allocate_integer(1, [10**18, 1]), [1, 0])


if __name__ == "__main__":
    unittest.main()

