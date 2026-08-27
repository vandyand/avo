import sys
import unittest

sys.path.insert(0, "/workspace/src")

from pilot_target import retry_delays


class BackoffHiddenTests(unittest.TestCase):
    def test_cap_below_base_applies_immediately(self) -> None:
        self.assertEqual(retry_delays(100, 3, 3, 50), [50, 50, 50])

    def test_factor_one_is_constant(self) -> None:
        self.assertEqual(retry_delays(7, 1, 4, 100), [7, 7, 7, 7])

    def test_large_integers_remain_exact(self) -> None:
        self.assertEqual(retry_delays(10**30, 10**5, 2, 10**100), [10**30, 10**35])

    def test_invalid_nonnegative_inputs(self) -> None:
        for arguments in ((-1, 2, 1, 10), (1, 2, -1, 10), (1, 2, 1, -1)):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                retry_delays(*arguments)


if __name__ == "__main__":
    unittest.main()
