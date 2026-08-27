import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from pilot_target import retry_delays


class BackoffPublicTests(unittest.TestCase):
    def test_basic_schedule(self) -> None:
        self.assertEqual(retry_delays(100, 2, 3, 10_000), [100, 200, 400])

    def test_zero_attempts(self) -> None:
        self.assertEqual(retry_delays(100, 2, 0, 1_000), [])

    def test_invalid_factor(self) -> None:
        with self.assertRaises(ValueError):
            retry_delays(100, 0, 2, 1_000)


if __name__ == "__main__":
    unittest.main()
