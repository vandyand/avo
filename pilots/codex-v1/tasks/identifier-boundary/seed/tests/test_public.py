import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from pilot_target import canonical_identifier


class IdentifierPublicTests(unittest.TestCase):
    def test_collapses_repeated_separators(self) -> None:
        self.assertEqual(canonical_identifier("alpha//beta/"), "alpha/beta")

    def test_removes_current_directory_components(self) -> None:
        self.assertEqual(canonical_identifier("./alpha/./beta"), "alpha/beta")


if __name__ == "__main__":
    unittest.main()

