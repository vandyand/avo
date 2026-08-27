import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from pilot_target import dependency_order


class DependencyPublicTests(unittest.TestCase):
    def test_simple_chain(self) -> None:
        self.assertEqual(
            dependency_order({"a": [], "b": ["a"], "c": ["b"]}),
            ["a", "b", "c"],
        )

    def test_empty_graph(self) -> None:
        self.assertEqual(dependency_order({}), [])


if __name__ == "__main__":
    unittest.main()
