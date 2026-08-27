import sys
import unittest

sys.path.insert(0, "/workspace/src")

from pilot_target import dependency_order


class DependencyHiddenTests(unittest.TestCase):
    def test_ready_ties_use_mapping_insertion_order(self) -> None:
        self.assertEqual(dependency_order({"z": [], "a": [], "m": []}), ["z", "a", "m"])

    def test_diamond_is_stable(self) -> None:
        graph = {"root": [], "right": ["root"], "left": ["root"], "top": ["left", "right"]}
        self.assertEqual(dependency_order(graph), ["root", "right", "left", "top"])

    def test_cycle_is_invalid(self) -> None:
        with self.assertRaises(ValueError):
            dependency_order({"a": ["b"], "b": ["a"]})

    def test_missing_dependency_is_invalid(self) -> None:
        with self.assertRaises(ValueError):
            dependency_order({"a": ["missing"]})


if __name__ == "__main__":
    unittest.main()
