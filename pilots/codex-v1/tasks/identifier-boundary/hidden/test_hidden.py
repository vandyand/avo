import sys
import unittest

sys.path.insert(0, "/workspace/src")

from pilot_target import canonical_identifier


class IdentifierHiddenTests(unittest.TestCase):
    def test_rejects_parent_traversal(self) -> None:
        for value in ("../secret", "alpha/../secret", r"alpha\..\secret"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                canonical_identifier(value)

    def test_rejects_absolute_paths(self) -> None:
        for value in ("/etc/passwd", r"\server\share", r"C:\temp\item"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                canonical_identifier(value)

    def test_rejects_empty_results(self) -> None:
        for value in ("", ".", "./"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                canonical_identifier(value)

    def test_normalizes_backslashes(self) -> None:
        self.assertEqual(canonical_identifier(r"alpha\beta"), "alpha/beta")


if __name__ == "__main__":
    unittest.main()

