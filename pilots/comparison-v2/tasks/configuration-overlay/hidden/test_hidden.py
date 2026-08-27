import sys
import unittest

sys.path.insert(0, "/workspace/src")

from pilot_target import overlay_config


class ConfigurationHiddenTests(unittest.TestCase):
    def test_nested_mappings_merge(self) -> None:
        self.assertEqual(
            overlay_config(
                {"service": {"host": "localhost", "port": 80}},
                {"service": {"port": 443}},
            ),
            {"service": {"host": "localhost", "port": 443}},
        )

    def test_none_deletes_at_any_depth(self) -> None:
        self.assertEqual(
            overlay_config(
                {"keep": 1, "remove": 2, "nested": {"a": 1, "b": 2}},
                {"remove": None, "nested": {"a": None}},
            ),
            {"keep": 1, "nested": {"b": 2}},
        )

    def test_lists_replace_and_result_is_isolated(self) -> None:
        base = {"nested": {"items": [1, 2]}}
        override = {"other": [3]}
        result = overlay_config(base, override)
        result["nested"]["items"].append(9)
        result["other"].append(4)
        self.assertEqual(base, {"nested": {"items": [1, 2]}})
        self.assertEqual(override, {"other": [3]})

    def test_non_string_nested_key_is_invalid(self) -> None:
        with self.assertRaises(ValueError):
            overlay_config({"nested": {1: "invalid"}}, {})


if __name__ == "__main__":
    unittest.main()
