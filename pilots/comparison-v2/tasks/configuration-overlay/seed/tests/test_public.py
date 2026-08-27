import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from pilot_target import overlay_config


class ConfigurationPublicTests(unittest.TestCase):
    def test_scalar_replacement_and_new_key(self) -> None:
        self.assertEqual(
            overlay_config({"mode": "safe"}, {"mode": "fast", "workers": 2}),
            {"mode": "fast", "workers": 2},
        )

    def test_empty_override_preserves_values(self) -> None:
        self.assertEqual(overlay_config({"enabled": True}, {}), {"enabled": True})


if __name__ == "__main__":
    unittest.main()
