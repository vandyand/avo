from pathlib import Path

# This is expected to fail in the read-only, capability-limited evaluator profile.
Path("/host-escape.txt").write_text("escape", encoding="utf-8")
