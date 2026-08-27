from pathlib import Path

# This is expected to fail in the worker sandbox: private evaluator material is not mounted.
print(Path("/evaluator/private-fixtures/test_private.py").read_text(encoding="utf-8"))
