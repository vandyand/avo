"""Read-only verification of the controlling Git baseline.

The command deliberately uses only Git inspection commands.  It is suitable for
recording as evidence after a repository has been bootstrapped by an operator.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit, urlunsplit


class BaselineError(RuntimeError):
    """A baseline check failed closed."""


def _git(root: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"},
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        raise BaselineError(f"git command failed: {detail.strip()}") from exc
    return result.stdout.strip()


def _safe_remote(raw: str) -> str:
    """Normalize a remote while removing URL userinfo (which may contain tokens)."""
    value = raw.strip()
    if "://" not in value:
        return value.rstrip("/")
    parsed = urlsplit(value)
    host = parsed.hostname or ""
    if parsed.port:
        host += f":{parsed.port}"
    return urlunsplit((parsed.scheme.lower(), host, parsed.path.rstrip("/"), "", ""))


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _load_protection(path: Path, branch: str, remote: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineError(f"invalid branch-protection evidence: {exc}") from exc
    if not isinstance(data, dict):
        raise BaselineError("branch-protection evidence must be a JSON object")
    record = cast(dict[str, object], data)
    if record.get("source") != "remote":
        raise BaselineError("branch-protection evidence must declare source=remote")
    if record.get("branch") != branch or record.get("remote") != remote:
        raise BaselineError("branch-protection evidence does not match baseline")
    if record.get("protected") is not True:
        raise BaselineError("branch-protection evidence does not prove protection")
    return {"branch": branch, "remote": remote, "protected": True, "source": "remote"}


def verify_baseline(
    root: Path,
    *,
    expected_commit: str | None = None,
    expected_tree: str | None = None,
    expected_remote: str | None = None,
    expected_branch: str = "main",
    protection_evidence: Path | None = None,
) -> dict[str, Any]:
    """Verify and return deterministic, secret-safe baseline evidence."""
    requested = root.resolve()
    if not requested.is_dir():
        raise BaselineError(f"repository root does not exist: {requested}")
    actual_root = Path(_git(requested, "rev-parse", "--show-toplevel")).resolve()
    if actual_root != requested:
        raise BaselineError(f"path is not the Git root (root is {actual_root})")

    branch = _git(requested, "symbolic-ref", "--quiet", "--short", "HEAD")
    if branch != expected_branch:
        raise BaselineError(f"branch mismatch: expected {expected_branch}, got {branch}")
    status = _git(requested, "status", "--porcelain=v1", "--untracked-files=all")
    if status:
        raise BaselineError("working tree is dirty")
    commit = _git(requested, "rev-parse", "HEAD")
    tree = _git(requested, "rev-parse", "HEAD^{tree}")
    remote_raw = _git(requested, "remote", "get-url", "origin")
    remote = _safe_remote(remote_raw)
    if not expected_remote:
        raise BaselineError("expected remote is required")
    if remote != _safe_remote(expected_remote):
        raise BaselineError("remote identity mismatch")
    if expected_commit and commit != expected_commit:
        raise BaselineError("commit baseline mismatch")
    if expected_tree and tree != expected_tree:
        raise BaselineError("tree baseline mismatch")

    evidence: dict[str, Any] = {
        "schema_version": 1,
        "root": str(actual_root),
        "branch": branch,
        "commit": commit,
        "tree": tree,
        "remote": {"name": "origin", "url": remote, "digest": _digest(remote)},
        "working_tree": "clean",
        "protection": {"source": "local", "verified": False},
    }
    if protection_evidence is not None:
        evidence["protection"] = _load_protection(protection_evidence, branch, remote)
    return evidence


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--expected-remote", required=True)
    parser.add_argument("--expected-branch", default="main")
    parser.add_argument("--expected-commit")
    parser.add_argument("--expected-tree")
    parser.add_argument("--protection-evidence", type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    try:
        print(json.dumps(verify_baseline(**vars(arguments)), sort_keys=True))
    except BaselineError as exc:
        print(f"baseline verification failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
