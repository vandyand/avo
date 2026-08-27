"""Bounded workspace tools for one private variation session."""

import os
import stat
import subprocess
import tempfile
import unicodedata
from pathlib import Path, PurePosixPath

from avo_correlate.application.capabilities import CapabilityIssuer
from avo_correlate.contracts.experiment import WorkspaceSpec, validate_manifest_path
from avo_correlate.domain.workspace import create_vcs_free_binary_patch


class ToolPolicyError(ValueError):
    pass


class WorkspaceToolBroker:
    def __init__(
        self,
        root: Path,
        workspace: WorkspaceSpec,
        *,
        issuer: CapabilityIssuer,
        session_id: str,
        workspace_digest: str,
        baseline_root: Path | None = None,
        git_metadata_parent: Path | None = None,
    ) -> None:
        self._root = root.resolve(strict=True)
        self._spec = workspace
        self._issuer = issuer
        self._session_id = session_id
        self._workspace_digest = workspace_digest
        self._baseline_root = (
            None if baseline_root is None else baseline_root.resolve(strict=True)
        )
        self._git_metadata_parent = (
            None
            if git_metadata_parent is None
            else git_metadata_parent.resolve(strict=True)
        )
        if (self._baseline_root is None) != (self._git_metadata_parent is None):
            raise ValueError("baseline_root and git_metadata_parent must be configured together")

    def read_file(self, token: str, relative_path: str) -> bytes:
        self._authorize(token, "read_file")
        path = self._resolve(relative_path)
        if path.stat().st_size > self._spec.max_file_bytes:
            raise ToolPolicyError("file exceeds workspace read limit")
        return path.read_bytes()

    def search_workspace(
        self, token: str, pattern: str, *, max_results: int = 100, max_bytes: int = 100_000
    ) -> list[str]:
        self._authorize(token, "search_workspace")
        if not pattern:
            raise ToolPolicyError("search pattern cannot be empty")
        results: list[str] = []
        total = 0
        for path in sorted(self._root.rglob("*"), key=lambda item: item.as_posix()):
            if path.is_symlink() or not path.is_file() or ".git" in path.parts:
                continue
            relative = path.relative_to(self._root).as_posix()
            if not self._path_is_permitted(relative):
                continue
            if path.stat().st_size > self._spec.max_file_bytes:
                continue
            for line_number, line in enumerate(
                path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
            ):
                if pattern not in line:
                    continue
                item = f"{relative}:{line_number}:{line}"
                total += len(item.encode())
                if total > max_bytes or len(results) >= max_results:
                    return results
                results.append(item)
        return results

    def inspect_diff(self, token: str, *, max_bytes: int = 1_000_000) -> bytes:
        self._authorize(token, "inspect_diff")
        if self._baseline_root is not None and self._git_metadata_parent is not None:
            with tempfile.TemporaryDirectory(dir=self._git_metadata_parent) as temporary:
                payload = create_vcs_free_binary_patch(
                    self._baseline_root,
                    self._root,
                    git_metadata=Path(temporary),
                )
            if len(payload) > max_bytes:
                raise ToolPolicyError("diff exceeds output limit")
            return payload
        completed = subprocess.run(
            ["git", "diff", "--no-ext-diff", "--binary", "--"],
            cwd=self._root,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=30,
            check=False,
            shell=False,
        )
        if completed.returncode != 0:
            raise ToolPolicyError("git diff failed")
        if len(completed.stdout) > max_bytes:
            raise ToolPolicyError("diff exceeds output limit")
        return completed.stdout

    def apply_patch(self, token: str, patch: bytes) -> None:
        self._authorize(token, "apply_patch")
        if len(patch) > self._spec.max_tree_bytes:
            raise ToolPolicyError("patch exceeds workspace limit")
        self._validate_patch_paths(patch)
        for check_only in (True, False):
            command = ["git", "apply", "--whitespace=error-all"]
            if check_only:
                command.append("--check")
            completed = subprocess.run(
                command,
                cwd=self._root,
                input=patch,
                capture_output=True,
                timeout=30,
                check=False,
                shell=False,
            )
            if completed.returncode != 0:
                raise ToolPolicyError(
                    completed.stderr.decode("utf-8", errors="replace")[:1000]
                    or "git apply failed"
                )
        self._scan_after_mutation()

    def replace_text(self, token: str, relative_path: str, old: str, new: str) -> bytes:
        """Atomically replace one exact normalized text span in a permitted file."""
        self._authorize(token, "replace_text")
        path = self._resolve(relative_path)
        original_bytes = path.read_bytes()
        try:
            original = original_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ToolPolicyError("replace_text requires a UTF-8 file") from exc
        normalized = _normalize_newlines(original)
        normalized_old = _normalize_newlines(old)
        normalized_new = _normalize_newlines(new)
        occurrences = normalized.count(normalized_old)
        if not normalized_old or occurrences != 1:
            raise ToolPolicyError(
                f"old text must occur exactly once; found {occurrences} occurrences"
            )
        updated = normalized.replace(normalized_old, normalized_new, 1)
        updated = (
            updated.rstrip("\n") + "\n"
            if normalized.endswith("\n")
            else updated.rstrip("\n")
        )
        newline = "\r\n" if _uses_crlf_exclusively(original) else "\n"
        updated_bytes = updated.replace("\n", newline).encode("utf-8")
        if len(updated_bytes) > self._spec.max_file_bytes:
            raise ToolPolicyError("replacement exceeds workspace file limit")
        mode = stat.S_IMODE(path.stat().st_mode)
        _atomic_replace(path, updated_bytes, mode)
        try:
            self._scan_after_mutation()
        except Exception:
            _atomic_replace(path, original_bytes, mode)
            raise
        return updated_bytes

    def _authorize(self, token: str, tool_id: str) -> None:
        self._issuer.verify(
            token,
            session_id=self._session_id,
            workspace_digest=self._workspace_digest,
            tool_id=tool_id,
        )

    def _resolve(self, relative_path: str) -> Path:
        normalized = validate_manifest_path(relative_path)
        if not self._path_is_permitted(normalized):
            raise ToolPolicyError(f"workspace path is not permitted: {normalized}")
        candidate_raw = self._root.joinpath(*PurePosixPath(normalized).parts)
        current = self._root
        for segment in PurePosixPath(normalized).parts:
            current = current / segment
            if current.is_symlink():
                raise ToolPolicyError("symlinks are not permitted in workspace paths")
        candidate = candidate_raw.resolve(strict=True)
        if not candidate.is_relative_to(self._root):
            raise ToolPolicyError("resolved path escapes the workspace")
        if not candidate.is_file():
            raise ToolPolicyError("path is not a permitted regular file")
        return candidate

    def _path_is_permitted(self, relative_path: str) -> bool:
        parts = PurePosixPath(relative_path).parts
        allowed = any(
            _is_within(parts, PurePosixPath(item).parts)
            for item in self._spec.allowed_paths
        )
        forbidden = any(
            _is_within(parts, PurePosixPath(item).parts) for item in self._spec.forbidden_paths
        )
        return allowed and not forbidden

    def _validate_patch_paths(self, patch: bytes) -> None:
        try:
            lines = patch.decode("utf-8").splitlines()
        except UnicodeDecodeError as exc:
            raise ToolPolicyError("patch must be UTF-8") from exc
        headers = [line[4:] for line in lines if line.startswith(("--- ", "+++ "))]
        if not headers:
            raise ToolPolicyError("patch has no file headers")
        for header in headers:
            raw = header.split("\t", 1)[0]
            if raw == "/dev/null":
                continue
            if not raw.startswith(("a/", "b/")):
                raise ToolPolicyError("patch paths must use a/ and b/ prefixes")
            relative = validate_manifest_path(raw[2:])
            if not self._path_is_permitted(relative):
                raise ToolPolicyError(f"patch path is not permitted: {relative}")

    def _scan_after_mutation(self) -> None:
        seen: set[str] = set()
        total = 0
        for path in self._root.rglob("*"):
            if self._baseline_root is not None and path.name == ".git":
                raise ToolPolicyError("VCS metadata was created in the candidate workspace")
            if ".git" in path.parts:
                continue
            relative = unicodedata.normalize("NFC", path.relative_to(self._root).as_posix())
            collision_key = relative.casefold()
            if collision_key in seen:
                raise ToolPolicyError(f"path normalization collision: {relative}")
            seen.add(collision_key)
            if path.is_symlink():
                raise ToolPolicyError(f"symlink created by patch: {relative}")
            if path.is_file():
                size = path.stat().st_size
                if size > self._spec.max_file_bytes:
                    raise ToolPolicyError(f"file exceeds limit after patch: {relative}")
                total += size
        if total > self._spec.max_tree_bytes:
            raise ToolPolicyError("workspace exceeds tree limit after patch")


def _is_within(path: tuple[str, ...], prefix: tuple[str, ...]) -> bool:
    return len(path) >= len(prefix) and path[: len(prefix)] == prefix


def _normalize_newlines(value: str) -> str:
    return value.replace("\r\n", "\n").replace("\r", "\n")


def _uses_crlf_exclusively(value: str) -> bool:
    return "\r\n" in value and "\n" not in value.replace("\r\n", "")


def _atomic_replace(path: Path, payload: bytes, mode: int) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=path.parent, prefix=".avo-replace-", delete=False
        ) as temporary:
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.chmod(temporary_path, mode)
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
