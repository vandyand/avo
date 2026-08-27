"""Read-only, bounded Git repository inspection for promotion dry-runs.

The adapter intentionally never checks out a ref or writes to the repository.  A
ref is materialized through ``git archive`` into a private temporary directory;
the resulting tree is scanned before it is hashed or used for a comparison.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import IO
from urllib.parse import urlsplit, urlunsplit

from avo_correlate.contracts.promotion_bundle import GitRefSnapshot, WorkspaceComparison
from avo_correlate.contracts.promotion_policy import is_valid_promotion_path


class GitRepositoryError(RuntimeError):
    """A repository, ref, archive, or candidate safety check failed closed."""


class StaleGitSnapshotError(GitRepositoryError):
    """The target ref changed after a snapshot was taken."""


@dataclass(frozen=True)
class _TreeScan:
    digest: str
    files: dict[str, tuple[int, str, int]]
    metadata: dict[str, tuple[int, int]]


class GitRepositoryReader:
    """Inspect one Git ref and compare it with a VCS-free candidate tree."""

    _COMMAND_TIMEOUT_SECONDS = 30
    _MAX_COMMAND_OUTPUT = 1024 * 1024

    def __init__(
        self,
        root: Path,
        target_ref: str,
        expected_remote: str,
        protection_evidence_digest: str,
        max_file_bytes: int,
        max_tree_bytes: int,
        max_entries: int = 100_000,
    ) -> None:
        if not target_ref or target_ref.startswith("-"):
            raise ValueError("target_ref must be a non-empty Git ref")
        if max_file_bytes <= 0 or max_tree_bytes <= 0:
            raise ValueError("tree bounds must be positive")
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        if not expected_remote:
            raise ValueError("expected_remote is required")
        self.root = root.resolve()
        self.target_ref = target_ref
        self.expected_remote = self._safe_remote(expected_remote)
        self.protection_evidence_digest = protection_evidence_digest
        self.max_file_bytes = max_file_bytes
        self.max_tree_bytes = max_tree_bytes
        self.max_entries = max_entries

    def snapshot(self) -> GitRefSnapshot:
        """Verify the repository and return a digest-bound immutable ref snapshot."""
        self._verify_git_root()
        remote = self._remote()
        if remote != self.expected_remote:
            raise GitRepositoryError("origin remote identity mismatch")
        commit, tree = self._resolve_ref()
        with self._materialized_archive(commit) as materialized:
            scanned = self._scan_tree(Path(materialized))
        return GitRefSnapshot(
            repository_digest=self._digest(remote),
            target_ref=self.target_ref,
            commit=commit,
            tree=tree,
            source_tree_digest=scanned.digest,
            protection_evidence_digest=self.protection_evidence_digest,
        )

    def compare_candidate(self, root: Path, snapshot: GitRefSnapshot) -> WorkspaceComparison:
        """Compare a VCS-free candidate against *snapshot* without mutating either tree."""
        self._verify_snapshot(snapshot)
        candidate = self._scan_candidate(root)
        with self._materialized_archive(snapshot.commit) as materialized:
            base = self._scan_tree(Path(materialized))
        if base.digest != snapshot.source_tree_digest:
            raise GitRepositoryError("ref archive digest differs from snapshot")
        changed_paths = sorted(
            path
            for path in set(base.files) | set(candidate.files)
            if base.files.get(path) != candidate.files.get(path)
        )
        changed_paths.sort(key=lambda path: (path.casefold(), path))
        if not changed_paths:
            raise GitRepositoryError("candidate has no changed files")
        return WorkspaceComparison(
            target_ref=self.target_ref,
            base_digest=base.digest,
            candidate_digest=candidate.digest,
            changed_paths=changed_paths,
        )

    def _verify_snapshot(self, snapshot: GitRefSnapshot) -> None:
        if snapshot.target_ref != self.target_ref:
            raise GitRepositoryError("snapshot does not belong to this repository/ref")
        if snapshot.repository_digest != self._digest(self.expected_remote):
            raise GitRepositoryError("snapshot remote digest mismatch")
        self._verify_git_root()
        if self._remote() != self.expected_remote:
            raise StaleGitSnapshotError("origin remote changed since snapshot")
        commit, tree = self._resolve_ref()
        if commit != snapshot.commit or tree != snapshot.tree:
            raise StaleGitSnapshotError("target ref changed since snapshot")

    def _verify_git_root(self) -> None:
        actual = Path(self._git("rev-parse", "--show-toplevel")).resolve()
        if actual != self.root:
            raise GitRepositoryError(f"path is not the Git root: {actual}")

    def _resolve_ref(self) -> tuple[str, str]:
        commit = self._git(
            "rev-parse", "--verify", "--end-of-options", f"{self.target_ref}^{{commit}}"
        )
        tree = self._git("rev-parse", "--verify", "--end-of-options", f"{commit}^{{tree}}")
        return commit, tree

    def _remote(self) -> str:
        return self._safe_remote(self._git("remote", "get-url", "origin"))

    def _git(self, *arguments: str) -> str:
        try:
            result = subprocess.run(
                ["git", *arguments],
                cwd=self.root,
                check=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self._COMMAND_TIMEOUT_SECONDS,
                shell=False,
                env={**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"},
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            detail = getattr(exc, "stderr", "") or str(exc)
            raise GitRepositoryError(self._redact(str(detail))[: self._MAX_COMMAND_OUTPUT]) from exc
        if len(result.stdout.encode("utf-8")) > self._MAX_COMMAND_OUTPUT:
            raise GitRepositoryError("Git command output exceeded configured bound")
        return result.stdout.strip()

    def _materialized_archive(self, commit: str) -> tempfile.TemporaryDirectory[str]:
        temporary = tempfile.TemporaryDirectory(prefix="avo-git-base-")
        try:
            self._archive_into(commit, Path(temporary.name))
        except BaseException:
            temporary.cleanup()
            raise
        return temporary

    def _archive_into(self, commit: str, destination: Path) -> None:
        try:
            process = subprocess.Popen(
                ["git", "archive", "--format=tar", commit],
                cwd=self.root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                env={**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0"},
            )
        except OSError as exc:
            raise GitRepositoryError(f"unable to start git archive: {exc}") from exc
        assert process.stdout is not None
        assert process.stderr is not None
        try:
            self._extract_archive(process.stdout, destination)
            process.stdout.close()
            stderr = process.stderr.read(self._MAX_COMMAND_OUTPUT + 1)
            return_code = process.wait(timeout=self._COMMAND_TIMEOUT_SECONDS)
            if len(stderr) > self._MAX_COMMAND_OUTPUT:
                raise GitRepositoryError("Git archive diagnostics exceeded configured bound")
            if return_code:
                raise GitRepositoryError(self._redact(stderr.decode("utf-8", "replace")))
        except BaseException as exc:
            process.kill()
            process.wait()
            if isinstance(exc, GitRepositoryError):
                raise
            raise GitRepositoryError(f"unsafe or invalid Git archive: {exc}") from exc
        finally:
            process.stdout.close()
            process.stderr.close()

    def _extract_archive(self, stream: IO[bytes], destination: Path) -> None:
        seen: set[str] = set()
        total = 0
        entries = 0
        with tarfile.open(fileobj=stream, mode="r|") as archive:
            for member in archive:
                entries += 1
                if entries > self.max_entries:
                    raise GitRepositoryError("archive entry count exceeds configured bound")
                relative = self._safe_relative(member.name, seen)
                if member.isdir():
                    continue
                if not member.isreg() or member.issym() or member.islnk():
                    raise GitRepositoryError(f"archive contains unsupported entry: {member.name}")
                if member.mode & 0o7000 or member.mode & 0o111 not in {0, 0o111}:
                    raise GitRepositoryError("archive contains unsupported file mode")
                if member.size > self.max_file_bytes:
                    raise GitRepositoryError("archive file exceeds configured bound")
                total += member.size
                if total > self.max_tree_bytes:
                    raise GitRepositoryError("archive tree exceeds configured bound")
                path = destination / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise GitRepositoryError("archive regular file has no payload")
                with source, path.open("xb") as target:
                    shutil.copyfileobj(source, target, length=1024 * 1024)
                path.chmod(member.mode & 0o777)

    def _scan_candidate(self, candidate_root: Path) -> _TreeScan:
        try:
            root = candidate_root.resolve(strict=True)
        except OSError as exc:
            raise GitRepositoryError(f"candidate root cannot be resolved: {exc}") from exc
        if self._is_reparse(candidate_root):
            raise GitRepositoryError("candidate root must not be a symlink")
        if not root.is_dir():
            raise GitRepositoryError("candidate root is not a directory")
        return self._scan_tree(root, require_vcs_free=True)

    def _scan_tree(self, root: Path, *, require_vcs_free: bool = False) -> _TreeScan:
        first = self._scan_tree_once(root, require_vcs_free=require_vcs_free)
        second = self._scan_tree_once(root, require_vcs_free=require_vcs_free)
        if (
            first.digest != second.digest
            or first.files != second.files
            or first.metadata != second.metadata
        ):
            raise GitRepositoryError("tree changed during stable scan")
        return first

    def _scan_tree_once(self, root: Path, *, require_vcs_free: bool = False) -> _TreeScan:
        records: list[bytes] = []
        files: dict[str, tuple[int, str, int]] = {}
        metadata_by_path: dict[str, tuple[int, int]] = {}
        seen_paths: set[str] = set()
        seen_inodes: set[tuple[int, int]] = set()
        total = 0
        entries = 0
        try:
            root = root.resolve(strict=True)
        except OSError as exc:
            raise GitRepositoryError(f"tree root cannot be resolved: {exc}") from exc
        for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
            entries += 1
            if entries > self.max_entries:
                raise GitRepositoryError("tree entry count exceeds configured bound")
            relative = path.relative_to(root).as_posix()
            safe = self._safe_relative(relative, seen_paths)
            if safe == ".git" or safe.startswith(".git/"):
                if require_vcs_free:
                    raise GitRepositoryError("candidate contains .git")
                raise GitRepositoryError("materialized archive contains .git")
            metadata = path.stat(follow_symlinks=False)
            if self._is_reparse(path) or path.is_symlink():
                raise GitRepositoryError(f"symlink or reparse point is not allowed: {safe}")
            mode = metadata.st_mode
            if stat.S_ISDIR(mode):
                continue
            if not stat.S_ISREG(mode):
                raise GitRepositoryError(f"unsupported file type: {safe}")
            if mode & 0o7000 or mode & 0o111 not in {0, 0o111}:
                raise GitRepositoryError(f"unsupported file mode: {safe}")
            identity = (metadata.st_dev, metadata.st_ino)
            if identity in seen_inodes:
                raise GitRepositoryError(f"hardlink alias is not allowed: {safe}")
            seen_inodes.add(identity)
            size = metadata.st_size
            if size > self.max_file_bytes:
                raise GitRepositoryError("candidate file exceeds configured bound")
            total += size
            if total > self.max_tree_bytes:
                raise GitRepositoryError("candidate tree exceeds configured bound")
            digest = self._file_digest(path, size, metadata)
            files[safe] = (size, digest, mode & 0o111)
            metadata_by_path[safe] = self._metadata_stamp(metadata)
            records.append(
                safe.encode("utf-8")
                + b"\0regular\0regular\0"
                + (b"755" if mode & 0o111 else b"644")
                + b"\0"
                + str(size).encode("ascii")
                + b"\0"
                + digest.encode("ascii")
                + b"\n"
            )
        return _TreeScan(
            "sha256:" + hashlib.sha256(b"".join(records)).hexdigest(),
            files,
            metadata_by_path,
        )

    def _safe_relative(self, value: str, seen: set[str]) -> str:
        if len(value) > 4096:
            raise GitRepositoryError("path exceeds configured bound")
        normalized = unicodedata.normalize("NFC", value)
        if not is_valid_promotion_path(normalized) or normalized != value:
            raise GitRepositoryError("path is not a portable normalized repository path")
        folded = normalized.casefold()
        if folded in seen:
            raise GitRepositoryError("case or Unicode path collision")
        seen.add(folded)
        return normalized

    @staticmethod
    def _file_digest(path: Path, expected_size: int, expected_metadata: os.stat_result) -> str:
        digest = hashlib.sha256()
        read = 0
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise GitRepositoryError(f"file cannot be opened safely: {path}") from exc
        try:
            opened = os.fstat(descriptor)
            GitRepositoryReader._validate_regular_metadata(opened)
            if not GitRepositoryReader._same_file_metadata(expected_metadata, opened):
                raise GitRepositoryError("file changed while being opened")
            with os.fdopen(descriptor, "rb", closefd=True) as handle:
                descriptor = -1
                while chunk := handle.read(1024 * 1024):
                    read += len(chunk)
                    digest.update(chunk)
            final = os.lstat(path)
            GitRepositoryReader._validate_regular_metadata(final)
            if not GitRepositoryReader._same_file_metadata(opened, final) or read != expected_size:
                raise GitRepositoryError("file changed while being hashed")
        finally:
            if descriptor != -1:
                os.close(descriptor)
        return "sha256:" + digest.hexdigest()

    @staticmethod
    def _same_file_metadata(left: os.stat_result, right: os.stat_result) -> bool:
        return (
            left.st_dev == right.st_dev
            and left.st_ino == right.st_ino
            and left.st_size == right.st_size
            and stat.S_IMODE(left.st_mode) == stat.S_IMODE(right.st_mode)
            and GitRepositoryReader._metadata_stamp(left)
            == GitRepositoryReader._metadata_stamp(right)
        )

    @staticmethod
    def _validate_regular_metadata(metadata: os.stat_result) -> None:
        if GitRepositoryReader._is_reparse_metadata(metadata):
            raise GitRepositoryError("reparse point is not allowed")
        if not stat.S_ISREG(metadata.st_mode):
            raise GitRepositoryError("file is not regular")
        if metadata.st_mode & 0o7000 or metadata.st_mode & 0o111 not in {0, 0o111}:
            raise GitRepositoryError("unsupported file mode")

    @staticmethod
    def _metadata_stamp(metadata: os.stat_result) -> tuple[int, int]:
        # Windows reports creation time as ctime and may update it merely by
        # opening a file; mtime is the stable mutation signal there.
        return (metadata.st_mtime_ns, metadata.st_ctime_ns if os.name != "nt" else 0)

    @staticmethod
    def _is_reparse(path: Path) -> bool:
        try:
            return GitRepositoryReader._is_reparse_metadata(os.lstat(path))
        except OSError as exc:
            raise GitRepositoryError(f"path cannot be inspected safely: {path}") from exc

    @staticmethod
    def _is_reparse_metadata(metadata: os.stat_result) -> bool:
        return bool((getattr(metadata, "st_file_attributes", 0) or 0) & 0x400)

    @staticmethod
    def _digest(value: str) -> str:
        return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _safe_remote(raw: str) -> str:
        value = raw.strip()
        if "://" not in value:
            return value.rstrip("/")
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        if parsed.port:
            host += f":{parsed.port}"
        return urlunsplit((parsed.scheme.lower(), host, parsed.path.rstrip("/"), "", ""))

    @staticmethod
    def _redact(value: str) -> str:
        return re.sub(r"([A-Za-z][A-Za-z0-9+.-]*://)[^\s/@]+@", r"\1", value)


GitRepository = GitRepositoryReader

__all__ = ["GitRepository", "GitRepositoryError", "GitRepositoryReader", "StaleGitSnapshotError"]
