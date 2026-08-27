"""Workspace ingestion and archive extraction security controls."""

import os
import shutil
import stat
import subprocess
import tarfile
import unicodedata
import zipfile
from collections.abc import Iterable
from pathlib import Path, PurePosixPath

from avo_correlate.contracts.experiment import WorkspaceSpec, validate_manifest_path
from avo_correlate.domain.canonical import source_tree_digest


class UnsafeWorkspaceError(ValueError):
    pass


def create_vcs_free_binary_patch(
    baseline: Path,
    candidate: Path,
    *,
    git_metadata: Path,
    timeout_seconds: int = 60,
) -> bytes:
    """Compare VCS-free trees using a Git index stored outside both workspaces."""
    baseline = baseline.resolve(strict=True)
    candidate = candidate.resolve(strict=True)
    metadata = git_metadata.resolve()
    if metadata.is_relative_to(baseline) or metadata.is_relative_to(candidate):
        raise UnsafeWorkspaceError("Git metadata must be outside candidate workspaces")
    for root in (baseline, candidate):
        if any(path.name == ".git" for path in root.rglob(".git")):
            raise UnsafeWorkspaceError("candidate workspaces must be VCS-free")
    if metadata.exists():
        if not metadata.is_dir() or any(metadata.iterdir()):
            raise UnsafeWorkspaceError("Git metadata target must be an empty directory")
    else:
        metadata.mkdir(parents=True)
    environment = {
        "PATH": os.environ.get("PATH", ""),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }

    def git(
        *arguments: str,
        work_tree: Path | None = None,
        acceptable_codes: frozenset[int] = frozenset({0}),
    ) -> subprocess.CompletedProcess[bytes]:
        command = ["git", f"--git-dir={metadata}"]
        if work_tree is not None:
            command.append(f"--work-tree={work_tree}")
        command.extend(arguments)
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
            env=environment,
        )
        if result.returncode not in acceptable_codes:
            raise UnsafeWorkspaceError(
                f"external Git metadata operation failed: {result.stderr.decode(errors='replace')}"
            )
        return result

    init = subprocess.run(
        ["git", "init", "--bare", str(metadata)],
        capture_output=True,
        check=False,
        timeout=timeout_seconds,
        env=environment,
    )
    if init.returncode != 0:
        raise UnsafeWorkspaceError("could not initialize external Git metadata")
    git("add", "--all", work_tree=baseline)
    result = git(
        "diff",
        "--binary",
        "--no-ext-diff",
        "--",
        work_tree=candidate,
        acceptable_codes=frozenset({0, 1}),
    )
    return result.stdout


def validate_workspace(root: Path, spec: WorkspaceSpec) -> str:
    resolved_root = root.resolve(strict=True)
    seen: set[str] = set()
    files: set[str] = set()
    total_bytes = 0
    for path in sorted(resolved_root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(resolved_root).as_posix()
        normalized = unicodedata.normalize("NFC", relative)
        if normalized != relative:
            raise UnsafeWorkspaceError(f"path is not NFC-normalized: {relative}")
        collision_key = normalized.casefold()
        if collision_key in seen:
            raise UnsafeWorkspaceError(f"case or Unicode path collision: {relative}")
        seen.add(collision_key)
        if path.is_symlink():
            if spec.symlinks == "deny":
                raise UnsafeWorkspaceError(f"symlink is forbidden: {relative}")
            target = path.resolve(strict=True)
            if not target.is_relative_to(resolved_root):
                raise UnsafeWorkspaceError(f"symlink escapes workspace: {relative}")
            continue
        if path.name == ".git" and spec.submodules == "deny":
            raise UnsafeWorkspaceError(f"nested Git metadata is forbidden: {relative}")
        if not path.is_file():
            continue
        if os.stat(path, follow_symlinks=False).st_nlink > 1:
            raise UnsafeWorkspaceError(f"hardlinked file is forbidden: {relative}")
        if not _permitted(
            relative,
            [*spec.allowed_paths, *spec.required_paths],
            spec.forbidden_paths,
        ):
            raise UnsafeWorkspaceError(f"file is outside the workspace manifest: {relative}")
        size = path.stat().st_size
        if size > spec.max_file_bytes:
            raise UnsafeWorkspaceError(f"file exceeds maximum size: {relative}")
        total_bytes += size
        if total_bytes > spec.max_tree_bytes:
            raise UnsafeWorkspaceError("workspace exceeds maximum tree size")
        files.add(relative)
    for required in spec.required_paths:
        if required not in files and not any(item.startswith(required + "/") for item in files):
            raise UnsafeWorkspaceError(f"required path is missing: {required}")
    return source_tree_digest(resolved_root, symlinks=spec.symlinks)


def safe_extract_zip(
    archive: Path, destination: Path, *, max_file_bytes: int, max_tree_bytes: int
) -> None:
    destination = destination.resolve(strict=True)
    total = 0
    with zipfile.ZipFile(archive) as source:
        for member in source.infolist():
            relative = _archive_path(member.filename)
            mode = member.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise UnsafeWorkspaceError(f"archive symlink is forbidden: {relative}")
            if member.is_dir():
                continue
            total = _check_archive_size(member.file_size, total, max_file_bytes, max_tree_bytes)
            target = _safe_target(destination, relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            with source.open(member) as input_stream, target.open("xb") as output_stream:
                shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)


def safe_extract_tar(
    archive: Path, destination: Path, *, max_file_bytes: int, max_tree_bytes: int
) -> None:
    destination = destination.resolve(strict=True)
    total = 0
    with tarfile.open(archive, mode="r:*") as source:
        for member in source:
            relative = _archive_path(member.name)
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise UnsafeWorkspaceError(f"archive special entry is forbidden: {relative}")
            if member.isdir():
                continue
            if not member.isfile():
                raise UnsafeWorkspaceError(f"unsupported archive entry: {relative}")
            total = _check_archive_size(member.size, total, max_file_bytes, max_tree_bytes)
            input_stream = source.extractfile(member)
            if input_stream is None:
                raise UnsafeWorkspaceError(f"archive entry cannot be read: {relative}")
            target = _safe_target(destination, relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            with input_stream, target.open("xb") as output_stream:
                shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)


def _archive_path(value: str) -> str:
    value = value.removesuffix("/")
    try:
        return validate_manifest_path(value)
    except ValueError as exc:
        raise UnsafeWorkspaceError(f"unsafe archive path: {value}") from exc


def _safe_target(destination: Path, relative: str) -> Path:
    target = destination.joinpath(*PurePosixPath(relative).parts).resolve()
    if not target.is_relative_to(destination):
        raise UnsafeWorkspaceError(f"archive path escapes destination: {relative}")
    return target


def _check_archive_size(size: int, total: int, per_file: int, tree: int) -> int:
    if size < 0 or size > per_file:
        raise UnsafeWorkspaceError("archive entry exceeds size limit")
    total += size
    if total > tree:
        raise UnsafeWorkspaceError("archive exceeds tree size limit")
    return total


def _permitted(relative: str, allowed: Iterable[str], forbidden: Iterable[str]) -> bool:
    path = PurePosixPath(relative).parts
    allow = any(_within(path, PurePosixPath(item).parts) for item in allowed)
    deny = any(_within(path, PurePosixPath(item).parts) for item in forbidden)
    return allow and not deny


def _within(path: tuple[str, ...], prefix: tuple[str, ...]) -> bool:
    return len(path) >= len(prefix) and path[: len(prefix)] == prefix
