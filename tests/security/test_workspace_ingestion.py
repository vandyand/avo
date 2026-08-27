import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from avo_correlate.domain.workspace import (
    UnsafeWorkspaceError,
    safe_extract_tar,
    safe_extract_zip,
)


def test_zip_path_escape_is_blocked(tmp_path: Path) -> None:
    archive = tmp_path / "attack.zip"
    with zipfile.ZipFile(archive, "w") as target:
        target.writestr("../escape.txt", "owned")
    destination = tmp_path / "output"
    destination.mkdir()
    with pytest.raises(UnsafeWorkspaceError, match="unsafe archive path"):
        safe_extract_zip(
            archive, destination, max_file_bytes=1_000, max_tree_bytes=10_000
        )
    assert not (tmp_path / "escape.txt").exists()


def test_tar_symlink_and_hardlink_are_blocked(tmp_path: Path) -> None:
    for link_type in (tarfile.SYMTYPE, tarfile.LNKTYPE):
        archive = tmp_path / f"attack-{link_type!r}.tar"
        with tarfile.open(archive, "w") as target:
            data = b"safe"
            regular = tarfile.TarInfo("safe.txt")
            regular.size = len(data)
            target.addfile(regular, io.BytesIO(data))
            link = tarfile.TarInfo("link.txt")
            link.type = link_type
            link.linkname = "safe.txt"
            target.addfile(link)
        destination = tmp_path / f"output-{link_type!r}"
        destination.mkdir()
        with pytest.raises(UnsafeWorkspaceError, match="special entry"):
            safe_extract_tar(
                archive, destination, max_file_bytes=1_000, max_tree_bytes=10_000
            )


def test_archive_expansion_limits_are_enforced(tmp_path: Path) -> None:
    archive = tmp_path / "large.zip"
    with zipfile.ZipFile(archive, "w") as target:
        target.writestr("large.txt", "x" * 100)
    destination = tmp_path / "output"
    destination.mkdir()
    with pytest.raises(UnsafeWorkspaceError, match="size limit"):
        safe_extract_zip(archive, destination, max_file_bytes=10, max_tree_bytes=1_000)
