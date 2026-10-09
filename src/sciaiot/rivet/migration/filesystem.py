"""Bounded no-follow filesystem access for explicit trusted roots."""

import contextlib
import hashlib
import os
import pathlib
import stat
from collections.abc import Iterator

from sciaiot.rivet.migration.models import MAX_FILE_BYTES, MigrationError


def digest(data: bytes) -> str:
    """Return a SHA-256 consistency checksum, never a secret representation."""
    return hashlib.sha256(data).hexdigest()


@contextlib.contextmanager
def directory(path: pathlib.Path) -> Iterator[int]:
    """Open each directory component without following symlinks."""
    absolute = pathlib.Path(os.path.abspath(path))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute.parts[1:]:
            next_fd = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
            )
            os.close(fd)
            fd = next_fd
        yield fd
    except OSError:
        raise MigrationError("unsafe or unavailable directory") from None
    finally:
        os.close(fd)


def read_file(path: pathlib.Path, limit: int = MAX_FILE_BYTES) -> bytes:
    """Read a single-link regular file and detect concurrent replacement."""
    try:
        with directory(path.parent) as parent:
            fd = os.open(
                path.name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=parent,
            )
            try:
                before = os.fstat(fd)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or before.st_size > limit
                ):
                    raise MigrationError("unsafe file type or size limit")
                with os.fdopen(os.dup(fd), "rb") as stream:
                    data = stream.read(limit + 1)
                after = os.fstat(fd)
                current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                keys = ("st_ino", "st_dev", "st_size", "st_mtime_ns", "st_ctime_ns")
                if len(data) > limit or any(
                    getattr(before, key) != getattr(after, key)
                    or getattr(before, key) != getattr(current, key)
                    for key in keys
                ):
                    raise MigrationError("source changed during snapshot")
                return data
            finally:
                os.close(fd)
    except OSError:
        raise MigrationError("unsafe or unavailable file") from None


def tree(root: pathlib.Path, max_entries: int) -> tuple[list[str], list[str]]:
    """List a bounded tree, rejecting links and special nodes before reading."""
    files: list[str] = []
    directories: list[str] = []

    def walk(path: pathlib.Path, prefix: str) -> None:
        if prefix.count("/") >= 64:
            raise MigrationError("directory depth limit exceeded")
        with directory(path) as fd:
            names = []
            with os.scandir(fd) as entries:
                for entry in entries:
                    names.append(entry.name)
                    if len(names) + len(files) + len(directories) > max_entries:
                        raise MigrationError("file count limit exceeded")
            for name in sorted(names):
                relative = f"{prefix}/{name}" if prefix else name
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if len(files) + len(directories) >= max_entries:
                    raise MigrationError("file count limit exceeded")
                if stat.S_ISDIR(info.st_mode):
                    directories.append(relative)
                    walk(path / name, relative)
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    files.append(relative)
                else:
                    raise MigrationError("unsafe source node")

    walk(root, "")
    return files, directories


def write_private(path: pathlib.Path, data: bytes) -> None:
    """Exclusively create and durably write a private artifact."""
    with directory(path.parent) as parent:
        fd = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent,
        )
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
