"""Bounded local archive storage using directory-relative operations."""

import os
import secrets
import stat
from collections.abc import Callable
from pathlib import Path

from sciaiot.rivet.application.storage import (
    ArchiveNotFoundError,
    ArchiveStoreError,
    archive_name,
    validate_content,
)
from sciaiot.rivet.application.vpn_control.schemas import MAX_ARCHIVE_BYTES


class LocalArchiveStore:
    """Keep archives under one configured directory with atomic replacement."""

    def __init__(self, directory: str | Path) -> None:
        """Remember the trusted archive directory without opening it yet."""
        self.directory = Path(directory)
        if not self.directory.is_absolute():
            raise ValueError("Archive directory must be absolute.")

    def _directory_fd(self, *, create: bool) -> int:
        """Open every directory component without following symlinks."""
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in self.directory.parts[1:]:
                if part in {"", ".", ".."}:
                    raise ArchiveStoreError("Invalid archive directory.")
                if create:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=descriptor)
                    except FileExistsError:
                        pass
                child = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
                os.close(descriptor)
                descriptor = child
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    def put(
        self,
        client_name: str,
        content: bytes,
        *,
        before_publish: Callable[[], None] | None = None,
    ) -> None:
        """Atomically replace one bounded archive without following links."""
        name = archive_name(client_name)
        data = validate_content(content)
        temporary = f".archive-{secrets.token_hex(16)}"
        try:
            directory = self._directory_fd(create=True)
            try:
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=directory,
                )
                try:
                    with os.fdopen(descriptor, "wb") as stream:
                        stream.write(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                    if before_publish is not None:
                        before_publish()
                    os.replace(
                        temporary,
                        name,
                        src_dir_fd=directory,
                        dst_dir_fd=directory,
                    )
                    os.fsync(directory)
                finally:
                    try:
                        os.unlink(temporary, dir_fd=directory)
                    except FileNotFoundError:
                        pass
            finally:
                os.close(directory)
        except (OSError, ArchiveStoreError) as error:
            raise ArchiveStoreError("Certificate archive write failed.") from error

    def get(self, client_name: str) -> bytes:
        """Read a stable, regular archive within the transfer size limit."""
        name = archive_name(client_name)
        try:
            directory = self._directory_fd(create=False)
            try:
                descriptor = os.open(
                    name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=directory,
                )
                try:
                    before = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(before.st_mode)
                        or before.st_nlink != 1
                        or before.st_size > MAX_ARCHIVE_BYTES
                    ):
                        raise ArchiveStoreError("Invalid certificate archive.")
                    with os.fdopen(descriptor, "rb", closefd=False) as stream:
                        content = stream.read(MAX_ARCHIVE_BYTES + 1)
                    after = os.fstat(descriptor)
                    if (
                        before.st_size,
                        before.st_mtime_ns,
                        before.st_ctime_ns,
                    ) != (
                        after.st_size,
                        after.st_mtime_ns,
                        after.st_ctime_ns,
                    ):
                        raise ArchiveStoreError("Certificate archive changed.")
                    return validate_content(content)
                finally:
                    os.close(descriptor)
            finally:
                os.close(directory)
        except FileNotFoundError as error:
            raise ArchiveNotFoundError("Certificate archive unavailable.") from error
        except (OSError, ArchiveStoreError) as error:
            if isinstance(error, ArchiveNotFoundError):
                raise
            raise ArchiveStoreError("Certificate archive read failed.") from error

    def delete(self, client_name: str) -> None:
        """Remove an archive if present without following its final symlink."""
        name = archive_name(client_name)
        try:
            directory = self._directory_fd(create=False)
            try:
                try:
                    os.unlink(name, dir_fd=directory)
                except FileNotFoundError:
                    pass
            finally:
                os.close(directory)
        except FileNotFoundError:
            pass
        except OSError as error:
            raise ArchiveStoreError("Certificate archive deletion failed.") from error

    def close(self) -> None:
        """No persistent local file handles are retained."""
